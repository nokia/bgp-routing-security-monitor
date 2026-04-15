#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RAVEN Demo Master Script
# Run from the raven project root: bash lab/demo-master.sh
#
#   demo-master.sh setup         — start full stack (lab + Routinator + RAVEN + Prometheus + Grafana)
#   demo-master.sh down          — stop everything in one command
#   demo-master.sh baseline      — show clean route table (slide 5)
#   demo-master.sh hijack        — inject origin hijack (slide 7)
#   demo-master.sh hijack-clean  — withdraw the hijack
#   demo-master.sh leak          — show route leak / ASPA detection (slide 8)
#   demo-master.sh leak-clean    — withdraw the route leak
#   demo-master.sh whatif        — run what-if simulator (slide 9)
#   demo-master.sh recommend     — run ASPA recommender (slide 10)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RAVEN_BIN="./raven"
RAVEN_ADDR="localhost:11020"
EDGE_CONTAINER="clab-raven-demo-edge"
GRAFANA_URL="http://localhost:3000/d/raven-security-posture"

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

header()  { echo -e "\n${CYAN}${BOLD}━━━  $1  ━━━${RESET}\n"; }
step()    { echo -e "${BOLD}▶ $1${RESET}"; }
ok()      { echo -e "${GREEN}✓ $1${RESET}"; }
warn()    { echo -e "${YELLOW}⚠ $1${RESET}"; }
alert()   { echo -e "${RED}🚨 $1${RESET}"; }

# Poll until FRR inside a container is accepting vtysh commands, or timeout.
wait_for_frr() {
  local container=$1
  local timeout=30
  local elapsed=0
  echo -n "  Waiting for FRR in $container..."
  while ! docker exec "$container" vtysh -c "show version" > /dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    echo -n "."
    if [ $elapsed -ge $timeout ]; then
      echo ""
      warn "FRR in $container did not become ready in ${timeout}s"
      return 1
    fi
  done
  echo " ready"
}

# ── get the WSL host IP that Docker containers can reach ─────────────────────
# ─────────────────────────────────────────────────────────────────────────────
CMD="${1:-help}"

case "$CMD" in

# ── SETUP ────────────────────────────────────────────────────────────────────
setup)
  header "RAVEN Demo Setup"

  # ── Containerlab ──
  step "Starting Containerlab topology..."
  cd lab && sudo containerlab deploy -t raven-demo.clab.yaml --reconfigure 2>/dev/null || true
  cd ..

  # Give FRR routers time to come up and establish BGP sessions before
  # RAVEN starts — this ensures a clean single table dump, not a mix of
  # incremental updates from a partially-converged topology.
  echo "  Waiting 15s for FRR BGP sessions to converge..."
  sleep 15

  # Wait for FRR to be vtysh-ready in all three containers before any config push.
  wait_for_frr clab-raven-demo-internet
  wait_for_frr clab-raven-demo-upstream
  wait_for_frr clab-raven-demo-edge

  # ── Routinator ──
  step "Starting Routinator..."
  pkill -x routinator 2>/dev/null || true
  sleep 1
  routinator server > /tmp/routinator.log 2>&1 &
  echo "  Waiting for Routinator to sync (up to 60s)..."
  for i in $(seq 1 12); do
    if curl -s http://127.0.0.1:8323/api/v1/status 2>/dev/null | grep -q '"vrpsTotal"'; then
      ok "Routinator ready"; break
    fi
    sleep 5; echo -n "."
  done
  echo ""

  # ── RAVEN — start AFTER lab is converged for a clean table dump ──
  step "Starting RAVEN daemon..."
  pkill -f "raven serve" 2>/dev/null || true
  sleep 2
  $RAVEN_BIN serve --config raven.yaml > /tmp/raven.log 2>&1 &

  # Wait for RTR sync (VRPs loaded) before checking routes
  echo "  Waiting for RAVEN to sync with Routinator..."
  for i in $(seq 1 12); do
    if grep -q "RTR sync complete" /tmp/raven.log 2>/dev/null; then
      ok "RAVEN RTR sync complete"; break
    fi
    sleep 5; echo -n "."
  done
  echo ""

  # Wait for BMP table dump to finish — both peers should have sent their full table
  echo "  Waiting for BMP table dump to settle..."
  sleep 8

  # ── Install permanent route-map on upstream for ASPA leak scenario ──────────
  # This route-map prepends AS2121 on 193.0.0.0/21 when upstream sends it to
  # the edge router, ensuring the AS_PATH [65000 2121] is always present for
  # ASPA validation. It is permanent infrastructure — never touched by
  # inject/clean cycles.
  step "Installing permanent ROUTE-LEAK route-map on upstream (AS65000)..."
  # seq 10: prepend AS2121 onto 193.0.0.0/21 → edge sees [65000,2121,2121], ASPA invalid
  # seq 20: prepend AS65001 onto 10.10.0.0/24 → edge sees [65000,65001], origin-invalid
  # seq 30: catch-all permit — without this FRR denies all other routes to edge
  if ! docker exec clab-raven-demo-upstream vtysh \
      -c "configure terminal" \
      -c "ip prefix-list LEAK-PREFIX permit 193.0.0.0/21" \
      -c "ip prefix-list EDGE-HIJACK-PREFIX permit 10.10.0.0/24" \
      -c "route-map ROUTE-LEAK permit 10" \
      -c " match ip address prefix-list LEAK-PREFIX" \
      -c " set as-path prepend 2121" \
      -c "exit" \
      -c "route-map ROUTE-LEAK permit 20" \
      -c " match ip address prefix-list EDGE-HIJACK-PREFIX" \
      -c " set as-path prepend 65001" \
      -c "exit" \
      -c "route-map ROUTE-LEAK permit 30" \
      -c "exit" \
      -c "router bgp 65000" \
      -c " address-family ipv4 unicast" \
      -c "  neighbor 10.0.0.2 route-map ROUTE-LEAK out" \
      -c " exit-address-family" \
      -c "end" ; then
    warn "Route-map install failed. Output:"
    docker exec clab-raven-demo-upstream vtysh -c "show running-config" 2>&1 | tail -20
  else
    ok "ROUTE-LEAK route-map installed on upstream"
  fi

  # Trigger a soft outbound reset so upstream resends all routes to edge
  # with the newly applied ROUTE-LEAK route-map (updated AS-paths)
  echo "  Triggering soft reset to push updated AS-paths to edge..."
  docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp 10.0.0.2 soft out" 2>/dev/null || true
  sleep 5

  # ── Inject the unverified demo route (no ROA, no ASPA — shows all posture states) ──
  step "Injecting unverified demo route (10.99.99.0/24)..."
  if ! docker exec clab-raven-demo-upstream vtysh \
      -c "configure terminal" \
      -c "router bgp 65000" \
      -c " address-family ipv4 unicast" \
      -c "  network 10.99.99.0/24" \
      -c " exit-address-family" \
      -c "end" ; then
    warn "Could not inject unverified demo route. Output:"
    docker exec clab-raven-demo-upstream vtysh -c "show running-config" 2>&1 | tail -20
  else
    sleep 3
    ok "Unverified route injected (no ROA = unverified posture in Grafana)"
  fi

  # ── Prometheus — always use 172.17.0.1 (Docker bridge gateway, stable across sessions) ──
  step "Starting Prometheus..."
  cat > /tmp/prometheus.yml << 'PROMEOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'raven'
    static_configs:
      - targets: ['172.17.0.1:9595']
PROMEOF

  sudo docker rm -f prometheus 2>/dev/null || true
  sudo docker run -d \
    --name prometheus \
    -p 9090:9090 \
    -v /tmp/prometheus.yml:/etc/prometheus/prometheus.yml \
    prom/prometheus:latest > /dev/null

  # Wait for Prometheus to start and run its first scrape
  echo "  Waiting for Prometheus first scrape..."
  for i in $(seq 1 10); do
    HEALTH=$(curl -s 'http://localhost:9090/api/v1/targets' 2>/dev/null \
      | python3 -c "import json,sys; t=json.load(sys.stdin)['data']['activeTargets']; print(t[0]['health'] if t else 'pending')" 2>/dev/null || echo "pending")
    if [ "$HEALTH" = "up" ]; then
      ok "Prometheus scraping RAVEN at 172.17.0.1:9595"; break
    fi
    sleep 5; echo -n "."
  done
  echo ""
  if [ "$HEALTH" != "up" ]; then
    warn "Prometheus target not yet up — may need another scrape cycle (15s)"
  fi

  # ── Grafana ──
  step "Starting Grafana..."
  if sudo docker ps -a --format '{{.Names}}' | grep -q '^grafana$'; then
    sudo docker start grafana > /dev/null
  else
    sudo docker run -d \
      --name grafana \
      -p 3000:3000 \
      -e GF_SECURITY_ADMIN_PASSWORD=raven123 \
      grafana/grafana:latest > /dev/null
  fi
  sleep 6

  # ── Configure Grafana datasource — always point at Prometheus on Docker bridge ──
  step "Configuring Grafana datasource..."
  DS_RESPONSE=$(curl -s http://admin:raven123@localhost:3000/api/datasources)
  DS_ID=$(echo "$DS_RESPONSE" | python3 -c "
import json,sys
sources=json.load(sys.stdin)
prom=next((s for s in sources if s['type']=='prometheus'),None)
print(prom['id'] if prom else 'new')
" 2>/dev/null || echo "new")
  DS_UID=$(echo "$DS_RESPONSE" | python3 -c "
import json,sys
sources=json.load(sys.stdin)
prom=next((s for s in sources if s['type']=='prometheus'),None)
print(prom['uid'] if prom else '')
" 2>/dev/null || echo "")

  DS_PAYLOAD="{
    \"name\": \"Prometheus\",
    \"type\": \"prometheus\",
    \"access\": \"proxy\",
    \"url\": \"http://172.17.0.1:9090\",
    \"isDefault\": true,
    \"jsonData\": {\"httpMethod\": \"POST\"}
  }"

  if [ "$DS_ID" = "new" ]; then
    curl -s -X POST http://admin:raven123@localhost:3000/api/datasources \
      -H "Content-Type: application/json" -d "$DS_PAYLOAD" > /dev/null
    DS_ID=$(curl -s http://admin:raven123@localhost:3000/api/datasources | python3 -c "
import json,sys; sources=json.load(sys.stdin)
print(next(s['id'] for s in sources if s['type']=='prometheus'))")
  else
    curl -s -X PUT "http://admin:raven123@localhost:3000/api/datasources/${DS_ID}" \
      -H "Content-Type: application/json" \
      -d "{\"id\":${DS_ID},\"uid\":\"${DS_UID}\",\"name\":\"Prometheus\",\"type\":\"prometheus\",\"access\":\"proxy\",\"url\":\"http://172.17.0.1:9090\",\"isDefault\":true,\"jsonData\":{\"httpMethod\":\"POST\"}}" > /dev/null
  fi
  ok "Grafana datasource → Prometheus at http://172.17.0.1:9090"

  # ── Import dashboard ──
  step "Importing Grafana dashboard..."
  PROM_UID=$(curl -s http://admin:raven123@localhost:3000/api/datasources | python3 -c "
import json,sys; sources=json.load(sys.stdin)
print(next(s['uid'] for s in sources if s['type']=='prometheus'))")
  curl -s -X POST http://admin:raven123@localhost:3000/api/dashboards/import \
    -H "Content-Type: application/json" \
    -d "{\"dashboard\":$(cat lab/grafana-dashboard.json),\"overwrite\":true,\"inputs\":[{\"name\":\"DS_PROMETHEUS\",\"type\":\"datasource\",\"pluginId\":\"prometheus\",\"value\":\"$PROM_UID\"}]}" \
    > /dev/null && ok "Dashboard imported" || warn "Dashboard import failed — import manually from lab/grafana-dashboard.json"

  # ── Final check ──
  echo ""
  step "Route table (should be stable and consistent):"
  $RAVEN_BIN --address $RAVEN_ADDR routes
  echo ""
  ok "Setup complete."
  echo ""
  echo "  Grafana:    http://localhost:3000/d/raven-security-posture  (admin / raven123)"
  echo "  Prometheus: http://localhost:9090"
  echo "  RAVEN API:  http://localhost:11020"
  echo "  Metrics:    http://localhost:9595/metrics"
  echo ""
  echo "  Expected postures (baseline — 5 routes, path-suspect = 0):"
  echo "    origin-only    → 100.64.0.0/24, 198.51.100.0/24, 203.0.113.0/24"
  echo "    origin-invalid → 10.10.0.0/24  (permanent baseline)"
  echo "    unverified     → 10.99.99.0/24 (no ROA)"
  echo "    path-suspect   → (none at baseline — run 'leak' to inject)"
  ;;

# ── DOWN — stop everything in one command ────────────────────────────────────
down)
  header "Bringing Down RAVEN Demo"
  pkill -f "raven serve"   2>/dev/null && ok "RAVEN stopped"      || warn "RAVEN was not running"
  pkill -x routinator      2>/dev/null && ok "Routinator stopped" || warn "Routinator was not running"
  sudo docker stop prometheus grafana 2>/dev/null && ok "Prometheus + Grafana stopped" || warn "Containers were not running"
  cd lab && sudo containerlab destroy -t raven-demo.clab.yaml 2>/dev/null && ok "Lab destroyed" || warn "Lab was not running"
  cd ..
  ok "All done."
  ;;

# ── BASELINE ─────────────────────────────────────────────────────────────────
baseline)
  header "Baseline — Clean Route Table"

  step "BMP peers connected:"
  $RAVEN_BIN --address $RAVEN_ADDR peers
  echo ""

  step "Current route table (all routes):"
  $RAVEN_BIN --address $RAVEN_ADDR routes
  echo ""

  warn "Note: 10.10.0.0/24 shows origin-invalid at baseline — the lab's permanent demo route."
  ok "Everything else is origin-only (Valid ROV, Unknown ASPA — lab ASNs have no ASPA objects)."
  ;;

# ── HIJACK ───────────────────────────────────────────────────────────────────
hijack)
  header "Attack Scenario 1 — Origin Hijack"

  alert "INJECTING BGP ORIGIN HIJACK"
  echo ""
  echo "  Prefix:             192.0.2.0/24"
  echo "  Legitimate origin:  AS65000  (per ROA in Routinator)"
  echo "  Hijacking router:   AS2121   (internet router — peer 10.0.0.1 via upstream)"
  echo ""
  echo "  Method: internet router (AS2121) originates 192.0.2.0/24 directly."
  echo "  Route travels AS2121 → AS65000 → AS65001, arriving as genuine pre-policy"
  echo "  at RAVEN via BMP. Origin AS2121 ≠ ROA origin AS65000 → ROV Invalid."
  echo ""

  step "Route table BEFORE hijack:"
  $RAVEN_BIN --address $RAVEN_ADDR routes | grep "192.0.2" || echo "  (not present — correct)"
  echo ""

  step "Injecting hijack via internet router (AS2121)..."
  docker exec clab-raven-demo-internet vtysh \
    -c "configure terminal" \
    -c "ip route 192.0.2.0/24 blackhole" \
    -c "router bgp 2121" \
    -c " address-family ipv4 unicast" \
    -c "  network 192.0.2.0/24" \
    -c " exit-address-family" \
    -c "end"

  echo "  Waiting 5s for BMP propagation..."
  sleep 5

  step "RAVEN detection:"
  $RAVEN_BIN --address $RAVEN_ADDR routes --posture origin-invalid
  echo ""

  alert "HIJACK DETECTED — switch to Grafana: $GRAFANA_URL"
  ;;

# ── HIJACK CLEAN ─────────────────────────────────────────────────────────────
hijack-clean)
  header "Withdrawing Hijack"
  docker exec clab-raven-demo-internet vtysh \
    -c "configure terminal" \
    -c "no ip route 192.0.2.0/24 blackhole" \
    -c "router bgp 2121" \
    -c " address-family ipv4 unicast" \
    -c "  no network 192.0.2.0/24" \
    -c " exit-address-family" \
    -c "end"
  sleep 4
  step "Route table after withdrawal:"
  $RAVEN_BIN --address $RAVEN_ADDR routes | grep "192.0.2" || echo "  (withdrawn — correct)"
  ok "Route table clean."
  ;;

# ── ROUTE LEAK ───────────────────────────────────────────────────────────────
leak)
  header "Attack Scenario 2 — Route Leak (ASPA)"

  echo "  Prefix:         193.0.0.0/21"
  echo "  Origin:         AS2121  (RIPE NCC — has valid ROA)"
  echo "  ASPA providers: AS3333 only"
  echo "  Simulated path: AS2121 → AS65000 → AS65001"
  echo "  Mechanism:      AS65000 originates 193.0.0.0/21, route-map prepends AS2121"
  echo "                  Edge sees AS_PATH [65000 2121], origin=AS2121"
  echo "  Violation:      AS65000 is NOT an authorised provider of AS2121"
  echo ""

  # ── Step 1: BEFORE state — 193.0.0.0/21 not in table, path-suspect = 0 ──
  step "BEFORE — path-suspect routes (should be empty):"
  $RAVEN_BIN --address $RAVEN_ADDR routes --posture path-suspect 2>&1 || true
  echo "  (none — path-suspect = 0)"
  echo ""
  ok "Baseline confirmed: path-suspect counter = 0 in Grafana"
  echo ""

  # ── Step 2: Originate 193.0.0.0/21 on upstream (AS65000) ──
  # The existing ROUTE-LEAK route-map (seq 10) prepends AS2121 on 193.0.0.0/21
  # when sending to the edge neighbour, so edge receives AS_PATH [65000 2121].
  # AS65000 is not in AS2121's ASPA provider set (only AS3333) → ASPA:Invalid.
  step "Injecting 193.0.0.0/21 on upstream (AS65000) — simulating route leak..."
  docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "ip route 193.0.0.0/21 blackhole" \
    -c "router bgp 65000" \
    -c " address-family ipv4 unicast" \
    -c "  network 193.0.0.0/21" \
    -c " exit-address-family" \
    -c "end"
  echo "  Triggering soft outbound reset to push route to edge immediately..."
  docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp 10.0.0.2 soft out" 2>/dev/null || true
  echo "  Waiting 5s for BMP propagation..."
  sleep 5

  # ── Step 3: Show detection ──
  step "RAVEN detection — 193.0.0.0/21 (ROV:Valid, ASPA:Invalid, posture:path-suspect):"
  $RAVEN_BIN --address $RAVEN_ADDR routes --prefix 193.0.0.0/21
  echo ""

  warn "ROV shows Valid — the origin AS2121 is legitimate."
  warn "A router running only ROV would accept this route with no alarm."
  echo ""
  echo "  Failing hop:  AS2121 (customer) → AS65000 (provider)"
  echo "  Reason:       AS65000 not in AS2121 ASPA provider set (only AS3333 is)"
  echo ""

  alert "ROUTE LEAK DETECTED — ASPA caught what ROV missed."
  echo ""
  alert "Switch to Grafana: $GRAFANA_URL"
  echo "  The path-suspect counter should have ticked up by 1."
  ;;

# ── LEAK CLEAN ───────────────────────────────────────────────────────────────
leak-clean)
  header "Withdrawing Route Leak"
  docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "no ip route 193.0.0.0/21 blackhole" \
    -c "router bgp 65000" \
    -c " address-family ipv4 unicast" \
    -c "  no network 193.0.0.0/21" \
    -c " exit-address-family" \
    -c "end" > /dev/null 2>&1 || true
  echo "  Triggering soft outbound reset to withdraw from edge..."
  docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp 10.0.0.2 soft out" 2>/dev/null || true
  sleep 4
  step "Route table after withdrawal:"
  $RAVEN_BIN --address $RAVEN_ADDR routes | grep "193.0" || echo "  (withdrawn — correct)"
  ok "Route leak withdrawn — path-suspect counter should drop back to 0."
  ;;

# ── WHAT-IF ──────────────────────────────────────────────────────────────────
whatif)
  header "What-If Simulator"

  step "Impact of deploying reject-invalid today:"
  $RAVEN_BIN --address $RAVEN_ADDR what-if --reject-invalid
  echo ""

  step "Impact of enforcing ASPA today:"
  $RAVEN_BIN --address $RAVEN_ADDR what-if --aspa-enforce
  echo ""

  ok "Read-only — no router config was touched."
  ;;

# ── ASPA RECOMMEND ───────────────────────────────────────────────────────────
recommend)
  header "ASPA Recommender"

  step "Analysing observed AS_PATHs..."
  $RAVEN_BIN --address $RAVEN_ADDR aspa recommend --min-observations 1
  echo ""

  step "ASPA record for AS2121 (from RTR cache):"
  $RAVEN_BIN --address $RAVEN_ADDR aspa --asn 2121
  echo ""

  ok "Recommendations are heuristic — verify with your peers before registering objects."
  ;;

# ── HELP ─────────────────────────────────────────────────────────────────────
*)
  echo ""
  echo "Usage: bash lab/demo-master.sh <command>"
  echo ""
  echo "  setup         Start full stack (lab, Routinator, RAVEN, Prometheus, Grafana)"
  echo "  down          Stop everything in one command"
  echo "  baseline      Show clean route table"
  echo "  hijack        Inject origin hijack scenario"
  echo "  hijack-clean  Withdraw the hijack"
  echo "  leak          Show route leak (ASPA) detection"
  echo "  leak-clean    Withdraw the route leak"
  echo "  whatif        Run what-if simulator"
  echo "  recommend     Run ASPA recommender"
  echo ""
  ;;

esac
