#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RAVEN Demo Master Script
# Run from inside the lab/ directory: ./demo-master.sh
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

# Resolve raven binary — prefer a local build, fall back to PATH
RAVEN_BIN=""
if [ -f "$(dirname "$0")/../raven" ]; then
    RAVEN_BIN="$(dirname "$0")/../raven"
elif [ -f "$(dirname "$0")/../bin/raven" ]; then
    RAVEN_BIN="$(dirname "$0")/../bin/raven"
elif command -v raven &>/dev/null; then
    RAVEN_BIN="raven"
else
    echo "ERROR: raven binary not found. Run 'make build' from the"
    echo "       repo root first, or install raven to PATH."
    exit 1
fi
RAVEN_ADDR="localhost:11020"
EDGE_CONTAINER="clab-raven-demo-edge"
ATTACKER_CONTAINER="clab-raven-demo-attacker"
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

# ── stale-process guard ─────────────────────────────────────────────────────
# A leftover 'raven serve' from a previous demo run will hold ports 11019,
# 11020, and 9595, causing the next setup to crash mid-startup with confusing
# bind errors. Detect and refuse early.
check_stale_raven() {
  local pids
  pids=$(pgrep -f "raven serve" 2>/dev/null || true)
  if [ -n "$pids" ]; then
    echo "ERROR: stale 'raven serve' process detected (PID: $(echo "$pids" | tr '\n' ' '))"
    echo "       This will cause port conflicts (11019/11020/9595) on startup."
    echo "       Run: ./demo-master.sh reset"
    echo "       (or manually: pkill -f 'raven serve' && sleep 2)"
    exit 1
  fi
}

# ── get the WSL host IP that Docker containers can reach ─────────────────────
# ─────────────────────────────────────────────────────────────────────────────
CMD="${1:-help}"

case "$CMD" in

# ── SETUP ────────────────────────────────────────────────────────────────────
setup)
  header "RAVEN Demo Setup"

  if ! curl -s http://localhost:8323/api/v1/status | grep -q vrps; then
    warn "Routinator is not ready. Routes will not be annotated until sync completes."
    warn "Start with: routinator server --config ~/.routinator.conf &"
    warn "Cold start takes ~4 minutes. Warm start (if cache exists) takes ~13 seconds."
  fi

  # Add to the top of the setup case, before containerlab deploy
  echo "▶ Building RAVEN binary..."
  (cd "$(dirname "$0")/.." && make build)
  echo "✓ RAVEN binary up to date"

  # ── Kill any stale raven before deploy so ports 11019/11020/9595 are free ──
  # Two passes with a brief pause between them: the first SIGTERM gives raven
  # a chance to release sockets cleanly, the second sweeps anything that
  # ignored it.
  step "Clearing any stale 'raven serve' processes..."
  pkill -f "raven serve" 2>/dev/null || true
  sleep 1
  pkill -f "raven serve" 2>/dev/null || true

  # ── Containerlab ──
  step "Starting Containerlab topology..."
  sudo containerlab deploy -t raven-demo.clab.yaml --reconfigure 2>/dev/null || true

  # Give FRR routers time to come up and establish BGP sessions before
  # RAVEN starts — this ensures a clean single table dump, not a mix of
  # incremental updates from a partially-converged topology.
  echo "  Waiting 15s for FRR BGP sessions to converge..."
  sleep 15

  # Wait for FRR to be vtysh-ready in all three containers before any config push.
  wait_for_frr clab-raven-demo-internet
  wait_for_frr clab-raven-demo-upstream
  wait_for_frr clab-raven-demo-edge

  # Remove hijack artifacts
  docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "no ip prefix-list EDGE-HIJACK-PREFIX permit 10.10.0.0/24" \
    -c "end" 2>/dev/null || true

  docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp * soft out" 2>/dev/null || true
  echo "  Waiting for BGP to converge after cleanup..."
  sleep 5

  # Remove leak artifacts
  docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "no ip prefix-list LEAK-PREFIX permit 145.102.136.0/22" \
    -c "end" 2>/dev/null || true

  # Remove internet router hijack announcement
  docker exec clab-raven-demo-internet vtysh \
    -c "configure terminal" \
    -c "no ip route 192.0.2.0/24 blackhole" \
    -c "router bgp 2121" \
    -c " address-family ipv4 unicast" \
    -c "  no network 192.0.2.0/24" \
    -c " exit-address-family" \
    -c "end" 2>/dev/null || true

  # ── Routinator ──
  step "Starting Routinator..."
  pkill -x routinator 2>/dev/null || true
  sleep 1
  # --enable-aspa is required for Routinator to fetch and serve ASPA objects
  # over RTR v2. Without it, AS2121's ASPA record (provider: AS3333) is
  # silently dropped and the route-leak scenario shows ASPA:Unknown instead
  # of ASPA:Invalid.
  routinator --enable-aspa server > /tmp/routinator.log 2>&1 &
  echo "  Waiting for Routinator to sync (up to 60s)..."
  for i in $(seq 1 12); do
    if curl -s http://127.0.0.1:8323/api/v1/status 2>/dev/null | grep -q '"vrpsTotal"'; then
      ok "Routinator ready"; break
    fi
    sleep 5; echo -n "."
  done
  echo ""

  # Verify AS2121 ASPA is present — without it the route-leak scenario
  # cannot show path-suspect. If missing, Routinator hasn't synced yet,
  # was started without --enable-aspa, or the global RPKI fetch is still
  # in progress.
  step "Waiting for Routinator ASPA sync (AS2121)..."
  ASPA_FOUND=0
  for i in $(seq 1 24); do
    ASPA_RESULT=$(curl -s http://127.0.0.1:8323/api/v1/aspas \
      2>/dev/null)
    if echo "$ASPA_RESULT" | python3 -c "
import json,sys
d=json.load(sys.stdin)
aspas=d.get('aspas',[])
match=[a for a in aspas if a.get('customer')==2121]
sys.exit(0 if match else 1)
" 2>/dev/null; then
      ASPA_FOUND=1
      ok "AS2121 ASPA record loaded."
      break
    fi
    echo -n "  waiting ($i/24)..."
    sleep 5
  done
  if [ $ASPA_FOUND -eq 0 ]; then
    alert "AS2121 ASPA not found after 2 minutes."
    alert "Route leak scenario will show ASPA:Unknown."
    alert "Check: routinator --enable-aspa server is running"
  fi

  # ── RAVEN — start AFTER lab is converged for a clean table dump ──
  step "Starting RAVEN daemon..."
  pkill -f "raven serve" 2>/dev/null || true
  sleep 2
  check_stale_raven
  if [ -f "../raven.local.yaml" ]; then
    RAVEN_CONFIG="../raven.local.yaml"
  else
    RAVEN_CONFIG="../raven.yaml"
  fi
  echo "Using config: $RAVEN_CONFIG"
  $RAVEN_BIN serve --config $RAVEN_CONFIG > /tmp/raven.log 2>&1 &

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
  # This route-map prepends AS1199 on 145.102.136.0/22 when upstream sends it to
  # the edge router, ensuring the AS_PATH [65000 1199] is always present for
  # ASPA validation. It is permanent infrastructure — never touched by
  # inject/clean cycles.
  step "Installing permanent ROUTE-LEAK route-map on upstream (AS65000)..."
  # seq 10: prepend AS1199 onto 145.102.136.0/22 → edge sees [65000,1199], ASPA invalid
  # seq 20: prepend AS65001 onto 10.10.0.0/24 → edge sees [65000,65001], origin-invalid
  # seq 30: catch-all permit — without this FRR denies all other routes to edge
  if ! docker exec clab-raven-demo-upstream vtysh \
      -c "configure terminal" \
      -c "ip prefix-list LEAK-PREFIX permit 145.102.136.0/22" \
      -c "ip prefix-list EDGE-HIJACK-PREFIX permit 10.10.0.0/24" \
      -c "route-map ROUTE-LEAK permit 10" \
      -c " match ip address prefix-list LEAK-PREFIX" \
      -c " set as-path prepend 1199" \
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

  # EDGE-HIJACK-PREFIX is created by the route-map block above so seq 20 has a
  # prefix-list to reference, but at baseline it must be empty — otherwise
  # 10.10.0.0/24 gets AS65001 prepended and shows origin-invalid before any
  # hijack scenario runs. The hijack) case re-adds the entry during injection.
  docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "no ip prefix-list EDGE-HIJACK-PREFIX permit 10.10.0.0/24" \
    -c "end"

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
  # Always remove and recreate Grafana for a clean state
  if sudo docker ps -a --format '{{.Names}}' | grep -q '^grafana$'; then
    sudo docker rm -f grafana > /dev/null
  fi
  sudo docker run -d \
    --name grafana \
    -p 3000:3000 \
    -e GF_SECURITY_ADMIN_PASSWORD=raven123 \
    -e GF_AUTH_ANONYMOUS_ENABLED=false \
    grafana/grafana:latest > /dev/null

  # Wait for Grafana to be ready (up to 30s)
  echo -n "  Waiting for Grafana to be ready..."
  for i in $(seq 1 30); do
    if curl -s http://admin:raven123@localhost:3000/api/health \
        | grep -q '"database": "ok"' 2>/dev/null; then
      echo " ready"
      break
    fi
    echo -n "."
    sleep 1
  done

  # ── Configure Grafana datasource — always point at Prometheus on Docker bridge ──
  step "Configuring Grafana datasource..."
  curl -s -X POST http://admin:raven123@localhost:3000/api/datasources \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"Prometheus\",
      \"type\": \"prometheus\",
      \"access\": \"proxy\",
      \"url\": \"http://172.17.0.1:9090\",
      \"isDefault\": true,
      \"jsonData\": {
        \"httpMethod\": \"POST\",
        \"timeInterval\": \"10s\"
      }
    }" > /dev/null
  ok "Grafana datasource → Prometheus at http://172.17.0.1:9090"

  PROM_UID=$(curl -s http://admin:raven123@localhost:3000/api/datasources \
    | python3 -c "
import json,sys
sources=json.load(sys.stdin)
print(next(s['uid'] for s in sources if s['type']=='prometheus'))
")

  # ── Import dashboard ──
  step "Importing Grafana dashboard..."
  curl -s -X POST http://admin:raven123@localhost:3000/api/dashboards/import \
    -H "Content-Type: application/json" \
    -d "{\"dashboard\":$(cat grafana-dashboard.json),\"overwrite\":true,\"inputs\":[{\"name\":\"DS_PROMETHEUS\",\"type\":\"datasource\",\"pluginId\":\"prometheus\",\"value\":\"$PROM_UID\"}]}" \
    > /dev/null && ok "Dashboard imported" || warn "Dashboard import failed — import manually from grafana-dashboard.json"

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
  echo "    origin-only    → 100.64.0.0/24, 198.51.100.0/24, 203.0.113.0/24, 10.10.0.0/24"
  echo "    unverified     → 10.99.99.0/24"
  echo "    path-suspect   → (none at baseline)"
  ;;

# ── DOWN — stop everything in one command ────────────────────────────────────
down)
  header "Bringing Down RAVEN Demo"
  pkill -f "raven serve"   2>/dev/null && ok "RAVEN stopped"      || warn "RAVEN was not running"
  pkill -x routinator      2>/dev/null && ok "Routinator stopped" || warn "Routinator was not running"
  sudo docker rm -f prometheus grafana 2>/dev/null || true
  ok "Prometheus + Grafana removed"
  sudo containerlab destroy -t raven-demo.clab.yaml 2>/dev/null && ok "Lab destroyed" || warn "Lab was not running"
  ok "All done."
  ;;

# ── RESET — kill stale raven and verify ports are free ──────────────────────
reset)
  header "Resetting RAVEN State"

  step "Killing any running 'raven serve'..."
  pkill -f "raven serve" 2>/dev/null || true
  sleep 1
  pkill -f "raven serve" 2>/dev/null || true
  sleep 2

  step "Checking ports 11019, 11020, 9595..."
  in_use=()
  for port in 11019 11020 9595; do
    if ss -tlnp 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}\$"; then
      in_use+=("$port")
    fi
  done

  if [ "${#in_use[@]}" -eq 0 ]; then
    ok "Ports clear — ready to restart"
  else
    warn "WARNING: ports still in use: ${in_use[*]}"
    echo "       Identify the holder with: ss -tlnp | grep -E ':(11019|11020|9595)\b'"
  fi

  # Remove hijack artifacts
  docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "no ip prefix-list EDGE-HIJACK-PREFIX permit 10.10.0.0/24" \
    -c "end" 2>/dev/null || true

  # Remove leak artifacts
  docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "no ip prefix-list LEAK-PREFIX permit 145.102.136.0/22" \
    -c "end" 2>/dev/null || true

  # Remove internet router hijack announcement
  docker exec clab-raven-demo-internet vtysh \
    -c "configure terminal" \
    -c "no ip route 192.0.2.0/24 blackhole" \
    -c "router bgp 2121" \
    -c " address-family ipv4 unicast" \
    -c "  no network 192.0.2.0/24" \
    -c " exit-address-family" \
    -c "end" 2>/dev/null || true

  # Soft reset all BGP sessions to propagate cleanup
  docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp * soft" 2>/dev/null || true
  docker exec clab-raven-demo-internet vtysh \
    -c "clear ip bgp * soft" 2>/dev/null || true

  echo ""
  echo "  Next: ./demo-master.sh setup"
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
  docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "no ip prefix-list EDGE-HIJACK-PREFIX permit 10.10.0.0/24" \
    -c "do clear ip bgp 10.0.0.2 soft out" \
    -c "do clear ip bgp 10.0.1.1 soft out" \
    -c "end"
  sleep 4
  step "Route table after withdrawal:"
  $RAVEN_BIN --address $RAVEN_ADDR routes | grep "192.0.2" || echo "  (withdrawn — correct)"
  ok "Route table clean."
  ;;

# ── ROUTE LEAK ───────────────────────────────────────────────────────────────
leak)
  header "Attack Scenario 2 — Route Leak (ASPA)"

  echo "  Prefix:         145.102.136.0/22"
  echo "  Origin:         AS1199  (SURFnet — has valid ROA)"
  echo "  ASPA providers: AS1103 only"
  echo "  Simulated path: AS1199 → AS65000 → AS65001"
  echo "  Mechanism:      AS65000 originates 145.102.136.0/22, route-map prepends AS1199"
  echo "                  Edge sees AS_PATH [65000 1199], origin=AS1199"
  echo "  Violation:      AS65000 is NOT an authorised provider of AS1199"
  echo ""

  # ── Step 1: BEFORE state — 145.102.136.0/22 not in table, path-suspect = 0 ──
  step "BEFORE — path-suspect routes (should be empty):"
  $RAVEN_BIN --address $RAVEN_ADDR routes --posture path-suspect 2>&1 || true
  echo "  (none — path-suspect = 0)"
  echo ""
  ok "Baseline confirmed: path-suspect counter = 0 in Grafana"
  echo ""

  # ── Step 2: Originate 145.102.136.0/22 on upstream (AS65000) ──
  # The existing ROUTE-LEAK route-map (seq 10) prepends AS1199 on 145.102.136.0/22
  # when sending to the edge neighbour, so edge receives AS_PATH [65000 1199].
  # AS65000 is not in AS1199's ASPA provider set (only AS1103) → ASPA:Invalid.
  step "Injecting 145.102.136.0/22 on upstream (AS65000) — simulating route leak..."
  docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "ip route 145.102.136.0/22 blackhole" \
    -c "router bgp 65000" \
    -c " address-family ipv4 unicast" \
    -c "  network 145.102.136.0/22" \
    -c " exit-address-family" \
    -c "end"
  echo "  Triggering soft outbound reset to push route to edge immediately..."
  docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp 10.0.0.2 soft out" 2>/dev/null || true
  echo "  Waiting 5s for BMP propagation..."
  sleep 5

  # ── Step 3: Show detection ──
  step "RAVEN detection — 145.102.136.0/22 (ROV:Valid, ASPA:Invalid, posture:path-suspect):"
  $RAVEN_BIN --address $RAVEN_ADDR routes --prefix 145.102.136.0/22
  echo ""

  warn "ROV shows Valid — the origin AS1199 is legitimate."
  warn "A router running only ROV would accept this route with no alarm."
  echo ""
  echo "  Failing hop:  AS1199 (customer) → AS65000 (provider)"
  echo "  Reason:       AS65000 not in AS1199 ASPA provider set (only AS1103 is)"
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
    -c "no ip route 145.102.136.0/22 blackhole" \
    -c "router bgp 65000" \
    -c " address-family ipv4 unicast" \
    -c "  no network 145.102.136.0/22" \
    -c " exit-address-family" \
    -c "end" > /dev/null 2>&1 || true
  echo "  Triggering soft outbound reset to withdraw from edge..."
  docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp 10.0.0.2 soft out" 2>/dev/null || true
  sleep 4
  step "Route table after withdrawal:"
  $RAVEN_BIN --address $RAVEN_ADDR routes | grep "145.102" || echo "  (withdrawn — correct)"
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

# ── WEBHOOK LISTENER ─────────────────────────────────────────────────────────
webhook-listen)
  step "Starting webhook listener on port 9999..."
  # Kill any existing webhook listener on port 9999
  existing=$(lsof -ti tcp:9999 2>/dev/null || true)
  if [ -n "$existing" ]; then
      echo "  Stopping existing webhook listener (PID $existing)..."
      kill "$existing" 2>/dev/null
      sleep 1
  fi
  python3 -c "
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        body = self.rfile.read(length)
        try:
            parsed = json.loads(body)
            print(json.dumps(parsed, indent=2))
        except Exception:
            print(body.decode())
        self.send_response(200)
        self.end_headers()
    def log_message(self, fmt, *args):
        pass  # suppress access log noise
http.server.HTTPServer(('0.0.0.0', 9999), H).serve_forever()
" &
  sleep 1
  if ! lsof -ti tcp:9999 &>/dev/null; then
      echo "ERROR: webhook listener failed to start on port 9999"
      exit 1
  fi
  echo "Webhook listener started (PID $!). Press Ctrl-C in this terminal to stop."
  ;;

# ── FLOWSPEC ─────────────────────────────────────────────────────────────────
flowspec)
  header "Flowspec Demo — Active Route Mitigation"
  echo ""
  echo "  Demonstrates the full Flowspec lifecycle:"
  echo "  detect → dry-run rule → toggle live → GoBGP injection → withdraw"
  echo ""

  step "Injecting origin hijack to trigger Flowspec rule..."
  bash "$0" hijack
  sleep 3

  step "Active Flowspec rules (dry-run — not yet injected into GoBGP):"
  $RAVEN_BIN --address $RAVEN_ADDR flowspec list
  echo ""

  echo "  GoBGP RIB before toggle (should be empty):"
  sudo docker exec clab-raven-demo-gobgp gobgp global rib -a ipv4-flowspec
  echo ""

  read -rp "  Toggle 192.0.2.0/24|drop to LIVE injection? [y/N] " answer
  if [[ "$answer" =~ ^[Yy]$ ]]; then
    echo ""
    step "Toggling 192.0.2.0/24|drop to LIVE..."
    $RAVEN_BIN --address $RAVEN_ADDR flowspec toggle "192.0.2.0/24|drop"
    echo ""

    step "GoBGP RIB after toggle (Flowspec rule should be present):"
    sudo docker exec clab-raven-demo-gobgp gobgp global rib -a ipv4-flowspec
    echo ""

    read -rp "  Withdraw rule and return to dry-run? [y/N] " answer2
    if [[ "$answer2" =~ ^[Yy]$ ]]; then
      echo ""
      step "Withdrawing — returning to dry-run..."
      $RAVEN_BIN --address $RAVEN_ADDR flowspec toggle "192.0.2.0/24|drop"
      echo ""
      step "GoBGP RIB after withdrawal (should be empty again):"
      sudo docker exec clab-raven-demo-gobgp gobgp global rib -a ipv4-flowspec
    fi
  else
    echo "  Skipped live injection — rule remains in dry-run."
  fi

  echo ""
  step "Cleaning up hijack..."
  bash "$0" hijack-clean
  ;;

# ── AUDIT ─────────────────────────────────────────────────────────────────────
audit)
  FORMAT=${2:-table}
  header "RAVEN Security Audit — edge router 10.0.0.1"
  $RAVEN_BIN --address $RAVEN_ADDR audit --router 10.0.0.1 --format "$FORMAT"
  ;;

# ── PHASE 3 ──────────────────────────────────────────────────────────────────
phase3)
  header "Phase 3: Active Response Demo"

  step "Starting webhook listener..."
  bash "$0" webhook-listen
  sleep 1

  echo ""
  step "--- Baseline audit ---"
  bash "$0" audit
  sleep 2

  echo ""
  step "--- Injecting origin hijack ---"
  bash "$0" hijack
  sleep 5
  alert ">>> Check webhook terminal for alert payload"
  sleep 3

  echo ""
  step "--- Audit after hijack ---"
  bash "$0" audit
  sleep 2

  echo ""
  # ── Flowspec lifecycle ──────────────────────────────────────────
  step "Flowspec rules (auto-generated in dry-run):"
  $RAVEN_BIN --address $RAVEN_ADDR flowspec list
  sleep 3

  step "Toggling 192.0.2.0/24|drop to LIVE injection..."
  $RAVEN_BIN --address $RAVEN_ADDR flowspec toggle "192.0.2.0/24|drop"
  sleep 2

  step "GoBGP RIB — Flowspec rule active:"
  sudo docker exec clab-raven-demo-gobgp gobgp global rib -a ipv4-flowspec
  sleep 3

  step "Withdrawing — returning to dry-run..."
  $RAVEN_BIN --address $RAVEN_ADDR flowspec toggle "192.0.2.0/24|drop"
  sleep 2
  ok "Flowspec lifecycle complete — inject, verify in GoBGP, withdraw."
  sleep 2

  echo ""
  step "--- Cleaning hijack ---"
  bash "$0" hijack-clean
  sleep 3

  echo ""
  step "--- Injecting route leak ---"
  bash "$0" leak
  sleep 5
  alert ">>> Check webhook terminal for path-suspect alert"
  sleep 3

  echo ""
  step "--- Audit after leak ---"
  bash "$0" audit
  sleep 2

  echo ""
  step "--- Cleaning up ---"
  bash "$0" leak-clean

  echo ""
  ok "=== Phase 3 demo complete ==="
  ;;

# ── HIJACK V2 (AS65099 attacker) ─────────────────────────────────────────────
hijack-v2)
  header "Attack Scenario — Origin Hijack via AS65099"

  alert "INJECTING BGP ORIGIN HIJACK FROM ATTACKER (AS65099)"
  echo ""
  echo "  Prefix:             203.0.113.0/24"
  echo "  Legitimate origin:  AS65001  (per ROA in Routinator)"
  echo "  Hijacking router:   AS65099  (attacker — peers with both upstream and edge)"
  echo ""
  echo "  Method: attacker originates 203.0.113.0/24 directly. The route reaches"
  echo "  RAVEN via BMP from upstream (AS65000) and edge (AS65001). Origin AS65099"
  echo "  ≠ ROA origin AS65001 → ROV Invalid → origin-invalid posture."
  echo ""

  step "Route table BEFORE hijack:"
  $RAVEN_BIN --address $RAVEN_ADDR routes | grep "203.0.113" || echo "  (legitimate origin only)"
  echo ""

  step "Injecting hijack from attacker (AS65099)..."
  docker exec $ATTACKER_CONTAINER vtysh \
    -c "configure terminal" \
    -c "ip route 203.0.113.0/24 blackhole" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "network 203.0.113.0/24" \
    -c "end"

  echo "  Waiting 5s for BMP propagation..."
  sleep 5

  step "RAVEN detection — origin-invalid routes:"
  $RAVEN_BIN --address $RAVEN_ADDR routes --posture origin-invalid
  echo ""

  alert "HIJACK DETECTED — switch to Grafana: $GRAFANA_URL"
  ;;

# ── HIJACK V2 CLEAN ──────────────────────────────────────────────────────────
hijack-v2-clean)
  header "Withdrawing AS65099 Hijack"
  docker exec $ATTACKER_CONTAINER vtysh \
    -c "configure terminal" \
    -c "no ip route 203.0.113.0/24 blackhole" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "no network 203.0.113.0/24" \
    -c "end"
  sleep 4
  step "Route table after withdrawal:"
  $RAVEN_BIN --address $RAVEN_ADDR routes | grep "203.0.113" || echo "  (withdrawn — correct)"
  ok "Hijack withdrawn."
  ;;

# ── STEALTHY HIJACK ──────────────────────────────────────────────────────────
stealthy)
  header "Scenario 3 — Stealthy Hijack"

  echo "  Mechanism: attacker (AS65099) announces 203.0.113.0/25 — a more"
  echo "             specific of the legitimate AS65000 /24. The edge router"
  echo "             accepts it (no ROV enforcement) and installs it in FIB."
  echo "             RAVEN's BMP RIB from upstream still shows the clean /24."
  echo "             Control plane looks fine — only data-plane probing reveals"
  echo "             the divergence."
  echo ""

  step "Control plane BEFORE stealthy hijack (should look clean):"
  $RAVEN_BIN --address $RAVEN_ADDR routes --prefix 203.0.113.0/24
  echo "  Control plane shows: CLEAN"
  echo ""

  step "Injecting stealthy /25 from attacker (AS65099)..."
  docker exec clab-raven-demo-attacker vtysh \
    -c "configure terminal" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "network 203.0.113.0/25" \
    -c "end"
  echo "  Waiting 5s for BGP/BMP propagation..."
  sleep 5

  step "Control plane AFTER stealthy hijack (legitimate /24 still looks clean):"
  $RAVEN_BIN --address $RAVEN_ADDR routes --prefix 203.0.113.0/24
  echo "  Control plane: still shows legitimate /24 — looks clean"
  echo ""

  step "Running stealthy check (traceroute from inside edge container):"
  echo "  Note: probing from inside clab-raven-demo-edge so traffic enters the"
  echo "  BGP topology (the WSL2 host is not part of it). The query targets the"
  echo "  clean /24 RIB entry — but data-plane forwarding LPMs onto the /25 and"
  echo "  goes via the attacker."
  echo ""
  $RAVEN_BIN --address $RAVEN_ADDR check stealthy \
    --prefix 203.0.113.0/24 \
    --probe-via clab-raven-demo-edge
  echo ""

  read -p "  [ENTER to clean up]" _
  docker exec clab-raven-demo-attacker vtysh \
    -c "configure terminal" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "no network 203.0.113.0/25" \
    -c "end"
  ok "Stealthy hijack withdrawn."
  ;;

# ── STEALTHY CLEAN (no prompts) ──────────────────────────────────────────────
stealthy-clean)
  header "Withdrawing Stealthy Hijack"
  docker exec clab-raven-demo-attacker vtysh \
    -c "configure terminal" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "no network 203.0.113.0/25" \
    -c "end" 2>/dev/null || true
  ok "Stealthy hijack withdrawn."
  ;;

# ── RTR FAIL ─────────────────────────────────────────────────────────────────
rtr-fail)
  header "Scenario 4 — RTR Cache Failure"

  step "Showing RAVEN RTR status before failure..."
  $RAVEN_BIN --address $RAVEN_ADDR status
  echo ""

  alert "Taking Routinator offline..."
  pkill -x routinator || true
  sleep 3

  step "RAVEN RTR status immediately after failure..."
  $RAVEN_BIN --address $RAVEN_ADDR status
  echo ""

  echo "  Prometheus staleness metric:"
  curl -s http://localhost:9595/metrics | grep raven_rtr | grep -v "^#"
  echo ""

  echo "  Note: RAVEN continues serving the last known RPKI state."
  echo "        Alert fires when cache exceeds expire interval."
  echo ""

  echo -n "  Holding offline for 10s"
  for i in 10 9 8 7 6 5 4 3 2 1; do
    echo -n " $i"
    sleep 1
  done
  echo ""

  alert "Restoring Routinator..."
  routinator --enable-aspa server >> /tmp/routinator.log 2>&1 &
  sleep 15

  step "RAVEN RTR status after restore..."
  $RAVEN_BIN --address $RAVEN_ADDR status
  echo ""

  ok "RTR session restored."
  ;;

# ── LACNIC FULL DEMO SEQUENCE ────────────────────────────────────────────────
lacnic)
  header "LACNIC Demo — Full Sequence"

  echo "  Ensure 'setup' has been run first."
  sleep 3

  step "Scenario 1 — Baseline"
  $RAVEN_BIN --address $RAVEN_ADDR routes
  echo ""
  $RAVEN_BIN --address $RAVEN_ADDR status
  echo ""
  read -p "  [ENTER to continue to Scenario 2]" _

  step "Scenario 2 — Origin Hijack (AS65099)"
  alert "INJECTING BGP ORIGIN HIJACK FROM ATTACKER (AS65099)"
  echo "  Prefix: 203.0.113.0/24 (legitimate origin AS65001) → hijacked by AS65099"
  echo ""
  docker exec $ATTACKER_CONTAINER vtysh \
    -c "configure terminal" \
    -c "ip route 203.0.113.0/24 blackhole" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "network 203.0.113.0/24" \
    -c "end"
  echo "  Waiting 5s for BMP propagation..."
  sleep 5
  step "RAVEN detection — origin-invalid routes:"
  $RAVEN_BIN --address $RAVEN_ADDR routes --posture origin-invalid
  echo ""
  read -p "  [ENTER to clean up and continue]" _
  step "Withdrawing AS65099 hijack..."
  docker exec $ATTACKER_CONTAINER vtysh \
    -c "configure terminal" \
    -c "no ip route 203.0.113.0/24 blackhole" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "no network 203.0.113.0/24" \
    -c "end"
  sleep 4
  ok "Hijack withdrawn."
  echo ""

  step "Scenario 3 — Stealthy Hijack (Control/Data-Plane Divergence)"
  echo "  Prefix: 203.0.113.0/25 (more-specific of legitimate AS65000 /24)"
  echo "  Attacker AS65099 announces /25 — edge accepts it without ROV check,"
  echo "  upstream's view (and RAVEN's BMP RIB for the /24) still looks clean."
  echo "  Only data-plane probing reveals the divergence."
  echo ""
  step "Control plane BEFORE stealthy hijack:"
  $RAVEN_BIN --address $RAVEN_ADDR routes --prefix 203.0.113.0/24
  echo ""
  step "Injecting stealthy /25 from attacker (AS65099)..."
  docker exec $ATTACKER_CONTAINER vtysh \
    -c "configure terminal" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "network 203.0.113.0/25" \
    -c "end"
  echo "  Waiting 5s for propagation..."
  sleep 5
  step "Control plane AFTER stealthy hijack (still looks clean for /24):"
  $RAVEN_BIN --address $RAVEN_ADDR routes --prefix 203.0.113.0/24
  echo ""
  step "RAVEN stealthy check — traceroute from inside edge container:"
  $RAVEN_BIN --address $RAVEN_ADDR check stealthy \
    --prefix 203.0.113.0/24 \
    --probe-via clab-raven-demo-edge
  echo ""
  alert "STEALTHY HIJACK DETECTED — control plane could not see this."
  echo ""
  read -p "  [ENTER to clean up and continue]" _
  step "Withdrawing stealthy hijack..."
  docker exec $ATTACKER_CONTAINER vtysh \
    -c "configure terminal" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "no network 203.0.113.0/25" \
    -c "end"
  sleep 4
  ok "Stealthy hijack withdrawn."
  echo ""

  step "Scenario 4 — Route Leak (ASPA)"
  echo "  Prefix: 193.0.0.0/21 (origin AS2121 / RIPE NCC)"
  echo "  AS65000 not in AS2121 ASPA provider set → ASPA:Invalid → path-suspect"
  echo ""
  docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "no route-map LEAK-INJECT" \
    -c "no ip prefix-list LEAK-PREFIX" \
    -c "end" > /dev/null 2>&1 || true
  docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "ip route 193.0.0.0/21 blackhole" \
    -c "router bgp 65000" \
    -c "address-family ipv4 unicast" \
    -c "network 193.0.0.0/21" \
    -c "neighbor 10.0.0.2 route-map LEAK-INJECT out" \
    -c "exit-address-family" \
    -c "end"
  docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "route-map LEAK-INJECT permit 10" \
    -c "match ip address prefix-list LEAK-PREFIX" \
    -c "set as-path prepend 2121" \
    -c "exit" \
    -c "route-map LEAK-INJECT permit 20" \
    -c "exit" \
    -c "ip prefix-list LEAK-PREFIX permit 193.0.0.0/21" \
    -c "end"
  docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp 10.0.0.2 soft out"
  echo "  Waiting 5s for BMP propagation..."
  sleep 5
  step "RAVEN detection — 193.0.0.0/21:"
  $RAVEN_BIN --address $RAVEN_ADDR routes --prefix 193.0.0.0/21
  echo ""
  alert "ROUTE LEAK DETECTED — ASPA caught what ROV missed."
  echo ""
  read -p "  [ENTER to clean up and continue]" _
  step "Withdrawing route leak..."
  docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "no ip route 193.0.0.0/21 blackhole" \
    -c "router bgp 65000" \
    -c "address-family ipv4 unicast" \
    -c "no network 193.0.0.0/21" \
    -c "no neighbor 10.0.0.2 route-map LEAK-INJECT out" \
    -c "exit-address-family" \
    -c "no route-map LEAK-INJECT" \
    -c "no ip prefix-list LEAK-PREFIX" \
    -c "end"
  docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp 10.0.0.2 soft out"
  sleep 4
  ok "Route leak withdrawn."
  echo ""

  step "Scenario 5 — RTR Cache Failure"
  step "Showing RAVEN RTR status before failure..."
  $RAVEN_BIN --address $RAVEN_ADDR status
  echo ""
  alert "Taking Routinator offline..."
  pkill -x routinator || true
  sleep 3
  step "RAVEN RTR status immediately after failure..."
  $RAVEN_BIN --address $RAVEN_ADDR status
  echo ""
  echo "  Prometheus staleness metric:"
  curl -s http://localhost:9595/metrics | grep raven_rtr | grep -v "^#"
  echo ""
  echo "  Note: RAVEN continues serving the last known RPKI state."
  echo "        Alert fires when cache exceeds expire interval."
  echo ""
  echo -n "  Holding offline for 10s"
  for i in 10 9 8 7 6 5 4 3 2 1; do
    echo -n " $i"
    sleep 1
  done
  echo ""
  alert "Restoring Routinator..."
  routinator --enable-aspa server >> /tmp/routinator.log 2>&1 &
  sleep 5
  step "RAVEN RTR status after restore..."
  $RAVEN_BIN --address $RAVEN_ADDR status
  echo ""
  ok "RTR session restored."
  echo ""
  read -p "  [ENTER to continue to Scenario 6]" _

  step "Scenario 6 — Audit Report"
  $RAVEN_BIN --address $RAVEN_ADDR audit --router 10.0.0.1
  echo ""

  ok "LACNIC demo sequence complete."
  ;;

# ── HELP ─────────────────────────────────────────────────────────────────────
*)
  echo ""
  echo "Usage: bash lab/demo-master.sh <command>"
  echo ""
  echo "  setup          Start full stack (lab, Routinator, RAVEN, Prometheus, Grafana)"
  echo "  down           Stop everything in one command"
  echo "  baseline       Show clean route table"
  echo "  hijack         Inject origin hijack scenario"
  echo "  hijack-clean   Withdraw the hijack"
  echo "  leak           Show route leak (ASPA) detection"
  echo "  leak-clean     Withdraw the route leak"
  echo "  whatif         Run what-if simulator"
  echo "  recommend      Run ASPA recommender"
  echo "  webhook-listen Start webhook listener on port 9999 (background)"
  echo "  flowspec       Full Flowspec lifecycle: hijack → dry-run rule →"
  echo "                 toggle live → GoBGP injection → withdraw"
  echo "  audit [fmt]    Security posture audit for edge router (fmt: table|json|markdown)"
  echo "  phase3         Full Phase 3 active-response demo sequence"
  echo ""
  ;;

esac
