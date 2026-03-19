#!/usr/bin/env bash
# demo-up.sh — bring up the full RAVEN demo stack
# Usage: ./lab/demo-up.sh

set -e

RAVEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_DIR="$RAVEN_DIR/lab"
RAVEN_BIN="$RAVEN_DIR/raven"
RAVEN_CONFIG="$RAVEN_DIR/raven.yaml"
PROMETHEUS_CONFIG="$HOME/raven-lab/prometheus.yml"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[UP]${NC} $*"; }
warn() { echo -e "${YELLOW}[WAIT]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

# ── 1. Build RAVEN binary ────────────────────────────────────────────────────
log "Building RAVEN..."
cd "$RAVEN_DIR"
go build -o raven ./cmd/raven || err "Build failed"
log "RAVEN built OK"

# ── 2. Containerlab ──────────────────────────────────────────────────────────
log "Deploying Containerlab topology..."
cd "$LAB_DIR"
sudo containerlab deploy -t raven-demo.clab.yaml --reconfigure 2>/dev/null || \
sudo containerlab deploy -t raven-demo.clab.yaml
log "Containerlab up"

# ── 3. Routinator ────────────────────────────────────────────────────────────
if pgrep -x routinator > /dev/null; then
    log "Routinator already running"
else
    log "Starting Routinator..."
    routinator server > /tmp/routinator.log 2>&1 &
    echo $! > /tmp/routinator.pid
    warn "Waiting for Routinator to complete initial validation..."
    for i in $(seq 1 300); do
        if curl -s http://127.0.0.1:8323/api/v1/status 2>/dev/null | grep -q '"vrpsTotal"'; then
            log "Routinator ready (${i}s)"
            break
        fi
        if [ $i -eq 300 ]; then
            err "Routinator did not complete validation in 300s — check /tmp/routinator.log"
        fi
        sleep 1
    done
fi

# ── 4. Prometheus ────────────────────────────────────────────────────────────
if sudo docker ps --format '{{.Names}}' | grep -q "^prometheus$"; then
    log "Prometheus already running"
elif sudo docker ps -a --format '{{.Names}}' | grep -q "^prometheus$"; then
    log "Restarting existing Prometheus container..."
    sudo docker start prometheus > /dev/null
    sleep 3
    log "Prometheus up"
else
    log "Starting Prometheus..."
    mkdir -p "$HOME/raven-lab"
    cat > "$PROMETHEUS_CONFIG" << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'raven'
    static_configs:
      - targets: ['172.17.0.1:9595']
EOF
    sudo docker rm -f prometheus 2>/dev/null || true
    sudo docker run -d \
        --name prometheus \
        -p 9090:9090 \
        -v "$PROMETHEUS_CONFIG:/etc/prometheus/prometheus.yml" \
        prom/prometheus > /dev/null
    sleep 3
    log "Prometheus up"
fi

# ── 5. Grafana ───────────────────────────────────────────────────────────────
if sudo docker ps --format '{{.Names}}' | grep -q "^grafana$"; then
    log "Grafana already running"
elif sudo docker ps -a --format '{{.Names}}' | grep -q "^grafana$"; then
    log "Restarting existing Grafana container..."
    sudo docker start grafana > /dev/null
    sleep 3
    log "Grafana up"
else
    log "Starting Grafana..."
    sudo docker run -d \
        --name grafana \
        --add-host=host.docker.internal:host-gateway \
        -p 3000:3000 \
        grafana/grafana:latest > /dev/null
    sleep 5
    log "Grafana up"
fi

# ── 6. RAVEN daemon ──────────────────────────────────────────────────────────
if pgrep -f "raven serve" > /dev/null; then
    log "RAVEN already running"
else
    log "Starting RAVEN..."
    cd "$RAVEN_DIR"
    ./raven serve --config "$RAVEN_CONFIG" > /tmp/raven.log 2>&1 &
    echo $! > /tmp/raven.pid
    sleep 3
    if pgrep -f "raven serve" > /dev/null; then
        log "RAVEN up (logs: /tmp/raven.log)"
    else
        err "RAVEN failed to start — check /tmp/raven.log"
    fi
fi

# ── 7. Wait for BGP ──────────────────────────────────────────────────────────
warn "Waiting for BGP sessions..."
for i in $(seq 1 30); do
    STATE=$(sudo docker exec clab-raven-demo-edge \
        vtysh -c "show bgp summary" 2>/dev/null | grep "10.0.0.1" | awk '{print $10}')
    if echo "$STATE" | grep -qE "^[0-9]+$"; then
        log "BGP established (${i}s) — ${STATE} prefixes received"
        break
    fi
    if [ $i -eq 30 ]; then
        warn "BGP not yet established — may need a few more seconds"
    fi
    sleep 1
done

# ── 8. Summary ───────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         RAVEN DEMO STACK IS UP           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "  RAVEN API:    http://localhost:11020"
echo "  Prometheus:   http://localhost:9090"
echo "  Grafana:      http://localhost:3000  (admin/raven123)"
echo "  RAVEN logs:   tail -f /tmp/raven.log"
echo "  Routinator:   tail -f /tmp/routinator.log"
echo ""
echo "  Quick checks:"
echo "    $RAVEN_DIR/raven status"
echo "    $RAVEN_DIR/raven routes"
echo "    $RAVEN_DIR/raven routes --posture origin-invalid"