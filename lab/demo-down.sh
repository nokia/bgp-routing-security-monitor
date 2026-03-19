#!/usr/bin/env bash
# demo-down.sh — tear down the full RAVEN demo stack
# Usage: ./lab/demo-down.sh [--keep-docker]
#   --keep-docker  stop RAVEN/Routinator but leave Prometheus+Grafana containers running

set -e

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEEP_DOCKER=false

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[DOWN]${NC} $*"; }
warn() { echo -e "${YELLOW}[SKIP]${NC} $*"; }

for arg in "$@"; do
    case $arg in
        --keep-docker) KEEP_DOCKER=true ;;
    esac
done

# ── 1. RAVEN daemon ──────────────────────────────────────────────────────────
if pgrep -f "raven serve" > /dev/null; then
    pkill -f "raven serve" && log "RAVEN stopped"
else
    warn "RAVEN not running"
fi
rm -f /tmp/raven.pid

# ── 2. Routinator ────────────────────────────────────────────────────────────
# NOTE: Routinator is intentionally NOT stopped between demos.
# Stopping it requires a 4-minute RRDP re-sync on next start.
# Only stop it with --full-reset flag.
if [[ "$*" == *"--full-reset"* ]]; then
    if pgrep -x routinator > /dev/null; then
        pkill -x routinator && log "Routinator stopped (full reset)"
    else
        warn "Routinator not running"
    fi
    rm -f /tmp/routinator.pid
else
    warn "Routinator kept running (use --full-reset to stop)"
fi

# ── 3. Containerlab ──────────────────────────────────────────────────────────
if sudo docker ps --format '{{.Names}}' | grep -q "clab-raven-demo"; then
    log "Destroying Containerlab topology..."
    cd "$LAB_DIR"
    sudo containerlab destroy -t raven-demo.clab.yaml 2>/dev/null || true
    log "Containerlab down"
else
    warn "Containerlab not running"
fi

# ── 4. Docker containers ─────────────────────────────────────────────────────
if $KEEP_DOCKER; then
    warn "Keeping Prometheus and Grafana running (--keep-docker)"
else
    for container in prometheus grafana; do
        if sudo docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
            sudo docker stop "$container" > /dev/null && log "$container stopped"
        else
            warn "$container not running"
        fi
    done
fi

echo ""
echo "  Demo stack is down."
echo "  To restart: ./lab/demo-up.sh"