#!/usr/bin/env bash
# 01-origin-hijack.sh — simulate and then clean up a BGP origin hijack
#
# Scenario: AS65001 (edge router) announces 192.0.2.0/24
# The SLURM ROA says 192.0.2.0/24 belongs to AS64496
# So this announcement is RPKI Invalid — RAVEN detects it immediately
#
# Usage:
#   ./lab/01-origin-hijack.sh          # inject hijack
#   ./lab/01-origin-hijack.sh --clean  # withdraw hijack

RAVEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAVEN_BIN="$RAVEN_DIR/raven"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[DEMO]${NC} $*"; }
warn() { echo -e "${YELLOW}[INFO]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

HIJACK_PREFIX="192.0.2.0/24"
EDGE_CONTAINER="clab-raven-demo-edge"

# Check edge container is running
sudo docker ps --format '{{.Names}}' | grep -q "^${EDGE_CONTAINER}$" || \
    err "Edge container not running. Run ./lab/demo-up.sh first."

if [[ "$1" == "--clean" ]]; then
    log "Withdrawing hijacked route ${HIJACK_PREFIX}..."
    sudo docker exec -it "$EDGE_CONTAINER" vtysh \
        -c "configure terminal" \
        -c "router bgp 65001" \
        -c "address-family ipv4 unicast" \
        -c "no network 192.0.2.0/24" \
        -c "end"

    sleep 5
    warn "Hijack withdrawn. Checking RAVEN..."
    echo ""
    "$RAVEN_BIN" routes --posture origin-invalid
    echo ""
    log "Origin-invalid routes should now be back to baseline (10.10.0.0/24 only)."

else
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║          INJECTING BGP ORIGIN HIJACK             ║${NC}"
    echo -e "${RED}║                                                  ║${NC}"
    echo -e "${RED}║  Prefix:  192.0.2.0/24                           ║${NC}"
    echo -e "${RED}║  Legitimate origin: AS65000 (per ROA)            ║${NC}"
    echo -e "${RED}║  Hijacking origin:  AS65001 (edge router)        ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════╝${NC}"
    echo ""

    warn "Current route table (before hijack):"
    "$RAVEN_BIN" routes
    echo ""

    log "Injecting hijacked announcement on edge router (AS65001)..."
    sudo docker exec -it "$EDGE_CONTAINER" vtysh \
        -c "configure terminal" \
        -c "router bgp 65001" \
        -c "address-family ipv4 unicast" \
        -c "network 192.0.2.0/24" \
        -c "end"

    warn "Waiting for BMP to propagate (3s)..."
    sleep 3

    echo ""
    log "RAVEN route table after hijack:"
    "$RAVEN_BIN" routes
    echo ""

    log "Origin-invalid routes detected:"
    "$RAVEN_BIN" routes --posture origin-invalid
    echo ""

    echo -e "${RED}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  🚨 HIJACK DETECTED — Check Grafana dashboard    ║${NC}"
    echo -e "${RED}║  http://localhost:3000/d/raven-security-posture  ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    warn "To clean up: ./lab/01-origin-hijack.sh --clean"
fi