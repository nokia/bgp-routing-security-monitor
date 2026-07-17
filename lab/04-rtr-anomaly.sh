#!/usr/bin/env bash
# 04-rtr-anomaly.sh — force a statistically abnormal RTR sync so RAVEN's
# anomaly detector fires in real time.
#
# Scenario: bulk-add a large batch of ROAs to Routinator's SLURM local
# exceptions all at once. With Routinator running on a short refresh it picks
# them up within seconds and pushes a single incremental RTR update, so RAVEN's
# next sync reports vrp_announced far past the observed baseline (P99 ~107
# announced, historical max 293) — tripping the detector's hard threshold on
# vrp_announced. No BGP/route change and no change to RAVEN itself is involved;
# this only manipulates the lab's Routinator VRP set.
#
# Demo flow (scenario docs are punted to the backlog — the narrative lives here):
#   1. Seed a baseline snapshot from the recorded 14-day collection so the
#      detector starts warm (no ~25h live warm-up on stage):
#        ./raven rtr seed-baseline \
#            --input ~/rtr-baseline.ndjson \
#            --output ~/.raven/anomaly-baseline.json
#   2. Prep Routinator for a fast demo (ONE-TIME; this restarts Routinator and
#      resets the RTR session, so do it BEFORE starting the monitor):
#        ./lab/04-rtr-anomaly.sh --setup
#   3. Start the monitor, warm-started from the seeded baseline:
#        ./raven rtr monitor \
#            --anomaly-snapshot ~/.raven/anomaly-baseline.json \
#            --log-file /tmp/rtr-anomaly.ndjson --prometheus :9595
#      and watch it in another pane:
#        tail -f /tmp/rtr-anomaly.ndjson | grep '"event_type":"anomaly"'
#      (or watch the raven_rtr_anomaly_total counter on :9595 / in Grafana)
#   4. Inject the churn:
#        ./lab/04-rtr-anomaly.sh
#      → within a few seconds an event_type:"anomaly" record appears
#        (category statistical, severity high, trigger vrp_announced).
#   5. Restore the baseline SLURM set:
#        ./lab/04-rtr-anomaly.sh --clean
#      (this withdraws the injected ROAs → a matching vrp_withdrawn spike, then
#       the detector returns to baseline).
#
# Usage:
#   ./lab/04-rtr-anomaly.sh --setup   # (re)start Routinator with a short refresh
#   ./lab/04-rtr-anomaly.sh           # inject the churn spike
#   ./lab/04-rtr-anomaly.sh --clean   # withdraw the injected ROAs

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[DEMO]${NC} $*"; }
warn() { echo -e "${YELLOW}[INFO]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

# Live SLURM exceptions file Routinator actually reads (per ~/.routinator.conf);
# note this is NOT the repo's lab/slurm.json template.
SLURM_FILE="${SLURM_FILE:-$HOME/raven-lab/slurm.json}"
ROUTINATOR_HTTP="${ROUTINATOR_HTTP:-http://127.0.0.1:8323}"
CHURN_COUNT="${CHURN_COUNT:-1200}"   # unambiguously past the historical max (293/249)
CHURN_ASN="${CHURN_ASN:-65000}"
REFRESH="${REFRESH:-5}"              # Routinator refresh (s) used by --setup
MARKER="RAVEN RTR anomaly demo churn (04-rtr-anomaly.sh)"

# routinator_vrps prints Routinator's total served VRP count, or "" on failure.
routinator_vrps() {
    curl -s "${ROUTINATOR_HTTP}/api/v1/status" 2>/dev/null | python3 -c '
import json, sys
def find(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if k == "vrpsTotal" and isinstance(v, int):
                return v
            r = find(v)
            if r is not None:
                return r
    elif isinstance(o, list):
        for x in o:
            r = find(x)
            if r is not None:
                return r
    return None
try:
    v = find(json.load(sys.stdin))
    print(v if v is not None else "")
except Exception:
    print("")
' 2>/dev/null
}

# routinator_serial prints Routinator's current RTR serial, or "" on failure.
# The serial increments once per completed validation cycle, so a change is a
# cleaner, more immediate "new data is live" signal than watching VRP counts.
routinator_serial() {
    curl -s "${ROUTINATOR_HTTP}/api/v1/status" 2>/dev/null | python3 -c '
import json, sys
try:
    v = json.load(sys.stdin).get("serial")
    print(v if isinstance(v, int) else "")
except Exception:
    print("")
' 2>/dev/null
}

# edit_slurm add|remove — atomically mutate the SLURM prefixAssertions array,
# printing the number added (add) or removed (remove). Always drops previously
# injected marked assertions first, so it is idempotent.
edit_slurm() {
    python3 - "$SLURM_FILE" "$1" "$CHURN_COUNT" "$CHURN_ASN" "$MARKER" << 'PY'
import json, os, sys
path, mode, count, asn, marker = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
with open(path) as f:
    doc = json.load(f)
arr = doc["locallyAddedAssertions"]["prefixAssertions"]
before = len(arr)
arr[:] = [a for a in arr if a.get("comment") != marker]
removed = before - len(arr)
added = 0
if mode == "add":
    for i in range(count):
        arr.append({"asn": asn, "prefix": f"240.{i // 256}.{i % 256}.0/24",
                    "maxPrefixLength": 24, "comment": marker})
        added += 1
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
os.replace(tmp, path)
print(added if mode == "add" else removed)
PY
}

# ── Preflight ────────────────────────────────────────────────────────────────
command -v python3 >/dev/null 2>&1 || err "python3 is required."
command -v curl    >/dev/null 2>&1 || err "curl is required."
pgrep -x routinator >/dev/null     || err "Routinator not running. Run ./lab/demo-up.sh first."
[[ -f "$SLURM_FILE" ]]             || err "SLURM exceptions file not found at ${SLURM_FILE}"

case "${1:-}" in
--setup)
    warn "Restarting Routinator with --refresh ${REFRESH}s so SLURM edits propagate quickly."
    warn "This resets the RTR session — start 'raven rtr monitor' AFTER this step."
    pkill -x routinator 2>/dev/null && sleep 2
    routinator server --refresh "$REFRESH" > /tmp/routinator.log 2>&1 &
    echo $! > /tmp/routinator.pid
    warn "Waiting for Routinator to finish validation..."
    for i in $(seq 1 300); do
        if [[ -n "$(routinator_vrps)" ]]; then
            log "Routinator ready (${i}s, refresh=${REFRESH}s)."
            break
        fi
        [[ $i -eq 300 ]] && err "Routinator did not become ready in 300s — check /tmp/routinator.log"
        sleep 1
    done
    log "Setup complete. Start the monitor, then run: $0"
    ;;

--clean)
    log "Withdrawing injected demo ROAs from ${SLURM_FILE}..."
    REMOVED="$(edit_slurm remove)"
    log "Removed ${REMOVED} injected assertion(s). Routinator withdraws them on its next refresh."
    warn "RAVEN's next sync should show a matching vrp_withdrawn spike, then return to baseline."
    ;;

"")
    # If Routinator isn't on a short refresh, the churn could take up to the
    # default 600s to appear. Warn, but proceed.
    if ! pgrep -af routinator | grep -q -- '--refresh'; then
        warn "Routinator does not appear to be running with a short --refresh."
        warn "The churn may take up to the default 600s to appear. Run '$0 --setup' first for a live demo."
    fi

    echo ""
    echo -e "${RED}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║            INJECTING RTR CHURN ANOMALY                 ║${NC}"
    echo -e "${RED}║                                                        ║${NC}"
    echo -e "${RED}║   Bulk-adding ROAs to Routinator's SLURM exceptions    ║${NC}"
    echo -e "${RED}║   Baseline: P99 ~107 announced, historical max 293     ║${NC}"
    echo -e "${RED}║   Expect a vrp_announced hard trip on the next sync    ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""

    BEFORE="$(routinator_vrps)"
    BEFORE_SERIAL="$(routinator_serial)"
    warn "Routinator VRPs before injection: ${BEFORE:-unknown} (serial ${BEFORE_SERIAL:-unknown})"

    log "Adding ${CHURN_COUNT} marked ROAs (AS${CHURN_ASN}) to ${SLURM_FILE}..."
    ADDED="$(edit_slurm add)"
    log "Injected ${ADDED} assertion(s). Waiting for Routinator to serve them..."

    # A full validation cycle on this instance takes ~100-105s regardless of
    # --refresh (refresh is the inter-cycle *delay*, not the single-cycle
    # duration, and here the cycle far outlasts the refresh interval). Poll
    # well past that. Watch the RTR serial incrementing — a new serial means a
    # fresh validation cycle was published, which is a cleaner and more
    # immediate signal than the served VRP count.
    LANDED=0
    for i in $(seq 1 180); do
        NOW_SERIAL="$(routinator_serial)"
        if [[ -n "$BEFORE_SERIAL" && -n "$NOW_SERIAL" && "$NOW_SERIAL" -gt "$BEFORE_SERIAL" ]]; then
            log "Routinator published serial ${NOW_SERIAL} (was ${BEFORE_SERIAL}) after ${i}s — churn is live."
            LANDED=1
            break
        fi
        sleep 1
    done
    [[ $LANDED -eq 0 ]] && warn "Injection written, but a new Routinator serial wasn't observed within 180s (check /tmp/routinator.log and --refresh)."

    echo ""
    log "Churn injected. RAVEN's next sync should emit an anomaly record:"
    warn "  tail -f <monitor --log-file> | grep '\"event_type\":\"anomaly\"'"
    warn "  (category statistical, severity high, trigger vrp_announced)"
    warn "or watch the raven_rtr_anomaly_total counter (Prometheus/Grafana)."
    warn "To clean up: $0 --clean"
    ;;

*)
    err "Unknown argument '$1'. Usage: $0 [--setup|--clean]"
    ;;
esac
