#!/usr/bin/env bash
# Phase 2b Demo: What-If Simulator + ASPA Recommender
set -euo pipefail
RAVEN_ADDR="${RAVEN_ADDR:-localhost:11020}"
raven_cmd() { ./raven --address "$RAVEN_ADDR" "$@"; }

echo "=== REJECT-INVALID IMPACT ==="
raven_cmd what-if --reject-invalid

echo "=== ASPA ENFORCEMENT IMPACT ==="
raven_cmd what-if --aspa-enforce

echo "=== ASPA RECOMMENDATIONS ==="
raven_cmd aspa recommend --min-observations 1

echo "=== ASPA RECORD LOOKUP ==="
raven_cmd aspa --asn 13335
