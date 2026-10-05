#!/bin/bash
# Loc-RIB (RFC 9069) lab: deploy, check and destroy.

set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/../.." && pwd)"
TOPOLOGY="$LAB_DIR/loc-rib.clab.yml"
API="http://172.31.90.10:11020/api/v1"
RR1_ID="10.0.12.1"
TIMEOUT="${TIMEOUT:-60}"

usage() {
  cat <<EOF
Usage: $(basename "$0") <command>

Loc-RIB lab: rr1 exports its Loc-RIB to RAVEN, rr2 exports the pre-policy
Adj-RIB-In of its iBGP session to rr1. rr1's router-id is also the address
rr2 peers with, so both views share the peer address $RR1_ID.

Commands:
  up       Build a static RAVEN binary and deploy the lab
  test     Run the live checks against the deployed lab
  down     Destroy the lab
  all      up, test, then down (the lab stays up if a check fails)
  -h, --help
           Show this help

Environment:
  TIMEOUT  Seconds to wait for each check to converge (default: 60)

Examples:
  $(basename "$0") all
  $(basename "$0") up && $(basename "$0") test
EOF
}

if [[ -t 1 ]]; then
  BOLD=$'\e[1;36m' GREEN=$'\e[32m' RED=$'\e[31m' RESET=$'\e[0m'
else
  BOLD="" GREEN="" RED="" RESET=""
fi

step() {
  printf '\n%s== %s%s\n' "$BOLD" "$1" "$RESET"
}

vtysh() {
  local node=$1
  shift
  local args=()
  for line in "$@"; do
    args+=(-c "$line")
  done
  docker exec "clab-loc-rib-$node" vtysh "${args[@]}" >/dev/null
}

# Routes of one RIB as "prefix as_path posture" lines, sorted.
routes() {
  local rib=$1
  curl -s --noproxy '*' "$API/routes" \
    | jq -r --arg rib "$rib" --arg peer "$RR1_ID" \
      '.[] | select(.rib == $rib and .peer == $peer) | "\(.prefix) \(.as_path | map(tostring) | join(",")) \(.posture)"' \
    | sort
}

# expect <description> <expected output> <command...>: retry until the
# command prints the expected output or TIMEOUT expires.
expect() {
  local desc=$1 want=$2
  shift 2
  local got="" i
  for ((i = 0; i < TIMEOUT; i++)); do
    got="$("$@" 2>/dev/null || true)"
    if [[ $got == "$want" ]]; then
      printf '  %sok%s    %s\n' "$GREEN" "$RESET" "$desc"
      return 0
    fi
    sleep 1
  done
  printf '  %sFAIL%s  %s\n' "$RED" "$RESET" "$desc"
  printf '        want: %s\n        got:  %s\n' "${want//$'\n'/ | }" "${got//$'\n'/ | }"
  return 1
}

peer_types() {
  curl -s --noproxy '*' "$API/peers" \
    | jq -r --arg peer "$RR1_ID" '[.[] | select(.addr == $peer) | .type] | sort | join(",")'
}

cmd_up() {
  step "Build a static RAVEN binary"
  (cd "$REPO_DIR" && CGO_ENABLED=0 go build -o "$LAB_DIR/bin/raven" ./cmd/raven)

  step "Deploy the lab"
  containerlab deploy -t "$TOPOLOGY" --reconfigure
}

cmd_test() {
  local loc_rib="192.0.2.0/24 64510 unverified
198.51.100.0/24 64510 origin-invalid
203.0.113.0/24 64510 origin-only"
  local pre_policy="192.0.2.0/24 64510 unverified
198.51.100.0/24 64510 origin-invalid
203.0.113.0/24 64510 origin-only"
  local failed=0

  step "Initial state"
  expect "rr1's Loc-RIB and rr2's view of rr1 are two peers on $RR1_ID" "global,loc-rib" peer_types || failed=1
  expect "Loc-RIB: one best route per prefix, 10.99.0.0/24 rejected by rr1's import policy" "$loc_rib" routes loc-rib || failed=1
  expect "pre-policy: rr2's Adj-RIB-In from rr1, stored apart" "$pre_policy" routes pre-policy || failed=1

  step "ext1 withdraws 192.0.2.0/24 and 203.0.113.0/24"
  vtysh ext1 "configure terminal" "router bgp 64510" "address-family ipv4 unicast" \
    "no network 192.0.2.0/24" "no network 203.0.113.0/24"
  expect "Loc-RIB: 192.0.2.0/24 is withdrawn, 203.0.113.0/24 moves to the ext2 path" \
    "198.51.100.0/24 64510 origin-invalid
203.0.113.0/24 64520,64510 origin-only" routes loc-rib || failed=1
  vtysh ext1 "configure terminal" "router bgp 64510" "address-family ipv4 unicast" \
    "network 192.0.2.0/24" "network 203.0.113.0/24"
  expect "Loc-RIB: back to the ext1 paths" "$loc_rib" routes loc-rib || failed=1

  step "Peer down on rr2 for $RR1_ID"
  vtysh rr2 "configure terminal" "router bgp 65000" "neighbor $RR1_ID shutdown"
  expect "pre-policy: rr2's routes from $RR1_ID are withdrawn" "" routes pre-policy || failed=1
  expect "Loc-RIB: rr1's routes on the same peer address stay" "$loc_rib" routes loc-rib || failed=1
  vtysh rr2 "configure terminal" "router bgp 65000" "no neighbor $RR1_ID shutdown"
  expect "pre-policy: rr2's routes are back" "$pre_policy" routes pre-policy || failed=1

  step "End of rr1's BMP session"
  vtysh rr1 "configure terminal" "router bgp 65000" "no bmp targets raven"
  expect "Loc-RIB: rr1's routes are withdrawn" "" routes loc-rib || failed=1
  expect "pre-policy: rr2's routes on the same peer address stay" "$pre_policy" routes pre-policy || failed=1
  vtysh rr1 "configure terminal" "router bgp 65000" "bmp targets raven" \
    "bmp monitor ipv4 unicast loc-rib" \
    "bmp connect 172.31.90.10 port 11019 min-retry 1000 max-retry 5000"
  expect "Loc-RIB: rr1's routes are back after the new session" "$loc_rib" routes loc-rib || failed=1

  step "Result"
  if ((failed)); then
    printf '%sSome checks failed.%s\n' "$RED" "$RESET"
    return 1
  fi
  printf '%sAll checks passed.%s\n' "$GREEN" "$RESET"
}

cmd_down() {
  step "Destroy the lab"
  containerlab destroy -t "$TOPOLOGY" --cleanup
}

case "${1:-}" in
  up) cmd_up ;;
  test) cmd_test ;;
  down) cmd_down ;;
  all) cmd_up && cmd_test && cmd_down ;;
  -h | --help) usage ;;
  *)
    usage >&2
    exit 2
    ;;
esac
