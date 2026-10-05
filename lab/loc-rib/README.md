# Loc-RIB lab

A small Containerlab topology that checks BMP Loc-RIB monitoring (RFC 9069) live: RAVEN must store each router's Loc-RIB apart from the Adj-RIB-In views, and withdraw it correctly.

## Topology

```text
  ext1 AS64510 ──┐
                 ├── rr1 AS65000 ──── rr2 AS65000
  ext2 AS64520 ──┘   router-id 10.0.12.1
                     BMP: Loc-RIB      BMP: pre-policy
                          │                 │
                          └──── RAVEN ──────┘ ◄── StayRTR (vrps.json)
```

| Node | Role |
|------|------|
| `ext1` | Announces `203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24` and `10.99.0.0/24` |
| `ext2` | Announces `203.0.113.0/24` with a longer path (`64520 64510`) |
| `rr1` | Rejects `10.99.0.0/24` on import, exports its Loc-RIB to RAVEN |
| `rr2` | iBGP to rr1 on `10.0.12.1`, exports the pre-policy Adj-RIB-In of that session to RAVEN |
| `raven` | The RAVEN binary built from this repository |
| `rtr` | StayRTR with three ROAs: `203.0.113.0/24` valid, `198.51.100.0/24` invalid, `192.0.2.0/24` not found |

rr1's router-id `10.0.12.1` is also the address rr2 peers with. RAVEN names a Loc-RIB by the router's BGP ID, so rr1's Loc-RIB and rr2's view of rr1 share one peer address: the lab checks that they stay separate.

## Run

```bash
./run.sh all       # build, deploy, check, destroy
./run.sh up        # build and deploy only
./run.sh test      # run the checks against a deployed lab
./run.sh down      # destroy
```

The management network is `172.31.90.0/24`. The RAVEN API is at `http://172.31.90.10:11020/api/v1`.

```bash
curl -s http://172.31.90.10:11020/api/v1/routes | jq -c '.[] | {prefix, peer, rib, as_path, posture}'
curl -s http://172.31.90.10:11020/api/v1/peers | jq -c '.[] | {addr, type, asn, route_count}'
```

## Checks

| Step | Expected |
|------|----------|
| Initial state | Two peers on `10.0.12.1` (`global` and `loc-rib`). The Loc-RIB holds one route per prefix, without the prefix rejected by rr1. rr2's pre-policy routes are stored apart |
| ext1 withdraws two prefixes | The Loc-RIB drops `192.0.2.0/24`, and `203.0.113.0/24` moves to the ext2 path |
| rr2 shuts its session to rr1 | rr2's pre-policy routes are withdrawn, rr1's Loc-RIB routes stay |
| rr1 removes its BMP target | rr1's Loc-RIB routes are withdrawn, rr2's pre-policy routes stay |

## FRR notes

- rr1 runs a pinned FRR master build (bgpd 10.8.0-dev, 2026-10-02). FRR 10.2.5 sends no Loc-RIB Peer Up, puts its own AS first in the Loc-RIB AS_PATH, and sends no Loc-RIB message after a best path change. RAVEN registers a Loc-RIB peer from its first Route Monitoring message for this reason.
- The master build sends no Loc-RIB withdrawal when a BGP session goes down, only when the neighbor withdraws a prefix. The lab uses prefix withdrawals on ext1 for this reason.
- rr2 needs `soft-reconfiguration inbound`: without it, FRR sends only End-of-RIB markers to a new BMP session in pre-policy mode.
- RAVEN uses RTR version 1 because StayRTR does not speak version 2, and the `auto` fallback from version 2 does not reach it.
