# Changelog

All notable changes to RAVEN are recorded here.

## Unreleased

### Added
- RTR anomaly detection: adaptive median/MAD-based detector for RTR sync
  telemetry (interval, duration, VRP/ASPA churn) with per-cache rolling
  baselines, hard-trip and correlated-trip classification.
- Restart-safe baseline persistence via `--anomaly-snapshot` on
  `raven rtr monitor` — anomaly detector windows survive process restarts.
- `raven rtr seed-baseline` command to seed a detector baseline from
  historical NDJSON telemetry, avoiding the ~25-hour warm-up window on
  every fresh deployment.
- New Prometheus metrics: `raven_rtr_anomaly_total`,
  `raven_rtr_anomaly_last_timestamp`.
- `lab/04-rtr-anomaly.sh` Containerlab demo scenario for live RTR
  anomaly detection (bulk SLURM ROA injection, serial-based confirmation).
- `/api/v1/audit` takes a `rib` parameter and `raven audit` a `--rib` flag (`pre-policy` by default, `post-policy`, `loc-rib`). The report shows its RIB and has one peer row per peer address and Peer Distinguisher.
- BMP Loc-RIB monitoring (RFC 9069, peer type 3): routes are stored as Loc-RIB under the router's BGP ID and the Peer Distinguisher, so the Loc-RIB of each router and of each VRF stays separate. A Loc-RIB peer is registered from its first Route Monitoring message when the router sends no Peer Up for it (FRR 10.2). `/api/v1/routes` lists pre-policy and Loc-RIB routes, with or without a `prefix`, `origin-asn`, `peer` or `posture` filter, and `/api/v1/watch` streams Loc-RIB routes too. `/api/v1/routes`, `/api/v1/watch` and `raven routes` show the RIB and the Peer Distinguisher of each route; `/api/v1/peers` and `raven peers` show the BMP peer type (`global`, `rd`, `local`, `loc-rib`) and the Peer Distinguisher.
- `lab/loc-rib/` Containerlab lab that checks Loc-RIB monitoring live with FRR, StayRTR and the RAVEN binary built from the repository (`./run.sh all`).
- `rib` event trigger (`ribs: ["pre-policy", "post-policy", "loc-rib"]`). In a `compound` trigger, it keeps a rule to the routes of some RIBs; see `raven.yaml`.

### Changed
- `raven routes` no longer decodes the AS path of each route, which it did not show.
- A route snapshot with an unknown RIB type is rejected instead of being restored as pre-policy.
- `raven_routes_total`, `raven_route_table_size` and the OTel `raven.routes.total` have a `rib` label (`pre-policy`, `post-policy`, `loc-rib`) and count the routes of every RIB. Before, they counted pre-policy routes only: filter on `rib="pre-policy"` to keep the old values, as `lab/grafana-dashboard.json` does.
- `raven_bmp_peer_state` has a `distinguisher` label, empty for a global peer.
- Route snapshots store the Peer Distinguisher of each route.
- Event rules fire once for each RIB and Peer Distinguisher of a route, so a router that sends several RIBs can trigger one action per RIB. Webhook payloads have new `rib` and `peer_distinguisher` fields, and the log action logs the peer, the Peer Distinguisher and the RIB.
- `proto/raven/v1/raven.proto` and the snapshot schema `internal/proto/snapshot/v1/snapshot.proto` have the new RIB, peer type and Peer Distinguisher fields of the JSON API and the snapshot file.
- `raven status` shows the RD and the type of each BMP peer, as `raven peers` does.
- The API, the CLI, the metric labels and the events show a Peer Distinguisher as a route distinguisher: `64500:100`, `192.0.2.1:7`, and `4200000000L:9` for a 4-byte AS, so RD types 0 and 2 stay apart.
- `lab/README-phase3.md` describes the event rule cooldown per route (prefix, peer, Peer Distinguisher and RIB).
- The audit report always has the `peer_distinguisher` field of each peer, empty for a global peer, as the routes and peers API does.

### Fixed
- A BGP withdrawal of a route that is not pre-policy now sends its `route_withdraw` event with the withdrawn route.
- A withdrawal now removes only the RIB it was sent for, and a peer down removes only the pre-policy and post-policy routes of that peer. Before, a pre-policy withdrawal also removed the post-policy and Loc-RIB routes held under the same peer address.
- An event rule cooldown applies per route (prefix, peer address, Peer Distinguisher and RIB), so the event of a route in one RIB no longer suppresses the event of a route in another RIB.
- Routes and BMP peers are keyed by peer address and Peer Distinguisher, so two RD peers with the same address no longer overwrite each other, and the peer down of one no longer removes the routes of the other.
- RTR anomaly detector no longer evaluates or contaminates its baseline
  with full (non-incremental) RTR syncs, which previously produced a
  false-positive high-severity anomaly on every `raven rtr monitor`
  startup.
  
- `raven check stealthy` and `raven check global` take the expected neighbor AS of a Loc-RIB route from the first AS of its path, not from its peer (the router itself), and `check stealthy` does not take a Loc-RIB peer for a BGP neighbor.
- The what-if simulator and the ASPA recommender read pre-policy routes only. Before, they counted a route once for each RIB that a router sent.
- The OTel `raven.peer.routes` metric has new `router`, `peer_distinguisher` and `peer_type` attributes, so BMP peers with the same address on different routers, instances or peer types no longer share one series.
- A withdraw-all without a RIB list removes the routes of the peer in every RIB, instead of none.
## v0.3.3 (2026-07-02)

### Added
- RTR session telemetry: structured per-sync event capture (VRP/ASPA
  announced/withdrawn deltas, sync duration, interval between serial
  advances, sync type full vs incremental) wired into the RTR client
  at four points: session connect, EndOfData, PDUCacheReset, and
  PDUErrorReport. Events written as NDJSON and mirrored on a buffered
  channel for downstream consumers.
- `raven rtr monitor` command: standalone RTR cache observer for
  baseline data collection and diagnostics. Config-file-free (flags
  only: `--cache`, `--log-file`, `--transport`, `--prometheus`).
  Graceful shutdown with bounded 70s grace period. Optional Prometheus
  endpoint. Useful for characterising normal RTR behaviour before
  deploying full RAVEN.
- `tls-min-version` config option for RTR and BMP TLS transports.
  Accepts `1.2` or `1.3`; defaults to TLS 1.2 minimum. Addresses
  operator transport security requirements (Orange/AS3215).

### Fixed
- RTR client: 65s read deadline with benign-timeout handling prevents
  shutdown from blocking indefinitely on idle caches while avoiding
  spurious reconnects on healthy sessions.
- RTR client: proto version reset to configured starting version on
  each reconnect, preventing permanent version downgrade caused by
  transient errors during cache startup.
- Telemetry event channel drained in standalone `rtr monitor` mode
  to prevent buffer fill and drop warnings during sustained reconnect
  loops.

### Changed
- Grafana: BGP Peers panel filtered to IPv4-only peers, height
  increased to accommodate IPv6 peer additions.

## v0.3.2 (2026-06-16)

### Fixed
- Demo lab: all `docker exec` calls in `demo-master.sh` now use `sudo` (silent
  injection failures occurred when run without root)
- Demo lab: `setup()` now injects `LEAK-PREFIX` prefix-list into running FRR
  containers via `vtysh` post-deploy; Containerlab mounts `frr.conf` but FRR
  does not reload on redeploy, causing the leak scenario to fail on cold start
- Demo lab: Routinator 0.15.1 changed CLI syntax; `--config` flag must now be
  passed as a global flag before the subcommand
  (`routinator -c ~/.routinator.conf server`) not after it
- Grafana: BGP Peers panel filtered to IPv4-only peers and panel height
  increased (IPv6 peer additions doubled tile count, causing overflow)

## v0.3.1 (2026-06-08)

### Added
- IPv6 route monitoring via BMP (`MP_REACH_NLRI` / `MP_UNREACH_NLRI` parsing)
- IPv6 ROV validation
- IPv6 origin hijack scenario in demo lab (`./demo-master.sh hijack6`)
- TLS support for BMP listener and RTR client; skip TCP buffer tuning
  (`SetReadBuffer`/`SetWriteBuffer`) for TLS connections (WSL2 compatibility)

### Fixed
- Demo lab: `lacnic` scenario 4 route leak used inline `LEAK-INJECT` route-map
  with wrong prepend ASN (AS64496 → ROV:Invalid); replaced with permanent
  `ROUTE-LEAK` route-map (prepend AS1199 → ROV:Valid, ASPA:Invalid,
  posture:path-suspect as intended)
- Demo lab: `leak` and `hijack6` vtysh commands converted to heredoc syntax
  (`docker exec ... bash -c "vtysh << 'VTYSH' ... VTYSH"`) to fix silent
  failures caused by leading spaces in `-c` arguments
- Demo lab: leak scenario prefix corrected to `193.0.0.0/21` (AS3333 /
  RIPE NCC); SLURM ASPA assertion added for AS3333 with provider AS1103
  (excluding AS65000 to trigger path-suspect)

### Changed
- Demo lab internet router ASN changed from AS2121 to AS64496 to avoid
  spurious `path-suspect` at baseline caused by real-world RPKI/ASPA
  records for AS2121

## v0.3.0 (2026-05-26)

### Added
- Event Engine: configurable triggers on posture changes
  (ROV state change, new route with specific posture,
  RTR cache failure) with webhook HTTP POST and file
  log actions
- Flowspec lifecycle management: detect origin-invalid
  route → generate Flowspec rule → inject via GoBGP →
  monitor → expire after configurable TTL. Dry-run mode
  and approval webhook supported.
- `raven audit` — full security posture report for a
  router: per-peer posture breakdown, ROV/ASPA coverage,
  recommendations. Outputs table, JSON, or markdown.
- `raven check stealthy` — detect stealthy BGP hijacks
  by comparing BMP control-plane view against data-plane
  forwarding via probes
- Warm-start persistence: snapshot route table and RPKI
  caches to disk on shutdown, restore on startup
- OpenTelemetry OTLP metrics export alongside Prometheus
- RTR-over-TLS: configure `transport: tls` and optional
  CA cert under any RTR cache entry
- BMP listener TLS: optional TLS termination on the BMP
  listener with mutual TLS support
- Event Engine ASN triggers: `asn` and `protected_asn`
  trigger types (contributed by Orange/AS3215)

### Fixed
- RTR `rtr-version` config field now correctly wired
  through to the client (was previously ignored)
- TCP socket buffer tuning skipped for TLS connections
  (prevented TLS sessions from establishing on some
  platforms)

## v0.2.0 (2026-05-18)

### Added
- ASPA path verification per draft-ietf-sidrops-aspa-verification-24
- Combined security posture matrix: Secured / Origin-Only / Path-Suspect /
  Path-Only / Unverified / Origin-Invalid
- ASPA store populated via RTR v2 ASPA PDUs; re-validation on ASPA
  store updates via dirty-set propagation
- `raven aspa` — show ASPA records for an ASN
- `raven aspa recommend` — suggest ASPA objects based on observed paths
- `raven what-if` — simulate impact of reject-invalid or ASPA enforcement
- `raven watch` — stream live validation state changes
- Prometheus posture metrics reflect full ROV × ASPA matrix

## v0.1.0 (2026-04-15)

Initial public release — Phase 1 (Foundation) complete.

### BMP Ingest
- Embedded BMP receiver (RFC 7854) on configurable TCP port (default: 11019)
- Parses BGP UPDATE messages from BMP Route Monitoring PDUs
- Supports Adj-RIB-In Pre-Policy, Post-Policy, and Loc-RIB
- Per-session lifecycle management (Initiation, Peer Up/Down, Termination)

### RPKI / RTR Client
- RTR v1 (RFC 8210) and RTR v2 (draft-ietf-sidrops-8210bis) client
- VRP store for Route Origin Validation
- Multi-cache support with preference ordering and automatic failover
- Re-validation on RPKI cache updates via dirty-set propagation

### Validation Engine
- Route Origin Validation (ROV) per RFC 6811: Valid / Invalid / NotFound

### CLI
- `raven serve` — start daemon
- `raven status` — BMP peer and RTR cache health
- `raven peers` — list BMP peers
- `raven routes` — query route table with filters (prefix, origin-asn, peer, posture)
- `raven validate` — one-shot prefix validation

### Observability
- Prometheus metrics endpoint (default: 9595)
- Pre-built Grafana dashboards (Security Posture Overview, Per-Peer Deep Dive)

### Demo Lab
- Containerlab topology: internet AS64496 → upstream AS65000 → edge AS65001
- Scripted demo scenarios: origin hijack, route leak