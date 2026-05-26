# Changelog

All notable changes to RAVEN will be documented in this file.

## [0.2.0] - 2026-05-26

### Active Response (Phase 3)
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

### Transport Security
- RTR-over-TLS: configure `transport: tls` and optional
  CA cert under any RTR cache entry
- BMP listener TLS: optional TLS termination on the BMP
  listener with mutual TLS support

### Bug Fixes
- RTR `rtr-version` config field now correctly wired
  through to the client (was previously ignored)
- TCP socket buffer tuning skipped for TLS connections
  (prevented TLS sessions from establishing on some
  platforms)

## [0.1.0] - 2026-04-15

Initial public release — Phase 1 (Foundation) and Phase 2 (ASPA Intelligence) complete.

### BMP Ingest
- Embedded BMP receiver (RFC 7854) on configurable TCP port (default: 11019)
- Parses BGP UPDATE messages from BMP Route Monitoring PDUs
- Supports Adj-RIB-In Pre-Policy, Post-Policy, and Loc-RIB
- Per-session lifecycle management (Initiation, Peer Up/Down, Termination)

### RPKI / RTR Client
- RTR v1 (RFC 8210) and RTR v2 (draft-ietf-sidrops-8210bis) client
- VRP store for Route Origin Validation
- ASPA store for AS_PATH validation (populated via RTR v2 ASPA PDUs)
- Multi-cache support with preference ordering and automatic failover
- Re-validation on RPKI cache updates via dirty-set propagation

### Validation Engine
- Route Origin Validation (ROV) per RFC 6811: Valid / Invalid / NotFound
- ASPA path verification per draft-ietf-sidrops-aspa-verification-24
- Combined security posture: Secured / Origin-Only / Path-Suspect /
  Path-Only / Unverified / Origin-Invalid

### CLI
- `raven serve` — start daemon
- `raven status` — BMP peer and RTR cache health
- `raven peers` — list BMP peers
- `raven routes` — query route table with filters (prefix, origin-asn, peer, posture)
- `raven validate` — one-shot prefix validation
- `raven watch` — stream live validation state changes
- `raven aspa` — show ASPA records for an ASN
- `raven aspa recommend` — suggest ASPA objects based on observed paths
- `raven what-if` — simulate impact of reject-invalid or ASPA enforcement

### Observability
- Prometheus metrics endpoint (default: 9595)
- Pre-built Grafana dashboards (Security Posture Overview, Per-Peer Deep Dive)

### Demo Lab
- Containerlab topology: internet AS2121 → upstream AS65000 → edge AS65001
- Scripted demo scenarios: origin hijack, more-specific hijack, route leak
- What-if simulation and ASPA recommender demo commands
