# 🐦‍⬛ RAVEN

**Routing Analysis, Validation, and Event Network**

*Ravens see what you can't.*

RAVEN is an open-source, lightweight, single-binary routing security observability tool. It connects directly to your routers via BMP, validates every route against RPKI ROV and ASPA path validation in real time, and exposes the results through a CLI, Prometheus metrics, and Grafana dashboards.

---

## Quick Start

```bash
# Install
go install github.com/nokia/bgp-routing-security-monitor/cmd/raven@latest

# Start RAVEN
raven serve --config raven.yaml

# See your routes
raven routes --posture origin-invalid
```

## What Does RAVEN Answer?

> *"Show me every route I'm receiving, whether the origin is RPKI-valid, whether the AS_PATH is ASPA-valid, and what I should do about the ones that aren't."*

## Key Capabilities

| Capability | Description |
|---|---|
| **BMP Ingest** | Accept BMP sessions from any vendor's router |
| **ROV** | Route Origin Validation per RFC 6811 |
| **ASPA** | AS_PATH validation per draft-ietf-sidrops-aspa-verification-24 |
| **Combined Posture** | Secured / Origin-Only / Path-Suspect / Unverified / Origin-Invalid |
| **What-If** | Simulate impact of reject-invalid or ASPA enforcement |
| **ASPA Recommender** | Suggest ASPA objects based on observed AS_PATHs |
| **Prometheus** | `/metrics` endpoint for Grafana dashboards |
| **Single Binary** | Zero dependencies — download and run |

## Documentation

Full documentation including installation, CLI reference, demo lab, and
production deployment guide:

**[ritmukhe.github.io/raven-docs](https://ritmukhe.github.io/raven-docs)**

## Demo Lab

Run the full stack on your laptop using Containerlab:

```bash
git clone https://github.com/nokia/bgp-routing-security-monitor.git
cd bgp-routing-security-monitor
bash lab/demo-master.sh setup
```

Includes scripted origin hijack, route leak, and what-if simulation scenarios.

## Standards

| Standard | Usage |
|---|---|
| RFC 7854 | BMP — BGP Monitoring Protocol |
| RFC 6811 | ROV — Route Origin Validation |
| RFC 8210 | RTR v1 — Router to Relying Party Protocol |
| draft-ietf-sidrops-8210bis | RTR v2 — VRP + ASPA delivery |
| draft-ietf-sidrops-aspa-verification-24 | ASPA path verification |

## License

BSD-3-Clause — Copyright (c) 2026, Nokia

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
