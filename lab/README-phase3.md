# RAVEN Phase 3 Lab Guide — Active Response

## What This Demonstrates

Phase 3 adds active response on top of the passive BGP validation from Phase 2.
Three capabilities are shown:

| Capability | What it does |
|---|---|
| **Event Engine** | Fires rules when route posture changes (new origin-invalid, new path-suspect) |
| **Webhook** | POSTs a JSON alert payload to an HTTP endpoint on each rule fire |
| **Flowspec (dry-run)** | Logs the BGP Flowspec mitigation rule that *would* be injected into GoBGP |
| **raven audit** | Prints a read-only security posture summary for a specific router |

The GoBGP container is management-network only — it provides the gRPC API target for
Flowspec injection. Because `dry_run: true` is set in `raven.yaml`, the lab works even
if the GoBGP gRPC endpoint is temporarily unreachable.

---

## Prerequisites

The lab must already be running from Phase 2:

```bash
bash lab/demo-master.sh setup
```

Verify RAVEN is healthy:

```bash
bash lab/demo-master.sh baseline
```

---

## Quick Start — Full Sequence

Run the entire Phase 3 demo in one command:

```bash
bash lab/demo-master.sh phase3
```

This automatically: starts the webhook listener, runs a baseline audit, injects the
hijack (triggering a webhook alert), audits again, cleans up, injects a route leak,
audits again, and cleans up.

---

## Running Individual Commands

### Webhook listener

Start a simple HTTP server on port 9999 that prints every incoming POST body:

```bash
bash lab/demo-master.sh webhook-listen
```

The listener runs in the background. Keep this terminal visible so you can watch
alert payloads arrive in real time.

### Hijack scenario (triggers origin-invalid alert)

```bash
bash lab/demo-master.sh hijack
```

After the hijack is injected, RAVEN detects the posture change from the Event Engine
and fires the `alert-origin-invalid` rule: a `WARN` log entry, a webhook POST to
`172.17.0.1:9999`, and a dry-run Flowspec drop rule for the hijacked prefix.

Clean up:

```bash
bash lab/demo-master.sh hijack-clean
```

### Route leak scenario (triggers path-suspect alert)

```bash
bash lab/demo-master.sh leak
```

Fires the `alert-route-leak` rule: a `WARN` log entry and a webhook POST.
No Flowspec rule is generated for path-suspect (only origin-invalid has the
flowspec action configured).

Clean up:

```bash
bash lab/demo-master.sh leak-clean
```

### Flowspec dry-run demo

Injects the hijack and shows the dry-run Flowspec rule that would be pushed to GoBGP:

```bash
bash lab/demo-master.sh flowspec
```

### Security audit

Run a posture audit against the edge router:

```bash
bash lab/demo-master.sh audit             # table format (default)
bash lab/demo-master.sh audit json        # JSON
bash lab/demo-master.sh audit markdown    # GFM markdown
```

Or call `raven audit` directly:

```bash
raven audit --router 172.20.20.3
raven audit --router 172.20.20.3 --format json
```

---

## Terminal Layout

Four windows give the clearest view of Phase 3 in action:

**Window 1 — RAVEN daemon logs**
```bash
tail -f /tmp/raven.log
```
Look for:
- `"msg":"raven event"` — Event Engine rule fired
- `"rule":"alert-origin-invalid"` — which rule matched
- `"flowspec: dry-run inject"` — Flowspec rule logged without GoBGP call

**Window 2 — Webhook listener**
```bash
bash lab/demo-master.sh webhook-listen
```
Watch for JSON payloads with `"type":"posture_change"`, `"new_posture":"origin-invalid"`,
prefix, peer address, and router ID.

**Window 3 — Grafana**

Open: `http://localhost:3000/d/raven-security-posture` (admin / raven123)

Watch the `origin-invalid` and `path-suspect` gauge panels update as scenarios run.

**Window 4 — Demo commands**
```bash
bash lab/demo-master.sh hijack
bash lab/demo-master.sh audit
bash lab/demo-master.sh leak
# etc.
```

---

## Troubleshooting

**Webhook not firing**

1. Check that the events block is present in `raven.yaml` — restart RAVEN if you
   edited the file after it started.
2. The rule has a 30 s cooldown per prefix. If you run hijack twice quickly, the
   second fire is suppressed. Wait 30 s between runs or restart RAVEN to reset cooldown state.
3. Confirm the listener is running: `curl -X POST http://localhost:9999 -d '{}'`

**GoBGP container not reachable**

The `dry_run: true` flag in `raven.yaml` bypasses the GoBGP gRPC call entirely.
Flowspec rules are logged but never sent, so the demo is unaffected even if the
`gobgp` container is not yet started. To verify: search `/tmp/raven.log` for
`"dry-run"`.

**audit returns zero routes**

`raven audit` filters by router ID (`RouterID` field on each route, populated by the
BMP peer's router-id advertisement). Make sure you are using the correct IP:

```bash
raven peers   # check the router_id column
raven audit --router <router_id_from_peers>
```

The edge router's router-id in this lab is `172.20.20.3`.

**Cooldown confusion**

Both rules have `cooldown: 30s`. This means a rule fires at most once per prefix
per 30 s window. If you clean and re-inject a scenario within 30 s, the second
injection will not trigger the webhook. Either wait 30 s or restart RAVEN.
