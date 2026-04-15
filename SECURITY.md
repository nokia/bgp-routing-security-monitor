# Security Policy

## Supported Versions

RAVEN is currently in active development. Security fixes are applied to the
latest release only.

| Version | Supported |
|---------|-----------|
| latest  | ✅        |
| older   | ❌        |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Report vulnerabilities by emailing the maintainers directly:
- Ritesh Mukherjee ([@ritmukhe](https://github.com/ritmukhe))

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested remediation if known

You can expect an acknowledgement within 48 hours and a resolution timeline
within 7 days of confirmation.

## Scope

RAVEN is a passive observability tool — it accepts inbound BMP sessions from
routers and outbound RTR connections to RPKI validators. Relevant scope
includes:

- BMP listener (default port 11019) — unauthenticated TCP, intended for
  trusted network segments only
- RTR client — connects to RPKI validators you configure
- REST/gRPC API (default port 11020) — intended for localhost access only
  unless explicitly exposed

RAVEN makes no changes to routing state and has no data-plane presence.
