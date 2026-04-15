# Contributing to RAVEN

Thank you for your interest in contributing to RAVEN!

## Getting Started

- Make sure you have Go 1.22+ installed
- Fork the repository and clone it locally
- Run `go build ./cmd/raven` to verify your setup

## Reporting Issues

Use GitHub Issues for bug reports and feature requests. Please include:
- RAVEN version (`raven version`)
- Your deployment setup (Containerlab, direct, etc.)
- Steps to reproduce
- Expected vs actual behaviour

## Submitting Changes

1. Open an issue first for anything beyond a trivial fix — let's align before you invest time
2. Fork and create a branch: `git checkout -b your-feature`
3. Make your changes with tests where applicable
4. Run `go test ./...` and `go vet ./...` — both must pass
5. Submit a pull request against `main` with a clear description of what and why

## Code Style

- Standard Go formatting: run `gofmt` before committing
- Follow existing patterns in the codebase
- Keep commits focused — one logical change per commit

## Areas Where Contributions Are Welcome

- Additional Grafana dashboards
- Bug fixes and test coverage
- Documentation improvements
- Containerlab topology examples

## Questions

Open a GitHub Discussion if you're unsure about anything before diving in.
