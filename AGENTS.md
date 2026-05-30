# Repository Guidelines

## Project Structure & Module Organization

This repository contains `tlsgate`, a small Go TCP proxy that fingerprints TLS
ClientHellos (JA3/JA4) and allow/blocks connections. Routes are generic
(`--route LISTEN=BACKEND`); IMAP/SMTPS are just the common preset.
Core source files live at the repository root:

- `main.go`: CLI commands (`serve`, `list`, `approve`, `correlate`, etc.).
- `proxy.go`: TCP listener, route flags, and forwarding logic.
- `ja3.go`: ClientHello parsing, JA3, and passive TLS metadata extraction.
- `ja4.go`: JA4 fingerprint computation.
- `store.go`: SQLite-backed fingerprint store.
- `*_test.go`: Go unit tests.
- `ansible/`: deployment inventory, playbook, and systemd unit template.

There are no generated assets or frontend files.

## Build, Test, and Development Commands

Use Go 1.26.3 or newer.

```bash
go build -o tlsgate .
```

Builds the local binary.

```bash
go test ./...
go vet ./...
```

Runs unit tests and static checks.

```bash
tlsgate serve --route [::]:993=127.0.0.1:10993 --db ./db.sqlite --allow-unknown
tlsgate list -v --db ./db.sqlite
tlsgate correlate --db ./db.sqlite --log ./syslog <fingerprint>
```

Useful local commands for exercising the service and CLI.

```bash
cd ansible
ansible-playbook --syntax-check playbook.yml
```

Validates deployment syntax.

## Coding Style & Naming Conventions

Format all Go code with `gofmt`. Keep functions small and explicit; prefer standard library APIs unless a dependency is already established. Use descriptive names such as `extractTLSMetadata`, `correlateSyslog`, and `StatusApproved`. Keep log messages consistent with the existing `BLOCKED`, `PENDING`, and `APPROVED` status style.

## Testing Guidelines

Tests use Go’s standard `testing` package. Add focused tests near the behavior being changed, using `*_test.go` files and names like `TestCorrelateSyslogMatchesSOGoRFC3339Lines`. Prefer temporary files/directories via `t.TempDir()` for store and log tests. Run `go test ./...` before committing.

## Commit & Pull Request Guidelines

Commit messages are short, imperative summaries, for example `Move fingerprint store to SQLite` or `Support SOGo syslog correlation`. Keep each commit focused. Pull requests should describe the behavioral change, mention deployment or data migration impact, and include the test commands run.

## Security & Configuration Tips

Do not terminate TLS unless explicitly required; this proxy is designed for passive ClientHello inspection. Keep the SQLite DB under `/var/lib/tlsgate/` with restricted permissions. Deployment changes should preserve the dedicated `tlsgate` system user and systemd hardening in `ansible/templates/tlsgate.service.j2`.
