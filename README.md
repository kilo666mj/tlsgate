# tlsgate

<p align="center">
  <img src="docs/art/tlsgate-mark.png" alt="tlsgate mark" width="260">
  <br>
  <a href="https://github.com/kilo666mj/gatehub"><img src="docs/art/porter-mascot.png" alt="Porter mascot for the gate tools" width="320"></a>
</p>

> **Written with AI.** This project was developed with the help of an AI
> assistant (Anthropic's Claude, via Claude Code). The code has been reviewed
> and tested, but treat it accordingly: read it before you run it, and see the
> security model below for what it does and does not protect.

`tlsgate` is a TCP proxy that fingerprints TLS ClientHellos with JA3 or JA4
and allows or blocks connections using an approval store. Routes are generic;
fronting mail submission and retrieval ports is the common case.

It can run standalone or report observations to
[Gatehub](https://github.com/kilo666mj/gatehub), the shared control plane for
the `*gate` tools.

https://github.com/user-attachments/assets/16ee363c-249f-4c97-a35c-2d30159c9f01

## How it works

`tlsgate` sits in front of one or more TLS backends and reads the ClientHello
before forwarding traffic. Unknown fingerprints are blocked by default. During
enrollment, `--allow-unknown` records new fingerprints as pending while
allowing them through; remove it after approving known clients.

```text
client ──► tlsgate ── approved fingerprint ──► TLS backend
                    └─ unknown or blocked ───► drop
```

The proxy does not terminate TLS. Approved traffic continues to the real
backend unchanged.

## Security model

**A TLS fingerprint is not a credential. JA3 and JA4 are trivially spoofable.**

Treat this as a noise filter against opportunistic scanners and generic
credential-stuffing traffic, not as authentication or access control. The real
security boundary remains the backend's TLS termination, authentication,
rate-limiting, and abuse controls. Do not weaken backend security because
`tlsgate` is present.

The proxy also enforces per-source and global connection limits and bounds
fingerprint-store growth. Those controls reduce resource abuse but do not make
fingerprints identities.

## JA3 or JA4

Use `--fingerprint ja3` (the default) or `--fingerprint ja4`.

- JA3 is order-sensitive and has a large public corpus, but clients that shuffle
  TLS extensions can produce unstable fingerprints.
- JA4 sorts ciphers and extensions before hashing, making it more stable for a
  small self-seeded allowlist.

The database records which method created its keys. Starting with a different
method fails rather than silently invalidating existing decisions. Switching
methods requires an explicit reset and re-enrollment.

## Quick start

Build and test with Go 1.26.3 or newer:

```sh
go build -o tlsgate .
go test ./...
```

Run a local route with a temporary enrollment window:

```sh
./tlsgate serve \
  --route [::]:993=127.0.0.1:10993 \
  --db ./tlsgate.db \
  --fingerprint ja4 \
  --allow-unknown
```

After connecting known clients, review and approve their fingerprints:

```sh
./tlsgate list -v --db ./tlsgate.db
./tlsgate approve --db ./tlsgate.db --label "Alice phone" <fingerprint>
```

Remove `--allow-unknown` for normal operation.

## Deployment

The included Ansible playbook is the primary deployment path:

```sh
cd ansible
ansible-playbook --syntax-check playbook.yml
ansible-playbook playbook.yml --ask-become-pass
```

The backend must first move from its public port to an internal-only port.
Deployment changes on an inline proxy need graceful handoff so active
connections are not dropped.

See [deployment](docs/deployment.md) for Ansible variables, graceful upgrades,
Docker, and PROXY protocol configuration.

## Documentation

- [Deployment](docs/deployment.md)
- [Operations](docs/operations.md) — fingerprint management, alerts, Gatehub
  sync, storage limits, logs, and enrollment
- [Repository guidance](AGENTS.md)

## License

MIT. See [LICENSE](LICENSE).
