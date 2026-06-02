# tlsgate

> **Written with AI.** This project was developed with the help of an AI
> assistant (Anthropic's Claude, via Claude Code). The code has been reviewed
> and tested, but treat it accordingly: read it before you run it, and see the
> security model below for what it does and does not protect.

TCP proxy that computes a TLS ClientHello fingerprint (JA3 or JA4) and
allows/blocks connections based on an approval store. Routes are generic
(`--route LISTEN=BACKEND`, repeatable); fronting a mail server on IMAP (993)
and SMTPS (465) is the common case but not the only one.

## How it works

Sits in front of one or more TLS backends, peeks at the ClientHello before
forwarding. Unknown fingerprints are **blocked by default** — only approved
fingerprints get forwarded. Pass `--allow-unknown` to temporarily let unknown
connections through while setting up.

The original and primary use is fronting [mailcow](https://mailcow.email/) on
the mail submission/retrieval ports; examples below use that setup.

## JA3 vs JA4

`--fingerprint ja3` (default) or `--fingerprint ja4` selects which fingerprint
is the allow/block key. Both are always computed and recorded; only the key
used for decisions changes. The store key changes with the method, so the
database records which method built it: starting `serve` with a different
`--fingerprint` than the stored one **refuses to start** rather than silently
orphaning every approval and block. To switch, either purge ahead of time with
`tlsgate reset --fingerprint <new>` (a one-off that exits) or pass
`serve --reset-fingerprints` to purge during startup. Either way you re-approve
clients afterward.

- **JA3** — MD5 over TLS version, cipher list, extension list, curves, and EC
  point formats. Order-sensitive: a client that shuffles its TLS extension order
  (GREASE, deliberate randomization) yields a different JA3 per connection,
  which can falsely block a legitimate client. Large public corpus.
- **JA4** — sorts ciphers and extensions before hashing, so it is stable across
  extension reordering — fewer false blocks. The fingerprint is also
  human-readable (e.g. `t13d1516h2_8daaf6152771_b186095e22b6`: TCP, TLS 1.3,
  SNI present, cipher/extension counts, ALPN, then two truncated SHA-256
  hashes). Recommended for a small self-seeded allow-list.

Neither is a credential — see the security model below. The choice only affects
the false-positive rate, not how hard the fingerprint is to spoof.

## Security model — read this

**A TLS fingerprint (JA3 or JA4) is not a credential. It is trivially
spoofable.** The proxy does not terminate TLS; it decides solely on the bytes
of the ClientHello. An attacker who crafts a ClientHello matching an approved
fingerprint is forwarded. The fingerprints of common clients (Apple Mail,
Thunderbird, Outlook, browsers) are publicly known, so an attacker does not
even need to observe your traffic to guess an approved value.

Treat this as a **noise filter, not access control**. It cheaply turns away the
constant background of opportunistic scanners and credential-stuffing bots that
don't bother matching a real client's TLS fingerprint, which keeps logs and
alerts readable. It does **not** authenticate anyone. The actual security
boundary remains the backend: real TLS termination plus the backend's own
authentication (e.g. IMAP/SMTP auth on mailcow). Do not weaken backend
hardening (strong passwords, fail2ban, rate limits) on the assumption that
fingerprint blocking gates access.

## Prerequisites

- the backend service must be moved off its public port to an internal-only
  port (for mailcow: ports 993 and 465 to e.g. 10993 and 10465)
- Go 1.26.3+ on the machine running the Ansible playbook

## Deploy

```bash
cd ansible
ansible-playbook playbook.yml --ask-become-pass
```

To temporarily allow unknown fingerprints (e.g. during initial setup), set
`allow_unknown=true` in `ansible/inventory` and re-run.

To use JA4 instead of JA3, set `fingerprint=ja4` in `ansible/inventory` (default
`ja3`). Switching the method on an existing database refuses to start until you
also pass `--reset-fingerprints` (purges stored fingerprints); re-approve
clients after.

## Docker

Prebuilt multi-arch images (`linux/amd64`, `linux/arm64`) are published to GHCR:

```bash
docker pull ghcr.io/kilo666mj/tlsgate:latest
```

Or build the static `FROM scratch` image yourself:

```bash
docker build -t tlsgate .
```

### docker compose

The repo ships an example [`docker-compose.yml`](docker-compose.yml) that fronts
a mailcow backend on the standard ports. Adjust the routes/backends, then:

```bash
docker compose up -d
```

It uses host networking so the localhost backends are reachable and tlsgate sees
real client source IPs; a bridge-network variant is included as a comment.

### docker run

Run it with persistent state mounted at the default database/config directory:

```bash
docker run --rm \
  -p 993:993 \
  -p 465:465 \
  -v tlsgate-data:/var/lib/tlsgate \
  tlsgate serve \
    --route [::]:993=127.0.0.1:10993 \
    --route [::]:465=127.0.0.1:10465 \
    --allow-unknown
```

Each `--route LISTEN=BACKEND` adds a proxied port; repeat it for as many
services as you need (host or container-network backend addresses):

```bash
docker run --rm \
  --network host \
  -v tlsgate-data:/var/lib/tlsgate \
  tlsgate serve \
    --route [::]:993=127.0.0.1:10993 \
    --route [::]:465=127.0.0.1:10465
```

## Managing fingerprints

```bash
# List all seen fingerprints
tlsgate list

# Include full passive TLS metadata, including the JA3 string
tlsgate list -v

# Correlate a fingerprint with Postfix/Dovecot/mailcow syslog lines
tlsgate correlate <fingerprint>

# Approve a fingerprint (optionally label it)
tlsgate approve --label "Alice iPhone" <fingerprint>

# Pre-approve a fingerprint before its first connection (seed the allow-list
# ahead of cutover so a known client is never blocked on first contact). The
# fingerprint must be a full hash matching the database's method (ja3 or ja4).
tlsgate approve --register --label "Alice iPhone" <fingerprint>

# Block a fingerprint (--register pre-blocks one not yet seen)
tlsgate block <fingerprint>

# Label an already-approved fingerprint
tlsgate label <fingerprint> "Alice MacBook"

# Delete a fingerprint entry
tlsgate delete <fingerprint>

# Purge all fingerprints (one-off, e.g. before switching ja3<->ja4).
# Pass --fingerprint to also record the new method so the next serve starts
# clean; omit it to wipe while keeping the current method.
tlsgate reset --fingerprint ja4
```

All commands accept `--db <path>` to point at a non-default database.
Default database: `/var/lib/tlsgate/db.sqlite`

When tlsgate is running with Docker Compose, run management commands inside the
running service container so they use the same mounted database:

```bash
docker compose exec tlsgate /tlsgate list

docker compose exec tlsgate /tlsgate approve --label "Alice iPhone" <fingerprint>
```

`correlate` reads `/var/log/syslog` by default and matches the fingerprint's
known IPs around its first/last seen timestamps. Use `--log <path>` for another
log file and `--window 5m` to widen the matching window.

In a container, `/var/log/syslog` is not present unless you mount it explicitly
into the running service. With Compose, add a read-only log bind mount:

```bash
volumes:
  - tlsgate-data:/var/lib/tlsgate
  - /var/log/syslog:/var/log/syslog:ro
```

Then run:

```bash
docker compose exec tlsgate /tlsgate correlate <fingerprint>
```

Correlation is most useful with host networking because tlsgate sees real
client IPs. With bridge networking, Docker NAT may record the Docker gateway IP
instead. If tlsgate is not already running, a one-off `docker run` works too,
but it must mount the exact same database volume or host path used by the
service.

## Blocked range alerts

`serve` reads optional alert configuration from
`/var/lib/tlsgate/config.json`, or another path passed with
`--config <path>`. If `alert_ranges` are configured, a blocked connection from
a matching CIDR sends a Shoutrrr notification the first time each source IP is
seen for that range. Alerts are deduplicated in SQLite, so repeated blocked
attempts from the same IP/range do not spam the channel.

Ansible deploys this config when `alert_ranges` is defined. Prefer the
router-advertised IPv6 delegated prefix over the narrower `/64` shown on a
single host interface.

For Ansible-managed alert config, create a local ignored file at
`ansible/group_vars/tlsgate.yml`:

```yaml
---
notification_urls:
  - "mattermost://tlsgate@matter.example/primary/logw"
  - "mattermost://tlsgate@matter2.example/secondary/logw"
notification_mode: failover

# Cap stored fingerprints (0 = unlimited). Approved entries are never evicted.
max_fingerprints: 100000

alert_ranges:
  - name: home
    cidrs:
      - "198.51.100.10/32"
      - "2001:db8:1234:5600::/59"
```

Do not commit this file; it may contain notification service secrets and
private network ranges.

`notification_urls` are Shoutrrr service URLs, so the same alert path can send
to Mattermost, Slack, Discord, Gotify, Matrix, Teams, Telegram, generic
webhooks, email, and other supported services. tlsgate refuses to start if a
notification URL would deliver over cleartext (an `+http` scheme or a
`disabletls` override), so alert content and webhook tokens are never sent in
the clear.

`notification_mode` defaults to `failover`, which tries URLs in order and stops
after the first successful delivery. Set it to `broadcast` to send every alert
to every URL and treat any failed destination as a failed delivery.

```json
{
  "notification_urls": [
    "mattermost://tlsgate@matter.example/primary/logw",
    "mattermost://tlsgate@matter2.example/secondary/logw"
  ],
  "notification_mode": "failover",
  "max_fingerprints": 100000,
  "alert_ranges": [
    {
      "name": "home",
      "cidrs": ["198.51.100.10/32", "2001:db8:1234:5600::/59"]
    }
  ]
}
```

## Limiting store growth

Every parseable ClientHello from an unknown client is recorded, including
blocked ones. The per-IP rate limit slows a single source, but many addresses
(e.g. a wide IPv6 range) can still grow the SQLite database over time.

Set `max_fingerprints` in the config to cap how many entries are kept (0, the
default, means unlimited). When the store exceeds the cap, the oldest
**non-approved** entries are pruned first — at startup and once a minute.
**Approved fingerprints are never evicted**, so the allow-list is unaffected;
if approved entries alone exceed the cap, the store is allowed to stay above it
rather than drop a real client. Pick a cap comfortably above your number of
real clients (which is small) so legitimate pending entries survive long enough
to be reviewed.

## Logs

```bash
journalctl -u tlsgate -f
```

Log lines show status per connection:

```
PENDING   fp=abc123... ja3=771,4865-4866...
APPROVED  fp=abc123...
BLOCKED   fp=def456...
RATELIMIT dropping connection
OVERLOAD  at capacity, dropping connection
```

Two limits protect against floods:

- **Per source IP** — a token bucket (~1 conn/s sustained, burst 120) checked
  before any handshake read or database write. A single IP over its budget is
  dropped with a `RATELIMIT` line. This bounds connection floods and
  fingerprint-store growth from randomized ClientHellos from one address. It
  throttles the *rate* of new entries per IP, not the lifetime total, and an
  attacker spread across many IPv6 addresses can still stay under the per-IP
  ceiling.
- **Global** — at most `maxConcurrentConns` (1024) connections are processed at
  once across all listeners, capping goroutines, file descriptors, and backend
  dials. Connections beyond the cap are dropped with an `OVERLOAD` line. This
  catches the distributed/IPv6 case the per-IP limiter misses. The systemd unit
  sets `LimitNOFILE=8192` to leave headroom above the resulting socket count.

Both limits are generous enough that legitimate clients — including many devices
behind one NAT address — do not hit them.

Fingerprint entries also store passive ClientHello metadata when available:
SNI, ALPN protocols, supported TLS versions, signature algorithms, and the
full JA3 string. This does not require terminating TLS.

The ClientHello is parsed strictly: the handshake is reassembled across TLS
records (so large, e.g. post-quantum, hellos that span multiple records are
handled), and any truncated or malformed handshake is rejected rather than
recorded as a fingerprint, so the store is not polluted by partial parses.

Verbose TLS metadata may show values such as `GREASE(0x6a6a)`. These are
reserved TLS placeholder values intentionally sent by modern clients to keep
servers tolerant of unknown TLS codes. They are not unknown protocol versions
or signature algorithms. JA3 generation skips GREASE values, while verbose
metadata keeps them visible for inspection.

## Setup workflow

1. Set `allow_unknown=true` in inventory and deploy
2. Connect from all your devices (phone, laptop, etc.)
3. Run `tlsgate list` and approve each one
4. Remove `allow_unknown=true` from inventory and re-deploy

## License

MIT. See [LICENSE](LICENSE).
