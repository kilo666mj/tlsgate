# Operations

Fingerprint management, alerting, Gatehub synchronization, storage limits, logs, and the enrollment workflow.

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

Labels are operator notes, not identities. JA3 and JA4 describe a client
implementation and algorithm set; multiple devices can share a fingerprint and
an attacker can copy one.

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

# Cap stored fingerprints (0/omitted = 100000; -1 = unlimited).
# Approved entries are never evicted.
max_fingerprints: 100000

# Source CIDRs that bypass the fingerprint gate (always forwarded, never
# auto-approve a fingerprint). Keep tight.
approve_ranges:
  - "198.51.100.0/24"

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
  "approve_ranges": ["198.51.100.0/24", "2001:db8:1234:5600::/59"],
  "control_plane": {
    "url": "https://gatehub.example.com",
    "instance_id": "mail-tls",
    "token": "replace-with-node-token",
    "sync_interval": "30s"
  },
  "alert_ranges": [
    {
      "name": "home",
      "cidrs": ["198.51.100.10/32", "2001:db8:1234:5600::/59"]
    }
  ]
}
```

Configuration fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `notification_urls` | With alert ranges | Shoutrrr destinations; cleartext transports are rejected. |
| `notification_mode` | No | `failover` (default) or `broadcast`. |
| `max_fingerprints` | No | `0` or omitted uses 100000; `-1` explicitly allows unlimited storage. |
| `approve_ranges` | No | Source CIDRs that bypass fingerprint gating for that connection. |
| `alert_ranges` | No | Named CIDR groups whose blocked connections trigger alerts. |
| `control_plane.url` | Enables sync | Gatehub base URL. |
| `control_plane.instance_id` | With URL | Stable name for this TLSGate instance. |
| `control_plane.token` | One auth method | Bearer token for Gatehub. |
| `control_plane.client_cert` | For mTLS | Client certificate path. |
| `control_plane.client_key` | For mTLS | Client private-key path. |
| `control_plane.ca` | For mTLS | CA bundle used to verify Gatehub. |
| `control_plane.server_name` | No | TLS name override when URL host and certificate differ. |
| `control_plane.sync_interval` | No | Go duration such as `30s`; defaults to 30 seconds. |

Use `doctor` with the same flags as the service to validate configuration,
routes, fingerprint method, and PROXY mode without opening the SQLite store,
connecting to a backend, sending alerts, or binding a port:

```bash
tlsgate doctor \
  --db /var/lib/tlsgate/db.sqlite \
  --config /var/lib/tlsgate/config.json \
  --route '[::]:993=127.0.0.1:10993' \
  --fingerprint ja4 \
  --proxy-protocol off
```

## Gatehub sync

`tlsgate` can optionally sync observed fingerprints and pull approval decisions
from `gatehub`. Configure `control_plane` in the JSON config used by `serve`:

```json
{
  "control_plane": {
    "url": "https://gatehub.example.com",
    "instance_id": "mail-tls",
    "token": "replace-with-node-token",
    "sync_interval": "30s"
  }
}
```

When `control_plane.url` is empty or omitted, sync is disabled and `tlsgate`
behaves exactly as before. The sync client periodically uploads the local
SQLite fingerprint state, then applies returned decisions locally with the same
store path used by `approve --register`. Set `token` for bearer-token auth, or
set `client_cert`, `client_key`, and `ca` for mTLS auth. The optional
`server_name` field overrides TLS server-name verification when the URL host
does not match the server certificate.

Current Gatehub policy responses may also publish expiring `trusted_ranges`.
TLSGate atomically replaces the dynamic portion of its source allowlist on each
sync while preserving local `approve_ranges`. If Gatehub omits the field,
TLSGate preserves its current dynamic set for compatibility with older servers.

## Trusted source ranges (`approve_ranges`)

`approve_ranges` lists CIDRs whose **source IP** bypasses the fingerprint gate:
connections from those addresses are always forwarded, even if the client
presents an unknown, pending, or blocked fingerprint.

Trust is **per-connection and IP-scoped only**. A whitelisted connection never
marks its fingerprint approved, so the *same* fingerprint arriving from a
non-whitelisted IP is still gated normally — an attacker who clones a trusted
client's JA3/JA4 gains nothing unless they also source from inside the range.
New fingerprints from whitelisted IPs are still recorded as `pending` (not
`blocked`) so you keep visibility into what trusted hosts present; they appear
in `tlsgate list` for review. Whitelisted connections log with a `WHITELIST`
tag.

This is the safe posture. It deliberately does **not** auto-approve
fingerprints, because the store is keyed by fingerprint, not IP — approving a
fingerprint would extend trust to every IP that can replay it. Use
`approve_ranges` for a trusted management subnet or a known-good origin; keep
the ranges as tight as possible. Removing a CIDR revokes its bypass
immediately, with no residual approvals left behind.

```json
{
  "approve_ranges": ["198.51.100.0/24", "2001:db8:1234:5600::/59"]
}
```

```yaml
approve_ranges:
  - "198.51.100.0/24"
  - "2001:db8:1234:5600::/59"
```

## Limiting store growth

Every parseable ClientHello from an unknown client is recorded, including
blocked ones. The per-IP rate limit slows a single source, but many addresses
(e.g. a wide IPv6 range) can still grow the SQLite database over time.

The store is capped at 100000 entries when `max_fingerprints` is omitted or
set to `0`. Set a smaller positive value for a tighter cap or `-1` to explicitly
allow unlimited storage. When the store exceeds the cap, the oldest
**non-approved** entries are pruned first — at startup and once a minute.
**Approved fingerprints are never evicted**, so the allow-list is unaffected;
if approved entries alone exceed the cap, the store is allowed to stay above it
rather than drop a real client. Pick a cap comfortably above your number of
real clients (which is small) so legitimate pending entries survive long enough
to be reviewed.

## Troubleshooting

- **Permission denied opening SQLite:** the runtime identity needs write access
  to the database directory, not just the database file. Containers run as
  UID/GID 65532.
- **`bind: permission denied`:** ports below 1024 require
  `CAP_NET_BIND_SERVICE`; use a high port such as 1993 for initial testing.
- **Backend connection refused:** verify the backend from TLSGate's network
  namespace. Under bridge networking, `127.0.0.1` is the container itself.
- **A client connects only during enrollment:** inspect `tlsgate list -v` and
  approve the intended fingerprint before removing `--allow-unknown`.
- **Fingerprint method mismatch:** the database records JA3 or JA4. Switching
  requires an explicit reset and complete re-enrollment; do not reset casually.
- **TLS fails immediately with PROXY v2 enabled:** every backend listener must
  be configured to expect PROXY v2 before TLS bytes.
- **The service is running but unreachable:** check listeners and firewall,
  then inspect `journalctl -u tlsgate -f` or `docker compose logs -f`.

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

1. Set `allow_unknown: true` in `ansible/group_vars/tlsgate.yml` and deploy
2. Connect from all your devices (phone, laptop, etc.)
3. Run `tlsgate list` and approve each one
4. Set `allow_unknown: false` and re-deploy
