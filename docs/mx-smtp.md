# SMTP deployment example

Place TLSGate's report-only SMTP observer in front of a PROXY-aware MTA without
changing the policy of strict TLS routes.

## Security boundary

The SMTP observer does not authenticate, approve, or block mail clients. It
passes plaintext SMTP through, observes a later STARTTLS ClientHello without
terminating TLS, and records bounded correlation events. The MTA still owns
TLS, relay policy, authentication, spam handling, and message acceptance.

Spam and ham classifications are evidence for an offline report, not
instructions to modify the shared TLS fingerprint allowlist. Keep automatic
blocking disabled unless a separate reviewed policy is introduced.

## Example traffic path

The addresses below are documentation values, not a private deployment:

```text
[2001:db8::25]:25
        |
        v
TLSGate SMTP observer -- PROXY v2 --> 192.0.2.25:10025 --> Postfix postscreen
```

Move the MTA's direct public SMTP listener to an internal-only address first.
The backend listener must accept the selected PROXY protocol version and trust
PROXY headers only from the TLSGate host. Keep the old listener available for a
bounded rollback window, but do not publish both paths at once.

Configure the route with `protocol: smtp`, a stable `smtp_instance`, a
root-owned event path, and the MTA's PROXY-aware backend. For example:

```json
{
  "routes": [
    {
      "listen": "[::]:25",
      "backend": "192.0.2.25:10025",
      "protocol": "smtp",
      "proxy_protocol": "v2",
      "smtp_instance": "example-public-smtp",
      "smtp_events": "/var/lib/tlsgate/smtp-events.jsonl"
    }
  ]
}
```

See [deployment](deployment.md) for runtime configuration and graceful reloads.

## Validation and cutover

Use a separate loopback staging listener with its own database and event file.
Validate all of the following before moving public port 25:

1. Plaintext SMTP reaches the backend and preserves the source address/port.
2. Certificate-verified STARTTLS succeeds without TLS termination at TLSGate.
3. The observer records the expected listener, source tuple, and fingerprint.
4. Existing strict TLS routes keep their prior policy and database decisions.
5. Connection and rate limits still apply to the SMTP route.
6. A graceful reload preserves established sessions.

After cutover, repeat IPv4 and IPv6 probes with `EHLO`, `NOOP`, `STARTTLS`, and
`QUIT` without submitting a message. Inspect both TLSGate events and MTA logs.
Keep a tested rollback that restores the old binary/configuration and direct
listener without overwriting newer fingerprint decisions.

## Scheduled correlation

The repository includes:

- `scripts/mx-smtp-correlate.py` for bounded rolling-window correlation;
- `examples/rspamd-tlsgate.lua` and `examples/rspamd-tlsgate-mx.lua` for Rspamd
  verdict export;
- `examples/systemd/tlsgate-smtp-correlate.service` and `.timer`; and
- `examples/logrotate/tlsgate-smtp-correlation`.

The Ansible playbook can manage these assets with
`tlsgate_smtp_collector_enabled: true`. Configure the input/output paths,
instance, timer schedule, Gatehub upload, and optional Rspamd exporter through
the `tlsgate_smtp_collector_*` and `tlsgate_smtp_rspamd_exporter_*` variables
documented in `ansible/group_vars/tlsgate.example.yml`. The feature is disabled
by default, so non-SMTP deployments are unchanged.

The collector snapshots complete input lines, waits for an event-age delay,
and processes each concrete listener separately. Missing or ambiguous joins
remain unmatched. Replay is idempotent. It writes both the existing correlation
report and a `campaign-latest-<listener-hash>.json` report from the offline
classifier. Reports are per listener, so unmatched counts from multiple reports
must not be added together. Pass `--network-prefixes` to the collector only for
a reviewed local prefix file; campaign classification never performs live
network enrichment.

Use a root-owned directory for the event stream, MTA verdict stream, generated
reports, and replay state. Rotate both input streams together. The observer
reopens its file after a graceful reload; draining connections may briefly
append to the rotated file. Keep uncompressed archives for at least the full
correlation window.

## Gatehub reporting

Gatehub upload is opt-in. Enable `--report-gatehub` only after registering the
TLSGate node and deploying a Gatehub version with the SMTP report endpoint.
`report-smtp` retries transport errors, HTTP 429, and 5xx responses up to three
times with backoff; Gatehub treats a repeated `replay_id` as a no-op. If an
upload still fails, the collector publishes the local reports and manifest,
records `gatehub_reported: false` for that listener, and then fails the oneshot
service visibly.

SMTP reports are isolated from Gatehub decisions and policy responses. They
cannot approve or block a fingerprint and never promote spam/ham predictions
into the shared TLS fingerprint store.

The scheduled collector includes the matching bounded campaign report in each
upload. Gatehub validates and displays its signature counts and evidence, but
does not create or distribute decisions from them.

## Operations and rollback

Check timer, service, and report freshness:

```sh
systemctl list-timers tlsgate-smtp-correlate.timer
journalctl -u tlsgate-smtp-correlate.service
jq . /var/lib/tlsgate/correlation/latest.json
```

To disable correlation without affecting SMTP forwarding:

```sh
systemctl disable --now tlsgate-smtp-correlate.timer
systemctl stop tlsgate-smtp-correlate.service
```

Remove the MTA exporter only after stopping the timer and preserving newer MTA
rules. Validate the MTA configuration, reload it with its supported mechanism,
and confirm ordinary mail handling. A forwarding rollback should restore the
previous listener mapping and firewall state; it need not restore the TLSGate
database unless a schema rollback specifically requires the saved snapshot.
