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

## Mail login routes on the same host

Strict TLS routes for IMAPS and SMTPS on the same host need the same treatment
as port 25: send PROXY v2 to a PROXY-aware listener, not to a Docker-published
loopback port. An unproxied login route makes the MTA and IMAP server see every
client as tlsgate or the container gateway. That blinds IP-based bans, and on
Mailcow it can make port 465 relay without authentication, because Mailcow's
`mynetworks` includes its container network. See
[Mail login backends](deployment.md#mail-login-backends-imaps-smtps-submission-pop3s)
for the Mailcow listeners and the Dovecot trust setting. `tlsgate doctor` warns
when a mail login route lacks PROXY protocol.

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

## Mailcow fail2ban whitelist

Once Mailcow sees real client addresses, its netfilter bans whole networks
(IPv6 `/64`, IPv4 `/24` by default) after a few failed logins. A single device
with a stale password can then lock out every device on a trusted network. A
static whitelist entry breaks when that network's address or prefix changes.

`scripts/mailcow-f2b-trusted-sync.py` keeps netfilter's whitelist in step with
Gatehub's trusted ranges, using TLSGate's
[`trusted_ranges_file`](operations.md#publishing-trusted-ranges):

- It adds each trusted range to the Redis hash `F2B_WHITELIST`, which
  netfilter re-reads every minute.
- It removes only entries it added itself, tracked in a state file. Entries
  entered in the Mailcow UI are never changed.
- It queues an unban for active bans that overlap a trusted range; a whitelist
  entry alone only prevents new bans.
- It refuses ranges broader than IPv4 `/16` or IPv6 `/32` and more than 32
  entries, and leaves Redis unchanged when the ranges file is missing or
  invalid.
- It passes the Redis password from `mailcow.conf` to `redis-cli` through the
  environment, not the command line.

Saving fail2ban settings in the Mailcow UI rewrites `F2B_WHITELIST`, so run the
script on a timer as well as when the file changes. The Ansible playbook does
both when `tlsgate_mailcow_f2b_sync_enabled` is true and `trusted_ranges_file`
is set; it installs `tlsgate-mailcow-f2b-sync.service` with a `.path` unit and
a five-minute `.timer`. Preview changes with `--dry-run`.

A whitelisted network is never banned by Mailcow, but TLSGate still applies
fingerprint policy outside the trusted ranges, and failed logins remain in the
Dovecot and Postfix logs.

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
