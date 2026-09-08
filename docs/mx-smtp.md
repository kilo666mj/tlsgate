# mx SMTP deployment

On 2026-09-08, mx deployed `v0.7.0-smtp-a7bbf2732424`, combining the
v0.7.0 runtime configuration change (upstream `1f0c0865`) with SMTP observation.

## Traffic path

Public IPv4/IPv6 port 25 is owned by the existing `tlsgate.service`:

```text
[::]:25 -> SMTP observer -> PROXY v2 -> 172.22.1.253:10025 -> Postfix postscreen
```

Port 10025 is Mailcow's existing PROXY-aware listener inside its Postfix
container, not a host listener. Its master.cf was unchanged. Mailcow's direct
plain SMTP publication is now `SMTP_PORT=127.0.0.1:10026` in
`/opt/mailcow-dockerized/mailcow.conf`, freeing public port 25.
Host firewalld permits public `25/tcp` in runtime and permanent configuration.

Plaintext SMTP passes through. STARTTLS passes through and its ClientHello is
fingerprinted without terminating TLS. SMTP fingerprint decisions do not block
connections; general connection/rate limits still apply. Existing strict TLS
routes on 443, 465 and 993 retain their policy and shared database.

The service loads `/etc/tlsgate/config.json`. The SMTP route uses
`protocol: smtp`, `proxy_protocol: v2`, `smtp_instance: mx-public-smtp`, and
`smtp_events: /var/lib/tlsgate/smtp-events.jsonl`. The ignored mx Ansible host
variables mirror these settings. A graceful reload applied the config and new
binary while existing sessions drained.

Postfix `extra.cf` persists `smtpd_client_port_logging = yes`, enabling exact
source-port correlation. See [SMTP correlation](smtp-correlation.md) for the
offline importer and Rspamd exporter example. The exporter and scheduled
correlation were subsequently installed as described below. Automatic spam-based
blocking remains disabled.

## Validation

A separate hardened staging process on loopback 2525 used its own database
and events. Plaintext and certificate-verified STARTTLS probes passed there.
After cutover, public IPv4 and IPv6 plaintext and verified STARTTLS probes
passed with EHLO/NOOP/QUIT and no submitted messages. Live event records and
Postfix logs preserved original source addresses and ports. Existing approved
IMAPS traffic resumed. Go tests, race tests and vet passed before deployment.
The staging service was stopped and its transient unit removed after validation.

## Backup and rollback

Root-only `/var/backups/tlsgate-smtp-20260908T130859Z/` holds the old binary,
config, unit, Mailcow config, Postfix extra.cf/main.cf, and a consistent SQLite
snapshot. The five-minute rollback timer was cancelled after validation and
the directory's `confirmed` marker records acceptance.

To deliberately roll back this cutover, inspect the saved script first, then
run as root (this interrupts connections and restores direct public SMTP):

```bash
backup=/var/backups/tlsgate-smtp-20260908T130859Z
rm "$backup/confirmed"
bash "$backup/rollback.sh"
```

The script restores the old binary/config and Mailcow port mapping, recreates
only the Postfix container, removes the host INPUT port-25 allowance, and
starts tlsgate. It does not restore the database, preserving newer decisions.
Revert mx's SMTP inventory settings before a subsequent deployment following
rollback. Review for newer host changes before using this historical rollback.

## Scheduled correlation

`tlsgate-smtp-correlate.timer` runs every five minutes with up to 15 seconds
of jitter. Its root-owned, hardened oneshot service runs
`/usr/local/libexec/mx-smtp-correlate.py`. It snapshots complete input lines,
selects completed sessions from a rolling 24-hour window ending two minutes
ago, and processes each concrete listener separately. Replay is idempotent.
Missing or ambiguous joins remain unmatched. The first run successfully
reported connection observations; no real message verdict had arrived yet.

The exporter is persisted in Mailcow's `data/conf/rspamd/lua/tlsgate.lua` and
loaded at the end of `lua/rspamd.local.lua`. It writes to the existing Rspamd
volume at `/var/lib/rspamd/tlsgate/verdicts.jsonl` inside the container.
The deployed source is [rspamd-tlsgate-mx.lua](../examples/rspamd-tlsgate-mx.lua).
Classification uses the existing `BAYES_SPAM` and `BAYES_HAM` symbols. These
are model predictions, not independently verified labels. Both or neither
means unknown; metric score/action and symbol names are retained as evidence.
A local scan-only probe verified JSON output without submitting or learning
mail; `TLSGATEPROBE` queue IDs are excluded from correlation inputs.

Reports and the separate SQLite database are root-only:

```bash
sudo systemctl list-timers tlsgate-smtp-correlate.timer
sudo journalctl -u tlsgate-smtp-correlate.service
sudo cat /var/lib/tlsgate/correlation/latest.json
```

The manifest maps listeners to `latest-<hash>.json` reports in the same
directory. Counts cover the current input batch, not lifetime totals. Each
listener's report evaluates the same Postfix batch, so unmatched counts must
not be summed across listeners. Historical messages before telemetry started
and sessions without queue IDs cannot acquire TLS attribution retroactively.

`/etc/logrotate.d/tlsgate-smtp-correlation` rotates both telemetry files daily
and keeps seven uncompressed archives. The observer reopens via graceful
reload; draining connections may keep appending to a rotated file. Each run
snapshots its initial size and never hands a live file to the Go importer.
An incomplete rotated tail causes a visible failure and is retried next run.
Combined input limits remain 64 MiB and 100,000 lines per source; a limit
failure leaves the previous report in place. Check manifest freshness and
service failures; shorten the input/retention window if volume reaches limits.
Sessions lasting beyond the 24-hour window are excluded.

Gatehub upload is available but remains opt-in. Add `--report-gatehub` to the
collector service only after deploying a Gatehub version with the dedicated
SMTP report endpoint. The manifest then records `gatehub_reported: true` for
each successfully uploaded listener; a failed upload fails the oneshot and
leaves the prior manifest in place for operational visibility. Reporting never
applies Gatehub decisions to SMTP and never promotes spam/ham predictions into
the shared TLS fingerprint store.

To disable scheduling, use `systemctl disable --now
tlsgate-smtp-correlate.timer` and stop the oneshot service if running. The
pre-exporter Lua entrypoint is backed up in
`/var/backups/tlsgate-correlation-20260908/rspamd.local.lua`. To remove the
exporter later, remove its dofile line (preserving newer custom rules), run
`docker exec mailcowdockerized-rspamd-mailcow-1 rspamadm configtest`, then
`docker kill --signal HUP mailcowdockerized-rspamd-mailcow-1`. The controller's
`rspamadm control reload` returned Not found on this installation; SIGHUP was
verified to reload gracefully. Disabling correlation does not affect SMTP
forwarding or existing TLS fingerprint policy.
