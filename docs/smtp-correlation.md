# SMTP TLS correlation (report only)

SMTP mode observes STARTTLS ClientHellos without terminating TLS. It never
applies the fingerprint approval/block database, and the correlation command
never installs a block. Use its report to measure false-positive risk first.

Configure a dedicated route and event file in the runtime JSON:

```json
{
  "routes": [
    {"listen": "[::]:25", "backend": "127.0.0.1:10025", "protocol": "smtp", "proxy_protocol": "v2"}
  ],
  "smtp_events": "/var/lib/tlsgate/smtp-events.jsonl",
  "smtp_instance": "mx-public",
  "fingerprint": "ja4"
}
```

Start it with `tlsgate serve --config /etc/tlsgate/config.json`. Explicit CLI
flags override their JSON counterparts; CLI routes replace configured routes.
The equivalent all-CLI invocation is:

```sh
tlsgate serve \
  --route '[::]:25=127.0.0.1:10025,protocol=smtp,proxy-protocol=v2' \
  --smtp-events /var/lib/tlsgate/smtp-events.jsonl \
  --smtp-instance mx-public \
  --db /var/lib/tlsgate/smtp-proxy.sqlite \
  --fingerprint ja4
```

The backend must trust PROXY headers only from tlsgate. For Postfix postscreen,
configure `postscreen_upstream_proxy_protocol = haproxy` (PROXY v2 requires
Postfix 3.5 or newer) and enable `smtpd_client_port_logging = yes`. The source
port is essential: the collector deliberately refuses IP-only joins.

Export spam-filter decisions as one JSON object per line. Every record must
contain an RFC3339 `timestamp`, the same `instance`, `queue_id`, and an explicit
`classification` of `spam`, `ham`, or `unknown`. `score`, `action`, and
`symbols` are evidence; action alone is never interpreted as ham or spam. See
[`examples/rspamd-tlsgate.lua`](../examples/rspamd-tlsgate.lua).

The example marker names `TLSGATE_CLASS_SPAM` and `TLSGATE_CLASS_HAM` are
placeholders. Rspamd does not create them. Connect them only to operator-verified
spam and ham policy signals; do not derive either marker from the metric action
or score alone. If neither marker, or both markers, are present, the exporter
records `unknown`.

Create the event directory with write access for the dedicated tlsgate service
user. The separate proxy database above avoids changing the fingerprint-method
setting used by existing implicit-TLS routes.

Install the example and add this line to `/etc/rspamd/rspamd.local.lua`,
preserving any existing custom rules (use deployment management and ownership
appropriate for your host):

```lua
dofile('/etc/rspamd/tlsgate.lua')
```

```sh
cp examples/rspamd-tlsgate.lua /etc/rspamd/tlsgate.lua
rspamadm configtest -c /etc/rspamd/rspamd.conf
```

Change the config path in the test command if your installation uses another
one. The example synchronously appends to a local regular file. Do not point it
at a network mount, pipe, or FIFO: storage latency would enter message scanning.
It logs write failures at a bounded rate. Configure log rotation and permissions
so every Rspamd worker can append safely.

Then correlate a bounded, completed log batch:

```sh
tlsgate correlate-smtp \
  --events /var/lib/tlsgate/smtp-events-2026-09-08.jsonl \
  --postfix-log /var/log/mail-2026-09-08.log \
  --verdicts /var/log/rspamd-tlsgate-2026-09-08.jsonl \
  --instance mx-public --listener '203.0.113.25:25' \
  --db /var/lib/tlsgate/smtp-correlation.sqlite --format json
```

`--listener` must exactly equal the `listener` value in tlsgate's start events,
which is the concrete local socket address observed for that connection. Use
one collector input batch for each instance and listener. Postfix smtpd records
do not carry the destination listener needed to separate a mixed batch safely.

Rotate all three input logs and process completed snapshots. Renaming the active
tlsgate event file alone does not reopen it. Rename it, send tlsgate `SIGHUP` for
its graceful handoff, and wait for the old process to drain before treating the
renamed file as complete. Rotate Postfix and Rspamd logs with their supported
service rotation/reopen mechanisms. Then run `correlate-smtp` on the three files
covering the same closed time period.

Inputs are capped at 64 MiB and 100,000 lines each, and the database retains at
most 100,000 correlation rows. Use shorter rotation periods if a batch reaches
either limit. The command uses
stable event keys and recomputes rows on replay. Timestamp tolerance defaults
to one second. Ambiguous connections, missing session boundaries, multiple
distinct verdicts for a reused queue ID, and messages too close to STARTTLS
remain unmatched.

For a shorter local retention period, stop concurrent collector runs and prune
by message time, then reclaim space if required:

```sh
sqlite3 /var/lib/tlsgate/smtp-correlation.sqlite \
  "DELETE FROM smtp_correlations WHERE julianday(message_at) < julianday('now','-90 days');"
sqlite3 /var/lib/tlsgate/smtp-correlation.sqlite "VACUUM;"
```

Postfix queue IDs can be reused, and content-filter reinjection can replace a
queue ID. Reinjection ID mapping is not supported yet, so those messages remain
unmatched and must not inform reputation. One SMTP connection may
carry multiple messages. Plaintext messages before a later STARTTLS transition
are not attributed to that TLS fingerprint.

The SMTP observer understands multiline replies, PIPELINING, DATA dot bodies,
and fragmented TLS records. It falls back to transparent forwarding when it
sees BDAT, oversized command state, or malformed TLS. Telemetry uses a bounded
queue; a full or failed collector path can lose observations but cannot stop
mail forwarding. Counts named `no_observed_upgrade` mean exactly that; missing
or incomplete telemetry is reported separately and is not proof of plaintext.

Rspamd API references: [`task:get_queue_id()`, `task:get_metric_result()`, and
`task:get_symbols_all()`](https://docs.rspamd.com/lua/rspamd_task/), and
[`rspamd_config:register_symbol()`](https://docs.rspamd.com/lua/rspamd_config/).
The [custom-rule loading guide](https://docs.rspamd.com/developers/examples/)
describes `rspamd.local.lua`.

The JSON report includes `records` with the queue ID, connection ID, client,
listener, message/session/verdict times, transport, classification, score,
action, symbols, and unmatched reason. The same evidence is stored in
`smtp_correlations.audit_json`; summaries describe the current input batch,
not every historical database row. All three snapshots must retain overlapping
session context at rotation boundaries. Incomplete final input lines are
rejected; do not feed a file while another process is appending it.

`TLSMessages`, `PlaintextMessages`, and `UnknownTransportMessages` count
message transports separately from connection totals. `STARTTLS` counts
accepted upgrades, not confirmed TLS handshakes. Only an observed ClientHello
after an accepted upgrade can supply a fingerprint, and timestamp overlap is
reported as unknown. Malformed records have separate counters; entire sessions
whose telemetry was lost cannot be counted. Historical logs from before this
feature was enabled cannot be retroactively fingerprinted.

Unsupported queue reinjection, absent queue IDs, and rejected sessions with no
queue assignment cannot produce a fingerprint-to-message verdict. This is a
batch collector, not a log-tailing daemon. No automatic block rules are created.

## Gatehub reporting

`tlsgate report-smtp` uploads one bounded rolling-window report to Gatehub's
dedicated `/v1/smtp/reports` endpoint. It uses the same HTTPS, bearer-token or
mTLS credentials as the normal control-plane client. The authenticated node
identity, SMTP event namespace, exact listener, coverage interval, generation
time and content-derived replay ID are included explicitly.

This endpoint is report-only. Its response carries no decisions, and TLSGate
does not copy spam or ham predictions into the fingerprint approval database.
Unknown classifications and unmatched reasons remain separate in the payload.
At most 256 fingerprint aggregates and 256 evidence records are sent, with
truncation counts; the encoded request is capped at 1 MiB.

The collector keeps upload disabled by default. Add `--report-gatehub` to its
systemd `ExecStart` only after the Gatehub SMTP report endpoint is available.
It reads credentials from `/etc/tlsgate/config.json` by default; `--config`
selects another file. Repeated windows are safe because their replay ID is
stable, while Gatehub rejects an older generation replacing a newer report.
