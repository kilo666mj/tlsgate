# SMTP TLS correlation (report only)

SMTP mode observes STARTTLS ClientHellos without terminating TLS. It never
applies the fingerprint approval/block database, and the correlation command
never installs a block. Use its report to measure false-positive risk first.

SMTP connections also produce normal service-journal entries prefixed
`OBSERVED smtp`, with `event="start"`, `event="starttls"`,
`event="fingerprint"`, or `event="end"`. They include a connection ID,
client address/port, listener, and backend. STARTTLS entries carry
`state="accepted"` or `state="refused"`; fingerprint entries include JA3 and
JA4. End entries report the final observation state. Backend/PROXY-header
setup failures end as `observer_incomplete` with a reason. Rate-limit
rejections use `BLOCKED smtp` with `state="rate_limit"`.

Journal logging works even without a JSONL event file and remains independent
of the JSONL writer's queue health. It does not log SMTP commands, message
content, or credentials. `OBSERVED` is an observation, not an approval or a
pending enforcement decision. To follow SMTP entries:

```sh
sudo journalctl -fu tlsgate | grep --line-buffered ' smtp '
```

### Content-free behavior fingerprints

Version 1 end events may also contain an additive `behavior` object. Existing
version 1 readers can ignore this unknown field. The object contains only a
closed vocabulary of behavioral dimensions; it never contains HELO names,
envelope arguments, recipients, AUTH material, DATA/BDAT bytes, or other raw
command text.

The v1 dimensions are:

- commands completed before the server greeting: `none`, `one`, or `many`;
- the first normalized verb and the first 12 normalized verbs as a `>`-joined
  shape, with extra verbs represented only by `verb_overflow=true`;
- command line endings: `crlf`, `lf`, `mixed`, or `none`;
- first-command and first-STARTTLS timing from TCP accept: `under_1s`,
  `1s_to_5s`, `5s_to_30s`, `30s_or_more`, or `unknown`;
- STARTTLS outcome: `accepted`, `refused`, `not_seen`, or `unknown` when
  observation became incomplete before an outcome was known.

Recognized SMTP verbs are emitted by name; every other token is `OTHER`.
`fingerprint` has the form `smtp-behavior/v1/<hex>`, where `<hex>` is the full
lowercase SHA-256 of this UTF-8 canonical record:

```text
v=1|pre=<bucket>|first=<verb>|eol=<style>|first_timing=<bucket>|starttls_timing=<bucket>|verbs=<shape>|overflow=<bool>|starttls=<outcome>
```

Absent verbs and shapes use `NONE`. Missing timings use `unknown`. These exact
values and field order are the v1 compatibility contract; changing them
requires a new behavior version. Timing is intentionally coarse telemetry and
the fingerprint remains report-only—it is not an authentication identity or a
TLSGate allow/block key.

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
BDAT byte counts, and fragmented TLS records. It falls back to transparent
forwarding when it sees malformed BDAT framing, oversized command state, or malformed TLS. Telemetry uses a bounded
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

## Offline campaign classification

`tlsgate classify-smtp` is a sibling, report-only classifier. It consumes the
same completed TLSGate event snapshots plus RFC3339-prefixed Postfix/Postscreen
logs; it does not read Rspamd verdicts, call a network enrichment service, or
write any TLSGate/Gatehub decision database.

```sh
tlsgate classify-smtp \
  --events /var/lib/tlsgate/smtp-events-2026-09-19.jsonl \
  --postfix-log /var/log/postfix-2026-09-19.log \
  --instance mx-public --listener '203.0.113.25:25' \
  --network-prefixes /etc/tlsgate/smtp-network-prefixes.json \
  --format json
```

The output schema is `smtp-campaign-report/v1`. A Postfix/Postscreen evidence
session is attributable only when exactly one TLSGate connection has the same
instance, invocation-scoped listener, canonical client IP **and source port**,
and contains every evidence timestamp within its completed, bounded lifetime.
The default maximum lifetime is ten minutes and timestamp tolerance is one
second. Missing and overlapping candidates remain visible as
`no_exact_connection` or `ambiguous_exact_connection`; there is no IP-only or
nearest-time fallback.

The initial signature is
`smtp/pregreet-helo-support-selfdomain/v1`. It requires all of the following:

1. TLSGate behavior v1 observed one or more pre-greeting commands and `HELO`
   as the first normalized verb.
2. Postscreen independently recorded a pre-greeting `HELO` on the exact tuple.
3. A rejection on that session recorded an envelope sender whose local part is
   `support`.
4. The canonical HELO domain exactly equals that sender's canonical domain.

This intentionally excludes unrelated Postscreen rule-5/PREGREET traffic,
`EHLO` probes, other sender local parts, and mismatched HELO domains. Provider
and recipient clustering are context only and never make a record match. Raw
sender, HELO, and recipient values are omitted from output; the recipient is a
lowercase SHA-256 cluster identifier.

Optional network context comes only from an operator-supplied regular JSON file
of at most 1 MiB. Prefixes must be canonical CIDRs; the longest match wins:

```json
{
  "prefixes": [
    {"prefix": "192.0.2.0/24", "provider": "example-cloud"}
  ]
}
```

This file is enrichment metadata, not an allow/block list. Classification has
no inline DNS, WHOIS, cloud API, or other live-network dependency. Treat log
payloads as untrusted evidence: malformed targeted records are counted, raw
payload text is never copied to reports, and only bounded parsed fields inform
the signature.

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
