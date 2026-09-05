# TLSGate security audit — 2026-09-05

Reviewed baseline `1e013f0` with Gatekit
`v0.4.1-0.20260904110711-df675f75a372`, then upgraded to Gatekit `v0.5.0`.
Scope: passive TLS parsing, fingerprint decisions, backend forwarding,
resource bounds, SQLite persistence, notifications, control-plane integration,
and deployment configuration. This was a source review with isolated local
reproductions, not a live-host penetration test.

## Findings and resolutions

All four findings below were reproduced on the audit baseline and addressed
in the accompanying TLSGate changes. Gatekit v0.5.0 alone did not fix them.

### High: pending fingerprints bypass strict mode

Location: `proxy.go`, `handleConn`, `case StatusPending`.

A fingerprint first observed during `--allow-unknown` enrollment or from a
trusted source is stored as pending. A subsequent strict-mode observation
preserves that status. The pending branch logs and falls through to the backend
dial even when the current source is untrusted and `blockThis` is true.
Consequently, removing enrollment mode does not restrict access to explicitly
approved fingerprints, and observing a fingerprint on a trusted source permits
that fingerprint from other sources too. This bypasses TLSGate's gate; it does
not bypass authentication provided by the TLS backend.

Reproduction: seed a pending entry from a captured TLS ClientHello, then replay
that ClientHello through strict-mode `handleConn` from a non-allowlisted source.
A local backend received the forwarded handshake for both JA3 and JA4.

Resolution: reject pending entries when `blockThis` is true. Regression tests
create pending entries through both enrollment and trusted-source connections,
then verify strict rejection, explicit approval, and trusted-source bypass for
both JA3 and JA4.

### Medium: notification URL validation permits plaintext SMTP

Location: `alerts.go`, `requireSecureNotificationURL`, and Shoutrrr's SMTP service.

Validation rejects HTTP and `disabletls`, but permits SMTP options
`encryption=None&starttls=No`. A syntactically accepted configuration can send
alert bodies in plaintext, exposing observed IPs, fingerprints, and TLS metadata
to network observers. Shoutrrr's default explicit-TLS mode also permits fallback
when the server does not advertise STARTTLS. Exploitation depends on SMTP being
configured and the network path; an unauthenticated TLS client cannot configure
the notification URL itself.

Reproduction: an accepted SMTP URL sent a synthetic alert to an isolated
loopback SMTP server without TLS. No real recipients or credentials were used.

Resolution: require explicit `encryption=ImplicitTLS` when loading configuration
and constructing senders. Reject insecure and ambiguous encryption options.
Tests verify there is no SMTP plaintext fallback and untrusted certificates
fail validation.

### Medium: blocked-range alert deduplication grows without a bound

Location: `alerts.go`, successful-send handling; Gatekit store's
`RecordBlockedRangeAlert` and `blocked_range_alerts` table.

Each successfully notified range/IP pair creates a persistent row. Fingerprint
pruning and reset do not remove these rows, and neither the fingerprint cap nor
Gatekit v0.5.0's per-fingerprint history limits cover this table. With blocked-range
notifications enabled, clients able to rotate source addresses inside a watched
range can cause continued database growth. Rate limits constrain growth speed,
not lifetime size; the bounded notification queue does not bound persistent rows.

Reproduction: 200 distinct range/IP deduplication records remained queryable
after `PruneToLimit(1)` and `ResetFingerprints()`.

Resolution: TLSGate installs a SQLite insert trigger limiting the shared table
to the latest 10,000 inserted range/IP pairs, and trims existing excess rows on
open. This enforces the bound for concurrent Gatekit writers without modifying
Gatekit v0.5.0. Evicted pairs may notify again. Integration tests cover old data,
concurrent writers, duplicates, and re-notification after eviction.

### Low: noncanonical fingerprints and raw JA4 log characters

Locations: `ja3.go`, `ja3FromHello`; `ja4.go`, `ja4ALPN`; `proxy.go`, fingerprint logs.

JA3 retains GREASE in ciphers, extensions, and curves, contrary to the
[JA3 specification](https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41/).
Adding only GREASE changes the resulting key. This causes key churn and can
prevent imported canonical allow/block decisions from matching. A correction
changes existing keys and needs an explicit compatibility or re-enrollment plan.

JA4 takes the first and last ALPN runes verbatim instead of applying the
[JA4 byte and hexadecimal fallback rules](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md).
A synthetic ALPN containing a newline produced newline characters in JA4, which
is interpolated into connection logs without escaping. This can split log lines
and yields noncanonical fingerprints; it is not evidence of code execution.

Resolution: exclude GREASE from JA3, implement JA4 ALPN endpoint-byte/hex rules,
and quote fingerprint fields in connection logs. Tests cover GREASE rotation
and published JA4 ALPN examples. A format marker prevents silently reinterpreting
existing decisions; populated older databases require explicit reset and
re-enrollment. See the [upgrade procedure](operations.md#upgrading-fingerprint-format-and-smtp-transport).

## Dependency changes applied

- Pin Gatekit `v0.5.0` and tidy module checksums.
- Pass configured `max_fingerprints` into the serving store so new observations
  enforce the cap transactionally, while preserving approved entries. Retain the
  startup and periodic pass for existing rows and control-plane insertions.
- Inherit 64 KiB observation metadata limits, 128-entry IP/port/sighting bounds,
  cleanup of preexisting oversized data, paginated control-plane snapshots,
  context cancellation, and rejection of control-plane redirects.
- Keep management CLI opens free of an implicit fingerprint-count policy.

Opening an existing database trims excess history and clears oversized metadata.
Back up historical data before upgrading if it must be retained. Verdicts,
labels, and observation counts are retained. The TLSGate fixes above are applied in addition to the Gatekit update.
The separate explicit format reset deletes decisions and fingerprint history.

## Validation

Baseline race tests and vet passed; govulncheck reported no known reachable
vulnerabilities. Local behavioral reproductions confirmed the findings above.
Upgrade regression tests cover immediate row limits, unlimited mode, approval
and fingerprint-method preservation, bounded history, TLS metadata retention,
and atomic rejection of oversized metadata. Existing tests cover legacy database
opening, TLS reassembly, forwarding, draining, and trusted-range updates.
The upgraded tree passed `go test -race ./...`, `go vet ./...`,
`golangci-lint run ./...` (v2.13.2), and `go mod verify`; govulncheck
reported no known reachable vulnerabilities. The original behavioral findings were reproduced with Gatekit v0.5.0 alone;
security regression tests now verify the corrected TLSGate behavior.

No live service was deployed or exercised. TLS fingerprints are reproducible
client characteristics, not authentication credentials.
