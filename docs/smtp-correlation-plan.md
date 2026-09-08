# SMTP fingerprint correlation implementation plan

## Outcome

Produce an auditable mapping from observed SMTP STARTTLS ClientHellos to
message spam-filter verdicts. Operators should be able to measure both spam
and legitimate traffic associated with a fingerprint before considering
blocking public MX connections. No live deployment or automatic reputation
blocking is part of this implementation.

## Components

1. An explicit SMTP route mode relays server-first SMTP and observes STARTTLS
   without terminating TLS. Existing implicit-TLS routes retain their current
   behavior. SMTP routes are observation-only and do not inherit fingerprint
   approval requirements from IMAPS, SMTPS, or HTTPS listeners.
2. A bounded asynchronous event writer records connection identity, original
   endpoints, timestamps, TLS fingerprints, and connection completion. It
   records no message content or SMTP credentials. Telemetry loss must not
   interrupt mail forwarding.
3. A separate `correlate-smtp` command ingests connection events, Postfix logs,
   and structured verdicts. It stores its evidence separately from the
   existing fingerprint approval database and can replay input without
   inflating counts.
4. A Rspamd integration example exports final queue-associated score/action
   data. A report shows per-message attribution, missing evidence, and
   aggregate fingerprint statistics. Filter classifications are observations,
   not authenticated statements that a sender is malicious or legitimate.

## Attribution rules

- Use a configured receiving-instance namespace. Preserve original TCP
  endpoints with PROXY v2 and enable Postfix client-port logging.
- Match client IP **and source port**, receiving listener scope, and connection
  lifetime. Never substitute an IP-only or nearest-timestamp guess.
- Track `smtpd` sessions between connect and disconnect events, scoped by
  process identity and instance. PID alone is not a session identifier.
- Queue IDs belong to a receiving instance and a bounded message lifetime;
  do not assume they are globally or eternally unique. A connection may
  contain multiple queued messages.
- Attribute only messages observed after the TLS transition to its
  fingerprint. Plaintext messages, including those preceding STARTTLS on the
  same connection, must not be counted as TLS messages.
- Preserve ambiguous, missing, unsupported, and conflicting evidence as
  unmatched. Missing completion events or log gaps reduce coverage rather
  than justify a broader match.
- Queue reinjection and verdicts without a usable queue ID require additional
  integration; unsupported paths must be visible and documented.

## Protocol and operational constraints

The observer must preserve original bytes and forwarding semantics, including
multiline greetings/replies, command pipelining, DATA payloads, STARTTLS
refusal, buffered bytes at the TLS transition, fragmented ClientHellos, and
TCP half-close draining. Unsupported SMTP extensions must not be mistaken for
commands inside message content. Parser state and telemetry queues are bounded.

Collection is independent of forwarding. Input replay, retention, log rotation,
clock precision, and dropped events require documented handling. Collector
files must come from trusted local services, not sender-supplied headers.
The PROXY-enabled backend must be restricted to the trusted proxy.

## Validation and rollout

Run existing tests before changes, then add network-level SMTP tests and
correlation fixtures covering same-IP concurrency, endpoint/PID/queue reuse,
multiple messages, plaintext, malformed records, replay, and conflicting
verdicts. Run the full Go tests, race detector, vet, and a build after review.
Check the exporter syntax locally and distinguish that from testing against a
live Rspamd installation.

The initial operational step is observation on a test listener followed by
an explicit production cutover. Compare correlated records with actual
Postfix/Rspamd sessions and quantify unmatched rates. Automatic blocking
requires a later decision based on observed false-positive rates, rule expiry,
and override behavior; it must not be inferred from this collection feature.
