package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

type smtpVerdict struct {
	Timestamp      time.Time `json:"timestamp"`
	Instance       string    `json:"instance"`
	QueueID        string    `json:"queue_id"`
	Classification string    `json:"classification"`
	Score          float64   `json:"score"`
	Action         string    `json:"action"`
	Symbols        []string  `json:"symbols,omitempty"`
}
type smtpConnRecord struct {
	ID, Instance, Client, Listener, JA3, JA4 string
	Start, End, TLS, Accepted                time.Time
	State                                    string
	Invalid                                  bool
}
type smtpMessage struct {
	Instance, QueueID, Client, PID string
	At, SessionStart               time.Time
	HasSession                     bool
}
type smtpCorrelation struct {
	QueueID        string   `json:"queue_id"`
	Classification string   `json:"classification"`
	JA3            string   `json:"ja3,omitempty"`
	JA4            string   `json:"ja4,omitempty"`
	Reason         string   `json:"reason"`
	ConnectionID   string   `json:"connection_id,omitempty"`
	Client         string   `json:"client,omitempty"`
	Listener       string   `json:"listener,omitempty"`
	Action         string   `json:"action,omitempty"`
	VerdictAt      string   `json:"verdict_at,omitempty"`
	MessageAt      string   `json:"message_at"`
	SessionStart   string   `json:"session_start,omitempty"`
	Symbols        []string `json:"symbols,omitempty"`
	Score          float64  `json:"score"`
	Transport      string   `json:"transport"`
}

func cmdCorrelateSMTP(args []string) {
	fs := flag.NewFlagSet("correlate-smtp", flag.ExitOnError)
	events := fs.String("events", "", "tlsgate SMTP event JSONL")
	postfix := fs.String("postfix-log", "", "RFC3339-prefixed Postfix log")
	verdicts := fs.String("verdicts", "", "structured verdict JSONL")
	dbPath := fs.String("db", "smtp-correlation.sqlite", "correlation database")
	instance := fs.String("instance", "", "Postfix instance namespace")
	listener := fs.String("listener", "", "exact tlsgate listener endpoint namespace")
	tolerance := fs.Duration("tolerance", time.Second, "timestamp precision tolerance")
	format := fs.String("format", "text", "text or json summary")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		fatalf("correlate-smtp takes flags only")
	}
	if *events == "" || *postfix == "" || *verdicts == "" || *instance == "" || *listener == "" {
		fatalf("correlate-smtp requires --events, --postfix-log, --verdicts, --instance, and --listener")
	}
	if *format != "text" && *format != "json" {
		fatalf("invalid --format %q", *format)
	}
	result, err := runSMTPCorrelation(*events, *postfix, *verdicts, *dbPath, *instance, *listener, *tolerance)
	if err != nil {
		fatalf("correlate SMTP: %v", err)
	}
	if *format == "json" {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			fatalf("write report: %v", err)
		}
		return
	}
	fmt.Printf("messages=%d matched=%d unmatched=%d spam=%d ham=%d unknown=%d\n", result.Messages, result.Matched, result.Unmatched, result.Spam, result.Ham, result.Unknown)
	fmt.Printf("connections=%d starttls_observed=%d no_observed_upgrade=%d incomplete=%d\n", result.Connections, result.STARTTLS, result.NoObservedTLS, result.Incomplete)
	fmt.Printf("malformed_events=%d malformed_verdicts=%d\n", result.MalformedEvents, result.MalformedVerdicts)
	fmt.Printf("messages_starttls=%d messages_plaintext=%d messages_transport_unknown=%d\n", result.TLSMessages, result.PlaintextMessages, result.UnknownTransportMessages)
	for _, r := range result.Reasons {
		fmt.Printf("unmatched[%s]=%d\n", r.Reason, r.Count)
	}
	for _, a := range result.Fingerprints {
		fmt.Printf("fingerprint ja4=%s spam=%d ham=%d unknown=%d\n", a.JA4, a.Spam, a.Ham, a.Unknown)
	}
}

type reasonCount struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}
type smtpSummary struct {
	Messages                 int                    `json:"messages"`
	Matched                  int                    `json:"matched"`
	Unmatched                int                    `json:"unmatched"`
	Spam                     int                    `json:"spam"`
	Ham                      int                    `json:"ham"`
	Unknown                  int                    `json:"unknown"`
	Connections              int                    `json:"connections"`
	STARTTLS                 int                    `json:"starttls"`
	NoObservedTLS            int                    `json:"no_observed_tls"`
	Incomplete               int                    `json:"incomplete"`
	MalformedEvents          int                    `json:"malformed_events"`
	MalformedVerdicts        int                    `json:"malformed_verdicts"`
	TLSMessages              int                    `json:"tls_messages"`
	PlaintextMessages        int                    `json:"plaintext_messages"`
	UnknownTransportMessages int                    `json:"unknown_transport_messages"`
	Reasons                  []reasonCount          `json:"unmatched_reasons"`
	Fingerprints             []fingerprintAggregate `json:"fingerprints"`
	Records                  []smtpCorrelation      `json:"records"`
}
type fingerprintAggregate struct {
	JA4     string `json:"ja4"`
	Spam    int    `json:"spam"`
	Ham     int    `json:"ham"`
	Unknown int    `json:"unknown"`
}

func runSMTPCorrelation(eventsPath, postfixPath, verdictPath, dbPath, instance, listener string, tolerance time.Duration) (result smtpSummary, err error) {
	if tolerance < 0 || tolerance > time.Minute {
		return smtpSummary{}, fmt.Errorf("tolerance must be between zero and one minute")
	}
	if instance == "" {
		return smtpSummary{}, fmt.Errorf("instance is required")
	}
	if _, _, err := net.SplitHostPort(listener); err != nil {
		return smtpSummary{}, fmt.Errorf("listener must be an exact IP:port endpoint: %w", err)
	}
	conns, malformedEvents, err := readSMTPConnectionsStats(eventsPath)
	if err != nil {
		return smtpSummary{}, err
	}
	filtered := conns[:0]
	for _, c := range conns {
		if c.Instance == instance && c.Listener == listener {
			filtered = append(filtered, c)
		}
	}
	conns = filtered
	byClient := map[string][]smtpConnRecord{}
	for _, c := range conns {
		byClient[c.Client] = append(byClient[c.Client], c)
	}
	messages, err := readPostfixMessages(postfixPath, instance)
	if err != nil {
		return smtpSummary{}, err
	}
	verdicts, malformed, err := readSMTPVerdicts(verdictPath)
	if err != nil {
		return smtpSummary{}, err
	}
	f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return smtpSummary{}, err
	}
	if err = f.Close(); err != nil {
		return smtpSummary{}, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return smtpSummary{}, err
	}
	defer closeWithError(&err, "close SMTP correlation database", db.Close)
	if _, err = db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		return smtpSummary{}, err
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS smtp_correlations (event_key TEXT PRIMARY KEY, instance TEXT NOT NULL, queue_id TEXT NOT NULL, message_at TEXT NOT NULL, connection_id TEXT, ja3 TEXT, ja4 TEXT, classification TEXT NOT NULL, score REAL NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL, audit_json TEXT NOT NULL)`); err != nil {
		return smtpSummary{}, err
	}
	tx, err := db.Begin()
	if err != nil {
		return smtpSummary{}, err
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback SMTP correlation transaction: %w", rollbackErr))
		}
	}()
	byQueue := map[string][]smtpVerdict{}
	for _, v := range verdicts {
		byQueue[v.Instance+"\x00"+v.QueueID] = append(byQueue[v.Instance+"\x00"+v.QueueID], v)
	}
	messageOccurrences := map[string]map[string]bool{}
	for _, m := range messages {
		k := m.Instance + "\x00" + m.QueueID
		if messageOccurrences[k] == nil {
			messageOccurrences[k] = map[string]bool{}
		}
		messageOccurrences[k][smtpMessageIdentity(m)] = true
	}
	s := smtpSummary{Connections: len(conns), MalformedEvents: malformedEvents, MalformedVerdicts: malformed}
	reasons := map[string]int{}
	aggregates := map[string]*fingerprintAggregate{}
	for _, c := range conns {
		if !c.completeObservation() {
			s.Incomplete++
		} else if c.State == "no_observed_upgrade" || c.State == "starttls_refused" || c.State == "premature_tls" {
			s.NoObservedTLS++
		} else {
			s.STARTTLS++
		}
	}
	seenMessages := map[string]bool{}
	for _, m := range messages {
		messageKey := smtpMessageIdentity(m)
		if seenMessages[messageKey] {
			continue
		}
		seenMessages[messageKey] = true
		s.Messages++
		r := smtpCorrelation{QueueID: m.QueueID, Classification: "unknown", Reason: "no_verdict", Client: m.Client, MessageAt: m.At.Format(time.RFC3339Nano), Transport: "unknown"}
		if m.HasSession {
			r.SessionStart = m.SessionStart.Format(time.RFC3339Nano)
		}
		candidates := matchSMTPConn(byClient[m.Client], m, tolerance)
		if len(messageOccurrences[m.Instance+"\x00"+m.QueueID]) > 1 {
			r.Reason = "reused_queue_id"
		} else if len(candidates) == 0 {
			r.Reason = "no_connection"
		} else if len(candidates) > 1 {
			r.Reason = "ambiguous_connection"
		} else {
			c := candidates[0]
			r.ConnectionID = c.ID
			r.Listener = c.Listener
			r.Transport = messageSMTPTransport(c, m.At, tolerance)
			if r.Transport != "starttls" {
				r.Reason = "message_before_observed_starttls"
				if r.Transport == "unknown" {
					r.Reason = "incomplete_or_uncertain_tls_observation"
				}
			} else if len(byQueue[m.Instance+"\x00"+m.QueueID]) == 0 {
				r.Reason = "no_verdict"
			} else {
				vs := byQueue[m.Instance+"\x00"+m.QueueID]
				v, ok := boundedVerdict(vs, m.At, time.Hour)
				if !ok {
					r.Reason = "ambiguous_or_distant_verdict"
				} else {
					r.Classification = v.Classification
					r.Score = v.Score
					r.Action = v.Action
					r.Symbols = v.Symbols
					r.VerdictAt = v.Timestamp.Format(time.RFC3339Nano)
					r.Reason = "matched"
				}
			}
			if r.Transport == "starttls" {
				r.JA3, r.JA4 = c.JA3, c.JA4
			}
		}
		switch r.Transport {
		case "starttls":
			s.TLSMessages++
		case "plaintext":
			s.PlaintextMessages++
		default:
			s.UnknownTransportMessages++
		}
		key := fmt.Sprintf("%x", sha256.Sum256([]byte(listener+"\x00"+messageKey)))
		audit, _ := json.Marshal(r)
		_, err = tx.Exec(`INSERT INTO smtp_correlations(event_key,instance,queue_id,message_at,connection_id,ja3,ja4,classification,score,reason,created_at,audit_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(event_key) DO UPDATE SET connection_id=excluded.connection_id,ja3=excluded.ja3,ja4=excluded.ja4,classification=excluded.classification,score=excluded.score,reason=excluded.reason,created_at=excluded.created_at,audit_json=excluded.audit_json`, key, m.Instance, m.QueueID, m.At.UTC().Format("2006-01-02T15:04:05.000000000Z"), r.ConnectionID, r.JA3, r.JA4, r.Classification, r.Score, r.Reason, time.Now().UTC().Format(time.RFC3339Nano), string(audit))
		if err != nil {
			return s, err
		}
		if r.Reason == "matched" {
			s.Matched++
			switch r.Classification {
			case "spam":
				s.Spam++
			case "ham":
				s.Ham++
			default:
				s.Unknown++
			}
		} else {
			s.Unmatched++
			reasons[r.Reason]++
		}
		s.Records = append(s.Records, r)
		if r.Reason == "matched" {
			a := aggregates[r.JA4]
			if a == nil {
				a = &fingerprintAggregate{JA4: r.JA4}
				aggregates[r.JA4] = a
			}
			switch r.Classification {
			case "spam":
				a.Spam++
			case "ham":
				a.Ham++
			default:
				a.Unknown++
			}
		}
	}
	for k, v := range reasons {
		s.Reasons = append(s.Reasons, reasonCount{k, v})
	}
	sort.Slice(s.Reasons, func(i, j int) bool { return s.Reasons[i].Reason < s.Reasons[j].Reason })
	for _, a := range aggregates {
		s.Fingerprints = append(s.Fingerprints, *a)
	}
	sort.Slice(s.Fingerprints, func(i, j int) bool { return s.Fingerprints[i].JA4 < s.Fingerprints[j].JA4 })
	if _, err := tx.Exec(`DELETE FROM smtp_correlations WHERE event_key IN (SELECT event_key FROM smtp_correlations ORDER BY message_at DESC,event_key DESC LIMIT -1 OFFSET 100000)`); err != nil {
		return s, err
	}
	if err := tx.Commit(); err != nil {
		return s, err
	}
	return s, nil
}

func (c smtpConnRecord) completeObservation() bool {
	if c.Invalid || c.Start.IsZero() || c.End.Before(c.Start) {
		return false
	}
	switch c.State {
	case "no_observed_upgrade", "starttls_refused", "premature_tls":
		return c.Accepted.IsZero() && c.TLS.IsZero()
	case "fingerprinted":
		return !c.Accepted.IsZero() && !c.TLS.Before(c.Accepted) && !c.Accepted.Before(c.Start) && !c.TLS.After(c.End) && c.JA3 != "" && c.JA4 != ""
	case "starttls_accepted_no_fingerprint":
		return !c.Accepted.IsZero() && !c.Accepted.Before(c.Start) && !c.Accepted.After(c.End)
	}
	return false
}

func smtpMessageIdentity(m smtpMessage) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s", m.Instance, m.QueueID, m.Client, m.PID, m.SessionStart.UTC().Format(time.RFC3339Nano), m.At.UTC().Format(time.RFC3339Nano))
}

func messageSMTPTransport(c smtpConnRecord, at time.Time, tolerance time.Duration) string {
	if !c.completeObservation() {
		return "unknown"
	}
	if c.State == "no_observed_upgrade" || c.State == "starttls_refused" {
		return "plaintext"
	}
	if !c.Accepted.IsZero() && at.Before(c.Accepted.Add(-tolerance)) {
		return "plaintext"
	}
	if c.State == "fingerprinted" && !at.Before(c.TLS.Add(tolerance)) {
		return "starttls"
	}
	return "unknown"
}

func readSMTPConnections(path string) ([]smtpConnRecord, error) {
	cs, _, err := readSMTPConnectionsStats(path)
	return cs, err
}
func readSMTPConnectionsStats(path string) ([]smtpConnRecord, int, error) {
	sc, e := newSMTPBatchScanner(path)
	if e != nil {
		return nil, 0, e
	}
	by := map[string]*smtpConnRecord{}
	seen := map[string]string{}
	bad := 0
	for sc.Scan() {
		var e smtpEvent
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.ConnectionID == "" || e.Instance == "" || e.Timestamp.IsZero() || e.Version != 1 {
			bad++
			continue
		}
		k := e.Instance + "\x00" + e.ConnectionID
		c := by[k]
		if c == nil {
			c = &smtpConnRecord{ID: e.ConnectionID, Instance: e.Instance}
			by[k] = c
		}
		if e.Client != "" {
			if c.Client != "" && c.Client != e.Client {
				c.Invalid = true
			}
			c.Client = e.Client
		}
		if e.Listener != "" {
			if c.Listener != "" && c.Listener != e.Listener {
				c.Invalid = true
			}
			c.Listener = e.Listener
		}
		if e.Type == "start" || e.Type == "end" || e.Type == "fingerprint" || (e.Type == "starttls" && e.State == "accepted") {
			raw, _ := json.Marshal(e)
			key := k + "\x00" + e.Type
			if old, ok := seen[key]; ok && old != string(raw) {
				c.Invalid = true
				bad++
				continue
			}
			seen[key] = string(raw)
		}
		switch e.Type {
		case "start":
			c.Start = e.Timestamp
			c.Client = e.Client
			c.Listener = e.Listener
		case "fingerprint":
			c.TLS = e.Timestamp
			c.JA3 = e.JA3
			c.JA4 = e.JA4
		case "starttls":
			if e.State == "accepted" {
				c.Accepted = e.Timestamp
			}
		case "end":
			c.End = e.Timestamp
			c.State = e.State
		default:
			bad++
			c.Invalid = true
		}
	}
	if e := sc.Err(); e != nil {
		return nil, bad, e
	}
	out := make([]smtpConnRecord, 0, len(by))
	for _, c := range by {
		out = append(out, *c)
	}
	return out, bad, nil
}

var postfixEnvelope = regexp.MustCompile(`^(\S+)\s+\S+\s+(?:[A-Za-z0-9_.-]+\[[0-9]+\]:\s+(?:[A-Z][a-z]{2}\s+[ 0-9][0-9]\s+[0-9:]{8}\s+(?:[A-Za-z0-9_.-]+\s+)?)?)?postfix/smtpd\[([0-9]+)\]:\s+([^\r\n]*)$`)
var postfixConnect = regexp.MustCompile(`^connect from .+\[([^]]+)\](?::([0-9]+))?$`)
var postfixQueue = regexp.MustCompile(`^([A-Za-z0-9]+): client=.+\[([^]]+)\](?::([0-9]+))?`)
var postfixDisconnect = regexp.MustCompile(`^disconnect from `)

func readPostfixMessages(path, instance string) ([]smtpMessage, error) {
	sc, e := newSMTPBatchScanner(path)
	if e != nil {
		return nil, e
	}
	type sess struct {
		client string
		epoch  time.Time
	}
	sessions := map[string]sess{}
	var out []smtpMessage
	for sc.Scan() {
		m := postfixEnvelope.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		at, e := time.Parse(time.RFC3339Nano, m[1])
		if e != nil {
			continue
		}
		pid, body := m[2], m[3]
		if x := postfixConnect.FindStringSubmatch(body); x != nil {
			if x[2] == "" {
				delete(sessions, pid)
				continue
			}
			sessions[pid] = sess{net.JoinHostPort(x[1], x[2]), at}
			continue
		}
		if postfixDisconnect.MatchString(body) {
			delete(sessions, pid)
			continue
		}
		if x := postfixQueue.FindStringSubmatch(body); x != nil {
			if x[3] == "" {
				out = append(out, smtpMessage{Instance: instance, QueueID: x[1], PID: pid, At: at})
				continue
			}
			client := net.JoinHostPort(x[2], x[3])
			s, ok := sessions[pid]
			if !ok || s.client != client || at.Before(s.epoch) {
				out = append(out, smtpMessage{Instance: instance, QueueID: x[1], Client: client, PID: pid, At: at})
				continue
			}
			out = append(out, smtpMessage{Instance: instance, QueueID: x[1], Client: client, PID: pid, At: at, SessionStart: s.epoch, HasSession: true})
		}
	}
	return out, sc.Err()
}

func readSMTPVerdicts(path string) ([]smtpVerdict, int, error) {
	sc, e := newSMTPBatchScanner(path)
	if e != nil {
		return nil, 0, e
	}
	var out []smtpVerdict
	bad := 0
	for sc.Scan() {
		var v smtpVerdict
		if json.Unmarshal(sc.Bytes(), &v) != nil || v.QueueID == "" || v.Instance == "" || (v.Classification != "spam" && v.Classification != "ham" && v.Classification != "unknown") || v.Timestamp.IsZero() {
			bad++
			continue
		}
		out = append(out, v)
	}
	return out, bad, sc.Err()
}
func matchSMTPConn(cs []smtpConnRecord, m smtpMessage, t time.Duration) []smtpConnRecord {
	var out []smtpConnRecord
	if !m.HasSession {
		return out
	}
	for _, c := range cs {
		if c.Instance != m.Instance || c.Client != m.Client || c.Start.IsZero() || c.Invalid || m.At.Before(m.SessionStart) {
			continue
		}
		end := c.End
		if end.IsZero() {
			continue
		}
		if !m.SessionStart.Before(c.Start.Add(-t)) && !m.SessionStart.After(end.Add(t)) && !m.At.After(end.Add(t)) {
			out = append(out, c)
		}
	}
	return out
}
func boundedVerdict(vs []smtpVerdict, at time.Time, window time.Duration) (smtpVerdict, bool) {
	var eligible []smtpVerdict
	seen := map[string]bool{}
	for _, v := range vs {
		if v.Timestamp.Before(at) || v.Timestamp.After(at.Add(window)) {
			continue
		}
		b, _ := json.Marshal(v)
		k := string(b)
		if !seen[k] {
			seen[k] = true
			eligible = append(eligible, v)
		}
	}
	if len(eligible) != 1 {
		return smtpVerdict{}, false
	}
	return eligible[0], true
}

const maxSMTPBatchBytes = 64 * 1024 * 1024
const maxSMTPBatchLines = 100000

// Snapshot bounded regular files so pipes, concurrently growing files, and
// oversized batches cannot cause unbounded collector memory use.
type smtpBatchScanner struct {
	*bufio.Scanner
	lines    int
	limitErr error
}

func newSMTPBatchScanner(path string) (_ *smtpBatchScanner, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxSMTPBatchBytes {
		return nil, fmt.Errorf("SMTP input must be a regular file of at most 64 MiB: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer closeWithError(&err, "close SMTP batch input", f.Close)
	b, err := io.ReadAll(io.LimitReader(f, maxSMTPBatchBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSMTPBatchBytes {
		return nil, fmt.Errorf("SMTP input exceeded 64 MiB: %s", path)
	}
	if len(b) != 0 && b[len(b)-1] != '\n' {
		return nil, fmt.Errorf("SMTP input has an incomplete final line: %s", path)
	}
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(make([]byte, 4096), 1024*1024)
	return &smtpBatchScanner{Scanner: s}, nil
}

func (s *smtpBatchScanner) Scan() bool {
	if !s.Scanner.Scan() {
		return false
	}
	s.lines++
	if s.lines > maxSMTPBatchLines {
		s.limitErr = fmt.Errorf("SMTP input exceeds %d lines; split into complete session batches", maxSMTPBatchLines)
		return false
	}
	return true
}

func (s *smtpBatchScanner) Err() error {
	if s.limitErr != nil {
		return s.limitErr
	}
	return s.Scanner.Err()
}
