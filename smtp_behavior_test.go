package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSMTPBehaviorCanonicalDimensionsAndFingerprint(t *testing.T) {
	start := time.Date(2026, 9, 20, 7, 0, 0, 0, time.UTC)
	now := start.Add(2 * time.Second)
	o := &smtpObserver{base: smtpEvent{Timestamp: start}, now: func() time.Time { return now }}
	o.server([]byte("220 ready\r\n"))
	o.client([]byte("EHLO sender.example\r"))
	o.client([]byte("\n"))
	now = start.Add(6 * time.Second)
	o.client([]byte("STARTTLS\n"))
	o.server([]byte("250 ok\r\n220 ready\r\n"))

	got := o.behaviorSnapshot()
	if got.Version != 1 || got.PreGreeting != "none" || got.FirstVerb != "EHLO" ||
		got.LineEndings != "mixed" || got.FirstCommandTiming != "1s_to_5s" ||
		got.STARTTLSTiming != "5s_to_30s" || got.VerbShape != "EHLO>STARTTLS" ||
		got.STARTTLSOutcome != "accepted" {
		t.Fatalf("unexpected behavior: %+v", got)
	}
	if !strings.HasPrefix(got.Fingerprint, "smtp-behavior/v1/") || len(got.Fingerprint) != len("smtp-behavior/v1/")+64 {
		t.Fatalf("unexpected fingerprint format: %q", got.Fingerprint)
	}
	if again := o.behaviorSnapshot(); again.Fingerprint != got.Fingerprint {
		t.Fatalf("fingerprint is not deterministic: %q != %q", got.Fingerprint, again.Fingerprint)
	}
}

func TestSMTPBehaviorPreGreetingAndPrivacy(t *testing.T) {
	start := time.Date(2026, 9, 20, 7, 0, 0, 0, time.UTC)
	o := &smtpObserver{base: smtpEvent{Timestamp: start}, now: func() time.Time { return start.Add(100 * time.Millisecond) }}
	o.client([]byte("EHLO private.example\r\nMAIL FROM:<secret@example.org>\r\n"))

	behavior := o.behaviorSnapshot()
	if behavior.PreGreeting != "many" || behavior.FirstVerb != "EHLO" || behavior.VerbShape != "EHLO>MAIL" {
		t.Fatalf("unexpected pre-greeting behavior: %+v", behavior)
	}
	wire, err := json.Marshal(smtpEvent{Version: 1, Type: "end", Behavior: behavior})
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"private.example", "secret@example.org"} {
		if strings.Contains(string(wire), private) {
			t.Fatalf("behavior metadata leaked %q: %s", private, wire)
		}
	}
}

func TestSMTPBehaviorVerbShapeBounded(t *testing.T) {
	o := &smtpObserver{}
	for range 300 {
		o.client([]byte("made-up-command private-value\r\n"))
	}
	got := o.behaviorSnapshot()
	if !got.VerbOverflow || len(o.behavior.verbs) != maxSMTPBehaviorVerbs || strings.Contains(got.VerbShape, "private") {
		t.Fatalf("unbounded or unsafe shape: %+v", got)
	}
	if !o.disabled || len(o.commands) != 256 {
		t.Fatalf("command queue was not bounded: disabled=%v commands=%d", o.disabled, len(o.commands))
	}
}

func TestSMTPBehaviorOldReaderCompatibility(t *testing.T) {
	type legacySMTPEvent struct {
		Version      int       `json:"version"`
		Type         string    `json:"type"`
		Timestamp    time.Time `json:"timestamp"`
		ConnectionID string    `json:"connection_id"`
		State        string    `json:"state,omitempty"`
	}
	encoded, err := json.Marshal(smtpEvent{
		Version: 1, Type: "end", Timestamp: time.Now().UTC(), ConnectionID: "c1", State: "no_observed_upgrade",
		Behavior: (&smtpBehaviorTracker{}).snapshot(time.Time{}, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	var old legacySMTPEvent
	if err := json.Unmarshal(encoded, &old); err != nil {
		t.Fatal(err)
	}
	if old.Version != 1 || old.Type != "end" || old.ConnectionID != "c1" {
		t.Fatalf("legacy reader lost existing fields: %+v", old)
	}
}

func TestSMTPTimingBuckets(t *testing.T) {
	start := time.Date(2026, 9, 20, 7, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		delay time.Duration
		want  string
	}{
		{0, "under_1s"},
		{time.Second, "1s_to_5s"},
		{5 * time.Second, "5s_to_30s"},
		{30 * time.Second, "30s_or_more"},
	} {
		if got := smtpTimingBucket(start, start.Add(test.delay)); got != test.want {
			t.Errorf("delay %v: got %q want %q", test.delay, got, test.want)
		}
	}
	if got := smtpTimingBucket(time.Time{}, start); got != "unknown" {
		t.Fatalf("missing start got %q", got)
	}
}
