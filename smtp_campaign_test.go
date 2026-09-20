package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSMTPCampaignObservedFixtureAndReplay(t *testing.T) {
	start := time.Date(2026, 9, 19, 12, 3, 13, 0, time.UTC)
	events := writeCampaignEvents(t, []smtpConnFixture{
		{id: "campaign", client: "198.51.100.45:57212", start: start, end: start.Add(6 * time.Second), behavior: campaignBehavior(start, "HELO", true)},
		{id: "same-ip-other-port", client: "198.51.100.45:57213", start: start, end: start.Add(6 * time.Second), behavior: campaignBehavior(start, "HELO", true)},
	})
	prefixes := filepath.Join(t.TempDir(), "prefixes.json")
	if err := os.WriteFile(prefixes, []byte(`{"prefixes":[{"prefix":"198.51.100.0/24","provider":"example-cloud"},{"prefix":"198.51.0.0/16","provider":"broader"}]}`), 0600); err != nil {
		t.Fatal(err)
	}

	first, err := runSMTPCampaignClassification(events, "testdata/smtp-campaign-postfix.log", prefixes, "mx", "127.0.0.1:25", 10*time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runSMTPCampaignClassification(events, "testdata/smtp-campaign-postfix.log", prefixes, "mx", "127.0.0.1:25", 10*time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("replaying identical evidence changed the report")
	}
	if first.Matched != 1 || first.Unmatched != 0 || first.ConnectionsWithoutEvidence != 1 || len(first.Records) != 1 {
		t.Fatalf("unexpected report: %+v", first)
	}
	record := first.Records[0]
	if record.ConnectionID != "campaign" || record.Signature != pregreetSupportSignature ||
		record.Provider != "example-cloud" || record.NetworkPrefix != "198.51.100.0/24" ||
		!strings.HasPrefix(record.RecipientCluster, "sha256:") {
		t.Fatalf("unexpected campaign record: %+v", record)
	}
	wire, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"support@campaign.example", "user@example.net", "campaign.example"} {
		if bytes.Contains(wire, []byte(private)) {
			t.Fatalf("report leaked raw SMTP value %q: %s", private, wire)
		}
	}
}

func TestSMTPCampaignNeverFallsBackToIPOnly(t *testing.T) {
	start := time.Date(2026, 9, 19, 12, 3, 13, 0, time.UTC)
	events := writeCampaignEvents(t, []smtpConnFixture{{
		id: "wrong-port", client: "198.51.100.45:57299", start: start, end: start.Add(6 * time.Second), behavior: campaignBehavior(start, "HELO", true),
	}})
	report, err := runSMTPCampaignClassification(events, "testdata/smtp-campaign-postfix.log", "", "mx", "127.0.0.1:25", 10*time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if report.Matched != 0 || report.Records[0].Reason != "no_exact_connection" || report.Records[0].ConnectionID != "" {
		t.Fatalf("IP-only attribution occurred: %+v", report)
	}
}

func TestSMTPCampaignUnrelatedRule5FixtureDoesNotMatch(t *testing.T) {
	start := time.Date(2026, 9, 19, 22, 58, 19, 0, time.UTC)
	events := writeCampaignEvents(t, []smtpConnFixture{{
		id: "unrelated", client: "203.0.113.145:49552", start: start, end: start.Add(4 * time.Second), behavior: campaignBehavior(start, "EHLO", true),
	}})
	report, err := runSMTPCampaignClassification(events, "testdata/smtp-campaign-unrelated.log", "", "mx", "127.0.0.1:25", 10*time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if report.Matched != 0 || len(report.Records) != 1 || report.Records[0].Signature != "" {
		t.Fatalf("unrelated pregreet traffic matched campaign: %+v", report)
	}
}

func TestSMTPCampaignRejectsAmbiguousExactLifetime(t *testing.T) {
	start := time.Date(2026, 9, 19, 12, 3, 13, 0, time.UTC)
	client := "198.51.100.45:57212"
	events := writeCampaignEvents(t, []smtpConnFixture{
		{id: "first", client: client, start: start, end: start.Add(6 * time.Second), behavior: campaignBehavior(start, "HELO", true)},
		{id: "second", client: client, start: start.Add(500 * time.Millisecond), end: start.Add(7 * time.Second), behavior: campaignBehavior(start, "HELO", true)},
	})
	report, err := runSMTPCampaignClassification(events, "testdata/smtp-campaign-postfix.log", "", "mx", "127.0.0.1:25", 10*time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if report.Matched != 0 || report.Records[0].Reason != "ambiguous_exact_connection" {
		t.Fatalf("ambiguous evidence was attributed: %+v", report)
	}
}

func TestSMTPCampaignFalsePositiveBoundaries(t *testing.T) {
	start := time.Date(2026, 9, 19, 12, 3, 13, 0, time.UTC)
	base := smtpCampaignEvidence{
		Client: "192.0.2.1:1234", Start: start, PregreetAt: start.Add(time.Second), RejectAt: start.Add(2 * time.Second),
		LastAt: start.Add(2 * time.Second), Pregreet: true, Rejected: true, PregreetVerb: "HELO",
		EnvelopeFrom: "support@example.org", EnvelopeTo: "user@example.net", HELO: "example.org",
	}
	behavior := campaignBehavior(start, "HELO", true)
	if got := classifySMTPCampaign(behavior, base); got != "matched" {
		t.Fatalf("baseline got %q", got)
	}
	tests := []struct {
		name     string
		behavior *smtpBehavior
		mutate   func(*smtpCampaignEvidence)
		want     string
	}{
		{"unrelated rule-5 EHLO", campaignBehavior(start, "EHLO", true), func(*smtpCampaignEvidence) {}, "behavior_not_pregreet_helo"},
		{"no pregreet", campaignBehavior(start, "HELO", false), func(*smtpCampaignEvidence) {}, "behavior_not_pregreet_helo"},
		{"postscreen mismatch", behavior, func(e *smtpCampaignEvidence) { e.PregreetVerb = "EHLO" }, "postscreen_not_pregreet_helo"},
		{"not support", behavior, func(e *smtpCampaignEvidence) { e.EnvelopeFrom = "sales@example.org" }, "sender_not_support_domain"},
		{"helo mismatch", behavior, func(e *smtpCampaignEvidence) { e.HELO = "other.example" }, "helo_sender_domain_mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := base
			test.mutate(&evidence)
			if got := classifySMTPCampaign(test.behavior, evidence); got != test.want {
				t.Fatalf("got %q want %q", got, test.want)
			}
		})
	}
}

func TestSMTPCampaignInvalidBehaviorCannotLeak(t *testing.T) {
	start := time.Date(2026, 9, 19, 12, 3, 13, 0, time.UTC)
	behavior := campaignBehavior(start, "HELO", true)
	behavior.Fingerprint = "support@private.example"
	events := writeCampaignEvents(t, []smtpConnFixture{{
		id: "invalid", client: "198.51.100.45:57212", start: start, end: start.Add(6 * time.Second), behavior: behavior,
	}})
	report, err := runSMTPCampaignClassification(events, "testdata/smtp-campaign-postfix.log", "", "mx", "127.0.0.1:25", 10*time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte("support@private.example")) || report.MalformedEvents != 1 || report.Records[0].Reason != "missing_or_invalid_behavior" {
		t.Fatalf("invalid behavior was trusted or leaked: %s", wire)
	}
}

func TestSMTPCampaignMalformedLogsRemainVisible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "postfix.log")
	data := "2026-09-19T12:03:14Z mx haproxy/postscreen[404]: PREGREET broken\n" +
		"2026-09-19T12:03:15Z mx haproxy/postscreen[404]: NOQUEUE: reject: RCPT from [192.0.2.1]:25: missing envelope fields\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	evidence, malformed, err := readSMTPCampaignEvidence(path, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 0 || malformed != 2 {
		t.Fatalf("evidence=%+v malformed=%d", evidence, malformed)
	}
}

func TestSMTPCampaignParsesPostfixSMTPDEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "postfix.log")
	data := "2026-09-19T12:03:14Z mx postfix/smtpd[991]: connect from unknown[2001:db8::1]:4242\n" +
		"2026-09-19T12:03:15Z mx postfix/smtpd[991]: NOQUEUE: reject: RCPT from unknown[2001:db8::1]:4242: 550 rejected; from=<support@example.org>, to=<user@example.net>, proto=SMTP, helo=<example.org>\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	evidence, malformed, err := readSMTPCampaignEvidence(path, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if malformed != 0 || len(evidence) != 1 || evidence[0].Client != "[2001:db8::1]:4242" || !evidence[0].Rejected {
		t.Fatalf("evidence=%+v malformed=%d", evidence, malformed)
	}
}

func TestSMTPNetworkPrefixesRequireCanonicalOfflineInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prefixes.json")
	if err := os.WriteFile(path, []byte(`{"prefixes":[{"prefix":"192.0.2.1/24","provider":"test"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSMTPNetworkPrefixes(path); err == nil {
		t.Fatal("non-canonical prefix accepted")
	}
}

type smtpConnFixture struct {
	id, client string
	start, end time.Time
	behavior   *smtpBehavior
}

func writeCampaignEvents(t *testing.T, fixtures []smtpConnFixture) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	var data bytes.Buffer
	encoder := json.NewEncoder(&data)
	for _, fixture := range fixtures {
		for _, event := range []smtpEvent{
			{Version: 1, Type: "start", Timestamp: fixture.start, Instance: "mx", ConnectionID: fixture.id, Client: fixture.client, Listener: "127.0.0.1:25"},
			{Version: 1, Type: "end", Timestamp: fixture.end, Instance: "mx", ConnectionID: fixture.id, Client: fixture.client, Listener: "127.0.0.1:25", State: "no_observed_upgrade", Behavior: fixture.behavior},
		} {
			if err := encoder.Encode(event); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func campaignBehavior(start time.Time, verb string, pregreet bool) *smtpBehavior {
	var tracker smtpBehaviorTracker
	tracker.command(verb+" example.org\r\n", verb, !pregreet, start.Add(100*time.Millisecond))
	return tracker.snapshot(start, false)
}
