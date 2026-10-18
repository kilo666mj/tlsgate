package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseSMTPSourceExclusion(t *testing.T) {
	exclude, err := parseSMTPSourceExclusion(" 192.0.2.7, 2001:db8:1::/48 ,,198.51.100.9/24")
	if err != nil {
		t.Fatal(err)
	}
	for client, want := range map[string]bool{
		"192.0.2.7:25":             true,
		"192.0.2.8:25":             false,
		"[2001:db8:1:5::1]:40000":  true,
		"[2001:db8:2::1]:40000":    false,
		"198.51.100.200:1234":      true, // prefix is masked to 198.51.100.0/24
		"[::ffff:192.0.2.7]:25":    true, // IPv4-mapped clients match the IPv4 entry
		"not-an-endpoint":          false,
		"unknown[192.0.2.7]:25000": false,
	} {
		if got := exclude.excludesClient(client); got != want {
			t.Errorf("excludesClient(%q) = %v, want %v", client, got, want)
		}
	}

	empty, err := parseSMTPSourceExclusion("")
	if err != nil || !empty.empty() || empty.excludesClient("192.0.2.7:25") {
		t.Fatalf("empty exclusion = %+v, %v", empty, err)
	}

	for _, bad := range []string{"192.0.2.300", "example.net", "2001:db8::/129", "fe80::1%eth0", "::ffff:192.0.2.0/120"} {
		if _, err := parseSMTPSourceExclusion(bad); err == nil {
			t.Errorf("parseSMTPSourceExclusion(%q) accepted an invalid source", bad)
		}
	}
	tooMany := strings.Repeat("192.0.2.1,", maxSMTPExcludedSources+1)
	if _, err := parseSMTPSourceExclusion(tooMany); err == nil {
		t.Error("accepted more than the maximum number of excluded sources")
	}
}

func TestSMTPCampaignExcludesMonitorSources(t *testing.T) {
	start := time.Date(2026, 9, 19, 12, 3, 13, 0, time.UTC)
	events := writeCampaignEvents(t, []smtpConnFixture{
		{id: "campaign", client: "198.51.100.45:57212", start: start, end: start.Add(6 * time.Second), behavior: campaignBehavior(start, "HELO", true)},
		{id: "monitor", client: "203.0.113.5:40000", start: start, end: start.Add(time.Second), behavior: campaignBehavior(start, "QUIT", false)},
	})
	postfix := filepath.Join(t.TempDir(), "postfix.log")
	fixture, err := os.ReadFile("testdata/smtp-campaign-postfix.log")
	if err != nil {
		t.Fatal(err)
	}
	monitor := "2026-09-19T12:03:13.200000Z mx container[405]: Sep 19 12:03:13 container haproxy/postscreen[405]: CONNECT from [203.0.113.5]:40000 to [127.0.0.1]:25\n"
	if err := os.WriteFile(postfix, append([]byte(monitor), fixture...), 0600); err != nil {
		t.Fatal(err)
	}

	baseline, err := runSMTPCampaignClassification(events, postfix, "", "mx", "127.0.0.1:25", 10*time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Connections != 2 || baseline.EvidenceSessions != 2 {
		t.Fatalf("baseline should include the monitor: %+v", baseline)
	}

	exclude, err := parseSMTPSourceExclusion("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	report, excluded, err := runSMTPCampaignClassificationExcluding(events, postfix, "", "mx", "127.0.0.1:25", 10*time.Minute, time.Second, exclude)
	if err != nil {
		t.Fatal(err)
	}
	if excluded.Connections != 1 || excluded.EvidenceSessions != 1 {
		t.Fatalf("excluded counts = %+v", excluded)
	}
	if report.Connections != 1 || report.EvidenceSessions != 1 || report.Matched != 1 || report.ConnectionsWithoutEvidence != 0 || len(report.Records) != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Records[0].ConnectionID != "campaign" {
		t.Fatalf("kept the wrong record: %+v", report.Records[0])
	}
	// The upload path validates the same invariants Gatehub enforces.
	if err := validateSMTPCampaignReport(report, "mx", "127.0.0.1:25"); err != nil {
		t.Fatalf("excluded report is inconsistent: %v", err)
	}
}

func TestSMTPCorrelationExcludesMonitorSources(t *testing.T) {
	d := t.TempDir()
	events := filepath.Join(d, "events.jsonl")
	logs := filepath.Join(d, "mail.log")
	verdicts := filepath.Join(d, "verdicts.jsonl")
	db := filepath.Join(d, "correlation.sqlite")
	mustWrite := func(path, s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(events, ""+
		`{"version":1,"type":"start","timestamp":"2026-09-08T12:49:00Z","instance":"mx","connection_id":"a","client":"167.71.57.227:33700","listener":"127.0.0.1:25"}`+"\n"+
		`{"version":1,"type":"end","state":"no_observed_upgrade","timestamp":"2026-09-08T12:50:00Z","instance":"mx","connection_id":"a"}`+"\n"+
		`{"version":1,"type":"start","timestamp":"2026-09-08T12:49:00Z","instance":"mx","connection_id":"probe","client":"[2001:db8::5]:40000","listener":"127.0.0.1:25"}`+"\n"+
		`{"version":1,"type":"end","state":"no_observed_upgrade","timestamp":"2026-09-08T12:49:01Z","instance":"mx","connection_id":"probe"}`+"\n")
	mustWrite(logs, ""+
		"2026-09-08T12:49:01Z mx postfix/smtpd[10]: connect from unknown[167.71.57.227]:33700\n"+
		"2026-09-08T12:49:03Z mx postfix/smtpd[10]: Q123: client=unknown[167.71.57.227]:33700\n"+
		"2026-09-08T12:49:00Z mx postfix/smtpd[11]: connect from probe.example[2001:db8::5]:40000\n"+
		"2026-09-08T12:49:00.5Z mx postfix/smtpd[11]: QPROBE: client=probe.example[2001:db8::5]:40000\n")
	mustWrite(verdicts, "")

	exclude, err := parseSMTPSourceExclusion("2001:db8::5")
	if err != nil {
		t.Fatal(err)
	}
	s, excluded, err := runSMTPCorrelationExcluding(events, logs, verdicts, db, "mx", "127.0.0.1:25", time.Second, exclude)
	if err != nil {
		t.Fatal(err)
	}
	if excluded.Connections != 1 || excluded.Messages != 1 {
		t.Fatalf("excluded counts = %+v", excluded)
	}
	if s.Connections != 1 || s.NoObservedTLS != 1 || s.Messages != 1 || len(s.Records) != 1 || s.Records[0].QueueID != "Q123" {
		t.Fatalf("summary %#v", s)
	}
}
