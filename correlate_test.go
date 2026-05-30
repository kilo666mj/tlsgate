package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFindFingerprintAllowsUniquePrefix(t *testing.T) {
	fps := map[string]Entry{
		"abcdef": {Label: "one"},
		"123456": {Label: "two"},
	}
	fp, entry, err := findFingerprint(fps, "abc")
	if err != nil {
		t.Fatalf("findFingerprint: %v", err)
	}
	if fp != "abcdef" || entry.Label != "one" {
		t.Fatalf("match = %q %+v, want abcdef one", fp, entry)
	}
}

func TestFindFingerprintRejectsAmbiguousPrefix(t *testing.T) {
	fps := map[string]Entry{
		"abcdef": {},
		"abc123": {},
	}
	if _, _, err := findFingerprint(fps, "abc"); err == nil {
		t.Fatal("expected ambiguous prefix error")
	}
}

func TestParseSyslogTimeUsesReferenceYear(t *testing.T) {
	ref := time.Date(2026, time.May, 29, 14, 39, 54, 0, time.Local)
	got, ok := parseSyslogTime("May 29 14:39:54 mx postfix/smtps/smtpd[1]: test", ref)
	if !ok {
		t.Fatal("parseSyslogTime failed")
	}
	want := time.Date(2026, time.May, 29, 14, 39, 54, 0, time.Local)
	if !got.Equal(want) {
		t.Fatalf("time = %s, want %s", got, want)
	}
}

func TestParseSyslogTimeSupportsRFC3339(t *testing.T) {
	ref := time.Date(2026, time.May, 29, 15, 2, 10, 0, time.Local)
	got, ok := parseSyslogTime("2026-05-29T14:20:20.044950+02:00 mx sogod[1]: test", ref)
	if !ok {
		t.Fatal("parseSyslogTime failed")
	}
	want := time.Date(2026, time.May, 29, 14, 20, 20, 44950000, time.FixedZone("", 2*60*60))
	if !got.Equal(want) {
		t.Fatalf("time = %s, want %s", got, want)
	}
}

func TestExtractUser(t *testing.T) {
	cases := map[string]string{
		`imap-login: Login: user=<me@example.com>, method=PLAIN, rip=192.0.2.10`:                                             "me@example.com",
		`postfix/smtps/smtpd[1]: client=x[192.0.2.10], sasl_username=me@example.com`:                                         "me@example.com",
		`mx abc[1]: 192.0.2.10 - me@example.com [29/May/2026:14:20:20 +0200] "OPTIONS /SOGo/dav/me%40example.com/ HTTP/1.1"`: "me@example.com",
		`mx sogod[50]: 192.0.2.10 "REPORT /SOGo/dav/me%40example.com/ HTTP/1.1"`:                                             "me@example.com",
	}
	for line, want := range cases {
		if got := extractUser(line); got != want {
			t.Fatalf("extractUser(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestCorrelateSyslog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "syslog")
	log := "" +
		"May 29 14:39:50 mx dovecot: imap-login: Login: user=<me@example.com>, rip=192.0.2.10\n" +
		"May 29 14:41:00 mx postfix/smtps/smtpd[1]: client=host[192.0.2.10], sasl_username=me@example.com\n" +
		"May 29 14:39:51 mx tlsgate[1]: [192.0.2.10:993] APPROVED fp=abc\n" +
		"May 29 14:39:52 mx dovecot: imap-login: Login: user=<other@example.com>, rip=198.51.100.5\n"
	if err := os.WriteFile(logPath, []byte(log), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entry := Entry{
		FirstSeen: time.Date(2026, time.May, 29, 14, 39, 54, 0, time.Local),
		LastSeen:  time.Date(2026, time.May, 29, 14, 39, 54, 0, time.Local),
		IPs:       []string{"192.0.2.10"},
	}
	matches, err := correlateSyslog(logPath, entry, 2*time.Minute, 100)
	if err != nil {
		t.Fatalf("correlateSyslog: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("matches = %d, want 2: %+v", len(matches), matches)
	}
	if matches[0].source != "dovecot" || matches[0].user != "me@example.com" {
		t.Fatalf("first match = %+v", matches[0])
	}
	if matches[1].source != "postfix" || matches[1].user != "me@example.com" {
		t.Fatalf("second match = %+v", matches[1])
	}
}

func TestCorrelateSyslogMatchesSOGoRFC3339Lines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "syslog")
	log := "" +
		`2026-05-29T14:20:20.044950+02:00 mx 0c4b016aaf9a[1090]: 2001:db8:a64c:1500:182a:21ee:97b3:53b0 - me@example.com [29/May/2026:14:20:20 +0200] "OPTIONS /SOGo/dav/me%40example.com/ HTTP/1.1" 200 0 "-" "iOS/26.5 (23F77) dataaccessd/1.0"` + "\n" +
		`2026-05-29T14:20:20.046236+02:00 mx c1fc66d724ec[1090]: May 29 14:20:20 c1fc66d724ec sogod [50]: 2001:db8:a64c:1500:182a:21ee:97b3:53b0 "OPTIONS /SOGo/dav/me%40example.com/ HTTP/1.1" 200 0/0 0.002 - - 160K - 11` + "\n"
	if err := os.WriteFile(logPath, []byte(log), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entry := Entry{
		FirstSeen: time.Date(2026, time.May, 29, 14, 19, 27, 0, time.FixedZone("", 2*60*60)),
		LastSeen:  time.Date(2026, time.May, 29, 15, 2, 10, 0, time.FixedZone("", 2*60*60)),
		IPs:       []string{"2001:db8:a64c:1500:182a:21ee:97b3:53b0"},
	}
	matches, err := correlateSyslog(logPath, entry, time.Hour, 100)
	if err != nil {
		t.Fatalf("correlateSyslog: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("matches = %d, want 2: %+v", len(matches), matches)
	}
	for _, match := range matches {
		if match.source != "sogo" {
			t.Fatalf("source = %q, want sogo", match.source)
		}
		if match.user != "me@example.com" {
			t.Fatalf("user = %q, want me@example.com", match.user)
		}
	}
}
