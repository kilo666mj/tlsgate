package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// muteStdout silences the fmt.Printf confirmations the CLI commands emit so
// they do not pollute test output.
func muteStdout(t *testing.T) {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open devnull: %v", err)
	}
	orig := os.Stdout
	os.Stdout = devnull
	t.Cleanup(func() {
		os.Stdout = orig
		devnull.Close()
	})
}

func TestCLIMutators(t *testing.T) {
	muteStdout(t)
	path := filepath.Join(t.TempDir(), "db.sqlite")

	seed, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, err := seed.Seen("fp1", "192.0.2.10", 993, TLSMetadata{}, false); err != nil {
		t.Fatalf("Seen: %v", err)
	}

	statusOf := func(fp string) (Entry, bool) {
		s, err := NewStore(path)
		if err != nil {
			t.Fatalf("reopen store: %v", err)
		}
		entries, err := s.List()
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		e, ok := entries[fp]
		return e, ok
	}

	cmdApprove([]string{"--db", path, "--label", "thunderbird", "fp1"})
	if e, _ := statusOf("fp1"); e.Status != StatusApproved || e.Label != "thunderbird" {
		t.Fatalf("after approve: status=%q label=%q", e.Status, e.Label)
	}

	cmdBlock([]string{"--db", path, "fp1"})
	if e, _ := statusOf("fp1"); e.Status != StatusBlocked {
		t.Fatalf("after block: status=%q, want blocked", e.Status)
	}

	cmdLabel([]string{"--db", path, "fp1", "renamed"})
	if e, _ := statusOf("fp1"); e.Label != "renamed" {
		t.Fatalf("after label: label=%q, want renamed", e.Label)
	}

	cmdDelete([]string{"--db", path, "fp1"})
	if _, ok := statusOf("fp1"); ok {
		t.Fatal("fp1 still present after delete")
	}
}

func TestListEntryOrder(t *testing.T) {
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	entries := map[string]Entry{
		"low-approved":    {Status: StatusApproved, Count: 1, FirstSeen: now.Add(-4 * time.Minute)},
		"high-pending":    {Status: StatusPending, Count: 3, FirstSeen: now.Add(-3 * time.Minute)},
		"high-blocked":    {Status: StatusBlocked, Count: 3, FirstSeen: now.Add(-2 * time.Minute)},
		"high-approved":   {Status: StatusApproved, Count: 3, FirstSeen: now.Add(-1 * time.Minute)},
		"middle-approved": {Status: StatusApproved, Count: 2, FirstSeen: now},
	}
	keys := []string{"low-approved", "high-pending", "high-blocked", "high-approved", "middle-approved"}

	sort.Slice(keys, func(i, j int) bool {
		return listEntryLess(keys[i], entries[keys[i]], keys[j], entries[keys[j]])
	})

	want := []string{"high-approved", "high-blocked", "high-pending", "middle-approved", "low-approved"}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("list order = %v, want %v", keys, want)
		}
	}
}

func TestTLSVersionList(t *testing.T) {
	got := tlsVersionList([]uint16{0x0304, 0x0303, 0x6a6a, 0x7a7b})
	want := "TLS1.3,TLS1.2,GREASE(0x6a6a),0x7a7b"
	if got != want {
		t.Fatalf("tlsVersionList = %q, want %q", got, want)
	}
}

func TestSignatureAlgorithmList(t *testing.T) {
	got := signatureAlgorithmList([]uint16{0x0804, 0x0403, 0x5a5a, 0xeaea, 0xaaaa, 0x1234})
	want := "RSA-PSS-SHA256,ECDSA-SHA256,GREASE(0x5a5a),GREASE(0xeaea),GREASE(0xaaaa),0x1234"
	if got != want {
		t.Fatalf("signatureAlgorithmList = %q, want %q", got, want)
	}
}

func TestValueOrDash(t *testing.T) {
	if got := valueOrDash(""); got != "-" {
		t.Fatalf("valueOrDash(\"\") = %q, want -", got)
	}
	if got := valueOrDash("imap"); got != "imap" {
		t.Fatalf("valueOrDash(\"imap\") = %q, want imap", got)
	}
}
