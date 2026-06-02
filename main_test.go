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

func TestCmdRegister(t *testing.T) {
	muteStdout(t)
	path := filepath.Join(t.TempDir(), "db.sqlite")

	seed, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, err := seed.ReconcileFingerprintMethod(MethodJA3, false); err != nil {
		t.Fatalf("reconcile: %v", err)
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

	// Without --register, approving an unseen fingerprint fails.
	if err := seed.SetStatus("ecdf4f49dd59effc439639da29186671", StatusApproved); err == nil {
		t.Fatal("SetStatus on unseen fingerprint: expected error, got nil")
	}

	// --register creates the entry, pre-approved with a label.
	approved := "ecdf4f49dd59effc439639da29186671"
	cmdApprove([]string{"--db", path, "--label", "preseed", "--register", approved})
	if e, ok := statusOf(approved); !ok || e.Status != StatusApproved || e.Label != "preseed" {
		t.Fatalf("registered approve = (%+v, %v), want approved/preseed", e, ok)
	}

	// --register can pre-block too.
	blocked := "16ee84a07b55074cb2751329bf1c8811"
	cmdBlock([]string{"--db", path, "--register", blocked})
	if e, ok := statusOf(blocked); !ok || e.Status != StatusBlocked {
		t.Fatalf("registered block = (%+v, %v), want blocked", e, ok)
	}
}

func TestValidFingerprintForMethod(t *testing.T) {
	ja3 := "ecdf4f49dd59effc439639da29186671"
	ja4 := "t13d1516h2_8daaf6152771_b186095e22b6"

	cases := []struct {
		method FingerprintMethod
		fp     string
		want   bool
	}{
		{MethodJA3, ja3, true},
		{MethodJA3, ja4, false},
		{MethodJA3, "ecdf4f49", false},            // too short
		{MethodJA3, "ECDF4F49DD59EFFC439639DA29186671", false}, // uppercase
		{MethodJA4, ja4, true},
		{MethodJA4, ja3, false},
		{MethodJA4, "t13d1516h2_8daaf6152771", false}, // missing section c
		{"", ja3, true},                                // unset: accept either
		{"", ja4, true},
		{"", "not-a-fingerprint", false},
	}
	for _, c := range cases {
		if got := validFingerprintForMethod(c.fp, c.method); got != c.want {
			t.Errorf("validFingerprintForMethod(%q, %q) = %v, want %v", c.fp, c.method, got, c.want)
		}
	}
}

func TestCmdReset(t *testing.T) {
	muteStdout(t)
	path := filepath.Join(t.TempDir(), "db.sqlite")

	seed, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, err := seed.ReconcileFingerprintMethod(MethodJA3, false); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, err := seed.Seen("fp1", "192.0.2.10", 993, TLSMetadata{}, false); err != nil {
		t.Fatalf("Seen: %v", err)
	}

	// Reset and switch the recorded method in one shot.
	cmdReset([]string{"--db", path, "--fingerprint", "ja4"})

	check, err := NewStore(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	entries, err := check.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries after reset = %d, want 0", len(entries))
	}
	if method, err := check.GetMeta(metaFingerprintMethod); err != nil || method != string(MethodJA4) {
		t.Fatalf("stored method = (%q, %v), want %q", method, err, MethodJA4)
	}

	// A plain reset (no --fingerprint) keeps the recorded method.
	cmdReset([]string{"--db", path})
	if method, err := check.GetMeta(metaFingerprintMethod); err != nil || method != string(MethodJA4) {
		t.Fatalf("method after plain reset = (%q, %v), want %q", method, err, MethodJA4)
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
