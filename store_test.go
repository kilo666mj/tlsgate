package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreSetLabelAndDelete(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Seen("fp1", "192.0.2.10", 993, TLSMetadata{}, false); err != nil {
		t.Fatalf("Seen: %v", err)
	}

	if err := store.SetLabel("fp1", "thunderbird"); err != nil {
		t.Fatalf("SetLabel: %v", err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if entries["fp1"].Label != "thunderbird" {
		t.Fatalf("label = %q, want thunderbird", entries["fp1"].Label)
	}
	if err := store.SetLabel("missing", "x"); err == nil {
		t.Fatal("SetLabel on unknown fingerprint: expected error, got nil")
	}

	if err := store.Delete("fp1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	entries, err = store.List()
	if err != nil {
		t.Fatalf("List after delete: %v", err)
	}
	if _, ok := entries["fp1"]; ok {
		t.Fatal("fp1 still present after Delete")
	}
	if err := store.Delete("fp1"); err == nil {
		t.Fatal("Delete of missing fingerprint: expected error, got nil")
	}
}

func TestReconcileFingerprintMethod(t *testing.T) {
	store := newTestStore(t)

	// Fresh store: adopts the method without purging.
	if purged, err := store.ReconcileFingerprintMethod(MethodJA3, false); err != nil || purged != 0 {
		t.Fatalf("first reconcile = (%d, %v), want (0, nil)", purged, err)
	}

	if _, err := store.Seen("fp1", "192.0.2.10", 993, TLSMetadata{}, false); err != nil {
		t.Fatalf("Seen: %v", err)
	}

	// Same method: no-op, fingerprints retained.
	if purged, err := store.ReconcileFingerprintMethod(MethodJA3, false); err != nil || purged != 0 {
		t.Fatalf("same-method reconcile = (%d, %v), want (0, nil)", purged, err)
	}

	// Switching method without reset: refused, fingerprints retained.
	if _, err := store.ReconcileFingerprintMethod(MethodJA4, false); err == nil {
		t.Fatal("method switch without --reset-fingerprints: expected error, got nil")
	}
	entries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, ok := entries["fp1"]; !ok {
		t.Fatal("fp1 purged despite refused switch")
	}

	// Switching with reset: purges and records the new method.
	purged, err := store.ReconcileFingerprintMethod(MethodJA4, true)
	if err != nil {
		t.Fatalf("reset reconcile: %v", err)
	}
	if purged != 1 {
		t.Fatalf("purged = %d, want 1", purged)
	}
	entries, err = store.List()
	if err != nil {
		t.Fatalf("List after reset: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries after reset = %d, want 0", len(entries))
	}
	if method, err := store.GetMeta(metaFingerprintMethod); err != nil || method != string(MethodJA4) {
		t.Fatalf("stored method = (%q, %v), want %q", method, err, MethodJA4)
	}
}

func TestStoreMigratesLegacyJSON(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"fingerprints":{"fpA":{` +
		`"status":"approved","label":"tb","count":3,` +
		`"first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-02T00:00:00Z",` +
		`"ips":["192.0.2.5"],"ports":[993],` +
		`"tls":{"ja3":"771,4865,0-23,29,0","sni":"mail.example.com","alpn":["imap"]}}}}`
	if err := os.WriteFile(filepath.Join(dir, "db.json"), []byte(legacy), 0644); err != nil {
		t.Fatalf("write legacy json: %v", err)
	}

	store, err := NewStore(filepath.Join(dir, "db.sqlite"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	e, ok := entries["fpA"]
	if !ok {
		t.Fatal("fpA not migrated from legacy json")
	}
	if e.Status != StatusApproved || e.Label != "tb" || e.Count != 3 {
		t.Fatalf("migrated entry = %+v, want approved/tb/count=3", e)
	}
	if len(e.IPs) != 1 || e.IPs[0] != "192.0.2.5" {
		t.Fatalf("migrated IPs = %v, want [192.0.2.5]", e.IPs)
	}
	if len(e.Ports) != 1 || e.Ports[0] != 993 {
		t.Fatalf("migrated Ports = %v, want [993]", e.Ports)
	}
	if e.TLS.SNI != "mail.example.com" {
		t.Fatalf("migrated SNI = %q, want mail.example.com", e.TLS.SNI)
	}
}

func TestStoreReloadsExternalStatusChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")

	daemonStore, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore daemon: %v", err)
	}
	status, err := daemonStore.Seen("fp1", "192.0.2.10", 993, TLSMetadata{}, true)
	if err != nil {
		t.Fatalf("Seen initial: %v", err)
	}
	if status != StatusBlocked {
		t.Fatalf("initial status = %q, want %q", status, StatusBlocked)
	}

	cliStore, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore cli: %v", err)
	}
	if err := cliStore.SetStatus("fp1", StatusApproved); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	status, err = daemonStore.Seen("fp1", "192.0.2.10", 993, TLSMetadata{}, true)
	if err != nil {
		t.Fatalf("Seen after approval: %v", err)
	}
	if status != StatusApproved {
		t.Fatalf("status after external approval = %q, want %q", status, StatusApproved)
	}
}

func TestStoreRecordsTLSMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite")
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	meta := TLSMetadata{
		JA3:                 "771,4865,0-16,29,0",
		SNI:                 "mail.example.com",
		ALPN:                []string{"imap"},
		SupportedVersions:   []uint16{0x0304, 0x0303},
		SignatureAlgorithms: []uint16{0x0804, 0x0403},
	}
	if _, err := store.Seen("fp1", "192.0.2.10", 993, meta, false); err != nil {
		t.Fatalf("Seen: %v", err)
	}

	entries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := entries["fp1"].TLS
	if got.SNI != meta.SNI || got.JA3 != meta.JA3 {
		t.Fatalf("TLS metadata = %+v, want %+v", got, meta)
	}
}
