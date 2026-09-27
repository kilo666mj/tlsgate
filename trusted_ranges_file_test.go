package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readTrustedRangesDoc(t *testing.T, path string) trustedRangesDocument {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc trustedRangesDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %s: %v\n%s", path, err, data)
	}
	return doc
}

func TestTrustedRangesWriterWritesOnChangeOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-ranges.json")
	w := newTrustedRangesWriter(path)
	w.now = func() time.Time { return time.Date(2026, 9, 27, 17, 0, 0, 0, time.UTC) }

	if err := w.update([]string{"192.0.2.10/32", "2001:db8:1::/64"}, true); err != nil {
		t.Fatal(err)
	}
	doc := readTrustedRangesDoc(t, path)
	if doc.Version != 1 || doc.Source != "gatehub" || !doc.UpdatedAt.Equal(w.now()) {
		t.Fatalf("unexpected header: %+v", doc)
	}
	if strings.Join(doc.Ranges, ",") != "192.0.2.10/32,2001:db8:1::/64" {
		t.Fatalf("ranges = %v", doc.Ranges)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", info.Mode().Perm())
	}

	// An unchanged sync must not rewrite the file.
	w.now = func() time.Time { return time.Date(2026, 9, 27, 18, 0, 0, 0, time.UTC) }
	if err := w.update([]string{"198.51.100.1/32"}, false); err != nil {
		t.Fatal(err)
	}
	if got := readTrustedRangesDoc(t, path); len(got.Ranges) != 2 {
		t.Fatalf("unchanged update rewrote file: %+v", got)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestTrustedRangesWriterRetriesAfterFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	path := filepath.Join(dir, "trusted-ranges.json")
	w := newTrustedRangesWriter(path)
	if err := w.update([]string{"192.0.2.10/32"}, true); err == nil {
		t.Fatal("expected write into a missing directory to fail")
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The ranges did not change, but the previous write failed.
	if err := w.update([]string{"192.0.2.10/32"}, false); err != nil {
		t.Fatal(err)
	}
	if got := readTrustedRangesDoc(t, path); strings.Join(got.Ranges, ",") != "192.0.2.10/32" {
		t.Fatalf("ranges = %v", got.Ranges)
	}
}

func TestTrustedRangesWriterEmptySetIsExplicit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-ranges.json")
	if err := newTrustedRangesWriter(path).update(nil, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"ranges": []`)) {
		t.Fatalf("empty set not written as []:\n%s", data)
	}
}

func TestTrustedRangesWriterDisabled(t *testing.T) {
	w := newTrustedRangesWriter("")
	if w != nil {
		t.Fatal("empty path should disable the writer")
	}
	if err := w.update([]string{"192.0.2.10/32"}, true); err != nil {
		t.Fatal(err)
	}
}

func TestIPAllowlistDynamicRangesCanonical(t *testing.T) {
	allow, err := newIPAllowlist([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := allow.replaceDynamic([]string{"2001:db8:1::5/64", "192.0.2.10/32", "192.0.2.10/32"}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(allow.dynamicRanges(), ","); got != "192.0.2.10/32,2001:db8:1::/64" {
		t.Fatalf("dynamicRanges = %q (static ranges must be excluded, host bits masked, duplicates removed)", got)
	}
}

func TestDoctorReportsTrustedRangesFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := []byte(`{"trusted_ranges_file":"/var/lib/tlsgate/trusted-ranges.json"}`)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runDoctor([]string{"--config", configPath, "--db", filepath.Join(dir, "db")}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "trusted ranges file: /var/lib/tlsgate/trusted-ranges.json (never written; requires the control plane)") {
		t.Fatalf("missing trusted ranges file line:\n%s", &out)
	}
}
