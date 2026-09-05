package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kilo666mj/gatekit/store"
)

func TestServingStoreImmediatelyLimitsNewFingerprints(t *testing.T) {
	for _, limit := range []int{2, -1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			st, err := newStoreWithLimit(filepath.Join(t.TempDir(), "db.sqlite"), limit)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if _, err := st.ReconcileFingerprintMethod("ja4", false); err != nil {
				t.Fatal(err)
			}
			if err := st.UpsertStatus("approved", StatusApproved, "mail client"); err != nil {
				t.Fatal(err)
			}
			for i := range 5 {
				if _, err := st.Observe(store.Observation{Fingerprint: fmt.Sprintf("unknown-%d", i), IP: "192.0.2.1", Port: 993}, true); err != nil {
					t.Fatal(err)
				}
				entries, err := st.List()
				if err != nil {
					t.Fatal(err)
				}
				if limit > 0 && len(entries) > limit {
					t.Fatalf("got %d entries, limit %d", len(entries), limit)
				}
				if limit < 0 && len(entries) != i+2 {
					t.Fatalf("unlimited store lost entries: %d", len(entries))
				}
			}
			approved, err := st.Get("approved")
			if err != nil {
				t.Fatal(err)
			}
			if approved.Status != StatusApproved || approved.Label != "mail client" {
				t.Fatalf("approval changed: %+v", approved)
			}
			if method, err := st.GetMeta(metaFingerprintMethod); err != nil || method != "ja4" {
				t.Fatalf("method = %q, error = %v", method, err)
			}
		})
	}
}

func TestTLSMetadataAndHistoryBoundsPreserveApproval(t *testing.T) {
	st, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.UpsertStatus("client", StatusApproved, "known client"); err != nil {
		t.Fatal(err)
	}
	for i := range 140 {
		if _, err := st.Observe(store.Observation{
			Fingerprint: "client", IP: fmt.Sprintf("2001:db8::%x", i+1), Port: 10000 + i,
			Meta: (TLSMetadata{JA3: "771,4865,,,", SNI: "mail.example.invalid"}).toMeta(),
		}, true); err != nil {
			t.Fatal(err)
		}
	}
	entry, err := st.Get("client")
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.IPs) != 128 || len(entry.Ports) != 128 || len(entry.Sightings) != 128 {
		t.Fatalf("unbounded history: IPs=%d ports=%d sightings=%d", len(entry.IPs), len(entry.Ports), len(entry.Sightings))
	}
	if entry.Status != StatusApproved || entry.Label != "known client" || entry.Count != 140 {
		t.Fatalf("lost decision or count: %+v", entry)
	}
	if tlsMetaOf(entry).SNI != "mail.example.invalid" {
		t.Fatal("lost TLS metadata")
	}
	if _, err := st.Observe(store.Observation{Fingerprint: "client", Meta: (TLSMetadata{SNI: strings.Repeat("x", 65536)}).toMeta()}, true); err == nil {
		t.Fatal("accepted oversized metadata")
	}
	after, err := st.Get("client")
	if err != nil {
		t.Fatal(err)
	}
	if after.Count != entry.Count || after.Status != StatusApproved || tlsMetaOf(after).SNI != tlsMetaOf(entry).SNI {
		t.Fatal("rejected observation changed stored client")
	}
}
