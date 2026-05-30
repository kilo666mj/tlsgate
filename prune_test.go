package main

import (
	"fmt"
	"testing"
)

func TestStorePruneToLimit(t *testing.T) {
	store := newTestStore(t)

	// 5 pending entries...
	for i := 0; i < 5; i++ {
		if _, err := store.Seen(fmt.Sprintf("pending%d", i), "192.0.2.10", 993, TLSMetadata{}, false); err != nil {
			t.Fatalf("Seen: %v", err)
		}
	}
	// ...and 2 approved.
	for i := 0; i < 2; i++ {
		fp := fmt.Sprintf("approved%d", i)
		if _, err := store.Seen(fp, "192.0.2.11", 993, TLSMetadata{}, false); err != nil {
			t.Fatalf("Seen: %v", err)
		}
		if err := store.SetStatus(fp, StatusApproved); err != nil {
			t.Fatalf("SetStatus: %v", err)
		}
	}

	// Cap at 4: delete 3 of the 5 pending, keep both approved.
	deleted, err := store.PruneToLimit(4)
	if err != nil {
		t.Fatalf("PruneToLimit: %v", err)
	}
	if deleted != 3 {
		t.Fatalf("deleted = %d, want 3", deleted)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("entry count = %d, want 4", len(entries))
	}
	for i := 0; i < 2; i++ {
		if _, ok := entries[fmt.Sprintf("approved%d", i)]; !ok {
			t.Fatalf("approved%d was evicted; approved entries must be kept", i)
		}
	}

	// Cap below the number of approved entries: never evict approved, so the
	// 2 remaining pending go and the 2 approved stay even though that is > cap.
	deleted, err = store.PruneToLimit(1)
	if err != nil {
		t.Fatalf("PruneToLimit: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d, want 2", deleted)
	}
	entries, _ = store.List()
	if len(entries) != 2 {
		t.Fatalf("entry count = %d, want 2 (approved kept above cap)", len(entries))
	}

	// max <= 0 disables pruning.
	if n, err := store.PruneToLimit(0); err != nil || n != 0 {
		t.Fatalf("PruneToLimit(0) = (%d, %v), want (0, nil)", n, err)
	}
}
