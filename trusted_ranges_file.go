package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const trustedRangesFileVersion = 1

// trustedRangesDocument is the JSON written to trusted_ranges_file. Consumers
// must treat a missing or unparsable file as "unknown", never as "empty".
type trustedRangesDocument struct {
	Version   int       `json:"version"`
	Source    string    `json:"source"`
	UpdatedAt time.Time `json:"updated_at"`
	Ranges    []string  `json:"ranges"`
}

// trustedRangesWriter publishes Gatehub trusted ranges to a local file. A
// failed write is retried on the next control-plane sync even when the ranges
// did not change, so a transient disk error does not leave the file stale.
type trustedRangesWriter struct {
	path string
	now  func() time.Time

	mu    sync.Mutex
	dirty bool
}

func newTrustedRangesWriter(path string) *trustedRangesWriter {
	if path == "" {
		return nil
	}
	return &trustedRangesWriter{path: path, now: time.Now}
}

// update writes ranges when they changed or a previous write failed.
func (w *trustedRangesWriter) update(ranges []string, changed bool) error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !changed && !w.dirty {
		return nil
	}
	err := writeTrustedRangesFile(w.path, trustedRangesDocument{
		Version:   trustedRangesFileVersion,
		Source:    "gatehub",
		UpdatedAt: w.now().UTC(),
		Ranges:    ranges,
	})
	w.dirty = err != nil
	return err
}

// writeTrustedRangesFile replaces path atomically: readers see either the old
// or the new complete document, never a partial write.
func writeTrustedRangesFile(path string, doc trustedRangesDocument) (err error) {
	if doc.Ranges == nil {
		doc.Ranges = []string{}
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary trusted ranges file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write trusted ranges file: %w", err)
	}
	if err = tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod trusted ranges file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync trusted ranges file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close trusted ranges file: %w", err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace trusted ranges file: %w", err)
	}
	return nil
}
