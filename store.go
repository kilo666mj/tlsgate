package main

import (
	"database/sql"
	"fmt"
	"net/url"

	"github.com/kilo666mj/gatekit/store"
)

// The fingerprint store itself lives in gatekit, shared with sshgate. What
// stays here is the TLS-specific part: which columns the pre-gatekit schema
// used, and how a TLSMetadata converts to and from the store's untyped
// metadata bag.

// Status and Entry are re-exported so the rest of the gate reads as it did
// before the store moved out.
type (
	Status = store.Status
	Entry  = store.Entry
)

const (
	StatusPending  = store.StatusPending
	StatusApproved = store.StatusApproved
	StatusBlocked  = store.StatusBlocked
)

// metaFingerprintMethod records which fingerprint method (ja3 or ja4) the
// stored keys were computed with. The key is method-specific, so switching
// methods changes the keyspace and silently invalidates every approval and
// block; this lets serve detect that.
const metaFingerprintMethod = store.MetaFingerprintMethod

// legacyColumns maps the typed columns of the pre-gatekit tlsgate schema onto
// keys in the metadata bag. Databases in service (mx, fronting mailcow on 993
// and 465) still have these columns; gatekit folds them in once on open, so
// approvals, blocks, labels and history carry over untouched. The columns are
// left in place, so rolling back to a pre-gatekit binary still works.
var legacyColumns = []store.LegacyColumn{
	{Column: "ja3", MetaKey: "ja3"},
	{Column: "ja4", MetaKey: "ja4"},
	{Column: "sni", MetaKey: "sni"},
	{Column: "alpn", MetaKey: "alpn", Kind: store.KindJSON},
	{Column: "supported_versions", MetaKey: "supported_versions", Kind: store.KindJSON},
	{Column: "signature_algorithms", MetaKey: "signature_algorithms", Kind: store.KindJSON},
}

// NewStore opens the fingerprint database, folding a pre-gatekit schema into
// the metadata bag if it finds one.
func NewStore(path string) (*store.Store, error) {
	return newStoreWithLimit(path, 0)
}

// newStoreWithLimit applies the serving process's row cap on each new observation.
// CLI opens remain uncapped so management operations do not apply a default policy.
func newStoreWithLimit(path string, limit int) (*store.Store, error) {
	st, err := store.Open(store.Options{Path: path, Legacy: legacyColumns, MaxFingerprints: limit})
	if err != nil {
		return nil, err
	}
	if err := boundBlockedRangeAlerts(path); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

// toMeta renders a fingerprinted ClientHello into the store's metadata bag.
func (m TLSMetadata) toMeta() map[string]any {
	return map[string]any{
		"ja3":                  m.JA3,
		"ja4":                  m.JA4,
		"sni":                  m.SNI,
		"alpn":                 m.ALPN,
		"supported_versions":   m.SupportedVersions,
		"signature_algorithms": m.SignatureAlgorithms,
	}
}

// tlsMetaOf reads a stored entry's metadata bag back into a TLSMetadata for
// display and correlation.
//
// Values that have been through SQLite arrive as JSON, so a numeric list comes
// back as []any of float64 and has to be narrowed rather than type-asserted.
// Values set in this process since the last read are still their original Go
// types, so both shapes are handled.
func tlsMetaOf(e Entry) TLSMetadata {
	return TLSMetadata{
		JA3:                 metaString(e.Meta, "ja3"),
		JA4:                 metaString(e.Meta, "ja4"),
		SNI:                 metaString(e.Meta, "sni"),
		ALPN:                metaStrings(e.Meta, "alpn"),
		SupportedVersions:   metaU16s(e.Meta, "supported_versions"),
		SignatureAlgorithms: metaU16s(e.Meta, "signature_algorithms"),
	}
}

func metaString(meta map[string]any, key string) string {
	s, _ := meta[key].(string)
	return s
}

func metaStrings(meta map[string]any, key string) []string {
	switch v := meta[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func metaU16s(meta map[string]any, key string) []uint16 {
	switch v := meta[key].(type) {
	case []uint16:
		return v
	case []any:
		out := make([]uint16, 0, len(v))
		for _, item := range v {
			if f, ok := item.(float64); ok {
				out = append(out, uint16(f))
			}
		}
		return out
	}
	return nil
}

// Deduplication retains the most recently inserted range/IP pairs. Once evicted,
// a pair can notify again. Keep this independent of the fingerprint row policy.
const maxBlockedRangeAlerts = 10000

// boundBlockedRangeAlerts installs a database-level limit so all Gatekit writers
// (including concurrent serving processes during handoff) enforce it atomically.
// This uses the Gatekit v0.5.0 table schema; keep an integration test on upgrades.
func boundBlockedRangeAlerts(path string) error {
	q := url.Values{"_pragma": {"busy_timeout=5000"}}
	db, err := sql.Open("sqlite", path+"?"+q.Encode())
	if err != nil {
		return err
	}
	defer db.Close()
	trim := fmt.Sprintf(`DELETE FROM blocked_range_alerts WHERE rowid <= (
 SELECT rowid FROM blocked_range_alerts ORDER BY rowid DESC LIMIT 1 OFFSET %d
 )`, maxBlockedRangeAlerts)
	if _, err := db.Exec(`CREATE TRIGGER IF NOT EXISTS tlsgate_bound_alerts_v1
 AFTER INSERT ON blocked_range_alerts BEGIN ` + trim + `; END`); err != nil {
		return fmt.Errorf("install alert retention: %w", err)
	}
	if _, err := db.Exec(trim); err != nil {
		return fmt.Errorf("trim alert history: %w", err)
	}
	return nil
}

const metaFingerprintFormat = "tlsgate_fingerprint_format"
const canonicalFingerprintFormat = "2"

// The old JA3/GREASE and JA4/ALPN algorithms used different keys. Never silently
// reinterpret stored decisions, including databases predating the format marker.
func reconcileFingerprintFormat(st *store.Store, reset bool) (int64, error) {
	format, err := st.GetMeta(metaFingerprintFormat)
	if err != nil {
		return 0, err
	}
	if format == canonicalFingerprintFormat {
		return 0, nil
	}
	last, err := st.LastFingerprint()
	if err != nil {
		return 0, err
	}
	if last != "" && !reset {
		return 0, fmt.Errorf("database uses an older or unsupported fingerprint format %q; back up the database, then use --reset-fingerprints and re-enroll clients for canonical JA3/JA4", format)
	}
	var deleted int64
	if last != "" {
		deleted, err = st.ResetFingerprints()
		if err != nil {
			return 0, err
		}
	}
	return deleted, st.SetMeta(metaFingerprintFormat, canonicalFingerprintFormat)
}
