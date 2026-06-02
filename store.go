package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusBlocked  Status = "blocked"
)

type Entry struct {
	Status    Status      `json:"status"`
	Label     string      `json:"label,omitempty"`
	FirstSeen time.Time   `json:"first_seen"`
	LastSeen  time.Time   `json:"last_seen"`
	IPs       []string    `json:"ips,omitempty"`
	Ports     []int       `json:"ports,omitempty"`
	Count     int         `json:"count"`
	TLS       TLSMetadata `json:"tls,omitempty"`
}

type Store struct {
	path string
	db   *sql.DB
}

func NewStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{path: path, db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) init() error {
	ctx := context.Background()
	for _, stmt := range []string{
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA journal_mode = WAL`,
		`CREATE TABLE IF NOT EXISTS fingerprints (
			fp TEXT PRIMARY KEY,
			status TEXT NOT NULL,
			label TEXT NOT NULL DEFAULT '',
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			count INTEGER NOT NULL DEFAULT 0,
			ja3 TEXT NOT NULL DEFAULT '',
			ja4 TEXT NOT NULL DEFAULT '',
			sni TEXT NOT NULL DEFAULT '',
			alpn TEXT NOT NULL DEFAULT '[]',
			supported_versions TEXT NOT NULL DEFAULT '[]',
			signature_algorithms TEXT NOT NULL DEFAULT '[]'
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprint_ips (
			fp TEXT NOT NULL REFERENCES fingerprints(fp) ON DELETE CASCADE,
			ip TEXT NOT NULL,
			PRIMARY KEY (fp, ip)
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprint_ports (
			fp TEXT NOT NULL REFERENCES fingerprints(fp) ON DELETE CASCADE,
			port INTEGER NOT NULL,
			PRIMARY KEY (fp, port)
		)`,
		`CREATE TABLE IF NOT EXISTS blocked_range_alerts (
			range_name TEXT NOT NULL,
			ip TEXT NOT NULL,
			fp TEXT NOT NULL,
			first_seen TEXT NOT NULL,
			PRIMARY KEY (range_name, ip)
		)`,
		`CREATE TABLE IF NOT EXISTS meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprints_last_seen ON fingerprints(last_seen)`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprint_ips_ip ON fingerprint_ips(ip)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if err := s.addColumnIfMissing(ctx, "fingerprints", "ja4", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	return nil
}

// metaFingerprintMethod is the meta key recording which fingerprint method
// (ja3 or ja4) the stored fp keys were computed with. The fp primary key is
// method-specific, so switching methods changes the keyspace and silently
// invalidates every approval and block; this lets serve detect that.
const metaFingerprintMethod = "fingerprint_method"

func (s *Store) GetMeta(key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(context.Background(),
		`SELECT value FROM meta WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO meta (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// ResetFingerprints deletes every fingerprint, cascading to the dependent ip
// and port rows. The blocked_range_alerts table is keyed by range+ip rather
// than fp, so it is left intact. Returns the number of fingerprints removed.
func (s *Store) ResetFingerprints() (int64, error) {
	res, err := s.db.ExecContext(context.Background(), `DELETE FROM fingerprints`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ReconcileFingerprintMethod aligns the store's keyspace with method. A fresh
// store (or one predating this metadata) simply records method. If the stored
// method differs, the caller must opt into a purge via reset, since switching
// ja3<->ja4 changes the fp keyspace and would otherwise silently orphan every
// approval and block. Returns the number of fingerprints purged, if any.
func (s *Store) ReconcileFingerprintMethod(method FingerprintMethod, reset bool) (int64, error) {
	stored, err := s.GetMeta(metaFingerprintMethod)
	if err != nil {
		return 0, err
	}
	if stored == string(method) {
		return 0, nil
	}
	var purged int64
	if stored != "" {
		if !reset {
			return 0, fmt.Errorf("database was built with fingerprint method %q but %q was requested; "+
				"re-run with --reset-fingerprints to purge stored fingerprints, or switch back to %q",
				stored, method, stored)
		}
		if purged, err = s.ResetFingerprints(); err != nil {
			return 0, err
		}
	}
	if err := s.SetMeta(metaFingerprintMethod, string(method)); err != nil {
		return purged, err
	}
	return purged, nil
}

// addColumnIfMissing adds a column to an existing table, tolerating older
// databases created before the column existed. CREATE TABLE IF NOT EXISTS
// never alters an already-present table, so new columns need this.
func (s *Store) addColumnIfMissing(ctx context.Context, table, column, def string) error {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return rows.Close()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, def))
	return err
}

func (s *Store) Seen(fp, ip string, port int, meta TLSMetadata, blockUnknown bool) (Status, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var status Status
	err = tx.QueryRowContext(ctx, `SELECT status FROM fingerprints WHERE fp = ?`, fp).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		status = StatusPending
		if blockUnknown {
			status = StatusBlocked
		}
		now := time.Now()
		_, err = tx.ExecContext(ctx, `
			INSERT INTO fingerprints (
				fp, status, first_seen, last_seen, count,
				ja3, ja4, sni, alpn, supported_versions, signature_algorithms
			) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)`,
			fp, status, encodeTime(now), encodeTime(now),
			meta.JA3, meta.JA4, meta.SNI, encodeStrings(meta.ALPN),
			encodeU16s(meta.SupportedVersions), encodeU16s(meta.SignatureAlgorithms),
		)
	}
	if err != nil {
		return status, err
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE fingerprints
		SET last_seen = ?, count = count + 1,
			ja3 = ?, ja4 = ?, sni = ?, alpn = ?, supported_versions = ?, signature_algorithms = ?
		WHERE fp = ?`,
		encodeTime(time.Now()), meta.JA3, meta.JA4, meta.SNI, encodeStrings(meta.ALPN),
		encodeU16s(meta.SupportedVersions), encodeU16s(meta.SignatureAlgorithms), fp,
	); err != nil {
		return status, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO fingerprint_ips (fp, ip) VALUES (?, ?)`, fp, ip); err != nil {
		return status, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO fingerprint_ports (fp, port) VALUES (?, ?)`, fp, port); err != nil {
		return status, err
	}
	if err := tx.Commit(); err != nil {
		return status, err
	}
	return status, nil
}

// PruneToLimit enforces a cap on the number of stored fingerprints, bounding
// disk growth from unauthenticated unknown clients. When the count exceeds
// max, it deletes the oldest non-approved entries (by last_seen) until the
// count is back at or below max, or until only approved entries remain.
// Approved fingerprints are authoritative and never evicted. max <= 0 disables
// pruning. Returns the number of entries deleted (ips/ports cascade).
func (s *Store) PruneToLimit(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}
	ctx := context.Background()
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM fingerprints`).Scan(&count); err != nil {
		return 0, err
	}
	excess := count - max
	if excess <= 0 {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM fingerprints
		WHERE fp IN (
			SELECT fp FROM fingerprints
			WHERE status != ?
			ORDER BY last_seen ASC
			LIMIT ?
		)`, StatusApproved, excess)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (s *Store) SetStatus(fp string, status Status) error {
	res, err := s.db.Exec(`UPDATE fingerprints SET status = ? WHERE fp = ?`, status, fp)
	if err != nil {
		return err
	}
	return requireAffected(res, fp)
}

func (s *Store) SetLabel(fp, label string) error {
	res, err := s.db.Exec(`UPDATE fingerprints SET label = ? WHERE fp = ?`, label, fp)
	if err != nil {
		return err
	}
	return requireAffected(res, fp)
}

func (s *Store) Delete(fp string) error {
	res, err := s.db.Exec(`DELETE FROM fingerprints WHERE fp = ?`, fp)
	if err != nil {
		return err
	}
	return requireAffected(res, fp)
}

func (s *Store) List() (map[string]Entry, error) {
	rows, err := s.db.Query(`
		SELECT fp, status, label, first_seen, last_seen, count,
			ja3, ja4, sni, alpn, supported_versions, signature_algorithms
		FROM fingerprints`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]Entry)
	for rows.Next() {
		var fp, firstSeen, lastSeen string
		var alpn, versions, sigAlgs string
		var e Entry
		if err := rows.Scan(
			&fp, &e.Status, &e.Label, &firstSeen, &lastSeen, &e.Count,
			&e.TLS.JA3, &e.TLS.JA4, &e.TLS.SNI, &alpn, &versions, &sigAlgs,
		); err != nil {
			return nil, err
		}
		var err error
		e.FirstSeen, err = decodeTime(firstSeen)
		if err != nil {
			return nil, fmt.Errorf("decode first_seen for %s: %w", fp, err)
		}
		e.LastSeen, err = decodeTime(lastSeen)
		if err != nil {
			return nil, fmt.Errorf("decode last_seen for %s: %w", fp, err)
		}
		if err := decodeJSON(alpn, &e.TLS.ALPN); err != nil {
			return nil, fmt.Errorf("decode alpn for %s: %w", fp, err)
		}
		if err := decodeJSON(versions, &e.TLS.SupportedVersions); err != nil {
			return nil, fmt.Errorf("decode supported_versions for %s: %w", fp, err)
		}
		if err := decodeJSON(sigAlgs, &e.TLS.SignatureAlgorithms); err != nil {
			return nil, fmt.Errorf("decode signature_algorithms for %s: %w", fp, err)
		}
		out[fp] = e
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for fp, e := range out {
		ips, err := s.listStrings(`SELECT ip FROM fingerprint_ips WHERE fp = ? ORDER BY ip`, fp)
		if err != nil {
			return nil, err
		}
		ports, err := s.listInts(`SELECT port FROM fingerprint_ports WHERE fp = ? ORDER BY port`, fp)
		if err != nil {
			return nil, err
		}
		e.IPs = ips
		e.Ports = ports
		out[fp] = e
	}
	return out, nil
}

func (s *Store) RecordBlockedRangeAlert(rangeName, ip, fp string) (bool, error) {
	res, err := s.db.Exec(`
		INSERT OR IGNORE INTO blocked_range_alerts (range_name, ip, fp, first_seen)
		VALUES (?, ?, ?, ?)`,
		rangeName, ip, fp, encodeTime(time.Now()),
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *Store) HasBlockedRangeAlert(rangeName, ip string) (bool, error) {
	var count int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM blocked_range_alerts WHERE range_name = ? AND ip = ?`,
		rangeName, ip,
	).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Store) ForgetBlockedRangeAlert(rangeName, ip string) error {
	_, err := s.db.Exec(`DELETE FROM blocked_range_alerts WHERE range_name = ? AND ip = ?`, rangeName, ip)
	return err
}

func requireAffected(res sql.Result, fp string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("fingerprint not found: %s", fp)
	}
	return nil
}

func (s *Store) listStrings(query, fp string) ([]string, error) {
	rows, err := s.db.Query(query, fp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) listInts(query, fp string) ([]int, error) {
	rows, err := s.db.Query(query, fp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []int
	for rows.Next() {
		var value int
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func encodeTime(t time.Time) string {
	return t.Format(time.RFC3339Nano)
}

func decodeTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}

func encodeStrings(vals []string) string {
	b, _ := json.Marshal(vals)
	return string(b)
}

func encodeU16s(vals []uint16) string {
	b, _ := json.Marshal(vals)
	return string(b)
}

func decodeJSON(s string, dest any) error {
	if s == "" {
		s = "[]"
	}
	return json.Unmarshal([]byte(s), dest)
}
