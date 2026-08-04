package main

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kilo666mj/gatekit/store"

	// Seeding a legacy schema opens SQLite directly rather than through
	// gatekit, so register the driver here instead of relying on gatekit's
	// choice of driver staying the same.
	_ "modernc.org/sqlite"
)

// The store itself is tested in gatekit. What needs covering here is the
// TLS-specific adapter: that a fingerprinted ClientHello survives a round trip
// through the untyped metadata bag, and that a database written by the
// pre-gatekit tlsgate still reads correctly through it.

func TestTLSMetadataRoundTripsThroughStore(t *testing.T) {
	st, err := NewStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()

	meta := TLSMetadata{
		JA3:                 "aabbccddeeff",
		JA4:                 "t13d1516h2_8daaf6152771_b186095e22b6",
		SNI:                 "mail.example.com",
		ALPN:                []string{"h2", "http/1.1"},
		SupportedVersions:   []uint16{0x0304, 0x0303},
		SignatureAlgorithms: []uint16{0x0804, 0x0403},
	}
	if _, err := st.Observe(store.Observation{
		Fingerprint: "fp1",
		IP:          "192.0.2.10",
		Port:        993,
		Meta:        meta.toMeta(),
	}, false); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// Re-open so the values come back off disk as JSON rather than out of the
	// in-process map: numeric lists decode as float64 and must be narrowed.
	st.Close()
	reopened, err := NewStore(filepath.Join(filepath.Dir(st.Path()), "db.sqlite"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	entry, err := reopened.Get("fp1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := tlsMetaOf(entry); !reflect.DeepEqual(got, meta) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, meta)
	}
}

func TestTLSMetadataOfEmptyEntry(t *testing.T) {
	// A row with no metadata (a placeholder written by --register or by a
	// gatehub decision) must render as a zero TLSMetadata, not panic.
	if got := tlsMetaOf(Entry{}); !reflect.DeepEqual(got, TLSMetadata{}) {
		t.Errorf("tlsMetaOf(empty) = %+v", got)
	}
}

// A database written by the pre-gatekit tlsgate must keep its verdicts and
// still surface its TLS fields through the adapter. This is the migration
// that runs against the live database on mx.
func TestOpensPreGatekitDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE fingerprints (
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
		);
		CREATE TABLE fingerprint_ips (
			fp TEXT NOT NULL REFERENCES fingerprints(fp) ON DELETE CASCADE,
			ip TEXT NOT NULL, PRIMARY KEY (fp, ip)
		);
		CREATE TABLE fingerprint_ports (
			fp TEXT NOT NULL REFERENCES fingerprints(fp) ON DELETE CASCADE,
			port INTEGER NOT NULL, PRIMARY KEY (fp, port)
		);
		CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		INSERT INTO fingerprints VALUES ('fp1','approved','imap-client',
			'2026-01-01T00:00:00Z','2026-02-01T00:00:00Z',17,
			'aabbcc','t13d1516h2_8daaf6152771_b186095e22b6','mail.example.com',
			'["h2","http/1.1"]','[772,771]','[2052,1027]');
		INSERT INTO fingerprint_ips VALUES ('fp1','192.0.2.10');
		INSERT INTO fingerprint_ports VALUES ('fp1',993);
		INSERT INTO meta VALUES ('fingerprint_method','ja4');
	`); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}
	db.Close()

	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore on legacy db: %v", err)
	}
	defer st.Close()

	entry, err := st.Get("fp1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry.Status != StatusApproved || entry.Label != "imap-client" {
		t.Errorf("verdict lost: status=%q label=%q", entry.Status, entry.Label)
	}
	if entry.Count != 17 {
		t.Errorf("count = %d, want 17", entry.Count)
	}
	if len(entry.Ports) != 1 || entry.Ports[0] != 993 {
		t.Errorf("ports = %v", entry.Ports)
	}
	tls := tlsMetaOf(entry)
	if tls.SNI != "mail.example.com" || tls.JA4 != "t13d1516h2_8daaf6152771_b186095e22b6" {
		t.Errorf("tls metadata = %+v", tls)
	}
	if !reflect.DeepEqual(tls.ALPN, []string{"h2", "http/1.1"}) {
		t.Errorf("alpn = %v", tls.ALPN)
	}
	if !reflect.DeepEqual(tls.SupportedVersions, []uint16{772, 771}) {
		t.Errorf("supported_versions = %v", tls.SupportedVersions)
	}

	// The recorded fingerprint method must survive too, or serve would think
	// the keyspace had changed and refuse to start.
	if _, err := st.ReconcileFingerprintMethod(string(MethodJA4), false); err != nil {
		t.Errorf("ReconcileFingerprintMethod: %v", err)
	}
}
