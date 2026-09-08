package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSMTPCorrelationEndpointLifetimeAndReplay(t *testing.T) {
	d := t.TempDir()
	events := filepath.Join(d, "events.jsonl")
	logs := filepath.Join(d, "mail.log")
	verdicts := filepath.Join(d, "verdicts.jsonl")
	db := filepath.Join(d, "correlation.sqlite")
	mustWrite := func(path, s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(events, ""+
		`{"version":1,"type":"start","timestamp":"2026-09-08T12:49:00Z","instance":"mx","connection_id":"a","client":"167.71.57.227:33700","listener":"127.0.0.1:25","backend":"127.0.0.1:10025"}`+"\n"+
		`{"version":1,"type":"starttls","state":"accepted","timestamp":"2026-09-08T12:49:01.5Z","instance":"mx","connection_id":"a"}`+"\n"+
		`{"version":1,"type":"fingerprint","timestamp":"2026-09-08T12:49:02Z","instance":"mx","connection_id":"a","ja3":"j3","ja4":"j4"}`+"\n"+
		`{"version":1,"type":"end","state":"fingerprinted","timestamp":"2026-09-08T12:50:00Z","instance":"mx","connection_id":"a"}`+"\n"+
		`{"version":1,"type":"start","timestamp":"2026-09-08T12:49:00Z","instance":"mx","connection_id":"b","client":"167.71.57.227:33701","listener":"127.0.0.1:25"}`+"\n"+
		`{"version":1,"type":"end","state":"no_observed_upgrade","timestamp":"2026-09-08T12:50:00Z","instance":"mx","connection_id":"b"}`+"\n")
	mustWrite(logs, "2026-09-08T12:49:01Z mx postfix/smtpd[10]: connect from unknown[167.71.57.227]:33700\n"+
		"2026-09-08T12:49:03Z mx postfix/smtpd[10]: Q123: client=unknown[167.71.57.227]:33700\n"+
		"2026-09-08T12:49:04Z mx postfix/smtpd[10]: disconnect from unknown[167.71.57.227]:33700\n")
	mustWrite(verdicts, `{"timestamp":"2026-09-08T12:49:04Z","instance":"mx","queue_id":"Q123","classification":"spam","score":15,"action":"reject"}`+"\n")
	for i := 0; i < 2; i++ {
		s, err := runSMTPCorrelation(events, logs, verdicts, db, "mx", "127.0.0.1:25", time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if s.Matched != 1 || s.Spam != 1 || s.Connections != 2 {
			t.Fatalf("summary %#v", s)
		}
	}
}

func TestSMTPCorrelationRejectsAmbiguousAndPlaintext(t *testing.T) {
	cs := []smtpConnRecord{{ID: "a", Instance: "mx", Client: "1.2.3.4:9", Start: time.Unix(0, 0), End: time.Unix(20, 0)}, {ID: "b", Instance: "mx", Client: "1.2.3.4:9", Start: time.Unix(0, 0), End: time.Unix(20, 0)}}
	m := smtpMessage{Instance: "mx", Client: "1.2.3.4:9", At: time.Unix(10, 0), SessionStart: time.Unix(1, 0), HasSession: true}
	if got := matchSMTPConn(cs, m, 0); len(got) != 2 {
		t.Fatalf("got %d candidates", len(got))
	}
}
