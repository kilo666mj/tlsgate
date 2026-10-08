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

func TestSMTPCorrelationUsesPostfixTLSOrder(t *testing.T) {
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
	fingerprinted := func(id, port string) string {
		return `{"version":1,"type":"start","timestamp":"2026-10-07T09:17:09.5Z","instance":"mx","connection_id":"` + id + `","client":"192.0.2.10:` + port + `","listener":"127.0.0.1:25"}` + "\n" +
			`{"version":1,"type":"starttls","state":"accepted","timestamp":"2026-10-07T09:17:10.0Z","instance":"mx","connection_id":"` + id + `"}` + "\n" +
			`{"version":1,"type":"fingerprint","timestamp":"2026-10-07T09:17:10.1Z","instance":"mx","connection_id":"` + id + `","ja3":"j3","ja4":"j4"}` + "\n" +
			`{"version":1,"type":"end","state":"fingerprinted","timestamp":"2026-10-07T09:17:15Z","instance":"mx","connection_id":"` + id + `"}` + "\n"
	}
	mustWrite(events, fingerprinted("fast", "51651")+fingerprinted("pre", "51652")+fingerprinted("nolog", "51653")+fingerprinted("twice", "51654")+
		`{"version":1,"type":"start","timestamp":"2026-10-07T09:17:09.5Z","instance":"mx","connection_id":"plain","client":"192.0.2.10:51655","listener":"127.0.0.1:25"}`+"\n"+
		`{"version":1,"type":"end","state":"no_observed_upgrade","timestamp":"2026-10-07T09:17:15Z","instance":"mx","connection_id":"plain"}`+"\n")
	tls := func(pid, port string) string {
		return "2026-10-07T09:17:10.17Z mx postfix/smtpd[" + pid + "]: Anonymous TLS connection established from mta.example.net[192.0.2.10]:" + port + ": TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)\n"
	}
	mustWrite(logs, ""+
		// Message logged 0.6 s after the ClientHello, inside the timing tolerance.
		"2026-10-07T09:17:09.54Z mx postfix/smtpd[1]: connect from mta.example.net[192.0.2.10]:51651\n"+tls("1", "51651")+
		"2026-10-07T09:17:10.7Z mx postfix/smtpd[1]: QFAST: client=mta.example.net[192.0.2.10]:51651\n"+
		// Plaintext message before a later STARTTLS stays plaintext even when logged late.
		"2026-10-07T09:17:09.54Z mx postfix/smtpd[2]: connect from mta.example.net[192.0.2.10]:51652\n"+
		"2026-10-07T09:17:11.5Z mx postfix/smtpd[2]: QPRE: client=mta.example.net[192.0.2.10]:51652\n"+
		"2026-10-07T09:17:11.6Z mx postfix/smtpd[2]: Anonymous TLS connection established from mta.example.net[192.0.2.10]:51652 to mx.example.com: TLSv1.3\n"+
		// Without a Postfix TLS line the timing rule still applies.
		"2026-10-07T09:17:09.54Z mx postfix/smtpd[3]: connect from mta.example.net[192.0.2.10]:51653\n"+
		"2026-10-07T09:17:10.7Z mx postfix/smtpd[3]: QNOLOG: client=mta.example.net[192.0.2.10]:51653\n"+
		// Two handshakes in one session are contradictory.
		"2026-10-07T09:17:09.54Z mx postfix/smtpd[4]: connect from mta.example.net[192.0.2.10]:51654\n"+tls("4", "51654")+tls("4", "51654")+
		"2026-10-07T09:17:10.7Z mx postfix/smtpd[4]: QTWICE: client=mta.example.net[192.0.2.10]:51654\n"+
		// Postfix TLS on a connection tlsgate saw as plaintext is contradictory.
		"2026-10-07T09:17:09.54Z mx postfix/smtpd[5]: connect from mta.example.net[192.0.2.10]:51655\n"+tls("5", "51655")+
		"2026-10-07T09:17:10.7Z mx postfix/smtpd[5]: QPLAIN: client=mta.example.net[192.0.2.10]:51655\n")
	mustWrite(verdicts, `{"timestamp":"2026-10-07T09:17:11Z","instance":"mx","queue_id":"QFAST","classification":"ham","score":-1}`+"\n")
	s, err := runSMTPCorrelation(events, logs, verdicts, db, "mx", "127.0.0.1:25", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{
		"QFAST":  {"starttls", "matched"},
		"QPRE":   {"plaintext", "message_before_observed_starttls"},
		"QNOLOG": {"unknown", "incomplete_or_uncertain_tls_observation"},
		"QTWICE": {"unknown", "incomplete_or_uncertain_tls_observation"},
		"QPLAIN": {"unknown", "incomplete_or_uncertain_tls_observation"},
	}
	for _, r := range s.Records {
		if got := [2]string{r.Transport, r.Reason}; got != want[r.QueueID] {
			t.Errorf("%s: got %v, want %v", r.QueueID, got, want[r.QueueID])
		}
		delete(want, r.QueueID)
	}
	if len(want) != 0 {
		t.Fatalf("missing records %v", want)
	}
	if s.Matched != 1 || s.Ham != 1 || s.TLSMessages != 1 || s.PlaintextMessages != 1 {
		t.Fatalf("summary %#v", s)
	}
}
