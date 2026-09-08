package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kilo666mj/gatekit/controlplane"
)

func TestSMTPReportBoundedStableReplayAndUpload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	summary := smtpSummary{Messages: 300, Unmatched: 300}
	for i := 0; i < 300; i++ {
		summary.Fingerprints = append(summary.Fingerprints, fingerprintAggregate{JA4: strings.Repeat("a", 20), Unknown: 1})
		summary.Records = append(summary.Records, smtpCorrelation{QueueID: "q", Classification: "unknown", Reason: "no_verdict", MessageAt: "2026-09-08T00:00:00Z", Transport: "unknown"})
	}
	b, _ := json.Marshal(summary)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}

	var got smtpReportEnvelope
	var auth string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/base/v1/smtp/reports" || r.URL.Query().Get("instance_id") != "mail-tls" {
			t.Errorf("unexpected endpoint %s", r.URL.String())
		}
		auth = r.Header.Get("Authorization")
		if err := json.NewDecoder(io.LimitReader(r.Body, maxSMTPReportBody+1)).Decode(&got); err != nil {
			t.Error(err)
		}
		return &http.Response{StatusCode: http.StatusNoContent, Status: "204 No Content", Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	cfg := controlplane.Config{URL: "https://gatehub.example/base", InstanceID: "mail-tls", Token: "test-token"}
	report, err := readSMTPReport(path, cfg, "mx-public-smtp", "[::]:25", "2026-09-07T00:00:00Z", "2026-09-08T00:00:00Z", "2026-09-08T00:02:00Z")
	if err != nil {
		t.Fatal(err)
	}
	second, err := readSMTPReport(path, cfg, "mx-public-smtp", "[::]:25", "2026-09-07T00:00:00Z", "2026-09-08T00:00:00Z", "2026-09-08T00:03:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if report.ReplayID != second.ReplayID {
		t.Fatal("generation time changed replay identity")
	}
	if len(report.Summary.Records) != 256 || report.Truncated.Records != 44 || report.Truncated.Fingerprints != 44 {
		t.Fatalf("bounds: %+v", report.Truncated)
	}
	if err := uploadSMTPReport(t.Context(), cfg, report, client); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer test-token" || got.SMTPInstance != "mx-public-smtp" || got.Listener != "[::]:25" {
		t.Fatalf("uploaded identity/auth mismatch: auth=%q report=%+v", auth, got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSMTPReportRejectsInvalidWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := controlplane.Config{URL: "https://gatehub.example", InstanceID: "mail-tls", Token: "token"}
	_, err := readSMTPReport(path, cfg, "mx", "[::]:25", "2026-09-08T01:00:00Z", "2026-09-08T00:00:00Z", time.Now().UTC().Format(time.RFC3339Nano))
	if err == nil {
		t.Fatal("reversed coverage accepted")
	}
}
