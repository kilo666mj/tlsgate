package main

import (
	"encoding/json"
	"fmt"
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
	report, err := readSMTPReport(path, "", cfg, "mx-public-smtp", "[::]:25", "2026-09-07T00:00:00Z", "2026-09-08T00:00:00Z", "2026-09-08T00:02:00Z")
	if err != nil {
		t.Fatal(err)
	}
	second, err := readSMTPReport(path, "", cfg, "mx-public-smtp", "[::]:25", "2026-09-07T00:00:00Z", "2026-09-08T00:00:00Z", "2026-09-08T00:03:00Z")
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
	_, err := readSMTPReport(path, "", cfg, "mx", "[::]:25", "2026-09-08T01:00:00Z", "2026-09-08T00:00:00Z", time.Now().UTC().Format(time.RFC3339Nano))
	if err == nil {
		t.Fatal("reversed coverage accepted")
	}
}

func TestSMTPReportIncludesBoundedCampaignEvidence(t *testing.T) {
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")
	if err := os.WriteFile(summaryPath, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	campaignPath := filepath.Join(dir, "campaign.json")
	campaign := smtpCampaignReport{
		Schema: smtpCampaignReportSchema, Instance: "mx-public-smtp", Listener: "[::]:25",
		Signature:   pregreetSupportSignature,
		Signatures:  []string{pregreetSupportSignature, pregreetEHLOUserSignature},
		Connections: 300, EvidenceSessions: 300, Matched: 300,
	}
	for i := 0; i < 300; i++ {
		campaign.Records = append(campaign.Records, smtpCampaignRecord{
			Timestamp: time.Date(2026, 9, 8, 11, 0, i%60, 0, time.UTC),
			Client:    fmt.Sprintf("192.0.2.1:%d", 10000+i), ConnectionID: fmt.Sprintf("c%d", i),
			Signature: pregreetEHLOUserSignature, Reason: "matched",
		})
	}
	b, err := json.Marshal(campaign)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(campaignPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := controlplane.Config{URL: "https://gatehub.example", InstanceID: "mail-tls", Token: "token"}
	report, err := readSMTPReport(summaryPath, campaignPath, cfg, "mx-public-smtp", "[::]:25", "2026-09-07T00:00:00Z", "2026-09-08T00:00:00Z", "2026-09-08T00:02:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if report.Campaign == nil || len(report.Campaign.Records) != maxSMTPReportItems || report.Truncated.CampaignRecords != 44 {
		t.Fatalf("campaign bounds = campaign=%+v truncated=%+v", report.Campaign, report.Truncated)
	}
	second, err := readSMTPReport(summaryPath, campaignPath, cfg, "mx-public-smtp", "[::]:25", "2026-09-07T00:00:00Z", "2026-09-08T00:00:00Z", "2026-09-08T00:03:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if report.ReplayID != second.ReplayID {
		t.Fatal("campaign replay identity changed with generation time")
	}
	campaign.Listener = "[::]:587"
	b, _ = json.Marshal(campaign)
	if err := os.WriteFile(campaignPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSMTPReport(summaryPath, campaignPath, cfg, "mx-public-smtp", "[::]:25", "2026-09-07T00:00:00Z", "2026-09-08T00:00:00Z", "2026-09-08T00:02:00Z"); err == nil {
		t.Fatal("mismatched campaign listener accepted")
	}
}

func TestSMTPReportWireGolden(t *testing.T) {
	dir := t.TempDir()
	summaryPath := filepath.Join(dir, "summary.json")
	summary := smtpSummary{
		Messages: 2, Matched: 1, Unmatched: 1, Spam: 1, Connections: 2,
		STARTTLS: 1, NoObservedTLS: 1, TLSMessages: 1, PlaintextMessages: 1,
		Reasons:      []reasonCount{{Reason: "message_before_observed_starttls", Count: 1}},
		Fingerprints: []fingerprintAggregate{{JA4: "t13d1516h2_abc_def", Spam: 1}},
		Records: []smtpCorrelation{{
			QueueID: "Q1", Classification: "spam", JA3: "0123456789abcdef0123456789abcdef",
			JA4: "t13d1516h2_abc_def", Reason: "matched", ConnectionID: "c1",
			Client: "192.0.2.1:12345", Listener: "[::]:25", Action: "add header",
			VerdictAt: "2026-09-08T11:00:02Z", MessageAt: "2026-09-08T11:00:01Z",
			SessionStart: "2026-09-08T11:00:00Z", Symbols: []string{"BAYES_SPAM"},
			Score: 12.5, Transport: "starttls",
		}},
	}
	for i := 1; i < 258; i++ {
		summary.Records = append(summary.Records, smtpCorrelation{
			QueueID: fmt.Sprintf("Q%d", i+1), Classification: "unknown", Reason: "no_verdict",
			MessageAt: "2026-09-08T11:00:01Z", Transport: "unknown",
		})
	}
	encodedSummary, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(summaryPath, encodedSummary, 0600); err != nil {
		t.Fatal(err)
	}
	report, err := readSMTPReport(summaryPath, "", controlplane.Config{
		URL: "https://gatehub.example", InstanceID: "mail-tls", Token: "token",
	}, "mx-public-smtp", "[::]:25", "2026-09-07T12:00:00Z", "2026-09-08T11:58:00Z", "2026-09-08T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/smtp-report-wire.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(string(want)) {
		t.Fatalf("SMTP report wire format changed; update both Gatehub and the golden fixture\ngot replay_id=%s", report.ReplayID)
	}
}

func TestSMTPReportUploadRetriesTransientFailures(t *testing.T) {
	saved := smtpReportRetryDelays
	smtpReportRetryDelays = []time.Duration{0, 0, 0}
	t.Cleanup(func() { smtpReportRetryDelays = saved })
	cfg := controlplane.Config{URL: "https://gatehub.example", InstanceID: "mail-tls", Token: "token"}
	report := smtpReportEnvelope{ReplayID: strings.Repeat("a", 64)}
	respond := func(code int) (*http.Response, error) {
		return &http.Response{StatusCode: code, Status: fmt.Sprintf("%d %s", code, http.StatusText(code)), Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	}

	for _, tc := range []struct {
		name     string
		steps    []func() (*http.Response, error)
		attempts int
		wantErr  string
	}{
		{"timeout then success", []func() (*http.Response, error){
			func() (*http.Response, error) {
				return nil, fmt.Errorf("Client.Timeout exceeded while awaiting headers")
			},
			func() (*http.Response, error) { return respond(530) },
			func() (*http.Response, error) { return respond(http.StatusOK) },
		}, 3, ""},
		{"exhausted", []func() (*http.Response, error){
			func() (*http.Response, error) { return respond(http.StatusBadGateway) },
		}, 4, "after 4 attempts: POST SMTP report returned 502"},
		{"client error is not retried", []func() (*http.Response, error){
			func() (*http.Response, error) { return respond(http.StatusBadRequest) },
		}, 1, "POST SMTP report returned 400"},
		{"forbidden is not retried", []func() (*http.Response, error){
			func() (*http.Response, error) { return respond(http.StatusForbidden) },
		}, 1, "not registered with gatehub"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempts := 0
			var bodies []string
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				b, _ := io.ReadAll(r.Body)
				bodies = append(bodies, string(b))
				step := tc.steps[min(attempts, len(tc.steps)-1)]
				attempts++
				return step()
			})}
			err := uploadSMTPReport(t.Context(), cfg, report, client)
			if attempts != tc.attempts {
				t.Fatalf("attempts = %d, want %d", attempts, tc.attempts)
			}
			if tc.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
			for _, b := range bodies[1:] {
				if b != bodies[0] {
					t.Fatal("retry changed the request body")
				}
			}
		})
	}
}
