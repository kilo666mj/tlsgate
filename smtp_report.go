package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kilo666mj/gatekit/controlplane"
)

const (
	maxSMTPReportInput = 8 << 20
	maxSMTPReportBody  = 1 << 20
	maxSMTPReportItems = 256
)

type smtpReportEnvelope struct {
	SchemaVersion int         `json:"schema_version"`
	InstanceID    string      `json:"instance_id"`
	SMTPInstance  string      `json:"smtp_instance"`
	Listener      string      `json:"listener"`
	CoverageStart time.Time   `json:"coverage_start"`
	CoverageEnd   time.Time   `json:"coverage_end"`
	GeneratedAt   time.Time   `json:"generated_at"`
	ReplayID      string      `json:"replay_id"`
	Summary       smtpSummary `json:"summary"`
	Truncated     struct {
		Fingerprints int `json:"fingerprints"`
		Records      int `json:"records"`
	} `json:"truncated"`
}

func cmdReportSMTP(args []string) {
	fs := flag.NewFlagSet("report-smtp", flag.ExitOnError)
	configPath := fs.String("config", defaultConfig, "JSON config containing control_plane credentials")
	reportPath := fs.String("report", "", "correlate-smtp JSON report")
	smtpInstance := fs.String("smtp-instance", "", "SMTP event namespace")
	listener := fs.String("listener", "", "exact SMTP listener endpoint")
	coverageStart := fs.String("coverage-start", "", "inclusive RFC3339 window start")
	coverageEnd := fs.String("coverage-end", "", "inclusive RFC3339 window end")
	generatedAt := fs.String("generated-at", "", "RFC3339 report generation time")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || *reportPath == "" || *smtpInstance == "" || *listener == "" || *coverageStart == "" || *coverageEnd == "" || *generatedAt == "" {
		fatalf("report-smtp requires --report, --smtp-instance, --listener, --coverage-start, --coverage-end, and --generated-at")
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fatalf("load config: %v", err)
	}
	if !cfg.ControlPlane.Enabled() {
		fatalf("control plane is disabled")
	}
	report, err := readSMTPReport(*reportPath, cfg.ControlPlane, *smtpInstance, *listener, *coverageStart, *coverageEnd, *generatedAt)
	if err != nil {
		fatalf("load SMTP report: %v", err)
	}
	if err := uploadSMTPReport(context.Background(), cfg.ControlPlane, report, nil); err != nil {
		fatalf("upload SMTP report: %v", err)
	}
	fmt.Printf("uploaded SMTP report replay_id=%s listener=%s\n", report.ReplayID, report.Listener)
}

func readSMTPReport(path string, cfg controlplane.Config, smtpInstance, listener, start, end, generated string) (_ smtpReportEnvelope, err error) {
	if err := cfg.Validate(); err != nil {
		return smtpReportEnvelope{}, err
	}
	if strings.TrimSpace(smtpInstance) == "" {
		return smtpReportEnvelope{}, fmt.Errorf("smtp instance is required")
	}
	if _, _, err := net.SplitHostPort(listener); err != nil {
		return smtpReportEnvelope{}, fmt.Errorf("listener must be an exact IP:port endpoint: %w", err)
	}
	parse := func(name, value string) (time.Time, error) {
		t, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return time.Time{}, fmt.Errorf("%s: %w", name, err)
		}
		return t.UTC(), nil
	}
	coverageStart, err := parse("coverage start", start)
	if err != nil {
		return smtpReportEnvelope{}, err
	}
	coverageEnd, err := parse("coverage end", end)
	if err != nil {
		return smtpReportEnvelope{}, err
	}
	generatedAt, err := parse("generated at", generated)
	if err != nil {
		return smtpReportEnvelope{}, err
	}
	if coverageEnd.Before(coverageStart) || generatedAt.Before(coverageEnd) {
		return smtpReportEnvelope{}, fmt.Errorf("require coverage_start <= coverage_end <= generated_at")
	}
	f, err := os.Open(path)
	if err != nil {
		return smtpReportEnvelope{}, err
	}
	defer closeWithError(&err, "close SMTP report", f.Close)
	info, err := f.Stat()
	if err != nil {
		return smtpReportEnvelope{}, err
	}
	if !info.Mode().IsRegular() {
		return smtpReportEnvelope{}, fmt.Errorf("report is not a regular file")
	}
	if info.Size() > maxSMTPReportInput {
		return smtpReportEnvelope{}, fmt.Errorf("report is %d bytes (maximum %d)", info.Size(), maxSMTPReportInput)
	}
	var summary smtpSummary
	dec := json.NewDecoder(io.LimitReader(f, maxSMTPReportInput+1))
	if err := dec.Decode(&summary); err != nil {
		return smtpReportEnvelope{}, err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return smtpReportEnvelope{}, fmt.Errorf("report must contain one JSON value")
	}
	report := smtpReportEnvelope{SchemaVersion: 1, InstanceID: cfg.InstanceID, SMTPInstance: smtpInstance, Listener: listener, CoverageStart: coverageStart, CoverageEnd: coverageEnd, GeneratedAt: generatedAt, Summary: summary}
	if len(report.Summary.Fingerprints) > maxSMTPReportItems {
		report.Truncated.Fingerprints = len(report.Summary.Fingerprints) - maxSMTPReportItems
		report.Summary.Fingerprints = report.Summary.Fingerprints[:maxSMTPReportItems]
	}
	if len(report.Summary.Records) > maxSMTPReportItems {
		report.Truncated.Records = len(report.Summary.Records) - maxSMTPReportItems
		report.Summary.Records = report.Summary.Records[:maxSMTPReportItems]
	}
	canonical, err := json.Marshal(struct {
		Instance, Listener string
		Start, End         time.Time
		Summary            smtpSummary
		Truncated          struct {
			Fingerprints int `json:"fingerprints"`
			Records      int `json:"records"`
		}
	}{smtpInstance, listener, coverageStart, coverageEnd, report.Summary, report.Truncated})
	if err != nil {
		return smtpReportEnvelope{}, err
	}
	sum := sha256.Sum256(canonical)
	report.ReplayID = hex.EncodeToString(sum[:])
	body, err := json.Marshal(report)
	if err != nil {
		return smtpReportEnvelope{}, err
	}
	if len(body) > maxSMTPReportBody {
		return smtpReportEnvelope{}, fmt.Errorf("bounded report is %d bytes (maximum %d)", len(body), maxSMTPReportBody)
	}
	return report, nil
}

func uploadSMTPReport(ctx context.Context, cfg controlplane.Config, report smtpReportEnvelope, client *http.Client) (err error) {
	if err := cfg.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if len(body) > maxSMTPReportBody {
		return fmt.Errorf("report exceeds %d bytes", maxSMTPReportBody)
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/smtp/reports"
	q := u.Query()
	q.Set("instance_id", cfg.InstanceID)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	if client == nil {
		client, err = smtpReportHTTPClient(cfg)
		if err != nil {
			return err
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer closeWithError(&err, "close Gatehub SMTP report response", resp.Body.Close)
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("POST SMTP report returned %s (instance %q not registered with gatehub?)", resp.Status, cfg.InstanceID)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("POST SMTP report returned %s", resp.Status)
	}
	return nil
}

func smtpReportHTTPClient(cfg controlplane.Config) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.ServerName}
	if cfg.ClientCert != "" || cfg.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	if cfg.CA != "" {
		pem, err := os.ReadFile(cfg.CA)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no CA certificates found in %s", cfg.CA)
		}
		tlsConfig.RootCAs = roots
	}
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}, nil
}
