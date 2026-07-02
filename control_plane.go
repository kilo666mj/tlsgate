package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const defaultControlPlaneSyncInterval = 30 * time.Second

type ControlPlaneConfig struct {
	URL          string `json:"url"`
	InstanceID   string `json:"instance_id"`
	Token        string `json:"token"`
	ClientCert   string `json:"client_cert"`
	ClientKey    string `json:"client_key"`
	CA           string `json:"ca"`
	ServerName   string `json:"server_name"`
	SyncInterval string `json:"sync_interval"`
}

type controlPlaneObservation struct {
	Fingerprint string         `json:"fingerprint"`
	Status      Status         `json:"status"`
	Label       string         `json:"label,omitempty"`
	FirstSeen   string         `json:"first_seen,omitempty"`
	LastSeen    string         `json:"last_seen,omitempty"`
	IPs         []string       `json:"ips,omitempty"`
	Ports       []int          `json:"ports,omitempty"`
	Count       int            `json:"count,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type controlPlaneObservationBatch struct {
	InstanceID   string                    `json:"instance_id"`
	Observations []controlPlaneObservation `json:"observations"`
}

type controlPlanePolicyResponse struct {
	Cursor    string                 `json:"cursor"`
	Decisions []controlPlaneDecision `json:"decisions"`
}

type controlPlaneDecision struct {
	Fingerprint string `json:"fingerprint"`
	Status      Status `json:"status"`
	Label       string `json:"label,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

func startControlPlaneSync(store *Store, cfg ControlPlaneConfig) {
	if strings.TrimSpace(cfg.URL) == "" {
		return
	}
	if err := cfg.validate(); err != nil {
		log.Printf("gatehub sync disabled: %v", err)
		return
	}
	interval := cfg.interval()
	client, err := newControlPlaneHTTPClient(cfg)
	if err != nil {
		log.Printf("gatehub sync disabled: %v", err)
		return
	}
	s := &controlPlaneSyncer{store: store, cfg: cfg, client: client}
	log.Printf("gatehub sync enabled: instance=%s url=%s interval=%s", cfg.InstanceID, cfg.URL, interval)
	go s.run(interval)
}

type controlPlaneSyncer struct {
	store  *Store
	cfg    ControlPlaneConfig
	client *http.Client
	cursor string
}

func (s *controlPlaneSyncer) run(interval time.Duration) {
	s.syncOnce()
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		s.syncOnce()
	}
}

func (s *controlPlaneSyncer) syncOnce() {
	if err := s.pushObservations(); err != nil {
		log.Printf("gatehub observation sync: %v", err)
	}
	if err := s.pullPolicy(); err != nil {
		log.Printf("gatehub policy sync: %v", err)
	}
}

func (s *controlPlaneSyncer) pushObservations() error {
	entries, err := s.store.List()
	if err != nil {
		return err
	}
	batch := controlPlaneObservationBatch{InstanceID: s.cfg.InstanceID}
	for fp, entry := range entries {
		batch.Observations = append(batch.Observations, tlsObservation(fp, entry))
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	endpoint, err := controlPlaneURL(s.cfg.URL, "/v1/observations/batch", s.cfg.InstanceID, "")
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	s.setAuth(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("POST observations returned %s", resp.Status)
	}
	return nil
}

func (s *controlPlaneSyncer) pullPolicy() error {
	endpoint, err := controlPlaneURL(s.cfg.URL, "/v1/policy", s.cfg.InstanceID, s.cursor)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	s.setAuth(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("GET policy returned %s", resp.Status)
	}
	var policy controlPlanePolicyResponse
	if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
		return err
	}
	for _, decision := range policy.Decisions {
		if decision.Fingerprint == "" {
			continue
		}
		switch decision.Status {
		case StatusApproved, StatusBlocked, StatusPending:
		default:
			log.Printf("gatehub policy ignored invalid status %q for %s", decision.Status, decision.Fingerprint)
			continue
		}
		if err := s.store.UpsertStatus(decision.Fingerprint, decision.Status, decision.Label); err != nil {
			return fmt.Errorf("apply decision for %s: %w", decision.Fingerprint, err)
		}
	}
	if policy.Cursor != "" {
		s.cursor = policy.Cursor
	}
	return nil
}

func (s *controlPlaneSyncer) setAuth(req *http.Request) {
	if s.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	}
}

func tlsObservation(fp string, entry Entry) controlPlaneObservation {
	return controlPlaneObservation{
		Fingerprint: fp,
		Status:      entry.Status,
		Label:       entry.Label,
		FirstSeen:   entry.FirstSeen.UTC().Format(time.RFC3339Nano),
		LastSeen:    entry.LastSeen.UTC().Format(time.RFC3339Nano),
		IPs:         entry.IPs,
		Ports:       entry.Ports,
		Count:       entry.Count,
		Metadata: map[string]any{
			"ja3":                  entry.TLS.JA3,
			"ja4":                  entry.TLS.JA4,
			"sni":                  entry.TLS.SNI,
			"alpn":                 entry.TLS.ALPN,
			"supported_versions":   entry.TLS.SupportedVersions,
			"signature_algorithms": entry.TLS.SignatureAlgorithms,
		},
	}
}

func (cfg ControlPlaneConfig) validate() error {
	if cfg.InstanceID == "" {
		return fmt.Errorf("control_plane.instance_id is required")
	}
	if cfg.Token == "" && (cfg.ClientCert == "" || cfg.ClientKey == "" || cfg.CA == "") {
		return fmt.Errorf("control_plane.token or client_cert, client_key, and ca are required")
	}
	if _, err := url.ParseRequestURI(cfg.URL); err != nil {
		return fmt.Errorf("control_plane.url: %w", err)
	}
	if cfg.SyncInterval != "" {
		if _, err := time.ParseDuration(cfg.SyncInterval); err != nil {
			return fmt.Errorf("control_plane.sync_interval: %w", err)
		}
	}
	return nil
}

func (cfg ControlPlaneConfig) interval() time.Duration {
	if cfg.SyncInterval == "" {
		return defaultControlPlaneSyncInterval
	}
	d, err := time.ParseDuration(cfg.SyncInterval)
	if err != nil || d <= 0 {
		return defaultControlPlaneSyncInterval
	}
	return d
}

func newControlPlaneHTTPClient(cfg ControlPlaneConfig) (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: cfg.ServerName,
	}
	if cfg.ClientCert != "" || cfg.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	if cfg.CA != "" {
		caPEM, err := os.ReadFile(cfg.CA)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no CA certificates found in %s", cfg.CA)
		}
		tlsConfig.RootCAs = roots
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, nil
}

func controlPlaneURL(base, path, instanceID, since string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	q := u.Query()
	q.Set("instance_id", instanceID)
	if since != "" {
		q.Set("since", since)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
