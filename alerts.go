package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

const defaultConfig = "/var/lib/tlsgate/config.json"

const (
	alertQueueSize   = 256
	alertWorkerCount = 4
)

type AppConfig struct {
	Mattermost  MattermostConfig   `json:"mattermost"`
	AlertRanges []AlertRangeConfig `json:"alert_ranges"`
}

type MattermostConfig struct {
	PrimaryURL   string `json:"primary_url"`
	SecondaryURL string `json:"secondary_url"`
	Channel      string `json:"channel"`
	IconURL      string `json:"icon_url"`
	Username     string `json:"username"`
}

type AlertRangeConfig struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

type blockedRange struct {
	name     string
	prefixes []netip.Prefix
}

type BlockedRangeAlerter struct {
	ranges  []blockedRange
	mm      MattermostConfig
	send    func(MattermostConfig, string) error
	queue   chan blockedRangeAlert
	mu      sync.Mutex
	pending map[string]struct{}
}

type blockedRangeAlert struct {
	store     *Store
	rangeName string
	ip        string
	fp        string
	message   string
}

type mattermostPayload struct {
	Username string `json:"username,omitempty"`
	Channel  string `json:"channel,omitempty"`
	Text     string `json:"text"`
	IconURL  string `json:"icon_url,omitempty"`
}

func loadConfig(path string) (AppConfig, error) {
	if path == "" {
		return AppConfig{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return AppConfig{}, nil
		}
		return AppConfig{}, err
	}
	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return AppConfig{}, err
	}
	return cfg, nil
}

func NewBlockedRangeAlerter(cfg AppConfig) (*BlockedRangeAlerter, error) {
	if len(cfg.AlertRanges) == 0 {
		return nil, nil
	}
	if cfg.Mattermost.PrimaryURL == "" {
		return nil, fmt.Errorf("mattermost primary_url is required when alert_ranges are configured")
	}
	a := &BlockedRangeAlerter{
		mm:      cfg.Mattermost,
		send:    sendMattermost,
		queue:   make(chan blockedRangeAlert, alertQueueSize),
		pending: make(map[string]struct{}),
	}
	for _, rangeCfg := range cfg.AlertRanges {
		if rangeCfg.Name == "" {
			return nil, fmt.Errorf("alert range missing name")
		}
		br := blockedRange{name: rangeCfg.Name}
		for _, cidr := range rangeCfg.CIDRs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("parse alert range %q CIDR %q: %w", rangeCfg.Name, cidr, err)
			}
			br.prefixes = append(br.prefixes, prefix)
		}
		if len(br.prefixes) == 0 {
			return nil, fmt.Errorf("alert range %q has no CIDRs", rangeCfg.Name)
		}
		a.ranges = append(a.ranges, br)
	}
	a.startWorkers(alertWorkerCount)
	return a, nil
}

func (a *BlockedRangeAlerter) AlertBlocked(store *Store, ip string, port int, fp string, meta TLSMetadata) {
	if a == nil {
		return
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	for _, r := range a.ranges {
		if !r.contains(addr) {
			continue
		}
		alreadySent, err := store.HasBlockedRangeAlert(r.name, ip)
		if err != nil {
			log.Printf("[%s:%d] blocked range alert dedupe error: %v", ip, port, err)
			continue
		}
		if alreadySent || !a.markPending(r.name, ip) {
			continue
		}
		alert := blockedRangeAlert{
			store:     store,
			rangeName: r.name,
			ip:        ip,
			fp:        fp,
			message:   blockedRangeMessage(r.name, ip, port, fp, meta),
		}
		select {
		case a.queue <- alert:
		default:
			a.clearPending(r.name, ip)
			log.Printf("[%s:%d] blocked range alert queue full, dropping alert", ip, port)
		}
	}
}

func (a *BlockedRangeAlerter) startWorkers(n int) {
	for range n {
		go func() {
			for alert := range a.queue {
				if err := a.send(a.mm, alert.message); err != nil {
					a.clearPending(alert.rangeName, alert.ip)
					log.Printf("[%s] blocked range alert send failed: %v", alert.ip, err)
					continue
				}
				if _, err := alert.store.RecordBlockedRangeAlert(alert.rangeName, alert.ip, alert.fp); err != nil {
					a.clearPending(alert.rangeName, alert.ip)
					log.Printf("[%s] blocked range alert dedupe record failed: %v", alert.ip, err)
					continue
				}
				a.clearPending(alert.rangeName, alert.ip)
			}
		}()
	}
}

func (a *BlockedRangeAlerter) markPending(rangeName, ip string) bool {
	key := rangeName + "\x00" + ip
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.pending[key]; ok {
		return false
	}
	a.pending[key] = struct{}{}
	return true
}

func (a *BlockedRangeAlerter) clearPending(rangeName, ip string) {
	key := rangeName + "\x00" + ip
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.pending, key)
}

func (r blockedRange) contains(addr netip.Addr) bool {
	for _, prefix := range r.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func blockedRangeMessage(rangeName, ip string, port int, fp string, meta TLSMetadata) string {
	fields := []string{
		fmt.Sprintf("range `%s`", rangeName),
		fmt.Sprintf("ip `%s`", ip),
		fmt.Sprintf("port `%d`", port),
		fmt.Sprintf("fp `%s`", fp),
	}
	if meta.SNI != "" {
		fields = append(fields, fmt.Sprintf("sni `%s`", sanitizeAlertField(meta.SNI)))
	}
	if meta.JA3 != "" {
		fields = append(fields, fmt.Sprintf("ja3 `%s`", sanitizeAlertField(meta.JA3)))
	}
	if meta.JA4 != "" {
		fields = append(fields, fmt.Sprintf("ja4 `%s`", sanitizeAlertField(meta.JA4)))
	}
	return ":warning: blocked TLS connection from known range: " + strings.Join(fields, " ")
}

func sendMattermost(cfg MattermostConfig, text string) error {
	if cfg.PrimaryURL == "" {
		return nil
	}
	username := cfg.Username
	if username == "" {
		username = "tlsgate"
	}
	payload := mattermostPayload{
		Username: username,
		Channel:  cfg.Channel,
		Text:     text,
		IconURL:  cfg.IconURL,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := postMattermost(cfg.PrimaryURL, body); err == nil {
		return nil
	} else if cfg.SecondaryURL == "" {
		return err
	}
	return postMattermost(cfg.SecondaryURL, body)
}

func postMattermost(url string, body []byte) error {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("mattermost webhook returned %s", resp.Status)
	}
	return nil
}
