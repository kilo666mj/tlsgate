package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/containrrr/shoutrrr"
	"github.com/containrrr/shoutrrr/pkg/types"
)

const defaultConfig = "/var/lib/tlsgate/config.json"

const (
	alertQueueSize   = 256
	alertWorkerCount = 4
)

type NotificationMode string

const (
	NotificationModeFailover  NotificationMode = "failover"
	NotificationModeBroadcast NotificationMode = "broadcast"
)

type AppConfig struct {
	NotificationURLs []string         `json:"notification_urls"`
	NotificationMode NotificationMode `json:"notification_mode"`
	// MaxFingerprints caps how many fingerprint entries are kept in the
	// store, bounding disk growth from unauthenticated unknown clients.
	// 0 means unlimited. Approved entries are never evicted; the oldest
	// non-approved (pending/blocked) entries are pruned first.
	MaxFingerprints int                `json:"max_fingerprints"`
	AlertRanges     []AlertRangeConfig `json:"alert_ranges"`
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
	send    func(string) error
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
	if cfg.MaxFingerprints < 0 {
		return AppConfig{}, fmt.Errorf("max_fingerprints must be >= 0, got %d", cfg.MaxFingerprints)
	}
	if cfg.NotificationMode == "" {
		cfg.NotificationMode = NotificationModeFailover
	}
	if cfg.NotificationMode != NotificationModeFailover && cfg.NotificationMode != NotificationModeBroadcast {
		return AppConfig{}, fmt.Errorf("notification_mode must be %q or %q, got %q", NotificationModeFailover, NotificationModeBroadcast, cfg.NotificationMode)
	}
	// Notification URLs carry alert content and webhook tokens, so require
	// TLS: reject any URL that would deliver them in cleartext.
	for _, rawURL := range cfg.NotificationURLs {
		if err := requireSecureNotificationURL(rawURL); err != nil {
			return AppConfig{}, err
		}
	}
	return cfg, nil
}

// requireSecureNotificationURL rejects Shoutrrr notification URLs that would
// deliver alert content and webhook tokens over cleartext. Shoutrrr opts into
// plaintext either via a "+http" scheme suffix (e.g. generic+http://) or a
// disabletls query parameter, so reject both.
func requireSecureNotificationURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse notification_urls entry: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "http" || strings.HasSuffix(scheme, "+http") {
		return fmt.Errorf("notification URL %s://%s uses cleartext transport; use an https/+https service URL", scheme, u.Host)
	}
	// Shoutrrr matches query keys case-insensitively, so normalize before
	// looking for a disabletls override.
	for key, vals := range u.Query() {
		if strings.ToLower(key) != "disabletls" {
			continue
		}
		for _, v := range vals {
			switch strings.ToLower(v) {
			case "yes", "true", "1", "on":
				return fmt.Errorf("notification URL %s://%s sets disabletls; remove it so alerts stay encrypted", scheme, u.Host)
			}
		}
	}
	return nil
}

func NewBlockedRangeAlerter(cfg AppConfig) (*BlockedRangeAlerter, error) {
	if len(cfg.AlertRanges) == 0 {
		return nil, nil
	}
	if cfg.NotificationMode == "" {
		cfg.NotificationMode = NotificationModeFailover
	}
	if len(cfg.NotificationURLs) == 0 {
		return nil, fmt.Errorf("notification_urls is required when alert_ranges are configured")
	}
	send, err := newNotificationSender(cfg.NotificationURLs, cfg.NotificationMode)
	if err != nil {
		return nil, fmt.Errorf("initialize notification sender: %w", err)
	}
	a := &BlockedRangeAlerter{
		send:    send,
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
				if err := a.send(alert.message); err != nil {
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

func newNotificationSender(urls []string, mode NotificationMode) (func(string) error, error) {
	switch mode {
	case NotificationModeFailover:
		senders := make([]func(string, *types.Params) []error, 0, len(urls))
		for _, rawURL := range urls {
			sender, err := shoutrrr.CreateSender(rawURL)
			if err != nil {
				return nil, err
			}
			senders = append(senders, sender.Send)
		}
		return sendShoutrrrFailover(senders), nil
	case NotificationModeBroadcast:
		sender, err := shoutrrr.CreateSender(urls...)
		if err != nil {
			return nil, err
		}
		return sendShoutrrrBroadcast(sender.Send), nil
	default:
		return nil, fmt.Errorf("unknown notification mode %q", mode)
	}
}

func sendShoutrrrFailover(senders []func(string, *types.Params) []error) func(string) error {
	return func(text string) error {
		var parts []string
		for _, send := range senders {
			errs := send(text, nil)
			err := shoutrrrErrors(errs)
			if err == nil {
				return nil
			}
			parts = append(parts, err.Error())
		}
		return fmt.Errorf("notification send failed: %s", strings.Join(parts, "; "))
	}
}

func sendShoutrrrBroadcast(send func(string, *types.Params) []error) func(string) error {
	return func(text string) error {
		if err := shoutrrrErrors(send(text, nil)); err != nil {
			return fmt.Errorf("notification send failed: %w", err)
		}
		return nil
	}
}

func shoutrrrErrors(errs []error) error {
	var parts []string
	for _, err := range errs {
		if err != nil {
			parts = append(parts, err.Error())
		}
	}
	if len(parts) > 0 {
		return fmt.Errorf("%s", strings.Join(parts, "; "))
	}
	return nil
}
