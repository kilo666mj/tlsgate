package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoadConfigAndAlertRangeParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{
		"mattermost": {"primary_url": "https://matter.example/hook", "channel": "#mail"},
		"alert_ranges": [{"name": "test-range", "cidrs": ["192.0.2.0/24", "2001:db8::/32"]}]
	}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	alerter, err := NewBlockedRangeAlerter(cfg)
	if err != nil {
		t.Fatalf("NewBlockedRangeAlerter: %v", err)
	}
	if alerter == nil || len(alerter.ranges) != 1 {
		t.Fatalf("alerter ranges = %+v, want one range", alerter)
	}
}

func TestBlockedRangeAlerterDedupesByRangeAndIP(t *testing.T) {
	store := newTestStore(t)
	alerter := newTestAlerter(t, "scanner-net", "192.0.2.0/24")
	messages := make(chan string, 4)
	alerter.send = func(_ MattermostConfig, text string) error {
		messages <- text
		return nil
	}

	meta := TLSMetadata{SNI: "webmail.example.com", JA3: "771,4865,0-23,29,0"}
	alerter.AlertBlocked(store, "192.0.2.10", 993, "fp1", meta)
	alerter.AlertBlocked(store, "192.0.2.10", 993, "fp2", meta)
	alerter.AlertBlocked(store, "198.51.100.10", 993, "fp3", meta)

	var msg string
	select {
	case msg = <-messages:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for alert message")
	}
	select {
	case extra := <-messages:
		t.Fatalf("unexpected duplicate message: %q", extra)
	case <-time.After(50 * time.Millisecond):
	}
	for _, want := range []string{"scanner-net", "192.0.2.10", "fp1", "webmail.example.com"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q missing %q", msg, want)
		}
	}
}

func TestBlockedRangeAlerterRetriesAfterSendFailure(t *testing.T) {
	store := newTestStore(t)
	alerter := newTestAlerter(t, "scanner-net", "192.0.2.0/24")
	var attempts atomic.Int32
	alerter.send = func(_ MattermostConfig, _ string) error {
		if attempts.Add(1) == 1 {
			return errors.New("mattermost down")
		}
		return nil
	}

	alerter.AlertBlocked(store, "192.0.2.10", 993, "fp1", TLSMetadata{})
	waitFor(t, func() bool { return attempts.Load() == 1 })
	alerter.AlertBlocked(store, "192.0.2.10", 993, "fp1", TLSMetadata{})
	waitFor(t, func() bool { return attempts.Load() == 2 })
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
}

func newTestAlerter(t *testing.T, name string, cidrs ...string) *BlockedRangeAlerter {
	t.Helper()
	alerter, err := NewBlockedRangeAlerter(AppConfig{
		Mattermost: MattermostConfig{PrimaryURL: "https://matter.example/hook"},
		AlertRanges: []AlertRangeConfig{{
			Name:  name,
			CIDRs: cidrs,
		}},
	})
	if err != nil {
		t.Fatalf("NewBlockedRangeAlerter: %v", err)
	}
	return alerter
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}
