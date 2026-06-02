package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containrrr/shoutrrr/pkg/types"
)

func TestLoadConfigAndAlertRangeParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{
		"notification_urls": ["logger://"],
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

func TestLoadConfigRejectsCleartextNotificationURLs(t *testing.T) {
	for _, rawURL := range []string{
		"generic+http://siem.internal/hook",
		"generic://siem.internal/hook?disabletls=yes",
		"gotify://gotify.internal/token?disableTLS=true",
	} {
		path := filepath.Join(t.TempDir(), "config.json")
		data := `{
			"notification_urls": ["` + rawURL + `"],
			"alert_ranges": [{"name": "test-range", "cidrs": ["192.0.2.0/24"]}]
		}`
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Fatalf("loadConfig accepted cleartext URL %q, want error", rawURL)
		}
	}
}

func TestLoadConfigAllowsSecureNotificationURLs(t *testing.T) {
	for _, rawURL := range []string{
		"logger://",
		"generic+https://siem.internal/hook",
		"mattermost://tlsgate@matter.example/token/channel",
		"slack://tlsgate@token-a/token-b/token-c",
	} {
		path := filepath.Join(t.TempDir(), "config.json")
		data := `{
			"notification_urls": ["` + rawURL + `"],
			"alert_ranges": [{"name": "test-range", "cidrs": ["192.0.2.0/24"]}]
		}`
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		if _, err := loadConfig(path); err != nil {
			t.Fatalf("loadConfig rejected secure URL %q: %v", rawURL, err)
		}
	}
}

func TestBlockedRangeAlerterDedupesByRangeAndIP(t *testing.T) {
	store := newTestStore(t)
	alerter := newTestAlerter(t, "scanner-net", "192.0.2.0/24")
	messages := make(chan string, 4)
	alerter.send = func(text string) error {
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
	alerter.send = func(_ string) error {
		if attempts.Add(1) == 1 {
			return errors.New("notifications down")
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

func TestShoutrrrFailoverStopsAfterSuccess(t *testing.T) {
	var primaryCalls, secondaryCalls atomic.Int32
	send := sendShoutrrrFailover([]func(string, *types.Params) []error{
		func(_ string, _ *types.Params) []error {
			primaryCalls.Add(1)
			return []error{errors.New("primary down")}
		},
		func(_ string, _ *types.Params) []error {
			secondaryCalls.Add(1)
			return []error{nil}
		},
		func(_ string, _ *types.Params) []error {
			t.Fatal("third sender should not be called after successful failover")
			return nil
		},
	})

	if err := send("test"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if primaryCalls.Load() != 1 || secondaryCalls.Load() != 1 {
		t.Fatalf("calls primary=%d secondary=%d, want 1/1", primaryCalls.Load(), secondaryCalls.Load())
	}
}

func TestShoutrrrFailoverFailsAfterAllSendersFail(t *testing.T) {
	send := sendShoutrrrFailover([]func(string, *types.Params) []error{
		func(_ string, _ *types.Params) []error { return []error{errors.New("primary down")} },
		func(_ string, _ *types.Params) []error { return []error{errors.New("secondary down")} },
	})

	err := send("test")
	if err == nil {
		t.Fatal("send succeeded, want failure")
	}
	for _, want := range []string{"primary down", "secondary down"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

func TestShoutrrrBroadcastRequiresAllSenders(t *testing.T) {
	send := sendShoutrrrBroadcast(func(_ string, _ *types.Params) []error {
		return []error{nil, errors.New("secondary down")}
	})

	err := send("test")
	if err == nil {
		t.Fatal("send succeeded, want failure")
	}
	if !strings.Contains(err.Error(), "secondary down") {
		t.Fatalf("error %q missing secondary failure", err)
	}
}

func newTestAlerter(t *testing.T, name string, cidrs ...string) *BlockedRangeAlerter {
	t.Helper()
	alerter, err := NewBlockedRangeAlerter(AppConfig{
		NotificationURLs: []string{"logger://"},
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
