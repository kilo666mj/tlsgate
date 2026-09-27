package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorReportsDefaultsWithoutCreatingDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "missing.db")
	configPath := filepath.Join(dir, "missing.json")
	var out bytes.Buffer
	err := runDoctor([]string{
		"--db", dbPath,
		"--config", configPath,
		"--route", "[::]:1993=127.0.0.1:10993",
		"--fingerprint", "ja4",
		"--proxy-protocol", "v2",
		"--allow-unknown",
	}, &out)
	if err != nil {
		t.Fatalf("runDoctor: %v", err)
	}
	for _, want := range []string{
		"database: " + dbPath + " (not created yet)",
		"config: " + configPath + " (absent; built-in defaults apply)",
		"fingerprint method: ja4",
		"backend PROXY protocol: v2",
		"unknown fingerprints: allowed as pending (enrollment mode)",
		"max fingerprints: 100000",
		"route: [::]:1993 -> 127.0.0.1:10993",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("doctor created database: %v", err)
	}
}

func TestDoctorRejectsInvalidAlertCIDR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{"notification_urls":["generic+https://example.com"],"alert_ranges":[{"name":"home","cidrs":["bad"]}]}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runDoctor([]string{"--config", path}, &out); err == nil {
		t.Fatal("runDoctor accepted invalid alert CIDR")
	}
}

func TestDoctorRejectsInvalidProxyProtocol(t *testing.T) {
	var out bytes.Buffer
	if err := runDoctor([]string{"--proxy-protocol", "v1"}, &out); err == nil {
		t.Fatal("runDoctor accepted invalid PROXY protocol")
	}
}

func TestDoctorUsesSMTPRuntimeConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	dbPath := filepath.Join(dir, "configured.db")
	data := []byte(`{"routes":[{"listen":"127.0.0.1:2525","backend":"127.0.0.1:10025","protocol":"smtp","proxy_protocol":"v2"}],"database":"` + dbPath + `","fingerprint":"ja4","drain_timeout":"45m","smtp_events":"` + filepath.Join(dir, "events.jsonl") + `","smtp_instance":"mx-public"}`)
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runDoctor([]string{"--config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"database: " + dbPath, "fingerprint method: ja4", "drain timeout: 45m0s", "SMTP events: " + filepath.Join(dir, "events.jsonl") + " (instance mx-public)", "protocol=smtp, observation-only, proxy-v2=true"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q:\n%s", want, &out)
		}
	}
}

func TestDoctorCLIOverridesSMTPRuntimeConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"routes":[{"listen":"127.0.0.1:2525","backend":"127.0.0.1:10025","protocol":"smtp"}],"smtp_events":"configured.jsonl","smtp_instance":"configured"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runDoctor([]string{"--config", configPath, "--smtp-events", "cli.jsonl", "--smtp-instance", "cli"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "SMTP events: cli.jsonl (instance cli)") {
		t.Fatalf("CLI override missing:\n%s", &out)
	}
}

func TestMailRouteHidesClient(t *testing.T) {
	for _, tc := range []struct {
		listen, backend string
		want            bool
	}{
		{"[::]:993", "127.0.0.1:10993", true},
		{"[::]:465", "127.0.0.1:10465", true},
		{"0.0.0.0:587", "[::1]:10587", true},
		{"[::]:995", "localhost:10995", true},
		{"[::]:993", "host.docker.internal:10993", true},
		{"[::]:993", "172.22.1.250:993", true},
		{"[::]:465", "[fd4d:6169:6c63:6f77::5]:465", true},
		{"[::]:465", "[::ffff:10.0.0.5]:465", true},
		{"[::]:993", "203.0.113.10:993", false},
		{"[::]:993", "mail.example.com:993", false},
		{"[::]:443", "127.0.0.1:8443", false},
		{"[::]:1993", "127.0.0.1:10993", false},
		{"[::]:25", "127.0.0.1:10025", false},
		{"bad", "127.0.0.1:10993", false},
		{"[::]:993", "bad", false},
	} {
		if got := mailRouteHidesClient(tc.listen, tc.backend); got != tc.want {
			t.Errorf("mailRouteHidesClient(%q, %q) = %t, want %t", tc.listen, tc.backend, got, tc.want)
		}
	}
}

func TestDoctorWarnsOnMailRouteWithoutProxyProtocol(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := []byte(`{"routes":[` +
		`{"listen":"[::]:993","backend":"127.0.0.1:10993"},` +
		`{"listen":"[::]:465","backend":"172.22.1.253:10465","proxy_protocol":"v2"},` +
		`{"listen":"[::]:25","backend":"172.22.1.253:10025","protocol":"smtp"}]}`)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runDoctor([]string{"--config", configPath, "--db", filepath.Join(dir, "db.sqlite")}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "warning: route [::]:993 -> 127.0.0.1:10993 forwards mail logins without PROXY protocol") {
		t.Errorf("missing warning for unproxied IMAPS route:\n%s", &out)
	}
	if n := strings.Count(out.String(), "warning:"); n != 1 {
		t.Errorf("got %d warnings, want 1 (PROXY v2 and SMTP observation routes must not warn):\n%s", n, &out)
	}
}

func TestDoctorGlobalProxyProtocolSilencesMailWarning(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor([]string{
		"--config", filepath.Join(t.TempDir(), "missing.json"),
		"--route", "[::]:993=127.0.0.1:10993",
		"--proxy-protocol", "v2",
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "warning:") {
		t.Errorf("unexpected warning with global PROXY v2:\n%s", &out)
	}
}
