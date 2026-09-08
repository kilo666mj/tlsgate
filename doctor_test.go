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

func TestDoctorUsesRuntimeSettingsFromConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	dbPath := filepath.Join(dir, "configured.db")
	data := []byte(`{
		"routes":[{"listen":"[::]:2443","backend":"127.0.0.1:1443","allow_unknown":true,"proxy_protocol":"v2"}],
		"database":"` + dbPath + `",
		"fingerprint":"ja4",
		"drain_timeout":"45m"
	}`)
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runDoctor([]string{"--config", configPath}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"database: " + dbPath,
		"fingerprint method: ja4",
		"drain timeout: 45m0s",
		"route: [::]:2443 -> 127.0.0.1:1443 (allow-unknown=true, proxy-v2=true)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q:\n%s", want, &out)
		}
	}
}

func TestDoctorCommandLineOverridesRuntimeConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(`{"fingerprint":"ja3","allow_unknown":true,"proxy_protocol":"v2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runDoctor([]string{
		"--config", configPath,
		"--fingerprint", "ja4",
		"--proxy-protocol", "off",
		"--route", "[::]:2993=127.0.0.1:10993,allow-unknown=false",
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"fingerprint method: ja4",
		"backend PROXY protocol: off",
		"route: [::]:2993 -> 127.0.0.1:10993 (allow-unknown=false, proxy-v2=false)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q:\n%s", want, &out)
		}
	}
}
