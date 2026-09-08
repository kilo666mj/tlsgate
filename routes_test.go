package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRoutePolicyOverrides(t *testing.T) {
	for _, tc := range []struct {
		options                                        string
		globalAllow, globalProxy, wantBlock, wantProxy bool
	}{
		{"", false, false, true, false},
		{"", true, true, false, true},
		{",allow-unknown=true,proxy-protocol=v2", false, false, false, true},
		{",allow-unknown=false,proxy-protocol=off", true, true, true, false},
		{",allow-unknown=false", true, true, true, true},
		{",proxy-protocol=off", true, true, false, false},
	} {
		t.Run(tc.options, func(t *testing.T) {
			var routes routeConfigs
			if err := routes.Set("[::]:443=127.0.0.1:1443" + tc.options); err != nil {
				t.Fatal(err)
			}
			proxy := "off"
			if tc.globalProxy {
				proxy = "v2"
			}
			block, sendProxy := routes[0].policy(tc.globalAllow, proxy)
			if block != tc.wantBlock || sendProxy != tc.wantProxy {
				t.Fatalf("policy = %t, %t", block, sendProxy)
			}
			var roundtrip routeConfigs
			if err := roundtrip.Set(routes.String()); err != nil {
				t.Fatal(err)
			}
			if b, p := roundtrip[0].policy(tc.globalAllow, proxy); b != block || p != sendProxy {
				t.Fatal("round-trip changed policy")
			}
		})
	}
}

func TestRouteRejectsInvalidOptionsWithoutMutation(t *testing.T) {
	for _, suffix := range []string{",", ",allow-unknown", ",allow-unknown=1", ",proxy-protocol=v1", ",alow-unknown=true", ",allow-unknown=true,allow-unknown=false", ",proxy-protocol=off,proxy-protocol=v2"} {
		var routes routeConfigs
		if err := routes.Set("[::]:443=127.0.0.1:1443" + suffix); err == nil || len(routes) != 0 {
			t.Fatalf("accepted %q or mutated routes", suffix)
		}
	}
	var routes routeConfigs
	if err := routes.Set("[::]:443=127.0.0.1:1443"); err != nil {
		t.Fatal(err)
	}
	if err := routes.Set("[::]:443=127.0.0.1:2443"); err == nil {
		t.Fatal("accepted duplicate listener")
	}
}

func TestDoctorReportsEffectiveRoutePolicy(t *testing.T) {
	var out bytes.Buffer
	err := runDoctor([]string{"--config", filepath.Join(t.TempDir(), "absent"), "--db", filepath.Join(t.TempDir(), "absent"),
		"--route", "[::]:993=127.0.0.1:10993,allow-unknown=false,proxy-protocol=off",
		"--route", "[::]:443=127.0.0.1:1443", "--allow-unknown", "--proxy-protocol", "v2"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"10993 (allow-unknown=false, proxy-v2=false)", "1443 (allow-unknown=true, proxy-v2=true)"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q: %s", want, &out)
		}
	}
}

// Run the real CLI in a child so this test covers parsing, listener closures,
// shared-store decisions, and bytes sent to each backend together.
func TestRouteServeProcess(t *testing.T) {
	if raw := os.Getenv("TLSGATE_TEST_ROUTE_ARGS"); raw != "" {
		var args []string
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			t.Fatal(err)
		}
		cmdServe(args)
		return
	}
	hello := captureClientHello(t)
	fp, _, err := extractTLSMetadata(hello, MethodJA4)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	db := filepath.Join(dir, "db.sqlite")
	var addresses []string
	var backends []net.Listener
	args := []string{"--db", db, "--config", filepath.Join(dir, "absent"), "--fingerprint", "ja4"}
	for i := range 2 {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		backends = append(backends, ln)
		t.Cleanup(func() { _ = ln.Close() })
		front, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addresses = append(addresses, front.Addr().String())
		_ = front.Close()
		route := addresses[i] + "=" + ln.Addr().String()
		if i == 1 {
			route += ",allow-unknown=true,proxy-protocol=v2"
		}
		args = append(args, "--route", route)
	}
	raw, _ := json.Marshal(args)
	cmd := exec.Command(os.Args[0], "-test.run=^TestRouteServeProcess$")
	cmd.Env = append(os.Environ(), "TLSGATE_TEST_ROUTE_ARGS="+string(raw))
	logfile, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logfile.Close() }()
	cmd.Stdout, cmd.Stderr = logfile, logfile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp4", addresses[1], 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			data, _ := os.ReadFile(logfile.Name())
			t.Fatalf("server not ready: %s", data)
		}
		time.Sleep(10 * time.Millisecond)
	}
	st, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	check := func(index int, allowed bool) {
		t.Helper()
		conn, err := net.DialTimeout("tcp4", addresses[index], time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(hello); err != nil {
			t.Fatal(err)
		}
		if !allowed {
			var b [1]byte
			if _, err := conn.Read(b[:]); err == nil {
				t.Fatal("blocked connection returned data")
			} else if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				t.Fatal("blocked connection stayed open")
			}
			return
		}
		_ = backends[index].(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
		backend, err := backends[index].Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = backend.Close() }()
		_ = backend.SetDeadline(time.Now().Add(2 * time.Second))
		offset := 0
		if index == 1 {
			offset = 28
		}
		got := make([]byte, offset+len(hello))
		if _, err := io.ReadFull(backend, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got[offset:], hello) {
			t.Fatal("backend TLS bytes changed")
		}
		if offset != 0 && !bytes.Equal(got[:12], proxyV2Signature[:]) {
			t.Fatal("missing PROXY v2")
		}
	}
	check(1, true) // Observe first: a shared pending entry must still be blocked on mail.
	check(0, false)
	if err := st.UpsertStatus(fp, StatusApproved, "test"); err != nil {
		t.Fatal(err)
	}
	check(0, true) // Mail forwards the original hello with no PROXY header.
	check(1, true)
	if err := st.UpsertStatus(fp, StatusBlocked, "test"); err != nil {
		t.Fatal(err)
	}
	check(1, false) // Enrollment must not override an explicit block.
	check(0, false)
}
