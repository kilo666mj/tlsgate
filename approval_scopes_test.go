package main

import (
	"bytes"
	"github.com/kilo666mj/gatekit/approval"
	"github.com/kilo666mj/gatekit/store"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

func TestApprovalScopeForwardingAndShadow(t *testing.T) {
	for _, tc := range []struct {
		name, address                    string
		strict, trusted, shadow, forward bool
		tag                              string
	}{
		{"inside IPv4", "192.0.2.10", true, false, false, true, "APPROVED"},
		{"outside strict", "198.51.100.10", true, false, false, false, "BLOCKED out_of_scope"},
		{"outside observe", "198.51.100.10", false, false, false, false, "BLOCKED out_of_scope"},
		{"outside shadow", "198.51.100.10", true, false, true, true, "would_block_out_of_scope"},
		{"trusted bypass", "198.51.100.10", true, true, false, true, "WHITELIST"},
		{"inside IPv6", "2001:db8:1::10", true, false, false, true, "APPROVED"},
		{"outside IPv6", "2001:db8:2::10", true, false, false, false, "BLOCKED out_of_scope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			defer func() {
				if err := st.Close(); err != nil {
					t.Error(err)
				}
			}()
			hello := captureClientHello(t)
			fp, _, err := extractTLSMetadata(hello, MethodJA4)
			if err != nil {
				t.Fatal(err)
			}
			scope, err := approval.New([]string{"192.0.2.0/24", "2001:db8:1::/64"})
			if err != nil {
				t.Fatal(err)
			}
			if err := st.ApplyDecisions([]store.Decision{{Fingerprint: fp, Status: StatusApproved, ApprovalRanges: scope}}, "", ""); err != nil {
				t.Fatal(err)
			}
			backend, got := backendRecorder(t)
			client, peer := net.Pipe()
			defer func() { _ = peer.Close() }()
			allow := &ipAllowlist{}
			if tc.trusted {
				allow, err = newIPAllowlist([]string{"198.51.100.0/24"})
				if err != nil {
					t.Fatal(err)
				}
			}
			var logs bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&logs)
			defer log.SetOutput(previous)
			done := make(chan struct{})
			go func() {
				defer close(done)
				handleConnWithScope(addressedConn{client, &net.TCPAddr{IP: net.ParseIP(tc.address), Port: 54321}}, backend, 993, st, tc.strict, MethodJA4, nil, nil, allow, false, tc.shadow)
			}()
			go func() { _, _ = peer.Write(hello) }()
			if tc.forward {
				select {
				case <-got:
				case <-time.After(2 * time.Second):
					t.Fatal("not forwarded")
				}
				_ = peer.Close()
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("connection stalled")
			}
			if !tc.forward {
				expectNoBackend(t, got)
			}
			if !strings.Contains(logs.String(), tc.tag) {
				t.Fatalf("missing %s: %s", tc.tag, logs.String())
			}
			e, err := st.Get(fp)
			if err != nil || e.Status != StatusApproved || e.ApprovalRanges == nil {
				t.Fatalf("connection changed policy: %+v %v", e, err)
			}
		})
	}
}
func TestExplicitScopedApprovalPreservesLabel(t *testing.T) {
	st := newTestStore(t)
	defer func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := st.Observe(store.Observation{Fingerprint: "one"}, true); err != nil {
		t.Fatal(err)
	}
	if err := st.SetLabel("one", "client"); err != nil {
		t.Fatal(err)
	}
	if err := approveWithScope(st, "one", "", "192.0.2.0/24", false, false); err != nil {
		t.Fatal(err)
	}
	if err := st.SetStatus("one", StatusApproved); err == nil {
		t.Fatal("implicit scope removal")
	}
	e, err := st.Get("one")
	if err != nil || e.Label != "client" || e.ApprovalRanges == nil {
		t.Fatalf("%+v %v", e, err)
	}
	if err := approveWithScope(st, "one", "", "", true, false); err != nil {
		t.Fatal(err)
	}
	e, err = st.Get("one")
	if err != nil || e.ApprovalRanges != nil {
		t.Fatalf("explicit removal failed %+v %v", e, err)
	}
}
