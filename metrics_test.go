package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

type fixedLimiter bool

func (l fixedLimiter) Allow(string) bool { return bool(l) }

func TestTrafficMetricsPerListener(t *testing.T) {
	m := newTrafficMetrics()
	g := newRouteGuard("[::]:443", 1, m)
	if !g.acquire() {
		t.Fatal("first route slot rejected")
	}
	if g.acquire() {
		t.Fatal("route capacity accepted a second connection")
	}
	l := &observedLimiter{limiter: fixedLimiter(false), metric: g.metric}
	if l.Allow("192.0.2.1") {
		t.Fatal("limiter allowed connection")
	}
	m.incGlobalOverload()

	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{
		`tlsgate_connections_active{listener="[::]:443",port="443"} 1`,
		`tlsgate_connections_total{listener="[::]:443",port="443"} 1`,
		`tlsgate_rate_limited_total{listener="[::]:443",port="443"} 1`,
		`tlsgate_overload_total{scope="global",listener=""} 1`,
		`tlsgate_overload_total{scope="route",listener="[::]:443",port="443"} 1`,
		`tlsgate_route_max_concurrent{listener="[::]:443",port="443"} 1`,
	} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Errorf("metrics missing %q:\n%s", want, rr.Body.String())
		}
	}
	g.release()
}
