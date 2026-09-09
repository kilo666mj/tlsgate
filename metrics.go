package main

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type connectionLimiter interface {
	Allow(string) bool
}

type routeMetrics struct {
	active          atomic.Int64
	total           atomic.Uint64
	rateLimited     atomic.Uint64
	overloaded      atomic.Uint64
	backendFailures atomic.Uint64
	port            string
	maxConcurrent   int
}

type trafficMetrics struct {
	mu             sync.RWMutex
	routes         map[string]*routeMetrics
	globalOverload atomic.Uint64
}

func newTrafficMetrics() *trafficMetrics {
	return &trafficMetrics{routes: make(map[string]*routeMetrics)}
}

func (m *trafficMetrics) route(name string, maxConcurrent int) *routeMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	if metric := m.routes[name]; metric != nil {
		return metric
	}
	_, port, _ := net.SplitHostPort(name)
	metric := &routeMetrics{maxConcurrent: maxConcurrent, port: port}
	m.routes[name] = metric
	return metric
}

func (m *trafficMetrics) incGlobalOverload() { m.globalOverload.Add(1) }

func metricLabel(value string) string {
	return strconv.Quote(value)
}

func (m *trafficMetrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	m.mu.RLock()
	names := make([]string, 0, len(m.routes))
	for name := range m.routes {
		names = append(names, name)
	}
	sort.Strings(names)
	routes := make([]*routeMetrics, len(names))
	for i, name := range names {
		routes[i] = m.routes[name]
	}
	m.mu.RUnlock()

	var b strings.Builder
	fmt.Fprintln(&b, "# HELP tlsgate_connections_active Connections currently handled by TLSGate.")
	fmt.Fprintln(&b, "# TYPE tlsgate_connections_active gauge")
	for i, name := range names {
		fmt.Fprintf(&b, "tlsgate_connections_active{listener=%s,port=%s} %d\n", metricLabel(name), metricLabel(routes[i].port), routes[i].active.Load())
	}
	fmt.Fprintln(&b, "# HELP tlsgate_connections_total Connections admitted by the global and route capacity guards.")
	fmt.Fprintln(&b, "# TYPE tlsgate_connections_total counter")
	for i, name := range names {
		fmt.Fprintf(&b, "tlsgate_connections_total{listener=%s,port=%s} %d\n", metricLabel(name), metricLabel(routes[i].port), routes[i].total.Load())
	}
	fmt.Fprintln(&b, "# HELP tlsgate_rate_limited_total Connections rejected by the per-source-IP rate limit.")
	fmt.Fprintln(&b, "# TYPE tlsgate_rate_limited_total counter")
	for i, name := range names {
		fmt.Fprintf(&b, "tlsgate_rate_limited_total{listener=%s,port=%s} %d\n", metricLabel(name), metricLabel(routes[i].port), routes[i].rateLimited.Load())
	}
	fmt.Fprintln(&b, "# HELP tlsgate_overload_total Connections rejected because a capacity limit was full.")
	fmt.Fprintln(&b, "# TYPE tlsgate_overload_total counter")
	fmt.Fprintf(&b, "tlsgate_overload_total{scope=\"global\",listener=\"\"} %d\n", m.globalOverload.Load())
	for i, name := range names {
		fmt.Fprintf(&b, "tlsgate_overload_total{scope=\"route\",listener=%s,port=%s} %d\n", metricLabel(name), metricLabel(routes[i].port), routes[i].overloaded.Load())
	}
	fmt.Fprintln(&b, "# HELP tlsgate_route_max_concurrent Configured per-route concurrent connection limit; zero means only the global limit applies.")
	fmt.Fprintln(&b, "# TYPE tlsgate_route_max_concurrent gauge")
	for i, name := range names {
		fmt.Fprintf(&b, "tlsgate_route_max_concurrent{listener=%s,port=%s} %d\n", metricLabel(name), metricLabel(routes[i].port), routes[i].maxConcurrent)
	}
	fmt.Fprintln(&b, "# HELP tlsgate_backend_connection_failures_total Backend TCP connection attempts that failed.")
	fmt.Fprintln(&b, "# TYPE tlsgate_backend_connection_failures_total counter")
	for i, name := range names {
		fmt.Fprintf(&b, "tlsgate_backend_connection_failures_total{listener=%s,port=%s} %d\n", metricLabel(name), metricLabel(routes[i].port), routes[i].backendFailures.Load())
	}
	_, _ = w.Write([]byte(b.String()))
}

type observedLimiter struct {
	limiter connectionLimiter
	metric  *routeMetrics
}

func (l *observedLimiter) Allow(ip string) bool {
	allowed := l.limiter.Allow(ip)
	if !allowed {
		l.metric.rateLimited.Add(1)
	}
	return allowed
}

func (l *observedLimiter) BackendFailure() { l.metric.backendFailures.Add(1) }

func recordBackendFailure(limiter connectionLimiter) {
	if observer, ok := limiter.(interface{ BackendFailure() }); ok {
		observer.BackendFailure()
	}
}

type routeGuard struct {
	sem    chan struct{}
	metric *routeMetrics
}

func newRouteGuard(name string, maxConcurrent int, metrics *trafficMetrics) *routeGuard {
	g := &routeGuard{metric: metrics.route(name, maxConcurrent)}
	if maxConcurrent > 0 {
		g.sem = make(chan struct{}, maxConcurrent)
	}
	return g
}

func (g *routeGuard) acquire() bool {
	if g.sem != nil {
		select {
		case g.sem <- struct{}{}:
		default:
			g.metric.overloaded.Add(1)
			return false
		}
	}
	g.metric.total.Add(1)
	g.metric.active.Add(1)
	return true
}

func (g *routeGuard) release() {
	g.metric.active.Add(-1)
	if g.sem != nil {
		<-g.sem
	}
}
