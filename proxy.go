package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kilo666mj/gatekit/controlplane"
	"github.com/kilo666mj/gatekit/lifecycle"
	gateproxy "github.com/kilo666mj/gatekit/proxy"
	"github.com/kilo666mj/gatekit/ratelimit"
	"github.com/kilo666mj/gatekit/sdnotify"
	"github.com/kilo666mj/gatekit/store"
)

const recordTypeHandshake = 0x16

const maxTLSRecordBody = 18 * 1024

// maxClientHello bounds the total reassembled ClientHello handshake message
// across TLS records. Large (e.g. post-quantum) hellos legitimately span
// several records; this caps how much we will buffer before giving up.
const maxClientHello = 64 * 1024

// idleTimeout bounds inactivity on a proxied connection once the
// handshake has been inspected and forwarded. Set above the IMAP IDLE
// re-issue cycle (~29min per RFC 2177, observed ~31min) so long-lived
// IDLE sessions are not severed mid-wait.
const idleTimeout = 35 * time.Minute

// Per-source-IP connection rate limit. Generous enough that legitimate
// clients (including many devices behind a single NAT address) never hit
// it, while throttling a flood of randomized ClientHellos that would
// otherwise grow the fingerprint store unbounded. rateLimitTTL must be
// >= connBurstPerIP/connRatePerIP so idle eviction only drops full buckets.
const (
	connRatePerIP   = 1.0 // tokens (connections) per second, sustained
	connBurstPerIP  = 120 // tolerated burst before throttling kicks in
	rateLimitTTL    = 5 * time.Minute
	rateSweepPeriod = time.Minute
)

// maxConcurrentConns caps connections processed at once across all
// listeners, bounding goroutines, file descriptors, and backend dials so a
// distributed flood cannot exhaust them. Each connection costs ~2 fds; keep
// LimitNOFILE in the systemd unit comfortably above 2x this value.
const maxConcurrentConns = 1024

// fingerprintPrunePeriod is how often the store is trimmed back to the
// configured max_fingerprints cap, if one is set.
const fingerprintPrunePeriod = time.Minute

const (
	// shutdownGrace bounds how long serve waits for in-flight connections to
	// drain after a SIGINT/SIGTERM before exiting anyway.
	shutdownGrace = 10 * time.Second

	// defaultDrainTimeout caps how long a process that has handed off to a new
	// binary (via SIGHUP/tableflip) keeps running to let its existing proxied
	// sessions finish. 0 means wait indefinitely.
	//
	// An hour, modeled on nginx's worker_shutdown_timeout. It has to comfortably
	// exceed idleTimeout above, because an IMAP IDLE session legitimately sits
	// quiet for half an hour and killing it on a deploy is precisely the
	// interruption this exists to avoid.
	defaultDrainTimeout = time.Hour
)

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var routes gateproxy.Routes
	fs.Var(&routes, "route", "LISTEN=BACKEND route to proxy, repeatable (e.g. [::]:993=127.0.0.1:10993)")
	dbPath := fs.String("db", defaultDB, "fingerprint database path")
	configPath := fs.String("config", defaultConfig, "JSON config path for alerting")
	allowUnknown := fs.Bool("allow-unknown", false, "allow unknown fingerprints through (default: block and record)")
	fingerprint := fs.String("fingerprint", string(MethodJA3), "fingerprint method used as the allow/block key: ja3 or ja4")
	resetFingerprints := fs.Bool("reset-fingerprints", false, "purge stored fingerprints when --fingerprint differs from the database's method")
	proxyProtocol := fs.String("proxy-protocol", "off", "PROXY protocol sent to backends: off or v2")
	drainTimeout := fs.Duration("drain-timeout", defaultDrainTimeout, "on upgrade/shutdown, how long to wait for existing connections to finish (0 = forever)")
	fs.Parse(args)

	if len(routes) == 0 {
		log.Fatalf("no routes: pass at least one --route LISTEN=BACKEND")
	}
	if *proxyProtocol != "off" && *proxyProtocol != "v2" {
		log.Fatalf("invalid --proxy-protocol %q (want off or v2)", *proxyProtocol)
	}
	sendProxyV2 := *proxyProtocol == "v2"

	log.Printf("tlsgate %s starting", version)

	// tableflip coordinates a zero-downtime handoff: on SIGHUP it re-execs the
	// (possibly newly installed) binary, passes it the listening sockets over
	// an inherited control fd, and lets this process keep serving its existing
	// connections until they drain.
	//
	// tlsgate fronts IMAPS and SMTPS on the mail host, so a hard restart drops
	// live mail sessions mid-transfer. That is a deploy interrupting mail,
	// which is a poor trade for updating a noise filter.
	process, err := lifecycle.New(log.Printf)
	if err != nil {
		log.Fatalf("process lifecycle: %v", err)
	}
	defer process.Close()

	// bgCtx stops background writers (pruning, control-plane sync) once this
	// process is draining, so a departing process stops touching the shared
	// database while a newer one owns it.
	bgCtx, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()

	// tlsgate needs no root privilege: binding low ports should be granted
	// narrowly via CAP_NET_BIND_SERVICE (systemd AmbientCapabilities or the
	// container's cap_add), not by running as root. Warn if we are uid 0 so
	// a misconfigured deployment is visible rather than silently overprivileged.
	if os.Geteuid() == 0 {
		log.Printf("WARNING: running as root; grant CAP_NET_BIND_SERVICE and run as an unprivileged user instead")
	}

	method, err := ParseFingerprintMethod(*fingerprint)
	if err != nil {
		log.Fatalf("%v", err)
	}

	if err := ensureDir(filepath.Dir(*dbPath)); err != nil {
		log.Fatalf("create db dir: %v", err)
	}

	st, err := NewStore(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}

	// The fp keyspace is method-specific, so guard against an accidental
	// ja3<->ja4 switch silently orphaning every approval and block. Purging
	// is opt-in via --reset-fingerprints.
	if purged, err := st.ReconcileFingerprintMethod(string(method), *resetFingerprints); err != nil {
		log.Fatalf("%v", err)
	} else if purged > 0 {
		log.Printf("reset %d fingerprint(s) switching to method %s", purged, method)
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	alerter, err := NewBlockedRangeAlerter(cfg)
	if err != nil {
		log.Fatalf("load alert ranges: %v", err)
	}

	allow, err := newIPAllowlist(cfg.ApproveRanges)
	if err != nil {
		log.Fatalf("load approve ranges: %v", err)
	}
	if len(cfg.ApproveRanges) > 0 {
		log.Printf("approve ranges (fingerprint gate bypassed): %s", strings.Join(cfg.ApproveRanges, ", "))
	}

	// Bound store growth from unauthenticated unknown clients: trim back to
	// the configured cap at startup and on a timer. Approved entries are
	// never evicted (see Store.PruneToLimit).
	if cfg.MaxFingerprints > 0 {
		log.Printf("max fingerprints: %d", cfg.MaxFingerprints)
		prune := func() {
			if n, err := st.PruneToLimit(cfg.MaxFingerprints); err != nil {
				log.Printf("prune fingerprints: %v", err)
			} else if n > 0 {
				log.Printf("pruned %d fingerprint(s) over limit %d", n, cfg.MaxFingerprints)
			}
		}
		prune()
		go func() {
			t := time.NewTicker(fingerprintPrunePeriod)
			defer t.Stop()
			for {
				select {
				case <-bgCtx.Done():
					return
				case <-t.C:
					prune()
				}
			}
		}()
	}
	if err := controlplane.Start(bgCtx, st, cfg.ControlPlane); err != nil {
		log.Fatalf("control plane: %v", err)
	}

	// One limiter shared across all listeners so a source IP's budget
	// spans every route combined rather than doubling per port.
	limiter := ratelimit.New(connRatePerIP, connBurstPerIP, rateLimitTTL)
	go limiter.RunSweeper(rateSweepPeriod, bgCtx.Done())

	// One semaphore shared across all listeners so the cap is a global
	// ceiling on concurrent connections, not per-port.
	log.Printf("fingerprint method: %s", method)
	if sendProxyV2 {
		log.Printf("backend PROXY protocol: v2")
	}
	blockUnknown := !*allowUnknown

	proxyServer := gateproxy.NewServer(maxConcurrentConns, log.Printf)
	var listeners []net.Listener
	for _, rt := range routes {
		// upg.Listen rather than net.Listen: on an upgrade the socket is
		// inherited from the departing process rather than rebound, so no
		// connection is refused in the gap between the two.
		ln, err := process.Listen("tcp", rt.Listen)
		if err != nil {
			log.Fatalf("listen %s: %v", rt.Listen, err)
		}
		listeners = append(listeners, ln)
		log.Printf("listening on %s -> %s", rt.Listen, rt.Backend)
		proxyServer.Serve(ln, rt, func(conn net.Conn, route gateproxy.Route) {
			handleConn(conn, route.Backend, route.Port, st, blockUnknown, method, alerter, limiter, allow, sendProxyV2)
		})
	}

	if err := process.Ready(); err != nil {
		log.Fatalf("tableflip ready: %v", err)
	}
	if err := sdnotify.Ready(); err != nil {
		log.Printf("sd_notify: %v", err)
	}

	// Block until this process is asked to exit: either a successful upgrade
	// handed serving off to a new process, or a termination signal arrived.
	process.Wait()

	// Stop accepting new connections and stop background DB writers. Existing
	// proxied streams keep running on their own goroutines.
	for _, ln := range listeners {
		_ = ln.Close()
	}
	stopBackground()

	timeout := *drainTimeout
	if process.Terminating() {
		timeout = shutdownGrace
		log.Printf("shutdown: draining in-flight connections (grace %s)", timeout)
	} else {
		log.Printf("upgrade: draining in-flight connections (timeout %s)", timeout)
	}
	if proxyServer.Drain(timeout) {
		log.Printf("all connections drained")
	} else {
		log.Printf("drain timeout after %s; exiting with connections still open", timeout)
	}
	if err := st.Close(); err != nil {
		log.Printf("shutdown: close store: %v", err)
	}
}

func handleConn(client net.Conn, backend string, port int, st *store.Store, blockUnknown bool, method FingerprintMethod, alerter *BlockedRangeAlerter, limiter *ratelimit.Limiter, allow ipAllowlist, sendProxyV2 bool) {
	defer client.Close()

	clientIP, _, _ := net.SplitHostPort(client.RemoteAddr().String())

	// Whitelisted source IPs bypass the gate: every block decision below
	// becomes non-blocking and the connection is forwarded. Trust is
	// per-connection and IP-scoped only — we never mark the fingerprint
	// approved, so the same fp from a non-whitelisted IP stays gated.
	whitelisted := allow.contains(clientIP)
	blockThis := blockUnknown && !whitelisted

	// Drop floods before any read or DB write so a single IP cannot pin
	// goroutines or grow the fingerprint store with randomized handshakes.
	if !limiter.Allow(clientIP) {
		log.Printf("[%s:%d] RATELIMIT dropping connection", clientIP, port)
		return
	}

	client.SetReadDeadline(time.Now().Add(10 * time.Second))

	header := make([]byte, 5)
	if _, err := io.ReadFull(client, header); err != nil {
		return
	}

	var peeked []byte

	if header[0] == recordTypeHandshake {
		// Reassemble the ClientHello, which may span multiple TLS records,
		// then parse it strictly. peeked holds every raw byte we read so the
		// backend receives the handshake unchanged.
		parseBuf, raw, rerr := readClientHello(client, header)
		peeked = raw
		if rerr != nil {
			log.Printf("[%s:%d] ClientHello error: %v", clientIP, port, rerr)
			if blockThis {
				log.Printf("[%s:%d] BLOCKED  unparseable ClientHello", clientIP, port)
				return
			}
			// allow-unknown or whitelisted: fall through and forward what we read.
		} else if fp, meta, perr := extractTLSMetadata(parseBuf, method); perr != nil {
			log.Printf("[%s:%d] parse error: %v", clientIP, port, perr)
			if blockThis {
				log.Printf("[%s:%d] BLOCKED  unparseable ClientHello", clientIP, port)
				return
			}
		} else {
			// Record new whitelisted fingerprints as pending (not blocked)
			// for visibility, without ever approving them.
			entry, err := st.Observe(store.Observation{
				Fingerprint: fp,
				IP:          clientIP,
				Port:        port,
				Meta:        meta.toMeta(),
			}, blockThis)
			if err != nil {
				log.Printf("[%s:%d] store error: %v; failing closed", clientIP, port, err)
				return
			}
			switch entry.Status {
			case StatusBlocked:
				if whitelisted {
					log.Printf("[%s:%d] WHITELIST forwarding blocked fp=%s", clientIP, port, fp)
					break
				}
				log.Printf("[%s:%d] BLOCKED  fp=%s", clientIP, port, fp)
				alerter.AlertBlocked(st, clientIP, port, fp, meta)
				return
			case StatusPending:
				tag := "PENDING "
				if whitelisted {
					tag = "WHITELIST"
				}
				log.Printf("[%s:%d] %s fp=%s sni=%q alpn=%q ja3=%s ja4=%s", clientIP, port, tag, fp, sanitizeLog(meta.SNI), sanitizeLog(strings.Join(meta.ALPN, ",")), meta.JA3, meta.JA4)
			case StatusApproved:
				log.Printf("[%s:%d] APPROVED fp=%s", clientIP, port, fp)
			}
		}
	} else {
		peeked = header
		if blockThis {
			log.Printf("[%s:%d] BLOCKED  non-TLS connection", clientIP, port)
			return
		}
		log.Printf("[%s:%d] ALLOWED  non-TLS connection", clientIP, port)
	}

	client.SetReadDeadline(time.Time{})

	upstream, err := net.DialTimeout("tcp", backend, 10*time.Second)
	if err != nil {
		log.Printf("[%s:%d] dial backend: %v", clientIP, port, err)
		return
	}
	defer upstream.Close()
	if sendProxyV2 {
		header, err := proxyV2Header(client.RemoteAddr(), client.LocalAddr())
		if err != nil {
			log.Printf("[%s:%d] build PROXY v2 header: %v", clientIP, port, err)
			return
		}
		if _, err := upstream.Write(header); err != nil {
			log.Printf("[%s:%d] write PROXY v2 header: %v", clientIP, port, err)
			return
		}
	}

	if _, err := upstream.Write(peeked); err != nil {
		return
	}

	// Bound idle time on the proxied stream so half-open / slowloris
	// connections cannot pin goroutines and backend sockets forever.
	pump := func(dst, src net.Conn) {
		buf := make([]byte, 32*1024)
		for {
			src.SetReadDeadline(time.Now().Add(idleTimeout))
			n, rerr := src.Read(buf)
			if n > 0 {
				dst.SetWriteDeadline(time.Now().Add(idleTimeout))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}

	done := make(chan struct{}, 2)
	go func() { pump(upstream, client); done <- struct{}{} }()
	go func() { pump(client, upstream); done <- struct{}{} }()
	<-done
}

// readClientHello reads TLS handshake records from conn, starting with the
// already-read firstHeader, until the full ClientHello handshake message is
// assembled. It returns parseBuf (a 5-byte record header followed by the
// reassembled handshake message, suitable for parseClientHello) and raw (every
// byte consumed from conn, so the caller can forward the handshake verbatim).
//
// It only reads beyond the first record when the handshake-length field says
// the message continues, so a truncated or tiny probe fails fast instead of
// blocking for more data. Total size is capped by maxClientHello.
func readClientHello(conn net.Conn, firstHeader []byte) (parseBuf, raw []byte, err error) {
	raw = append(raw, firstHeader...)
	hdr := firstHeader
	var bodies []byte
	for {
		if hdr[0] != recordTypeHandshake {
			return nil, raw, fmt.Errorf("non-handshake record type 0x%02x", hdr[0])
		}
		bodyLen := int(hdr[3])<<8 | int(hdr[4])
		if bodyLen == 0 || bodyLen > maxTLSRecordBody {
			return nil, raw, fmt.Errorf("invalid record body length %d", bodyLen)
		}
		if len(bodies)+bodyLen > maxClientHello {
			return nil, raw, fmt.Errorf("ClientHello exceeds %d bytes", maxClientHello)
		}
		body := make([]byte, bodyLen)
		if _, err = io.ReadFull(conn, body); err != nil {
			return nil, raw, err
		}
		raw = append(raw, body...)
		bodies = append(bodies, body...)

		// The 4-byte handshake header carries the declared message length. The
		// RFC permits fragmenting at any byte boundary, so the first record may
		// hold fewer than 4 bytes; keep reading records until the header lands
		// rather than rejecting the connection.
		if len(bodies) >= 4 {
			total := 4 + (int(bodies[1])<<16 | int(bodies[2])<<8 | int(bodies[3]))
			if total > maxClientHello {
				return nil, raw, fmt.Errorf("ClientHello message too large: %d bytes", total)
			}
			if len(bodies) >= total {
				break // full handshake message assembled
			}
		}

		// Message continues in another record.
		hdr = make([]byte, 5)
		if _, err = io.ReadFull(conn, hdr); err != nil {
			return nil, raw, err
		}
		raw = append(raw, hdr...)
	}
	parseBuf = append(append([]byte{}, firstHeader...), bodies...)
	return parseBuf, raw, nil
}

func sanitizeLog(s string) string {
	return strings.Map(func(r rune) rune {
		// Strip C0 controls, DEL, and the C1 range (0x80-0x9f): the latter
		// includes CSI (0x9b), which some terminals act on like ESC '[',
		// so a raw C1 byte could still drive an escape sequence.
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

// sanitizeAlertField prepares an attacker-controlled value (notably SNI) for
// inclusion in a Mattermost message. On top of stripping control characters
// it removes backticks, so the value cannot break out of the code span it is
// wrapped in to inject markdown, links, or @mentions into the channel.
func sanitizeAlertField(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '`' {
			return -1
		}
		return r
	}, s)
}

func ensureDir(path string) error {
	return os.MkdirAll(path, 0750)
}
