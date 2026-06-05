package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var routes routeFlag
	fs.Var(&routes, "route", "LISTEN=BACKEND route to proxy, repeatable (e.g. [::]:993=127.0.0.1:10993)")
	dbPath := fs.String("db", defaultDB, "fingerprint database path")
	configPath := fs.String("config", defaultConfig, "JSON config path for alerting")
	allowUnknown := fs.Bool("allow-unknown", false, "allow unknown fingerprints through (default: block and record)")
	fingerprint := fs.String("fingerprint", string(MethodJA3), "fingerprint method used as the allow/block key: ja3 or ja4")
	resetFingerprints := fs.Bool("reset-fingerprints", false, "purge stored fingerprints when --fingerprint differs from the database's method")
	fs.Parse(args)

	if len(routes) == 0 {
		log.Fatalf("no routes: pass at least one --route LISTEN=BACKEND")
	}

	log.Printf("tlsgate %s starting", version)

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

	store, err := NewStore(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}

	// The fp keyspace is method-specific, so guard against an accidental
	// ja3<->ja4 switch silently orphaning every approval and block. Purging
	// is opt-in via --reset-fingerprints.
	if purged, err := store.ReconcileFingerprintMethod(method, *resetFingerprints); err != nil {
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
			if n, err := store.PruneToLimit(cfg.MaxFingerprints); err != nil {
				log.Printf("prune fingerprints: %v", err)
			} else if n > 0 {
				log.Printf("pruned %d fingerprint(s) over limit %d", n, cfg.MaxFingerprints)
			}
		}
		prune()
		go func() {
			t := time.NewTicker(fingerprintPrunePeriod)
			defer t.Stop()
			for range t.C {
				prune()
			}
		}()
	}

	// One limiter shared across all listeners so a source IP's budget
	// spans every route combined rather than doubling per port.
	limiter := newRateLimiter(connRatePerIP, connBurstPerIP, rateLimitTTL)
	go limiter.runSweeper(rateSweepPeriod)

	// One semaphore shared across all listeners so the cap is a global
	// ceiling on concurrent connections, not per-port.
	sem := newSemaphore(maxConcurrentConns)

	log.Printf("fingerprint method: %s", method)
	blockUnknown := !*allowUnknown
	// Run every route but the last in its own goroutine; the last holds
	// the main goroutine so the process stays up.
	for i, rt := range routes {
		if i == len(routes)-1 {
			listenAndProxy(rt.listen, rt.backend, rt.port, store, blockUnknown, method, alerter, limiter, sem, allow)
		} else {
			go listenAndProxy(rt.listen, rt.backend, rt.port, store, blockUnknown, method, alerter, limiter, sem, allow)
		}
	}
}

// route is a single LISTEN=BACKEND mapping. port is parsed from the listen
// address for log labels and the stored port set; 0 if it cannot be parsed.
type route struct {
	listen  string
	backend string
	port    int
}

// routeFlag collects repeated --route flags.
type routeFlag []route

func (r *routeFlag) String() string {
	parts := make([]string, len(*r))
	for i, rt := range *r {
		parts[i] = rt.listen + "=" + rt.backend
	}
	return strings.Join(parts, ",")
}

func (r *routeFlag) Set(v string) error {
	listen, backend, ok := strings.Cut(v, "=")
	if !ok || listen == "" || backend == "" {
		return fmt.Errorf("route must be LISTEN=BACKEND, got %q", v)
	}
	port := 0
	if _, portStr, err := net.SplitHostPort(listen); err == nil {
		port, _ = strconv.Atoi(portStr)
	}
	*r = append(*r, route{listen: listen, backend: backend, port: port})
	return nil
}

func listenAndProxy(listen, backend string, port int, store *Store, blockUnknown bool, method FingerprintMethod, alerter *BlockedRangeAlerter, limiter *rateLimiter, sem *semaphore, allow ipAllowlist) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("listen %s: %v", listen, err)
	}
	log.Printf("listening on %s -> %s", listen, backend)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		// Cap total in-flight connections before spending a goroutine or
		// backend socket on this one.
		if !sem.acquire() {
			clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			log.Printf("[%s:%d] OVERLOAD at capacity, dropping connection", clientIP, port)
			conn.Close()
			continue
		}
		go func() {
			defer sem.release()
			handleConn(conn, backend, port, store, blockUnknown, method, alerter, limiter, allow)
		}()
	}
}

func handleConn(client net.Conn, backend string, port int, store *Store, blockUnknown bool, method FingerprintMethod, alerter *BlockedRangeAlerter, limiter *rateLimiter, allow ipAllowlist) {
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
	if !limiter.allow(clientIP) {
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
			status, err := store.Seen(fp, clientIP, port, meta, blockThis)
			if err != nil {
				log.Printf("[%s:%d] store error: %v; failing closed", clientIP, port, err)
				return
			}
			switch status {
			case StatusBlocked:
				if whitelisted {
					log.Printf("[%s:%d] WHITELIST forwarding blocked fp=%s", clientIP, port, fp)
					break
				}
				log.Printf("[%s:%d] BLOCKED  fp=%s", clientIP, port, fp)
				alerter.AlertBlocked(store, clientIP, port, fp, meta)
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
