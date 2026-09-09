package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type smtpEvent struct {
	Version      int       `json:"version"`
	Type         string    `json:"type"`
	Timestamp    time.Time `json:"timestamp"`
	Instance     string    `json:"instance"`
	ConnectionID string    `json:"connection_id"`
	Client       string    `json:"client"`
	Listener     string    `json:"listener"`
	Backend      string    `json:"backend"`
	JA3          string    `json:"ja3,omitempty"`
	JA4          string    `json:"ja4,omitempty"`
	Error        string    `json:"error,omitempty"`
	State        string    `json:"state,omitempty"`
}

type smtpEventWriter struct {
	instance string
	ch       chan smtpEvent
	done     chan struct{}
	dropped  atomic.Uint64
	mu       sync.RWMutex
	closed   bool
}

func newSMTPEventWriter(path, instance string) (*smtpEventWriter, error) {
	if info, err := os.Stat(path); err == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("SMTP events must be a regular file: %s", path)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	w := &smtpEventWriter{instance: instance, ch: make(chan smtpEvent, 1024), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		defer func() {
			if err := f.Close(); err != nil {
				log.Printf("close SMTP event log: %v", err)
			}
		}()
		failed := false
		for e := range w.ch {
			if failed {
				w.dropped.Add(1)
				continue
			}
			line, err := json.Marshal(e)
			if err == nil {
				line = append(line, '\n')
				var n int
				n, err = f.Write(line)
				if err == nil && n != len(line) {
					err = io.ErrShortWrite
				}
			}
			if err != nil {
				failed = true
				w.dropped.Add(1)
				log.Printf("SMTP telemetry disabled after write error: %v", err)
			}
		}
	}()
	return w, nil
}

// Journal observations independently of JSONL configuration or queue health.
func logSMTPEvent(status string, e smtpEvent) {
	details := ""
	if e.State != "" {
		details += fmt.Sprintf(" state=%q", e.State)
	}
	if e.JA3 != "" {
		details += fmt.Sprintf(" ja3=%q", e.JA3)
	}
	if e.JA4 != "" {
		details += fmt.Sprintf(" ja4=%q", e.JA4)
	}
	if e.Error != "" {
		details += fmt.Sprintf(" reason=%q", e.Error)
	}
	log.Printf("%s smtp event=%q connection_id=%q client=%q listener=%q backend=%q%s",
		status, e.Type, e.ConnectionID, e.Client, e.Listener, e.Backend, details)
}

func (w *smtpEventWriter) emit(e smtpEvent) {
	logSMTPEvent("OBSERVED", e)
	if w == nil {
		return
	}
	e.Version = 1
	e.Instance = w.instance
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return
	}
	select {
	case w.ch <- e:
	default:
		if w.dropped.Add(1) == 1 {
			log.Printf("SMTP event queue full; dropping telemetry")
		}
	}
}
func (w *smtpEventWriter) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.ch)
	}
	w.mu.Unlock()
	select {
	case <-w.done:
	case <-time.After(time.Second):
		// A stuck filesystem must not hold up process shutdown. No new events
		// can enter the channel; the writer closes its file if it recovers.
	}
}

func connectionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().String()))
	}
	return hex.EncodeToString(b[:])
}

type smtpObserver struct {
	mu                                        sync.Mutex
	method                                    FingerprintMethod
	events                                    *smtpEventWriter
	base                                      smtpEvent
	clientLines, serverLines                  []byte
	commands                                  []string
	inData, disabled, tlsArmed, fingerprinted bool
	refused, premature                        bool
	greeted                                   bool
	tlsBytes                                  []byte
}

func (o *smtpObserver) client(p []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fingerprinted || o.disabled {
		return
	}
	if o.tlsArmed {
		o.observeTLS(p)
		return
	}
	if len(o.clientLines) == 0 && !o.inData && len(p) > 0 && p[0] == recordTypeHandshake {
		o.premature, o.disabled = true, true
		return
	}
	o.clientLines = append(o.clientLines, p...)
	if len(o.clientLines) > 64*1024 {
		o.disabled = true
		return
	}
	for {
		i := strings.Index(string(o.clientLines), "\n")
		if i < 0 {
			return
		}
		line := strings.TrimRight(string(o.clientLines[:i+1]), "\r\n")
		o.clientLines = o.clientLines[i+1:]
		if o.inData {
			if line == "." {
				o.inData = false
				o.commands = append(o.commands, ".")
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		verb := strings.ToUpper(fields[0])
		if verb == "BDAT" {
			o.disabled = true
			return
		}
		o.commands = append(o.commands, verb)
		if len(o.commands) > 256 {
			o.disabled = true
			return
		}
	}
}

func (o *smtpObserver) server(p []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fingerprinted || o.disabled || o.tlsArmed {
		return
	}
	o.serverLines = append(o.serverLines, p...)
	if len(o.serverLines) > 64*1024 {
		o.disabled = true
		return
	}
	for {
		i := strings.Index(string(o.serverLines), "\n")
		if i < 0 {
			return
		}
		line := strings.TrimRight(string(o.serverLines[:i+1]), "\r\n")
		o.serverLines = o.serverLines[i+1:]
		if len(line) < 3 {
			continue
		}
		// A dash continues a multiline reply; only the final line consumes a command.
		if len(line) > 3 && line[3] == '-' {
			continue
		}
		if !o.greeted {
			o.greeted = true
			continue
		}
		if len(o.commands) == 0 {
			continue
		}
		cmd := o.commands[0]
		o.commands = o.commands[1:]
		if cmd == "DATA" && strings.HasPrefix(line, "354") {
			o.inData = true
		}
		if cmd == "STARTTLS" {
			e := o.base
			e.Type = "starttls"
			e.Timestamp = time.Now().UTC()
			if strings.HasPrefix(line, "220") {
				e.State = "accepted"
				o.events.emit(e)
				o.tlsArmed = true
				o.clientLines = nil
				o.serverLines = nil
				o.commands = nil
				return
			}
			e.State = "refused"
			o.refused = true
			o.events.emit(e)
		}
	}
}

func (o *smtpObserver) observeTLS(p []byte) {
	o.tlsBytes = append(o.tlsBytes, p...)
	if len(o.tlsBytes) > maxClientHello {
		o.disabled = true
		return
	}
	parse, complete, err := clientHelloFromBytes(o.tlsBytes)
	if err != nil {
		o.disabled = true
		return
	}
	if !complete {
		return
	}
	_, meta, err := extractTLSMetadata(parse, o.method)
	if err != nil {
		o.disabled = true
		return
	}
	o.fingerprinted = true
	e := o.base
	e.Type = "fingerprint"
	e.Timestamp = time.Now().UTC()
	e.JA3 = meta.JA3
	e.JA4 = meta.JA4
	o.events.emit(e)
}

func (o *smtpObserver) state() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fingerprinted {
		return "fingerprinted"
	}
	if o.tlsArmed {
		return "starttls_accepted_no_fingerprint"
	}
	if o.disabled {
		if o.premature {
			return "premature_tls"
		}
		return "observer_incomplete"
	}
	if o.refused {
		return "starttls_refused"
	}
	if !o.greeted || len(o.clientLines) != 0 || len(o.serverLines) != 0 {
		return "observer_incomplete"
	}
	return "no_observed_upgrade"
}

func clientHelloFromBytes(raw []byte) ([]byte, bool, error) {
	var bodies []byte
	off := 0
	var first []byte
	for {
		if len(raw)-off < 5 {
			return nil, false, nil
		}
		h := raw[off : off+5]
		if first == nil {
			first = append([]byte{}, h...)
		}
		if h[0] != recordTypeHandshake {
			return nil, false, errors.New("not handshake")
		}
		n := int(h[3])<<8 | int(h[4])
		if n == 0 || n > maxTLSRecordBody {
			return nil, false, errors.New("bad TLS record")
		}
		if len(raw)-off-5 < n {
			return nil, false, nil
		}
		bodies = append(bodies, raw[off+5:off+5+n]...)
		off += 5 + n
		if len(bodies) >= 4 {
			total := 4 + (int(bodies[1])<<16 | int(bodies[2])<<8 | int(bodies[3]))
			if total > maxClientHello {
				return nil, false, errors.New("large ClientHello")
			}
			if len(bodies) >= total {
				return append(first, bodies...), true, nil
			}
		}
	}
}

func handleSMTPConn(client net.Conn, backend string, port int, method FingerprintMethod, limiter connectionLimiter, sendProxyV2 bool, events *smtpEventWriter) {
	defer func() {
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("close SMTP client connection: %v", err)
		}
	}()
	id := connectionID()
	base := smtpEvent{Timestamp: time.Now().UTC(), ConnectionID: id, Client: client.RemoteAddr().String(), Listener: client.LocalAddr().String(), Backend: backend}
	ip, _, _ := net.SplitHostPort(client.RemoteAddr().String())
	if limiter != nil && !limiter.Allow(ip) {
		blocked := base
		blocked.Type, blocked.State = "blocked", "rate_limit"
		logSMTPEvent("BLOCKED", blocked)
		return
	}
	start := base
	start.Type = "start"
	events.emit(start)
	end := base
	end.Type, end.State = "end", "observer_incomplete"
	defer func() {
		end.Timestamp = time.Now().UTC()
		events.emit(end)
	}()
	upstream, err := net.DialTimeout("tcp", backend, 10*time.Second)
	if err != nil {
		recordBackendFailure(limiter)
		end.Error = "backend_connect_failed"
		log.Printf("[%s:%d] dial backend: %v", ip, port, err)
		return
	}
	defer func() {
		if err := upstream.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("close SMTP upstream connection: %v", err)
		}
	}()
	if sendProxyV2 {
		h, e := proxyV2Header(client.RemoteAddr(), client.LocalAddr())
		if e != nil {
			end.Error = "proxy_header_failed"
			return
		}
		_ = upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, e = upstream.Write(h); e != nil {
			end.Error = "proxy_header_write_failed"
			return
		}
		_ = upstream.SetWriteDeadline(time.Time{})
	}
	o := &smtpObserver{method: method, events: events, base: base}
	proxySMTPBidirectional(client, upstream, o)
	end.State = o.state()
}

func proxySMTPBidirectional(client, upstream net.Conn, o *smtpObserver) {
	pump := func(dst, src net.Conn, observe func([]byte)) error {
		b := make([]byte, 32*1024)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
			n, e := src.Read(b)
			if n > 0 {
				observe(b[:n])
				_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
				for off := 0; off < n; {
					m, w := dst.Write(b[off:n])
					off += m
					if w != nil {
						return w
					}
					if m == 0 {
						return io.ErrShortWrite
					}
				}
			}
			if e != nil {
				if errors.Is(e, io.EOF) {
					if c, ok := dst.(closeWriter); ok {
						_ = c.CloseWrite()
					}
					return nil
				}
				return e
			}
		}
	}
	done := make(chan error, 2)
	go func() { done <- pump(upstream, client, o.client) }()
	go func() { done <- pump(client, upstream, o.server) }()
	if <-done != nil {
		_ = client.Close()
		_ = upstream.Close()
	}
	<-done
}
