package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

const defaultSyslog = "/var/log/syslog"

var userPatterns = []*regexp.Regexp{
	regexp.MustCompile(`user=<([^>]+)>`),
	regexp.MustCompile(`sasl_username=([^,\s]+)`),
	regexp.MustCompile(`login: ([^,\s]+)`),
	regexp.MustCompile(`\s-\s([^ \[]+)\s+\[`),
	regexp.MustCompile(`/SOGo/dav/([^/\s"]+)`),
}

type logMatch struct {
	when   time.Time
	ip     string
	source string
	user   string
	line   string
}

func cmdCorrelate(args []string) {
	fs := flag.NewFlagSet("correlate", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "database path")
	logPath := fs.String("log", defaultSyslog, "syslog path")
	window := fs.Duration("window", 2*time.Minute, "time window around first/last seen")
	limit := fs.Int("limit", 100, "maximum matches to print")
	fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: correlate [--log <path>] [--window <duration>] <fingerprint>")
	}

	store, err := NewStore(*dbPath)
	if err != nil {
		fatalf("open store: %v", err)
	}
	fps, err := store.List()
	if err != nil {
		fatalf("list fingerprints: %v", err)
	}
	fp, entry, err := findFingerprint(fps, fs.Arg(0))
	if err != nil {
		fatalf("%v", err)
	}
	if len(entry.IPs) == 0 {
		fatalf("fingerprint %s has no IPs to correlate", fp)
	}

	matches, err := correlateSyslog(*logPath, entry, *window, *limit)
	if err != nil {
		fatalf("correlate syslog: %v", err)
	}

	fmt.Printf("fingerprint: %s\n", fp)
	if entry.Label != "" {
		fmt.Printf("label: %s\n", displayValue(entry.Label))
	}
	fmt.Printf("window: +/- %s around first_seen=%s and last_seen=%s\n",
		window.String(),
		entry.FirstSeen.Format("2006-01-02 15:04:05"),
		entry.LastSeen.Format("2006-01-02 15:04:05"),
	)
	if len(matches) == 0 {
		fmt.Println("no matching Postfix/Dovecot/mailcow log lines found")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tIP\tSOURCE\tUSER\tLINE")
	for _, m := range matches {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			m.when.Format("2006-01-02 15:04:05"),
			m.ip,
			valueOrDash(m.source),
			valueOrDash(sanitizeLog(m.user)),
			sanitizeLog(m.line),
		)
	}
	w.Flush()
}

func findFingerprint(fps map[string]Entry, query string) (string, Entry, error) {
	if e, ok := fps[query]; ok {
		return query, e, nil
	}
	var matches []string
	for fp := range fps {
		if strings.HasPrefix(fp, query) {
			matches = append(matches, fp)
		}
	}
	sort.Strings(matches)
	switch len(matches) {
	case 0:
		return "", Entry{}, fmt.Errorf("fingerprint not found: %s", query)
	case 1:
		return matches[0], fps[matches[0]], nil
	default:
		return "", Entry{}, fmt.Errorf("ambiguous fingerprint prefix %q matches: %s", query, strings.Join(matches, ", "))
	}
}

func correlateSyslog(path string, entry Entry, window time.Duration, limit int) ([]logMatch, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ipSet := make(map[string]struct{}, len(entry.IPs))
	for _, ip := range entry.IPs {
		ipSet[ip] = struct{}{}
	}

	var matches []logMatch
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !isUsefulMailLog(line) {
			continue
		}
		ip, ok := lineContainsAnyIP(line, ipSet)
		if !ok {
			continue
		}
		when, ok := parseSyslogTime(line, entry.LastSeen)
		if !ok {
			continue
		}
		if !withinCorrelationWindows(when, entry, window) {
			continue
		}
		matches = append(matches, logMatch{
			when:   when,
			ip:     ip,
			source: logSource(line),
			user:   extractUser(line),
			line:   line,
		})
		if limit > 0 && len(matches) >= limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return matches, nil
}

func lineContainsAnyIP(line string, ips map[string]struct{}) (string, bool) {
	for ip := range ips {
		if lineHasIPToken(line, ip) {
			return ip, true
		}
	}
	return "", false
}

// lineHasIPToken reports whether ip appears in line as a whole address rather
// than a substring of a longer one. A bare strings.Contains would match
// "10.0.0.1" inside "10.0.0.10" or "210.0.0.1"; requiring the neighbouring
// characters to not be part of an IP literal (hex digit, dot, or colon) avoids
// those false correlations for both IPv4 and IPv6 forms.
func lineHasIPToken(line, ip string) bool {
	for from := 0; ; {
		i := strings.Index(line[from:], ip)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(ip)
		if !ipBoundaryByte(line, start-1) && !ipBoundaryByte(line, end) {
			return true
		}
		from = start + 1
	}
}

// ipBoundaryByte reports whether the byte at index i is part of an IP literal,
// so a match touching it is a substring of a larger address. Out-of-range
// indices (line edges) count as clean boundaries.
func ipBoundaryByte(line string, i int) bool {
	if i < 0 || i >= len(line) {
		return false
	}
	c := line[i]
	return c == '.' || c == ':' ||
		(c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}

func withinCorrelationWindows(t time.Time, entry Entry, window time.Duration) bool {
	return withinWindow(t, entry.FirstSeen, window) || withinWindow(t, entry.LastSeen, window)
}

func withinWindow(t, center time.Time, window time.Duration) bool {
	if center.IsZero() {
		return false
	}
	return !t.Before(center.Add(-window)) && !t.After(center.Add(window))
}

func parseSyslogTime(line string, ref time.Time) (time.Time, bool) {
	if fields := strings.Fields(line); len(fields) > 0 {
		if when, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
			return when, true
		}
	}

	if len(line) < len("Jan  2 15:04:05") {
		return time.Time{}, false
	}
	prefix := line[:len("Jan  2 15:04:05")]
	parsed, err := time.ParseInLocation("Jan _2 15:04:05", prefix, ref.Location())
	if err != nil {
		return time.Time{}, false
	}
	when := time.Date(ref.Year(), parsed.Month(), parsed.Day(), parsed.Hour(), parsed.Minute(), parsed.Second(), 0, ref.Location())
	if when.After(ref.AddDate(0, 6, 0)) {
		when = when.AddDate(-1, 0, 0)
	} else if when.Before(ref.AddDate(0, -6, 0)) {
		when = when.AddDate(1, 0, 0)
	}
	return when, true
}

func isUsefulMailLog(line string) bool {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "tlsgate") {
		return false
	}
	return strings.Contains(lower, "dovecot") ||
		strings.Contains(lower, "postfix") ||
		strings.Contains(lower, "sogod") ||
		strings.Contains(lower, "/sogo/") ||
		strings.Contains(lower, "imap-login") ||
		strings.Contains(lower, "sasl_username=") ||
		strings.Contains(lower, "mailcow")
}

func logSource(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "dovecot"), strings.Contains(lower, "imap-login"):
		return "dovecot"
	case strings.Contains(lower, "postfix"):
		return "postfix"
	case strings.Contains(lower, "sogod"), strings.Contains(lower, "/sogo/"):
		return "sogo"
	case strings.Contains(lower, "mailcow"):
		return "mailcow"
	default:
		return ""
	}
}

func extractUser(line string) string {
	for _, pattern := range userPatterns {
		match := pattern.FindStringSubmatch(line)
		if len(match) == 2 {
			user := strings.Trim(match[1], "<>,")
			if decoded, err := url.PathUnescape(user); err == nil {
				return decoded
			}
			return user
		}
	}
	return ""
}
