package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	smtpCampaignReportSchema = "smtp-campaign-report/v1"
	pregreetSupportSignature = "smtp/pregreet-helo-support-selfdomain/v1"
	maxSMTPPrefixInput       = 1 << 20
)

type smtpCampaignReport struct {
	Schema                     string               `json:"schema"`
	Instance                   string               `json:"instance"`
	Listener                   string               `json:"listener"`
	Signature                  string               `json:"signature"`
	Connections                int                  `json:"connections"`
	EvidenceSessions           int                  `json:"evidence_sessions"`
	Matched                    int                  `json:"matched"`
	Unmatched                  int                  `json:"unmatched"`
	ConnectionsWithoutEvidence int                  `json:"connections_without_evidence"`
	MalformedEvents            int                  `json:"malformed_events"`
	MalformedLogLines          int                  `json:"malformed_log_lines"`
	Records                    []smtpCampaignRecord `json:"records"`
}

type smtpCampaignRecord struct {
	Timestamp           time.Time `json:"timestamp"`
	Client              string    `json:"client"`
	ConnectionID        string    `json:"connection_id,omitempty"`
	BehaviorFingerprint string    `json:"behavior_fingerprint,omitempty"`
	Signature           string    `json:"signature,omitempty"`
	Reason              string    `json:"reason"`
	Provider            string    `json:"provider,omitempty"`
	NetworkPrefix       string    `json:"network_prefix,omitempty"`
	RecipientCluster    string    `json:"recipient_cluster,omitempty"`
}

type smtpCampaignEvidence struct {
	Client                                string
	Start, PregreetAt, RejectAt, LastAt   time.Time
	Pregreet, Rejected                    bool
	PregreetVerb                          string
	EnvelopeFrom, EnvelopeTo, HELO        string
	sawPostscreenConnect, sawSMTPDConnect bool
}

type smtpNetworkPrefix struct {
	Prefix   netip.Prefix
	Provider string
}

type smtpNetworkPrefixFile struct {
	Prefixes []struct {
		Prefix   string `json:"prefix"`
		Provider string `json:"provider"`
	} `json:"prefixes"`
}

func cmdClassifySMTP(args []string) {
	fs := flag.NewFlagSet("classify-smtp", flag.ExitOnError)
	events := fs.String("events", "", "tlsgate SMTP event JSONL")
	postfix := fs.String("postfix-log", "", "RFC3339-prefixed Postfix/Postscreen log")
	instance := fs.String("instance", "", "receiving instance namespace")
	listener := fs.String("listener", "", "exact tlsgate listener endpoint namespace")
	prefixes := fs.String("network-prefixes", "", "optional operator-supplied JSON prefix map")
	maxLifetime := fs.Duration("max-lifetime", 10*time.Minute, "maximum attributable connection lifetime")
	tolerance := fs.Duration("tolerance", time.Second, "timestamp precision tolerance")
	format := fs.String("format", "text", "text or json report")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || *events == "" || *postfix == "" || *instance == "" || *listener == "" {
		fatalf("classify-smtp requires --events, --postfix-log, --instance, and --listener")
	}
	if *format != "text" && *format != "json" {
		fatalf("invalid --format %q", *format)
	}
	report, err := runSMTPCampaignClassification(*events, *postfix, *prefixes, *instance, *listener, *maxLifetime, *tolerance)
	if err != nil {
		fatalf("classify SMTP: %v", err)
	}
	if *format == "json" {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			fatalf("write campaign report: %v", err)
		}
		return
	}
	fmt.Printf("connections=%d evidence_sessions=%d matched=%d unmatched=%d connections_without_evidence=%d\n",
		report.Connections, report.EvidenceSessions, report.Matched, report.Unmatched, report.ConnectionsWithoutEvidence)
	fmt.Printf("malformed_events=%d malformed_log_lines=%d signature=%s\n",
		report.MalformedEvents, report.MalformedLogLines, report.Signature)
	for _, record := range report.Records {
		fmt.Printf("campaign client=%q connection_id=%q signature=%q reason=%q provider=%q recipient_cluster=%q\n",
			record.Client, record.ConnectionID, record.Signature, record.Reason, record.Provider, record.RecipientCluster)
	}
}

func runSMTPCampaignClassification(eventsPath, postfixPath, prefixPath, instance, listener string, maxLifetime, tolerance time.Duration) (smtpCampaignReport, error) {
	if strings.TrimSpace(instance) == "" {
		return smtpCampaignReport{}, fmt.Errorf("instance is required")
	}
	if _, _, err := net.SplitHostPort(listener); err != nil {
		return smtpCampaignReport{}, fmt.Errorf("listener must be an exact IP:port endpoint: %w", err)
	}
	if maxLifetime <= 0 || maxLifetime > time.Hour {
		return smtpCampaignReport{}, fmt.Errorf("max lifetime must be between zero and one hour")
	}
	if tolerance < 0 || tolerance > time.Minute {
		return smtpCampaignReport{}, fmt.Errorf("tolerance must be between zero and one minute")
	}

	connections, malformedEvents, err := readSMTPConnectionsStats(eventsPath)
	if err != nil {
		return smtpCampaignReport{}, err
	}
	filtered := connections[:0]
	for _, connection := range connections {
		if connection.Instance != instance || connection.Listener != listener {
			continue
		}
		host, port, splitErr := net.SplitHostPort(connection.Client)
		if splitErr != nil {
			malformedEvents++
			continue
		}
		client, ok := canonicalClientTuple(host, port)
		if !ok {
			malformedEvents++
			continue
		}
		connection.Client = client
		if connection.Behavior != nil && !validSMTPBehavior(connection.Behavior) {
			malformedEvents++
			connection.Behavior = nil
		}
		filtered = append(filtered, connection)
	}
	connections = filtered
	evidence, malformedLogs, err := readSMTPCampaignEvidence(postfixPath, maxLifetime)
	if err != nil {
		return smtpCampaignReport{}, err
	}
	prefixMap, err := readSMTPNetworkPrefixes(prefixPath)
	if err != nil {
		return smtpCampaignReport{}, err
	}

	report := smtpCampaignReport{
		Schema: smtpCampaignReportSchema, Instance: instance, Listener: listener,
		Signature: pregreetSupportSignature, Connections: len(connections), EvidenceSessions: len(evidence),
		MalformedEvents: malformedEvents, MalformedLogLines: malformedLogs,
	}
	byClient := make(map[string][]smtpConnRecord)
	for _, connection := range connections {
		byClient[connection.Client] = append(byClient[connection.Client], connection)
	}
	seenConnections := make(map[string]bool)
	for _, item := range evidence {
		record := smtpCampaignRecord{Timestamp: item.evidenceTime(), Client: item.Client, Reason: "no_exact_connection"}
		if recipient := normalizeMailbox(item.EnvelopeTo); recipient != "" {
			record.RecipientCluster = smtpValueHash(recipient)
		}
		if addr, _, parseErr := net.SplitHostPort(item.Client); parseErr == nil {
			if parsed, parseAddrErr := netip.ParseAddr(addr); parseAddrErr == nil {
				record.NetworkPrefix, record.Provider = matchSMTPNetworkPrefix(prefixMap, parsed)
			}
		}
		matches := matchingSMTPConnections(byClient[item.Client], item, maxLifetime, tolerance)
		if len(matches) == 1 {
			connection := matches[0]
			record.ConnectionID = connection.ID
			seenConnections[connection.ID] = true
			if connection.Behavior != nil {
				record.BehaviorFingerprint = connection.Behavior.Fingerprint
			}
			record.Reason = classifySMTPCampaign(connection.Behavior, item)
			if record.Reason == "matched" {
				record.Signature = pregreetSupportSignature
				report.Matched++
			} else {
				report.Unmatched++
			}
		} else {
			if len(matches) > 1 {
				record.Reason = "ambiguous_exact_connection"
			}
			report.Unmatched++
		}
		report.Records = append(report.Records, record)
	}
	for _, connection := range connections {
		if !seenConnections[connection.ID] {
			report.ConnectionsWithoutEvidence++
		}
	}
	sort.Slice(report.Records, func(i, j int) bool {
		if report.Records[i].Timestamp.Equal(report.Records[j].Timestamp) {
			return report.Records[i].Client < report.Records[j].Client
		}
		return report.Records[i].Timestamp.Before(report.Records[j].Timestamp)
	})
	return report, nil
}

func matchingSMTPConnections(candidates []smtpConnRecord, evidence smtpCampaignEvidence, maxLifetime, tolerance time.Duration) []smtpConnRecord {
	var matches []smtpConnRecord
	for _, connection := range candidates {
		if connection.Invalid || connection.Start.IsZero() || connection.End.IsZero() || connection.End.Before(connection.Start) || connection.End.Sub(connection.Start) > maxLifetime {
			continue
		}
		inside := func(at time.Time) bool {
			return at.IsZero() || (!at.Before(connection.Start.Add(-tolerance)) && !at.After(connection.End.Add(tolerance)))
		}
		if inside(evidence.Start) && inside(evidence.PregreetAt) && inside(evidence.RejectAt) && inside(evidence.LastAt) {
			matches = append(matches, connection)
		}
	}
	return matches
}

func classifySMTPCampaign(behavior *smtpBehavior, evidence smtpCampaignEvidence) string {
	if !validSMTPBehavior(behavior) {
		return "missing_or_invalid_behavior"
	}
	if behavior.PreGreeting == "none" || behavior.FirstVerb != "HELO" {
		return "behavior_not_pregreet_helo"
	}
	if !evidence.Pregreet || evidence.PregreetVerb != "HELO" {
		return "postscreen_not_pregreet_helo"
	}
	if !evidence.Rejected {
		return "no_rejection_evidence"
	}
	local, domain := splitMailbox(evidence.EnvelopeFrom)
	if !strings.EqualFold(local, "support") || domain == "" {
		return "sender_not_support_domain"
	}
	if canonicalDomain(evidence.HELO) != domain {
		return "helo_sender_domain_mismatch"
	}
	return "matched"
}

func (e smtpCampaignEvidence) evidenceTime() time.Time {
	for _, value := range []time.Time{e.RejectAt, e.PregreetAt, e.Start, e.LastAt} {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}

var (
	smtpCampaignEnvelope = regexp.MustCompile(`^(\S+)\s+\S+\s+(?:(?:[A-Za-z0-9_.-]+\[[0-9]+\]:\s+)?(?:[A-Z][a-z]{2}\s+[ 0-9][0-9]\s+[0-9:]{8}\s+[A-Za-z0-9_.-]+\s+)?)?(?:postfix|haproxy)/(postscreen|smtpd)\[[0-9]+\]:\s+([^\r\n]*)$`)
	smtpCampaignConnect  = regexp.MustCompile(`^(?:CONNECT|connect) from (?:[^\[]*)?\[([^]]+)\]:(\d+)`)
	smtpCampaignPregreet = regexp.MustCompile(`^PREGREET [0-9]+ after [^ ]+ from \[([^]]+)\]:(\d+):[ \t]*([A-Za-z]+)(?:[ \t]+([^\\\r\n \t]+))?`)
	smtpCampaignReject   = regexp.MustCompile(`^NOQUEUE: reject: [A-Z]+ from (?:[^\[]*)?\[([^]]+)\]:(\d+):`)
	smtpEnvelopeFrom     = regexp.MustCompile(`(?:^|[,;][ \t]+)from=<([^>]*)>`)
	smtpEnvelopeTo       = regexp.MustCompile(`(?:^|[,;][ \t]+)to=<([^>]*)>`)
	smtpEnvelopeHELO     = regexp.MustCompile(`(?:^|[,;][ \t]+)helo=<([^>]*)>`)
)

func readSMTPCampaignEvidence(path string, maxLifetime time.Duration) ([]smtpCampaignEvidence, int, error) {
	scanner, err := newSMTPBatchScanner(path)
	if err != nil {
		return nil, 0, err
	}
	active := make(map[string]smtpCampaignEvidence)
	var result []smtpCampaignEvidence
	malformed := 0
	flush := func(client string) {
		if item, ok := active[client]; ok {
			result = append(result, item)
			delete(active, client)
		}
	}
	for scanner.Scan() {
		match := smtpCampaignEnvelope.FindStringSubmatch(scanner.Text())
		if match == nil {
			continue
		}
		at, parseErr := time.Parse(time.RFC3339Nano, match[1])
		if parseErr != nil {
			malformed++
			continue
		}
		service, body := match[2], match[3]
		if connect := smtpCampaignConnect.FindStringSubmatch(body); connect != nil {
			client, ok := canonicalClientTuple(connect[1], connect[2])
			if !ok {
				malformed++
				continue
			}
			item := active[client]
			if service == "smtpd" && item.sawPostscreenConnect && !item.sawSMTPDConnect &&
				!at.Before(item.LastAt) && at.Sub(item.LastAt) <= maxLifetime {
				item.sawSMTPDConnect = true
				item.LastAt = at
				active[client] = item
				continue
			}
			flush(client)
			item = smtpCampaignEvidence{Client: client, Start: at, LastAt: at}
			item.sawPostscreenConnect = service == "postscreen"
			item.sawSMTPDConnect = service == "smtpd"
			active[client] = item
			continue
		}
		if pregreet := smtpCampaignPregreet.FindStringSubmatch(body); pregreet != nil {
			client, ok := canonicalClientTuple(pregreet[1], pregreet[2])
			if !ok {
				malformed++
				continue
			}
			item := active[client]
			if item.Pregreet || (!item.LastAt.IsZero() && (at.Before(item.LastAt) || at.Sub(item.LastAt) > maxLifetime)) {
				flush(client)
				item = smtpCampaignEvidence{}
			}
			if item.Client == "" {
				item.Client, item.Start = client, at
			}
			item.Pregreet, item.PregreetAt, item.LastAt = true, at, at
			item.PregreetVerb = canonicalSMTPVerb(pregreet[3])
			active[client] = item
			continue
		}
		if reject := smtpCampaignReject.FindStringSubmatch(body); reject != nil {
			client, ok := canonicalClientTuple(reject[1], reject[2])
			if !ok {
				malformed++
				continue
			}
			item := active[client]
			if item.Client == "" || at.Before(item.LastAt) || at.Sub(item.LastAt) > maxLifetime {
				flush(client)
				item = smtpCampaignEvidence{Client: client, Start: at}
			}
			from, fromOK := boundedSMTPLogField(smtpEnvelopeFrom, body)
			to, toOK := boundedSMTPLogField(smtpEnvelopeTo, body)
			helo, heloOK := boundedSMTPLogField(smtpEnvelopeHELO, body)
			if !fromOK || !toOK || !heloOK {
				malformed++
				continue
			}
			item.Rejected, item.RejectAt, item.LastAt = true, at, at
			item.EnvelopeFrom, item.EnvelopeTo, item.HELO = from, to, helo
			active[client] = item
			flush(client)
			continue
		}
		if strings.HasPrefix(body, "PREGREET ") || strings.HasPrefix(body, "NOQUEUE: reject:") ||
			strings.HasPrefix(body, "CONNECT from ") || strings.HasPrefix(body, "connect from ") {
			malformed++
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, malformed, err
	}
	keys := make([]string, 0, len(active))
	for key := range active {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		flush(key)
	}
	return result, malformed, nil
}

func boundedSMTPLogField(pattern *regexp.Regexp, line string) (string, bool) {
	match := pattern.FindStringSubmatch(line)
	if match == nil || len(match[1]) > 320 || strings.ContainsAny(match[1], "\r\n\x00") {
		return "", false
	}
	return match[1], true
}

func canonicalClientTuple(host, port string) (string, bool) {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return "", false
	}
	return net.JoinHostPort(addr.String(), strconv.FormatUint(n, 10)), true
}

func normalizeMailbox(value string) string {
	local, domain := splitMailbox(value)
	if local == "" || domain == "" {
		return ""
	}
	return strings.ToLower(local) + "@" + domain
}

func splitMailbox(value string) (string, string) {
	value = strings.TrimSpace(value)
	at := strings.LastIndexByte(value, '@')
	if at <= 0 || at == len(value)-1 {
		return "", ""
	}
	local := value[:at]
	domain := canonicalDomain(value[at+1:])
	if len(local) > 64 || domain == "" {
		return "", ""
	}
	return local, domain
}

func canonicalDomain(value string) string {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "@[]<>\r\n\x00") {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}
		for i, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && !(char == '-' && i > 0 && i < len(label)-1) {
				return ""
			}
		}
	}
	return value
}

func smtpValueHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func readSMTPNetworkPrefixes(path string) ([]smtpNetworkPrefix, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer closeWithError(&err, "close SMTP network prefix file", file.Close)
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxSMTPPrefixInput {
		return nil, fmt.Errorf("network prefix input must be a regular file no larger than %d bytes", maxSMTPPrefixInput)
	}
	var input smtpNetworkPrefixFile
	decoder := json.NewDecoder(io.LimitReader(file, maxSMTPPrefixInput+1))
	if err := decoder.Decode(&input); err != nil {
		return nil, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("network prefix input must contain one JSON value")
	}
	result := make([]smtpNetworkPrefix, 0, len(input.Prefixes))
	for _, item := range input.Prefixes {
		prefix, parseErr := netip.ParsePrefix(item.Prefix)
		if parseErr != nil || prefix != prefix.Masked() {
			return nil, fmt.Errorf("invalid canonical network prefix %q", item.Prefix)
		}
		provider := strings.TrimSpace(item.Provider)
		if provider == "" || len(provider) > 64 || strings.ContainsAny(provider, "\r\n\x00") {
			return nil, fmt.Errorf("invalid provider label for prefix %q", item.Prefix)
		}
		result = append(result, smtpNetworkPrefix{Prefix: prefix, Provider: provider})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Prefix.Bits() > result[j].Prefix.Bits() })
	return result, nil
}

func matchSMTPNetworkPrefix(prefixes []smtpNetworkPrefix, address netip.Addr) (string, string) {
	for _, item := range prefixes {
		if item.Prefix.Contains(address) {
			return item.Prefix.String(), item.Provider
		}
	}
	return "", ""
}
