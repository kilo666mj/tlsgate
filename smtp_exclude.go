package main

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// maxSMTPExcludedSources bounds the operator-supplied exclusion list.
const maxSMTPExcludedSources = 256

// smtpSourceExclusion drops the operator's own monitoring probes from SMTP
// reports. A probe that connects every minute would otherwise dominate the
// connection counts and the bounded campaign evidence uploaded to Gatehub.
type smtpSourceExclusion struct {
	prefixes []netip.Prefix
}

// parseSMTPSourceExclusion accepts a comma-separated list of IP addresses and
// CIDR prefixes. A bare address excludes exactly that host.
func parseSMTPSourceExclusion(value string) (smtpSourceExclusion, error) {
	var result smtpSourceExclusion
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		var prefix netip.Prefix
		if strings.Contains(item, "/") {
			parsed, err := netip.ParsePrefix(item)
			if err != nil {
				return smtpSourceExclusion{}, fmt.Errorf("invalid excluded source %q: %w", item, err)
			}
			prefix = parsed.Masked()
		} else {
			addr, err := netip.ParseAddr(item)
			if err != nil {
				return smtpSourceExclusion{}, fmt.Errorf("invalid excluded source %q: %w", item, err)
			}
			if addr.Zone() != "" {
				return smtpSourceExclusion{}, fmt.Errorf("invalid excluded source %q: zones are not supported", item)
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if prefix.Addr().Is4In6() {
			return smtpSourceExclusion{}, fmt.Errorf("invalid excluded source %q: use the plain IPv4 form", item)
		}
		if len(result.prefixes) == maxSMTPExcludedSources {
			return smtpSourceExclusion{}, fmt.Errorf("at most %d excluded sources are supported", maxSMTPExcludedSources)
		}
		result.prefixes = append(result.prefixes, prefix)
	}
	return result, nil
}

func (e smtpSourceExclusion) empty() bool { return len(e.prefixes) == 0 }

// excludesClient reports whether a "host:port" or "[host]:port" client
// endpoint belongs to an excluded source. Unparseable endpoints are kept so
// that the existing malformed-input accounting still sees them.
func (e smtpSourceExclusion) excludesClient(client string) bool {
	if e.empty() {
		return false
	}
	host, _, err := net.SplitHostPort(client)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap().WithZone("")
	for _, prefix := range e.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
