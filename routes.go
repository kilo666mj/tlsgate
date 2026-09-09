package main

import (
	"fmt"
	"strconv"
	"strings"

	gateproxy "github.com/kilo666mj/gatekit/proxy"
)

// routeConfig adds optional per-listener overrides to the shared TCP route.
// Unset values inherit the global flags, regardless of flag ordering.
type routeConfig struct {
	gateproxy.Route
	allowUnknown  *bool
	proxyProtocol string
	protocol      string
	maxConcurrent int
}

func (r routeConfig) policy(allowUnknown bool, proxyProtocol string) (blockUnknown, sendProxyV2 bool) {
	if r.allowUnknown != nil {
		allowUnknown = *r.allowUnknown
	}
	if r.proxyProtocol != "" {
		proxyProtocol = r.proxyProtocol
	}
	return !allowUnknown, proxyProtocol == "v2"
}

type routeConfigs []routeConfig

func (rs *routeConfigs) Set(value string) error {
	parts := strings.Split(value, ",")
	base, err := gateproxy.ParseRoute(parts[0])
	if err != nil {
		return err
	}
	r := routeConfig{Route: base}
	seen := make(map[string]bool)
	for _, part := range parts[1:] {
		key, value, ok := strings.Cut(part, "=")
		if !ok || seen[key] {
			return fmt.Errorf("invalid or duplicate route option %q", part)
		}
		seen[key] = true
		switch key {
		case "allow-unknown":
			// Accept only explicit booleans to make policy changes easy to audit.
			if value != "true" && value != "false" {
				return fmt.Errorf("route allow-unknown must be true or false, got %q", value)
			}
			allow := value == "true"
			r.allowUnknown = &allow
		case "proxy-protocol":
			if value != "off" && value != "v2" {
				return fmt.Errorf("route proxy-protocol must be off or v2, got %q", value)
			}
			r.proxyProtocol = value
		case "protocol":
			if value != "tls" && value != "smtp" {
				return fmt.Errorf("route protocol must be tls or smtp, got %q", value)
			}
			r.protocol = value
		case "max-concurrent":
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				return fmt.Errorf("route max-concurrent must be a positive integer, got %q", value)
			}
			r.maxConcurrent = n
		default:
			return fmt.Errorf("unknown route option %q", key)
		}
	}
	for _, existing := range *rs {
		if existing.Listen == r.Listen {
			return fmt.Errorf("duplicate route listener %q", r.Listen)
		}
	}
	*rs = append(*rs, r)
	return nil
}

func (rs *routeConfigs) String() string {
	var values []string
	for _, r := range *rs {
		value := r.Listen + "=" + r.Backend
		if r.allowUnknown != nil {
			value += ",allow-unknown=" + strconv.FormatBool(*r.allowUnknown)
		}
		if r.proxyProtocol != "" {
			value += ",proxy-protocol=" + r.proxyProtocol
		}
		if r.protocol != "" {
			value += ",protocol=" + r.protocol
		}
		if r.maxConcurrent != 0 {
			value += ",max-concurrent=" + strconv.Itoa(r.maxConcurrent)
		}
		values = append(values, value)
	}
	return strings.Join(values, " ")
}
