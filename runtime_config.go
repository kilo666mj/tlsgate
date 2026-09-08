package main

import (
	"flag"
	"fmt"
	"time"
)

// RouteFileConfig is the JSON representation of a listener and its policy.
// Pointer booleans preserve the distinction between an omitted per-route
// override and an explicit false value.
type RouteFileConfig struct {
	Listen        string `json:"listen"`
	Backend       string `json:"backend"`
	AllowUnknown  *bool  `json:"allow_unknown,omitempty"`
	ProxyProtocol string `json:"proxy_protocol,omitempty"`
}

func applyRuntimeConfig(fs *flag.FlagSet, cfg AppConfig, routes *routeConfigs, dbPath *string, allowUnknown *bool, fingerprint *string, resetFingerprints *bool, proxyProtocol *string, drainTimeout *time.Duration) error {
	explicit := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	if len(*routes) == 0 {
		for i, route := range cfg.Routes {
			if route.Listen == "" || route.Backend == "" {
				return fmt.Errorf("routes[%d] requires listen and backend", i)
			}
			spec := route.Listen + "=" + route.Backend
			if route.AllowUnknown != nil {
				spec += fmt.Sprintf(",allow-unknown=%t", *route.AllowUnknown)
			}
			if route.ProxyProtocol != "" {
				spec += ",proxy-protocol=" + route.ProxyProtocol
			}
			if err := routes.Set(spec); err != nil {
				return fmt.Errorf("routes[%d]: %w", i, err)
			}
		}
	}
	if !explicit["db"] && cfg.Database != "" {
		*dbPath = cfg.Database
	}
	if !explicit["allow-unknown"] {
		*allowUnknown = cfg.AllowUnknown
	}
	if !explicit["fingerprint"] && cfg.Fingerprint != "" {
		*fingerprint = cfg.Fingerprint
	}
	if !explicit["reset-fingerprints"] {
		*resetFingerprints = cfg.ResetFingerprints
	}
	if !explicit["proxy-protocol"] && cfg.ProxyProtocol != "" {
		*proxyProtocol = cfg.ProxyProtocol
	}
	if !explicit["drain-timeout"] && cfg.DrainTimeout != "" {
		parsed, err := time.ParseDuration(cfg.DrainTimeout)
		if err != nil {
			return fmt.Errorf("parse drain_timeout %q: %w", cfg.DrainTimeout, err)
		}
		*drainTimeout = parsed
	}
	return nil
}
