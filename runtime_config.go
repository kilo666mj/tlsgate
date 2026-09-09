package main

import (
	"flag"
	"fmt"
	"time"
)

type RouteFileConfig struct {
	Listen        string `json:"listen"`
	Backend       string `json:"backend"`
	AllowUnknown  *bool  `json:"allow_unknown,omitempty"`
	ProxyProtocol string `json:"proxy_protocol,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	MaxConcurrent int    `json:"max_concurrent,omitempty"`
}

func applyRuntimeConfig(fs *flag.FlagSet, cfg AppConfig, routes *routeConfigs, dbPath *string, allowUnknown *bool, fingerprint *string, resetFingerprints *bool, proxyProtocol *string, drainTimeout *time.Duration, smtpEvents, smtpInstance *string) error {
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if len(*routes) == 0 {
		for i, r := range cfg.Routes {
			if r.Listen == "" || r.Backend == "" {
				return fmt.Errorf("routes[%d] requires listen and backend", i)
			}
			spec := r.Listen + "=" + r.Backend
			if r.AllowUnknown != nil {
				spec += fmt.Sprintf(",allow-unknown=%t", *r.AllowUnknown)
			}
			if r.ProxyProtocol != "" {
				spec += ",proxy-protocol=" + r.ProxyProtocol
			}
			if r.Protocol != "" {
				spec += ",protocol=" + r.Protocol
			}
			if r.MaxConcurrent != 0 {
				spec += fmt.Sprintf(",max-concurrent=%d", r.MaxConcurrent)
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
		v, err := time.ParseDuration(cfg.DrainTimeout)
		if err != nil {
			return fmt.Errorf("parse drain_timeout %q: %w", cfg.DrainTimeout, err)
		}
		*drainTimeout = v
	}
	if !explicit["smtp-events"] && cfg.SMTPEvents != "" {
		*smtpEvents = cfg.SMTPEvents
	}
	if !explicit["smtp-instance"] && cfg.SMTPInstance != "" {
		*smtpInstance = cfg.SMTPInstance
	}
	return nil
}
