package main

import (
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
)

func cmdDoctor(args []string) {
	if err := runDoctor(args, os.Stdout); err != nil {
		fatalf("doctor: %v", err)
	}
}

// runDoctor validates startup inputs without listening, connecting to a
// backend, sending alerts, or opening the SQLite store. It is safe to run while
// another tlsgate process owns the database.
func runDoctor(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var routes routeConfigs
	fs.Var(&routes, "route", "LISTEN=BACKEND[,protocol=tls|smtp][,allow-unknown=true|false][,proxy-protocol=off|v2], repeatable")
	dbPath := fs.String("db", defaultDB, "fingerprint database path")
	configPath := fs.String("config", defaultConfig, "JSON config path")
	allowUnknown := fs.Bool("allow-unknown", false, "report enrollment mode")
	fingerprint := fs.String("fingerprint", string(MethodJA3), "fingerprint method: ja3 or ja4")
	proxyProtocol := fs.String("proxy-protocol", "off", "backend PROXY protocol: off or v2")
	smtpEvents := fs.String("smtp-events", "", "SMTP observation event JSONL")
	smtpInstance := fs.String("smtp-instance", "", "stable SMTP event namespace")
	resetFingerprints := fs.Bool("reset-fingerprints", false, "report fingerprint reset policy")
	drainTimeout := fs.Duration("drain-timeout", defaultDrainTimeout, "report drain timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := applyRuntimeConfig(fs, cfg, &routes, dbPath, allowUnknown, fingerprint, resetFingerprints, proxyProtocol, drainTimeout, smtpEvents, smtpInstance); err != nil {
		return fmt.Errorf("load runtime config: %w", err)
	}
	method, err := ParseFingerprintMethod(*fingerprint)
	if err != nil {
		return err
	}
	if *proxyProtocol != "off" && *proxyProtocol != "v2" {
		return fmt.Errorf("invalid --proxy-protocol %q (want off or v2)", *proxyProtocol)
	}
	hasSMTP := false
	for _, r := range routes {
		if r.protocol == "smtp" {
			hasSMTP = true
		}
	}
	if *smtpEvents != "" && *smtpInstance == "" {
		return fmt.Errorf("--smtp-instance is required with --smtp-events")
	}
	if *smtpEvents != "" && !hasSMTP {
		return fmt.Errorf("--smtp-events requires at least one protocol=smtp route")
	}

	// A diagnostic whose output is truncated is worse than no diagnostic, so
	// keep the first write failure and report it to the caller.
	var writeErr error
	emit := func(format string, args ...any) {
		if writeErr != nil {
			return
		}
		_, writeErr = fmt.Fprintf(out, format, args...)
	}
	emit("version: %s\n", version)
	emit("database: %s", *dbPath)
	if info, err := os.Stat(*dbPath); err == nil {
		emit(" (present, mode %s)\n", info.Mode().Perm())
	} else if os.IsNotExist(err) {
		emit(" (not created yet)\n")
	} else {
		return fmt.Errorf("inspect database: %w", err)
	}

	emit("config: %s", *configPath)
	if _, err := os.Stat(*configPath); err == nil {
		emit(" (present)\n")
	} else if os.IsNotExist(err) {
		emit(" (absent; built-in defaults apply)\n")
	} else {
		return fmt.Errorf("inspect config: %w", err)
	}
	if err := validateDoctorConfig(cfg); err != nil {
		return err
	}

	emit("fingerprint method: %s\n", method)
	emit("drain timeout: %s\n", *drainTimeout)
	if *smtpEvents != "" {
		emit("SMTP events: %s (instance %s)\n", *smtpEvents, *smtpInstance)
	} else {
		emit("SMTP events: disabled\n")
	}
	emit("backend PROXY protocol: %s\n", *proxyProtocol)
	if *allowUnknown {
		emit("unknown fingerprints: allowed as pending (enrollment mode)\n")
	} else {
		emit("unknown fingerprints: blocked\n")
	}
	emit("max fingerprints: %d\n", cfg.MaxFingerprints)
	emit("max concurrent connections: %d\n", cfg.MaxConnections)
	emit("connection rate per IP: %g/s (burst %d)\n", cfg.ConnectionRate, cfg.ConnectionBurst)
	if cfg.MetricsListen == "" {
		emit("metrics: disabled\n")
	} else {
		emit("metrics: %s/metrics\n", cfg.MetricsListen)
	}
	emit("trusted source ranges: %d\n", len(cfg.ApproveRanges))
	emit("alert ranges: %d\n", len(cfg.AlertRanges))
	if cfg.ControlPlane.Enabled() {
		emit("control plane: enabled (%s)\n", cfg.ControlPlane.URL)
	} else {
		emit("control plane: disabled\n")
	}
	if len(routes) == 0 {
		emit("routes: none configured; configure routes or pass --route\n")
	} else {
		for _, route := range routes {
			block, proxy := route.policy(*allowUnknown, *proxyProtocol)
			protocol := route.protocol
			if protocol == "" {
				protocol = "tls"
			}
			if protocol == "smtp" {
				emit("route: %s -> %s (protocol=smtp, observation-only, proxy-v2=%t)\n", route.Listen, route.Backend, proxy)
			} else {
				emit("route: %s -> %s (allow-unknown=%t, proxy-v2=%t)\n", route.Listen, route.Backend, !block, proxy)
			}
			if route.maxConcurrent > 0 {
				emit("route capacity: %s max-concurrent=%d\n", route.Listen, route.maxConcurrent)
			}
		}
	}
	return writeErr
}

func validateDoctorConfig(cfg AppConfig) error {
	if _, err := newIPAllowlist(cfg.ApproveRanges); err != nil {
		return err
	}
	if len(cfg.AlertRanges) > 0 && len(cfg.NotificationURLs) == 0 {
		return fmt.Errorf("notification_urls is required when alert_ranges are configured")
	}
	for _, alertRange := range cfg.AlertRanges {
		if alertRange.Name == "" {
			return fmt.Errorf("alert range missing name")
		}
		if len(alertRange.CIDRs) == 0 {
			return fmt.Errorf("alert range %q has no CIDRs", alertRange.Name)
		}
		for _, cidr := range alertRange.CIDRs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				return fmt.Errorf("parse alert range %q CIDR %q: %w", alertRange.Name, cidr, err)
			}
		}
	}
	if cfg.ControlPlane.Enabled() {
		if err := cfg.ControlPlane.Validate(); err != nil {
			return err
		}
	}
	return nil
}
