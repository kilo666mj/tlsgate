package main

import (
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"

	gateproxy "github.com/kilo666mj/gatekit/proxy"
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
	var routes gateproxy.Routes
	fs.Var(&routes, "route", "LISTEN=BACKEND route to validate, repeatable")
	dbPath := fs.String("db", defaultDB, "fingerprint database path")
	configPath := fs.String("config", defaultConfig, "JSON config path")
	allowUnknown := fs.Bool("allow-unknown", false, "report enrollment mode")
	fingerprint := fs.String("fingerprint", string(MethodJA3), "fingerprint method: ja3 or ja4")
	proxyProtocol := fs.String("proxy-protocol", "off", "backend PROXY protocol: off or v2")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	method, err := ParseFingerprintMethod(*fingerprint)
	if err != nil {
		return err
	}
	if *proxyProtocol != "off" && *proxyProtocol != "v2" {
		return fmt.Errorf("invalid --proxy-protocol %q (want off or v2)", *proxyProtocol)
	}

	fmt.Fprintf(out, "version: %s\n", version)
	fmt.Fprintf(out, "database: %s", *dbPath)
	if info, err := os.Stat(*dbPath); err == nil {
		fmt.Fprintf(out, " (present, mode %s)\n", info.Mode().Perm())
	} else if os.IsNotExist(err) {
		fmt.Fprintln(out, " (not created yet)")
	} else {
		return fmt.Errorf("inspect database: %w", err)
	}

	fmt.Fprintf(out, "config: %s", *configPath)
	if _, err := os.Stat(*configPath); err == nil {
		fmt.Fprintln(out, " (present)")
	} else if os.IsNotExist(err) {
		fmt.Fprintln(out, " (absent; built-in defaults apply)")
	} else {
		return fmt.Errorf("inspect config: %w", err)
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := validateDoctorConfig(cfg); err != nil {
		return err
	}

	fmt.Fprintf(out, "fingerprint method: %s\n", method)
	fmt.Fprintf(out, "backend PROXY protocol: %s\n", *proxyProtocol)
	if *allowUnknown {
		fmt.Fprintln(out, "unknown fingerprints: allowed as pending (enrollment mode)")
	} else {
		fmt.Fprintln(out, "unknown fingerprints: blocked")
	}
	fmt.Fprintf(out, "max fingerprints: %d\n", cfg.MaxFingerprints)
	fmt.Fprintf(out, "trusted source ranges: %d\n", len(cfg.ApproveRanges))
	fmt.Fprintf(out, "alert ranges: %d\n", len(cfg.AlertRanges))
	if cfg.ControlPlane.Enabled() {
		fmt.Fprintf(out, "control plane: enabled (%s)\n", cfg.ControlPlane.URL)
	} else {
		fmt.Fprintln(out, "control plane: disabled")
	}
	if len(routes) == 0 {
		fmt.Fprintln(out, "routes: none supplied; pass the same --route flags used by serve")
	} else {
		for _, route := range routes {
			fmt.Fprintf(out, "route: %s -> %s\n", route.Listen, route.Backend)
		}
	}
	return nil
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
