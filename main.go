package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

const defaultDB = "/var/lib/tlsgate/db.sqlite"

const usage = `Usage: tlsgate <command> [options]

Commands:
  serve    Start the proxy
  list     List all fingerprints
  correlate Correlate a fingerprint with service logs
  approve  Approve a fingerprint
  block    Block a fingerprint
  label    Set a label on a fingerprint
  delete   Delete a fingerprint
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "correlate":
		cmdCorrelate(os.Args[2:])
	case "approve":
		cmdApprove(os.Args[2:])
	case "block":
		cmdBlock(os.Args[2:])
	case "label":
		cmdLabel(os.Args[2:])
	case "delete":
		cmdDelete(os.Args[2:])
	default:
		fmt.Printf("unknown command: %s\n\n", os.Args[1])
		fmt.Print(usage)
		os.Exit(1)
	}
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "database path")
	verbose := fs.Bool("v", false, "show full TLS metadata")
	fs.Parse(args)

	store, err := NewStore(*dbPath)
	if err != nil {
		fatalf("open store: %v", err)
	}

	fps, err := store.List()
	if err != nil {
		fatalf("list fingerprints: %v", err)
	}
	if len(fps) == 0 {
		fmt.Println("no fingerprints recorded yet")
		return
	}

	keys := make([]string, 0, len(fps))
	for k := range fps {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return listEntryLess(keys[i], fps[keys[i]], keys[j], fps[keys[j]])
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if *verbose {
		fmt.Fprintln(w, "FINGERPRINT\tSTATUS\tLABEL\tCOUNT\tLAST SEEN\tSNI\tALPN\tTLS\tSIGALGS\tJA3\tJA4\tIPs")
	} else {
		fmt.Fprintln(w, "FINGERPRINT\tSTATUS\tLABEL\tCOUNT\tLAST SEEN\tSNI\tALPN\tTLS\tIPs")
	}
	for _, k := range keys {
		e := fps[k]
		label := e.Label
		if label == "" {
			label = "-"
		}
		ips := strings.Join(e.IPs, ",")
		if ips == "" {
			ips = "-"
		}
		if *verbose {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				k, e.Status, label, e.Count,
				e.LastSeen.Format("2006-01-02 15:04:05"),
				valueOrDash(e.TLS.SNI),
				valueOrDash(strings.Join(e.TLS.ALPN, ",")),
				valueOrDash(tlsVersionList(e.TLS.SupportedVersions)),
				valueOrDash(signatureAlgorithmList(e.TLS.SignatureAlgorithms)),
				valueOrDash(e.TLS.JA3),
				valueOrDash(e.TLS.JA4),
				ips,
			)
		} else {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
				k, e.Status, label, e.Count,
				e.LastSeen.Format("2006-01-02 15:04:05"),
				valueOrDash(e.TLS.SNI),
				valueOrDash(strings.Join(e.TLS.ALPN, ",")),
				valueOrDash(tlsVersionList(e.TLS.SupportedVersions)),
				ips,
			)
		}
	}
	w.Flush()
}

func listEntryLess(fpA string, a Entry, fpB string, b Entry) bool {
	if a.Count != b.Count {
		return a.Count > b.Count
	}
	if statusRank(a.Status) != statusRank(b.Status) {
		return statusRank(a.Status) < statusRank(b.Status)
	}
	if !a.FirstSeen.Equal(b.FirstSeen) {
		return a.FirstSeen.Before(b.FirstSeen)
	}
	return fpA < fpB
}

func statusRank(status Status) int {
	switch status {
	case StatusApproved:
		return 0
	case StatusBlocked:
		return 1
	case StatusPending:
		return 2
	default:
		return 3
	}
}

func valueOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func tlsVersionList(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, tlsVersionName(v))
	}
	return strings.Join(parts, ",")
}

func signatureAlgorithmList(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, signatureAlgorithmName(v))
	}
	return strings.Join(parts, ",")
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS1.3"
	case 0x0303:
		return "TLS1.2"
	case 0x0302:
		return "TLS1.1"
	case 0x0301:
		return "TLS1.0"
	default:
		if isGREASE(v) {
			return fmt.Sprintf("GREASE(0x%04x)", v)
		}
		return fmt.Sprintf("0x%04x", v)
	}
}

func signatureAlgorithmName(v uint16) string {
	switch v {
	case 0x0403:
		return "ECDSA-SHA256"
	case 0x0503:
		return "ECDSA-SHA384"
	case 0x0603:
		return "ECDSA-SHA512"
	case 0x0804:
		return "RSA-PSS-SHA256"
	case 0x0805:
		return "RSA-PSS-SHA384"
	case 0x0806:
		return "RSA-PSS-SHA512"
	case 0x0401:
		return "RSA-SHA256"
	case 0x0501:
		return "RSA-SHA384"
	case 0x0601:
		return "RSA-SHA512"
	case 0x0807:
		return "ED25519"
	case 0x0808:
		return "ED448"
	default:
		if isGREASE(v) {
			return fmt.Sprintf("GREASE(0x%04x)", v)
		}
		return fmt.Sprintf("0x%04x", v)
	}
}

func cmdApprove(args []string) {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "database path")
	label := fs.String("label", "", "label for this fingerprint")
	fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: approve [--label <name>] <fingerprint>")
	}
	fp := fs.Arg(0)
	store, err := NewStore(*dbPath)
	if err != nil {
		fatalf("open store: %v", err)
	}
	if err := store.SetStatus(fp, StatusApproved); err != nil {
		fatalf("%v", err)
	}
	if *label != "" {
		if err := store.SetLabel(fp, *label); err != nil {
			fatalf("%v", err)
		}
	}
	fmt.Printf("approved %s\n", fp)
}

func cmdBlock(args []string) {
	fs := flag.NewFlagSet("block", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "database path")
	fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: block <fingerprint>")
	}
	store, err := NewStore(*dbPath)
	if err != nil {
		fatalf("open store: %v", err)
	}
	if err := store.SetStatus(fs.Arg(0), StatusBlocked); err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("blocked %s\n", fs.Arg(0))
}

func cmdLabel(args []string) {
	fs := flag.NewFlagSet("label", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "database path")
	fs.Parse(args)
	if fs.NArg() < 2 {
		fatalf("usage: label <fingerprint> <name>")
	}
	store, err := NewStore(*dbPath)
	if err != nil {
		fatalf("open store: %v", err)
	}
	if err := store.SetLabel(fs.Arg(0), fs.Arg(1)); err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("labeled %s as %q\n", fs.Arg(0), fs.Arg(1))
}

func cmdDelete(args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	dbPath := fs.String("db", defaultDB, "database path")
	fs.Parse(args)
	if fs.NArg() == 0 {
		fatalf("usage: delete <fingerprint>")
	}
	store, err := NewStore(*dbPath)
	if err != nil {
		fatalf("open store: %v", err)
	}
	if err := store.Delete(fs.Arg(0)); err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("deleted %s\n", fs.Arg(0))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
