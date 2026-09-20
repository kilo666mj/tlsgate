package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	smtpBehaviorVersion  = 1
	maxSMTPBehaviorVerbs = 12
)

// smtpBehavior is deliberately content-free. Every string is selected from a
// closed vocabulary; SMTP arguments and message bytes never enter this value.
type smtpBehavior struct {
	Version            int    `json:"version"`
	Fingerprint        string `json:"fingerprint"`
	PreGreeting        string `json:"pre_greeting"`
	FirstVerb          string `json:"first_verb"`
	LineEndings        string `json:"line_endings"`
	FirstCommandTiming string `json:"first_command_timing"`
	STARTTLSTiming     string `json:"starttls_timing"`
	VerbShape          string `json:"verb_shape"`
	VerbOverflow       bool   `json:"verb_overflow,omitempty"`
	STARTTLSOutcome    string `json:"starttls_outcome"`
}

type smtpBehaviorTracker struct {
	preGreeting       int
	firstVerb         string
	verbs             []string
	verbOverflow      bool
	sawCRLF, sawLF    bool
	firstCommandAt    time.Time
	starttlsCommandAt time.Time
	starttlsOutcome   string
}

func (b *smtpBehaviorTracker) command(raw, verb string, greeted bool, at time.Time) {
	if strings.HasSuffix(raw, "\r\n") {
		b.sawCRLF = true
	} else {
		b.sawLF = true
	}
	verb = canonicalSMTPVerb(verb)
	if b.firstVerb == "" {
		b.firstVerb = verb
		b.firstCommandAt = at
	}
	if !greeted {
		b.preGreeting++
	}
	if len(b.verbs) < maxSMTPBehaviorVerbs {
		b.verbs = append(b.verbs, verb)
	} else {
		b.verbOverflow = true
	}
	if verb == "STARTTLS" && b.starttlsCommandAt.IsZero() {
		b.starttlsCommandAt = at
	}
}

func canonicalSMTPVerb(verb string) string {
	switch strings.ToUpper(verb) {
	case "HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "VRFY", "EXPN",
		"HELP", "NOOP", "QUIT", "STARTTLS", "AUTH", "BDAT", "BURL", "ATRN",
		"ETRN", "XCLIENT", "XFORWARD":
		return strings.ToUpper(verb)
	default:
		return "OTHER"
	}
}

func (b *smtpBehaviorTracker) snapshot(start time.Time, incomplete bool) *smtpBehavior {
	behavior := &smtpBehavior{
		Version:            smtpBehaviorVersion,
		PreGreeting:        countBucket(b.preGreeting),
		FirstVerb:          b.firstVerb,
		LineEndings:        b.lineEndingBucket(),
		FirstCommandTiming: smtpTimingBucket(start, b.firstCommandAt),
		STARTTLSTiming:     smtpTimingBucket(start, b.starttlsCommandAt),
		VerbShape:          strings.Join(b.verbs, ">"),
		VerbOverflow:       b.verbOverflow,
		STARTTLSOutcome:    b.starttlsOutcome,
	}
	if behavior.FirstVerb == "" {
		behavior.FirstVerb = "NONE"
	}
	if behavior.VerbShape == "" {
		behavior.VerbShape = "NONE"
	}
	if behavior.STARTTLSOutcome == "" {
		if incomplete {
			behavior.STARTTLSOutcome = "unknown"
		} else {
			behavior.STARTTLSOutcome = "not_seen"
		}
	}
	behavior.Fingerprint = smtpBehaviorFingerprint(behavior)
	return behavior
}

func smtpBehaviorFingerprint(behavior *smtpBehavior) string {
	canonical := fmt.Sprintf(
		"v=%d|pre=%s|first=%s|eol=%s|first_timing=%s|starttls_timing=%s|verbs=%s|overflow=%t|starttls=%s",
		behavior.Version, behavior.PreGreeting, behavior.FirstVerb, behavior.LineEndings,
		behavior.FirstCommandTiming, behavior.STARTTLSTiming, behavior.VerbShape,
		behavior.VerbOverflow, behavior.STARTTLSOutcome,
	)
	digest := sha256.Sum256([]byte(canonical))
	return "smtp-behavior/v1/" + hex.EncodeToString(digest[:])
}

func validSMTPBehavior(behavior *smtpBehavior) bool {
	if behavior == nil || behavior.Version != smtpBehaviorVersion {
		return false
	}
	if !oneOf(behavior.PreGreeting, "none", "one", "many") ||
		!oneOf(behavior.LineEndings, "none", "crlf", "lf", "mixed") ||
		!oneOf(behavior.FirstCommandTiming, "unknown", "under_1s", "1s_to_5s", "5s_to_30s", "30s_or_more") ||
		!oneOf(behavior.STARTTLSTiming, "unknown", "under_1s", "1s_to_5s", "5s_to_30s", "30s_or_more") ||
		!oneOf(behavior.STARTTLSOutcome, "unknown", "not_seen", "refused", "accepted") {
		return false
	}
	if behavior.FirstVerb != "NONE" && behavior.FirstVerb != canonicalSMTPVerb(behavior.FirstVerb) {
		return false
	}
	if behavior.VerbShape == "NONE" {
		if behavior.FirstVerb != "NONE" || behavior.VerbOverflow {
			return false
		}
	} else {
		verbs := strings.Split(behavior.VerbShape, ">")
		if len(verbs) == 0 || len(verbs) > maxSMTPBehaviorVerbs || verbs[0] != behavior.FirstVerb {
			return false
		}
		for _, verb := range verbs {
			if verb == "NONE" || verb != canonicalSMTPVerb(verb) {
				return false
			}
		}
	}
	return behavior.Fingerprint == smtpBehaviorFingerprint(behavior)
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func countBucket(n int) string {
	switch n {
	case 0:
		return "none"
	case 1:
		return "one"
	default:
		return "many"
	}
}

func (b *smtpBehaviorTracker) lineEndingBucket() string {
	switch {
	case b.sawCRLF && b.sawLF:
		return "mixed"
	case b.sawCRLF:
		return "crlf"
	case b.sawLF:
		return "lf"
	default:
		return "none"
	}
}

func smtpTimingBucket(start, observed time.Time) string {
	if start.IsZero() || observed.IsZero() || observed.Before(start) {
		return "unknown"
	}
	switch elapsed := observed.Sub(start); {
	case elapsed < time.Second:
		return "under_1s"
	case elapsed < 5*time.Second:
		return "1s_to_5s"
	case elapsed < 30*time.Second:
		return "5s_to_30s"
	default:
		return "30s_or_more"
	}
}
