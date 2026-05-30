package main

import (
	"testing"
	"time"
)

func TestRateLimiterAllowsBurstThenDenies(t *testing.T) {
	rl := newRateLimiter(1, 3, time.Minute)
	now := time.Now()
	rl.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("allow %d: denied within burst", i)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("allow: expected denial once burst is exhausted")
	}
	// A different source IP has its own independent budget.
	if !rl.allow("5.6.7.8") {
		t.Fatal("allow: independent key should start with a full burst")
	}
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	rl := newRateLimiter(2, 2, time.Minute) // 2 tokens/sec, capacity 2
	now := time.Now()
	rl.now = func() time.Time { return now }

	rl.allow("ip")
	rl.allow("ip")
	if rl.allow("ip") {
		t.Fatal("expected denial after burst exhausted")
	}
	now = now.Add(time.Second) // refills 2 tokens
	if !rl.allow("ip") {
		t.Fatal("expected refill to permit a connection after 1s")
	}
}

func TestRateLimiterSweepEvictsIdleBuckets(t *testing.T) {
	rl := newRateLimiter(1, 5, time.Minute)
	now := time.Now()
	rl.now = func() time.Time { return now }

	rl.allow("ip")
	if len(rl.buckets) != 1 {
		t.Fatalf("buckets = %d, want 1", len(rl.buckets))
	}
	now = now.Add(2 * time.Minute) // idle past ttl
	rl.sweep()
	if len(rl.buckets) != 0 {
		t.Fatalf("buckets after sweep = %d, want 0", len(rl.buckets))
	}
}

func TestRateLimiterNilSafe(t *testing.T) {
	var rl *rateLimiter
	if !rl.allow("ip") {
		t.Fatal("nil limiter should allow everything")
	}
	rl.sweep() // must not panic
}
