package main

import (
	"sync"
	"time"
)

// rateLimiter caps how frequently a single source IP can have connections
// processed. This bounds two things at once: connection-flood load, and the
// velocity of unbounded fingerprint-row growth from randomized ClientHellos
// (a single attacker IP can only ever persist new rows at the refill rate).
//
// It is a per-key token bucket. A key (source IP) starts with burst tokens;
// each accepted connection spends one; tokens refill at rate per second up to
// burst. Idle buckets are evicted by sweep so the map itself cannot grow
// without bound. ttl must be >= burst/rate so that an evicted bucket would
// already have refilled to full — eviction is then indistinguishable from
// keeping a full bucket, and never resets a still-throttled attacker.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64 // tokens added per second
	burst   float64 // bucket capacity
	ttl     time.Duration
	now     func() time.Time
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate, burst float64, ttl time.Duration) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    rate,
		burst:   burst,
		ttl:     ttl,
		now:     time.Now,
	}
}

// allow consumes a token for key and reports whether the event may proceed.
// A nil limiter allows everything.
func (rl *rateLimiter) allow(key string) bool {
	if rl == nil {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	b := rl.buckets[key]
	if b == nil {
		b = &tokenBucket{tokens: rl.burst, last: now}
		rl.buckets[key] = b
	} else {
		b.tokens += now.Sub(b.last).Seconds() * rl.rate
		if b.tokens > rl.burst {
			b.tokens = rl.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep evicts buckets idle longer than ttl. Safe because such a bucket has
// refilled to burst and is identical to a freshly created one.
func (rl *rateLimiter) sweep() {
	if rl == nil {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := rl.now().Add(-rl.ttl)
	for k, b := range rl.buckets {
		if b.last.Before(cutoff) {
			delete(rl.buckets, k)
		}
	}
}

// runSweeper evicts idle buckets every interval for the life of the process.
func (rl *rateLimiter) runSweeper(interval time.Duration) {
	if rl == nil {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		rl.sweep()
	}
}
