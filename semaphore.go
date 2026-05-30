package main

// semaphore is a counting semaphore used to bound the number of connections
// processed concurrently, regardless of source IP. The per-IP rate limiter
// stops a single address from flooding; this caps the total goroutines, file
// descriptors, and backend dials in flight so a distributed flood (e.g. many
// IPv6 source addresses, each below the per-IP ceiling) cannot exhaust them.
type semaphore struct {
	slots chan struct{}
}

func newSemaphore(n int) *semaphore {
	return &semaphore{slots: make(chan struct{}, n)}
}

// acquire takes a slot without blocking and reports whether one was free.
// A nil semaphore is unbounded and always succeeds.
func (s *semaphore) acquire() bool {
	if s == nil {
		return true
	}
	select {
	case s.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// release returns a slot. It must be called exactly once per successful
// acquire. A nil semaphore is a no-op.
func (s *semaphore) release() {
	if s == nil {
		return
	}
	<-s.slots
}
