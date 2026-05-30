package main

import "testing"

func TestSemaphoreCapsAcquires(t *testing.T) {
	sem := newSemaphore(2)
	if !sem.acquire() {
		t.Fatal("acquire 1: denied with free slots")
	}
	if !sem.acquire() {
		t.Fatal("acquire 2: denied with free slots")
	}
	if sem.acquire() {
		t.Fatal("acquire 3: expected denial at capacity")
	}

	sem.release()
	if !sem.acquire() {
		t.Fatal("acquire after release: expected a freed slot")
	}
}

func TestSemaphoreNilUnbounded(t *testing.T) {
	var sem *semaphore
	for i := 0; i < 1000; i++ {
		if !sem.acquire() {
			t.Fatalf("nil semaphore denied at %d, want unbounded", i)
		}
	}
	sem.release() // must not panic
}
