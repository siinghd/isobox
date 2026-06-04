// Package sched holds the global concurrency gate. Every execution must acquire
// a slot before a sandbox is launched, bounding how many sandboxes run at once.
// Together with the hard-capped isobox.slice this is what keeps the sandbox
// subsystem from starving the rest of a shared host.
package sched

import (
	"context"
	"time"

	"golang.org/x/sync/semaphore"
)

// Limiter is a counting semaphore with a bounded acquire wait.
type Limiter struct {
	sem *semaphore.Weighted
	max int64
}

// New returns a Limiter allowing max concurrent holders.
func New(max int) *Limiter {
	if max < 1 {
		max = 1
	}
	return &Limiter{sem: semaphore.NewWeighted(int64(max)), max: int64(max)}
}

// Acquire blocks for at most wait for a slot. Returns false if the wait elapses
// or ctx is cancelled (caller should respond 429 + Retry-After).
func (l *Limiter) Acquire(ctx context.Context, wait time.Duration) bool {
	c, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	return l.sem.Acquire(c, 1) == nil
}

// Release returns a slot.
func (l *Limiter) Release() { l.sem.Release(1) }

// Max reports the configured concurrency ceiling.
func (l *Limiter) Max() int64 { return l.max }
