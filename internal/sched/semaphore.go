// Package sched holds the global concurrency gate. Every execution must acquire
// a slot before a sandbox is launched, bounding how many sandboxes run at once.
// Together with the hard-capped isobox.slice this is what keeps the sandbox
// subsystem from starving the rest of a shared host.
package sched

import (
	"context"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"
)

// Limiter is a counting semaphore with a bounded acquire wait.
type Limiter struct {
	sem *semaphore.Weighted
	max int64

	// inUse tracks live holders for the isobox_sema_inuse metric gauge. It is a
	// bare atomic bumped ONLY on a successful Acquire and dropped on Release, so it
	// can never drift negative (a failed/timed-out Acquire does not touch it). This
	// is purely observational — it does not change acquire timing or semantics.
	inUse atomic.Int64
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
	if l.sem.Acquire(c, 1) == nil {
		l.inUse.Add(1)
		return true
	}
	return false
}

// Release returns a slot.
func (l *Limiter) Release() {
	l.sem.Release(1)
	l.inUse.Add(-1)
}

// Max reports the configured concurrency ceiling.
func (l *Limiter) Max() int64 { return l.max }

// InUse reports the number of currently-held slots (for metrics).
func (l *Limiter) InUse() int64 { return l.inUse.Load() }
