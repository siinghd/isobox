// Package queue is the OPTIONAL job-distribution seam. Its entire reason to exist
// is to let multiple isobox worker nodes share ONE job stream WITHOUT changing the
// single-node behaviour. By default (driver "inproc") it is the current direct
// path: acquire the local concurrency slot, run the job on this host, return the
// result — no serialization, no broker, no extra latency.
//
// A "valkey" driver swaps that out for an XADD/XREADGROUP/XACK Redis-Streams job
// bus so any worker in a pool can pick up a job. Per-host concurrency stays LOCAL
// (each worker still gates on its own Sema). At-least-once delivery is acceptable
// here because a default job runs with --network=none and is therefore idempotent
// (re-running it can only recompute the same pure result).
//
// SCOPE: the point is the seam plus a working driver, not a full job system. SSE
// streaming is deliberately NOT routed through the queue (a broker cannot stream
// live stdout chunks back to the original HTTP connection); the API keeps the SSE
// path direct and only the buffered one-shot /execute may travel the queue.
package queue

import (
	"context"

	"github.com/siinghd/isobox/internal/executor"
)

// Job is a self-contained unit of buffered work: a fully-resolved spec plus the
// language identity needed to build the response envelope. It is what crosses the
// wire in the valkey driver and what the inproc driver runs in-process.
type Job struct {
	ID       string        `json:"id"`
	Language string        `json:"language"`
	Version  string        `json:"version"`
	Spec     executor.Spec `json:"spec"`
}

// Queue is the seam. Submit runs one buffered job to completion and returns its
// result. For the inproc driver this is a direct, synchronous local run (today's
// behaviour). For the valkey driver it enqueues the job and waits for whichever
// worker in the pool produces the result.
//
// Submit MUST gate on the local concurrency limiter exactly as the direct path
// does, so a single node behaves identically whichever driver is selected.
type Queue interface {
	// Name reports the driver identity: "inproc" | "valkey".
	Name() string
	// Submit runs/dispatches one job and returns its terminal result. ctx carries
	// the request deadline / cancellation.
	Submit(ctx context.Context, j Job) (executor.Result, error)
	// Close releases any driver resources (broker connection, worker goroutines).
	Close() error
}

// Runner is the local execution capability a driver needs: acquire a concurrency
// slot, run the spec on THIS host, release the slot. Both drivers depend on it —
// inproc to serve every job, valkey for the worker side that drains the stream.
// It is the single chokepoint that keeps per-host concurrency local.
type Runner interface {
	// Run gates on the local Sema (returning ErrCapacity if no slot frees in time),
	// executes the spec on this host with a nil sink (buffered), and releases the
	// slot. It is exactly the work the direct /execute path does today.
	Run(ctx context.Context, spec executor.Spec) (executor.Result, error)
}
