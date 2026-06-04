package queue

import (
	"context"

	"github.com/siinghd/isobox/internal/executor"
)

// InProc is the DEFAULT driver: Submit runs the job directly on this host through
// the supplied Runner. It is byte-for-byte the current /execute behaviour — the
// Runner is the existing "acquire Sema -> Exec.Execute -> release" path, so wiring
// the queue seam in with the inproc driver changes nothing observable.
type InProc struct {
	run Runner
}

// NewInProc returns the passthrough driver.
func NewInProc(run Runner) *InProc { return &InProc{run: run} }

func (q *InProc) Name() string { return "inproc" }

// Submit runs the job locally and returns its result — no broker, no serialization.
func (q *InProc) Submit(ctx context.Context, j Job) (executor.Result, error) {
	return q.run.Run(ctx, j.Spec)
}

func (q *InProc) Close() error { return nil }
