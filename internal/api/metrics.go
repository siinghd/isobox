package api

import (
	"context"
	"net/http"
	"sync"

	"github.com/siinghd/isobox/internal/executor"
	"github.com/siinghd/isobox/internal/obs"
	"github.com/siinghd/isobox/internal/queue"
)

var metricsOnce sync.Once

// handleMetrics serves Prometheus text exposition. Gauges are read live at scrape
// time from the server's components (nil-guarded), so the output always reflects
// the instant it is scraped. Registration happens once, lazily, so it picks up the
// fully-wired Server (Sessions/Kernels/Pool may be attached after construction).
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metricsOnce.Do(s.registerGauges)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	obs.M().Render(w)
}

// registerGauges wires the live-read gauges. Each closure is cheap and non-blocking.
func (s *Server) registerGauges() {
	m := obs.M()
	m.RegisterGauge("isobox_sema_inuse", "Concurrency slots currently held.", func() float64 {
		if s.Sema == nil {
			return 0
		}
		return float64(s.Sema.InUse())
	})
	m.RegisterGauge("isobox_sema_max", "Configured concurrency ceiling.", func() float64 {
		if s.Sema == nil {
			return 0
		}
		return float64(s.Sema.Max())
	})
	m.RegisterGauge("isobox_sessions", "Live stateful sessions.", func() float64 {
		if s.Sessions == nil {
			return 0
		}
		return float64(s.Sessions.Count())
	})
	m.RegisterGauge("isobox_kernels", "Resident kernel containers.", func() float64 {
		if s.Sessions == nil || s.Sessions.Kernels == nil {
			return 0
		}
		return float64(s.Sessions.Kernels.Count())
	})
	m.RegisterGauge("isobox_slice_memory_bytes", "Current memory usage of isobox.slice (cgroup memory.current).", func() float64 {
		return obs.SliceMemoryBytes()
	})
	m.RegisterGauge("isobox_warmpool_size", "Configured warm-pool target size.", func() float64 {
		return float64(s.Pool.Size())
	})
	m.RegisterGauge("isobox_warmpool_ready", "Warm containers currently booted and idle.", func() float64 {
		return float64(s.Pool.Ready())
	})
}

// Runner returns the server's local execution path as a queue.Runner: it acquires
// the local Sema, runs the spec on this host (buffered, nil sink), and releases the
// slot — exactly what the direct /execute path does today. Both the inproc and
// valkey queue drivers run jobs through this, keeping per-host concurrency LOCAL.
func (s *Server) Runner() queue.Runner { return localRunner{s: s} }

type localRunner struct{ s *Server }

func (l localRunner) Run(ctx context.Context, spec executor.Spec) (executor.Result, error) {
	if !l.s.Sema.Acquire(ctx, l.s.AcquireWait) {
		return executor.Result{}, errCapacity
	}
	defer l.s.Sema.Release()
	return l.s.Exec.Execute(ctx, spec, nil)
}
