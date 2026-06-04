package obs

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
)

// Metrics is a tiny, dependency-free Prometheus text-exposition source. We
// hand-roll the format (it is trivial and stable) rather than pull in
// client_golang, keeping the single static binary lean.
//
// COUNTERS are pushed: callers bump ExecTotal(status) as executions finish.
// GAUGES are pulled at scrape time: the HTTP handler is built with closures that
// read live values (sema in-use, session/kernel counts, slice memory, pool size)
// so the exposition always reflects the instant it is scraped — nothing to keep in
// sync, nothing that can drift.
type Metrics struct {
	mu        sync.Mutex
	execTotal map[string]int64 // status label -> count

	// gauges are registered name->fn closures evaluated at scrape time.
	gaugesMu sync.RWMutex
	gauges   []gauge
}

type gauge struct {
	name string
	help string
	fn   func() float64
}

// global is the process-wide metrics registry. A single instance is fine: metrics
// are inherently process-global and the API server holds the same pointer.
var global = &Metrics{execTotal: map[string]int64{}}

// M returns the process-wide metrics registry.
func M() *Metrics { return global }

// ExecTotal increments the isobox_exec_total counter for a status label, one of
// "ok" | "error" (execution failed) | "rejected" (no capacity / bad request handled
// elsewhere). Cheap: a map bump under a small mutex on the request-completion path.
func (m *Metrics) ExecTotal(status string) {
	m.mu.Lock()
	m.execTotal[status]++
	m.mu.Unlock()
}

// RegisterGauge adds a named gauge evaluated lazily at every scrape. Call once per
// gauge at wiring time. fn must be cheap and non-blocking (it runs inside the
// /metrics handler).
func (m *Metrics) RegisterGauge(name, help string, fn func() float64) {
	m.gaugesMu.Lock()
	m.gauges = append(m.gauges, gauge{name: name, help: help, fn: fn})
	m.gaugesMu.Unlock()
}

// Render writes the current metrics in Prometheus text-exposition format 0.0.4.
// (Named Render, not WriteTo, to avoid colliding with the io.WriterTo convention.)
func (m *Metrics) Render(w io.Writer) {
	// --- counters ---
	m.mu.Lock()
	statuses := make([]string, 0, len(m.execTotal))
	for s := range m.execTotal {
		statuses = append(statuses, s)
	}
	sort.Strings(statuses)
	counters := make(map[string]int64, len(m.execTotal))
	for _, s := range statuses {
		counters[s] = m.execTotal[s]
	}
	m.mu.Unlock()

	fmt.Fprintln(w, "# HELP isobox_exec_total Total executions by terminal status.")
	fmt.Fprintln(w, "# TYPE isobox_exec_total counter")
	if len(statuses) == 0 {
		// Emit a zero series so the metric always exists for scrapers.
		fmt.Fprintln(w, `isobox_exec_total{status="ok"} 0`)
	}
	for _, s := range statuses {
		fmt.Fprintf(w, "isobox_exec_total{status=%q} %d\n", s, counters[s])
	}

	// --- gauges ---
	m.gaugesMu.RLock()
	gs := make([]gauge, len(m.gauges))
	copy(gs, m.gauges)
	m.gaugesMu.RUnlock()
	for _, g := range gs {
		if g.help != "" {
			fmt.Fprintf(w, "# HELP %s %s\n", g.name, g.help)
		}
		fmt.Fprintf(w, "# TYPE %s gauge\n", g.name)
		v := g.fn()
		// Integers render without a trailing ".000000"; keep the output clean.
		if v == float64(int64(v)) {
			fmt.Fprintf(w, "%s %d\n", g.name, int64(v))
		} else {
			fmt.Fprintf(w, "%s %g\n", g.name, v)
		}
	}
}

// SliceMemoryBytes reads memory.current for isobox.slice across both cgroup layouts
// (mirrors api/health.go's dual-path probe). Returns 0 if neither path is readable.
func SliceMemoryBytes() float64 {
	for _, p := range []string{
		"/sys/fs/cgroup/isobox.slice/memory.current",
		"/sys/fs/cgroup/system.slice/isobox.slice/memory.current",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			continue
		}
		var n int64
		if _, err := fmt.Sscan(v, &n); err == nil {
			return float64(n)
		}
	}
	return 0
}
