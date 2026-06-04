package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/siinghd/isobox/internal/executor"
	"github.com/siinghd/isobox/internal/obs"
	"github.com/siinghd/isobox/internal/queue"
	"github.com/siinghd/isobox/internal/registry"
)

var errNoSource = errors.New("no source")

// buildSpec resolves the request's files (or `code`) and clamped limits into an
// executor.Spec for the given language. Shared by /execute and session exec.
func (s *Server) buildSpec(lang *registry.Language, req execRequest) (executor.Spec, error) {
	files := req.Files
	if len(files) == 0 && req.Code != "" {
		files = []executor.File{{Name: lang.SourceFile, Content: req.Code}}
	}
	if len(files) == 0 {
		return executor.Spec{}, errNoSource
	}
	limits := clampLimits(lang.DefaultLimits(), req.Limits)
	return lang.BuildSpec(files, req.Stdin, req.Args, limits, req.Network), nil
}

type execRequest struct {
	Language string          `json:"language"`
	Version  string          `json:"version"`
	Code     string          `json:"code"`  // convenience: single source file
	Files    []executor.File `json:"files"` // or explicit multi-file
	Stdin    string          `json:"stdin"`
	Args     []string        `json:"args"`
	Limits   *limitsOverride `json:"limits"`
	Network  bool            `json:"network"`
}

type limitsOverride struct {
	MemoryBytes *int64   `json:"memoryBytes"`
	CPUs        *float64 `json:"cpus"`
	Pids        *int     `json:"pids"`
	OutputBytes *int64   `json:"outputBytes"`
	WallTimeMs  *int     `json:"wallTimeMs"`
}

type runResult struct {
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exitCode"`
	TimedOut   bool   `json:"timedOut"`
	OOMKilled  bool   `json:"oomKilled"`
	Truncated  bool   `json:"truncated"`
	DurationMs int64  `json:"durationMs"`
	Network    bool   `json:"network"` // whether filtered egress was actually applied
}

type execResponse struct {
	Language string    `json:"language"`
	Version  string    `json:"version"`
	Backend  string    `json:"backend"`
	Run      runResult `json:"run"`
	Warning  string    `json:"warning,omitempty"`
}

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request) {
	var req execRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if strings.TrimSpace(req.Language) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "language_required"})
		return
	}
	lang, ok := s.Reg.Resolve(req.Language, req.Version)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "unknown_language", "detail": fmt.Sprintf("%q is not a known runtime; see GET /runtimes", req.Language),
		})
		return
	}

	spec, err := s.buildSpec(lang, req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no_source", "detail": "provide `code` or `files`"})
		return
	}

	// SSE STREAMING stays on the DIRECT path: it acquires the global concurrency
	// gate inline and runs locally, because a broker cannot stream live stdout
	// chunks back to this HTTP connection. This is byte-for-byte today's behaviour.
	if wantsSSE(r) {
		// Global concurrency gate. If saturated, shed load with 429 + Retry-After.
		if !s.Sema.Acquire(r.Context(), s.AcquireWait) {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "capacity", "detail": "no free execution slot"})
			return
		}
		defer s.Sema.Release()
		s.executeSSE(w, r, lang.Name, lang.Version, spec)
		return
	}

	// BUFFERED one-shot: route through the Queue seam. The default "inproc" driver
	// runs the job locally via the Runner, which itself acquires/releases the same
	// global Sema (returning capacity errors) — so this is identical to the old
	// direct path on a single node. A "valkey" driver dispatches to a worker pool.
	res, err := s.Queue.Submit(r.Context(), queue.Job{
		ID:       uuid.NewString(),
		Language: lang.Name,
		Version:  lang.Version,
		Spec:     spec,
	})
	if err != nil {
		if errors.Is(err, errCapacity) {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "capacity", "detail": "no free execution slot"})
			obs.M().ExecTotal("rejected")
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "execution_failed", "detail": err.Error()})
		obs.M().ExecTotal("error")
		return
	}
	obs.M().ExecTotal("ok")
	resp := execResponse{
		Language: lang.Name, Version: lang.Version, Backend: s.Exec.Name(),
		Run: toRunResult(res),
	}
	if spec.Network && !res.Network {
		resp.Warning = "network requested but currently unavailable (egress firewall not verified); ran with network OFF"
	}
	writeJSON(w, http.StatusOK, resp)
}

// errCapacity signals the local concurrency gate is saturated. It is returned by
// the queue Runner and mapped to 429 + Retry-After by handleExecute.
var errCapacity = errors.New("no free execution slot")

// executeSSE streams stdout/stderr chunks as Server-Sent Events, then a final
// `done` event carrying the structured result. Requires the proxy to disable
// buffering (Caddy flush_interval -1).
func (s *Server) executeSSE(w http.ResponseWriter, r *http.Request, name, version string, spec executor.Spec) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming_unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	sink := &sseSink{w: w, flusher: flusher}
	res, err := s.Exec.Execute(r.Context(), spec, sink)
	if err != nil {
		obs.M().ExecTotal("error")
		sink.event("error", map[string]any{"error": err.Error()})
		return
	}
	obs.M().ExecTotal("ok")
	done := map[string]any{
		"language": name, "version": version, "backend": s.Exec.Name(),
		"run": toRunResult(res),
	}
	if spec.Network && !res.Network {
		done["warning"] = "network requested but currently unavailable (egress firewall not verified); ran with network OFF"
	}
	sink.event("done", done)
}

func toRunResult(res executor.Result) runResult {
	return runResult{
		Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode,
		TimedOut: res.TimedOut, OOMKilled: res.OOMKilled, Truncated: res.Truncated,
		DurationMs: res.DurationMs, Network: res.Network,
	}
}

func wantsSSE(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/event-stream") ||
		r.URL.Query().Get("stream") == "1"
}

// sseSink forwards live output chunks as SSE events. Safe for concurrent use.
type sseSink struct {
	w       http.ResponseWriter
	flusher http.Flusher
	mu      sync.Mutex
}

func (s *sseSink) Stdout(b []byte) { s.event("stdout", map[string]string{"chunk": string(b)}) }
func (s *sseSink) Stderr(b []byte) { s.event("stderr", map[string]string{"chunk": string(b)}) }

func (s *sseSink) event(name string, payload any) {
	data, _ := json.Marshal(payload)
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", name, data)
	s.flusher.Flush()
}

// clampLimits starts from the language defaults, applies any caller overrides,
// and clamps every field to the global hard ceiling. A caller can only ever
// request equal-or-tighter bounds than the defaults allow up to the ceiling.
func clampLimits(def executor.Limits, o *limitsOverride) executor.Limits {
	l := def
	if o != nil {
		if o.MemoryBytes != nil {
			l.MemoryBytes = *o.MemoryBytes
		}
		if o.CPUs != nil {
			l.CPUs = *o.CPUs
		}
		if o.Pids != nil {
			l.Pids = *o.Pids
		}
		if o.OutputBytes != nil {
			l.OutputBytes = *o.OutputBytes
		}
		if o.WallTimeMs != nil {
			l.WallTimeMs = *o.WallTimeMs
		}
	}
	l.MemoryBytes = clamp64(l.MemoryBytes, 8<<20, maxMemoryBytes)
	l.OutputBytes = clamp64(l.OutputBytes, 1<<10, maxOutputBytes)
	l.Pids = clampInt(l.Pids, 1, maxPids)
	l.WallTimeMs = clampInt(l.WallTimeMs, 100, maxWallTimeMs)
	if l.CPUs < 0.1 {
		l.CPUs = 0.1
	}
	if l.CPUs > maxCPUs {
		l.CPUs = maxCPUs
	}
	return l
}

func clamp64(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
