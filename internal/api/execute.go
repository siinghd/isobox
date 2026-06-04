package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/siinghd/isobox/internal/executor"
)

type execRequest struct {
	Language string            `json:"language"`
	Version  string            `json:"version"`
	Code     string            `json:"code"`  // convenience: single source file
	Files    []executor.File   `json:"files"` // or explicit multi-file
	Stdin    string            `json:"stdin"`
	Args     []string          `json:"args"`
	Limits   *limitsOverride   `json:"limits"`
	Network  bool              `json:"network"`
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

	files := req.Files
	if len(files) == 0 && req.Code != "" {
		files = []executor.File{{Name: lang.SourceFile, Content: req.Code}}
	}
	if len(files) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no_source", "detail": "provide `code` or `files`"})
		return
	}

	limits := clampLimits(lang.DefaultLimits(), req.Limits)
	spec := lang.BuildSpec(files, req.Stdin, req.Args, limits, req.Network)

	// Global concurrency gate. If saturated, shed load with 429 + Retry-After
	// rather than piling sandboxes onto a shared host.
	if !s.Sema.Acquire(r.Context(), s.AcquireWait) {
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "capacity", "detail": "no free execution slot"})
		return
	}
	defer s.Sema.Release()

	if wantsSSE(r) {
		s.executeSSE(w, r, lang.Name, lang.Version, spec)
		return
	}

	res, err := s.Exec.Execute(r.Context(), spec, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "execution_failed", "detail": err.Error()})
		return
	}
	resp := execResponse{
		Language: lang.Name, Version: lang.Version, Backend: s.Exec.Name(),
		Run: toRunResult(res),
	}
	if spec.Network && !res.Network {
		resp.Warning = "network requested but currently unavailable (egress firewall not verified); ran with network OFF"
	}
	writeJSON(w, http.StatusOK, resp)
}

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
		sink.event("error", map[string]any{"error": err.Error()})
		return
	}
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
