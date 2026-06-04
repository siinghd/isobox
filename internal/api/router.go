// Package api is the HTTP control plane: routing, validation, auth, rate
// limiting, the global concurrency gate, and the execute/runtimes/health
// endpoints. It is stateless — every execution is independent — so the binary
// scales horizontally behind a load balancer.
package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/siinghd/isobox/internal/auth"
	"github.com/siinghd/isobox/internal/executor"
	"github.com/siinghd/isobox/internal/memory"
	"github.com/siinghd/isobox/internal/queue"
	"github.com/siinghd/isobox/internal/registry"
	"github.com/siinghd/isobox/internal/sched"
	"github.com/siinghd/isobox/internal/session"
	"github.com/siinghd/isobox/internal/web"
)

// Hard ceilings. Per-request overrides are clamped to these regardless of the
// language defaults — a caller can ask for less, never more.
const (
	maxMemoryBytes = 512 << 20 // 512 MiB
	maxOutputBytes = 256 << 10 // 256 KiB
	maxWallTimeMs  = 20_000    // 20 s
	maxPids        = 256
	maxCPUs        = 2.0
	maxBodyBytes   = 256 << 10 // 256 KiB request body
)

// Server holds the wired dependencies shared by all handlers.
type Server struct {
	Reg      *registry.Registry
	Exec     executor.Executor
	Sema     *sched.Limiter
	Sessions *session.Manager // stateful sessions (v2); nil disables /v1/sessions
	Volumes  *memory.Manager  // tier-2 filesystem volumes; nil disables /v1/volumes
	Memory   *memory.Store    // tier-3 bbolt KV; nil disables /v1/memory

	// Queue is the OPTIONAL job-distribution seam for buffered (non-SSE) /execute.
	// Default driver is "inproc" — the verbatim direct path — so wiring it changes
	// nothing on a single node. nil also means the direct path (defensive). The SSE
	// path never routes through the queue (a broker can't stream live chunks back).
	Queue queue.Queue

	// Pool is the optional warm-container pool, reported by /metrics. It is the SAME
	// object set as Exec when enabled; held separately only so /metrics can read its
	// size without a type assertion. nil => disabled.
	Pool *executor.WarmPool

	// Keys is the single auth gate: it resolves an API key to a server-derived
	// tenant id. There is NO separate APIKey field — that second gate was deleted
	// so the keystore is the only authority (red-team: avoid a confusing second
	// gate that never derives a tenant).
	Keys *auth.KeyStore

	// RequireAuth: if true, a request with no API key is rejected (401) instead of
	// running as the shared public tenant. Default false (open). MemoryRequireKey:
	// if true, /v1/memory + /v1/volumes require a real (non-public) tenant — i.e. an
	// API key — so anonymous callers can't share/abuse public memory, while the rest
	// of the API stays open.
	RequireAuth      bool
	MemoryRequireKey bool

	AcquireWait time.Duration // max wait for a concurrency slot before 429
	ipLimiter   *ipLimiter
}

// Config parameterises Router construction.
type Config struct {
	AcquireWait time.Duration
	RatePerMin  int
	RateBurst   int
}

// Router builds the chi router with all middleware and routes.
func (s *Server) Router(cfg Config) http.Handler {
	if s.AcquireWait <= 0 {
		s.AcquireWait = 2 * time.Second
	}
	s.ipLimiter = newIPLimiter(cfg.RatePerMin, cfg.RateBurst)

	r := chi.NewRouter()
	// NOTE: middleware.RealIP is intentionally NOT used — it ranks spoofable
	// headers (True-Client-IP/X-Forwarded-For) above the trusted one, which would
	// let a caller rotate the rate-limit key. clientIP() resolves the IP safely.
	r.Use(middleware.Recoverer)
	r.Use(requestLogger)
	r.Use(corsMiddleware)

	// Embedded chatbot UI + docs (agent- and machine-readable).
	r.Get("/", web.Handler())
	r.Get("/llms.txt", web.LLMs())
	r.Get("/openapi.yaml", web.OpenAPI())
	// Self-hosted flux-md bundle (JS + Web Worker + WASM + CSS) for the chatbot UI.
	// Served with explicit MIME types (application/wasm, text/javascript) inside the
	// handler — required for WebAssembly streaming-compile and the module worker.
	r.Handle("/assets/*", web.Assets())

	// Unauthenticated, cheap endpoints.
	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)
	r.Get("/runtimes", s.handleRuntimes)
	r.Get("/metrics", s.handleMetrics)

	// Execution endpoints: body cap -> rate limit -> auth.
	r.Group(func(r chi.Router) {
		r.Use(maxBody(maxBodyBytes))
		r.Use(s.ipLimiter.middleware)
		r.Use(s.authMiddleware)
		r.Post("/execute", s.handleExecute)
	})

	// Stateful sessions (v2): rate limit + global auth; per-session capability
	// token is checked inside each handler. File uploads get a larger body cap.
	if s.Sessions != nil {
		r.Group(func(r chi.Router) {
			r.Use(s.ipLimiter.middleware)
			r.Use(s.authMiddleware)
			r.With(maxBody(maxBodyBytes)).Post("/v1/sessions", s.handleCreateSession)
			r.With(maxBody(maxBodyBytes)).Post("/v1/sessions/{id}/exec", s.handleSessionExec)
			r.Get("/v1/sessions/{id}/fs", s.handleSessionFSGet)
			r.With(maxBody(maxSessionUpload)).Put("/v1/sessions/{id}/fs", s.handleSessionFSPut)
			r.Delete("/v1/sessions/{id}/fs", s.handleSessionFSDelete)
			r.Delete("/v1/sessions/{id}", s.handleDestroySession)
		})
	}

	// Phase 3 tier-2: persistent filesystem VOLUMES. Tenant is server-derived in
	// authMiddleware; every handler reads it via auth.TenantFrom.
	if s.Volumes != nil {
		r.Group(func(r chi.Router) {
			r.Use(s.ipLimiter.middleware)
			r.Use(s.authMiddleware)
			r.Use(s.requireTenantKey)
			r.With(maxBody(maxBodyBytes)).Post("/v1/volumes", s.handleCreateVolume)
			r.Get("/v1/volumes", s.handleListVolumes)
			r.Get("/v1/volumes/{id}", s.handleGetVolume)
			r.Delete("/v1/volumes/{id}", s.handleDeleteVolume)
		})
	}

	// Phase 3 tier-3: structured KV MEMORY. PUT bodies are capped at the single
	// value size; list/get/delete carry no body.
	if s.Memory != nil {
		r.Group(func(r chi.Router) {
			r.Use(s.ipLimiter.middleware)
			r.Use(s.authMiddleware)
			r.Use(s.requireTenantKey)
			r.With(maxBody(maxKVValue)).Put("/v1/memory/{namespace}/{key}", s.handleKVPut)
			r.Get("/v1/memory/{namespace}/{key}", s.handleKVGet)
			r.Delete("/v1/memory/{namespace}/{key}", s.handleKVDelete)
			r.Get("/v1/memory/{namespace}", s.handleKVList)
		})
	}

	return r
}

// --- middleware & helpers --------------------------------------------------

// authMiddleware is the ONE auth gate. It resolves the API key to a
// server-derived tenant id via the keystore and stamps that tenant into the
// request context (auth.WithTenant). Every downstream handler reads the tenant
// ONLY via auth.TenantFrom — never from a body/query/path/header — which is the
// load-bearing multi-tenancy invariant.
//
//   - empty keystore  => open/demo mode: tenant = auth.PublicTenant, allowed.
//   - non-empty + match => tenant = hex(sha256(key)), allowed.
//   - non-empty + miss  => 401.
//
// Constant-time key comparison happens inside KeyStore.Resolve.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Trim whitespace so a stray space/newline doesn't hash to a different key
		// and 401 — configured keys are already trimmed at load (keystore), so this
		// removes that asymmetry.
		key := strings.TrimSpace(r.Header.Get("X-API-Key"))
		if key == "" {
			if b := r.Header.Get("Authorization"); len(b) > 7 && b[:7] == "Bearer " {
				key = strings.TrimSpace(b[7:])
			}
		}
		var tenant string
		if key == "" {
			// No key: open access as the shared public tenant, UNLESS the operator
			// requires auth globally. Keeps /execute + /v1/sessions open on the demo
			// while still allowing keyed (per-tenant) access.
			if s.RequireAuth {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
				return
			}
			tenant = auth.PublicTenant
		} else {
			t, ok := s.Keys.Resolve(key)
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
				return
			}
			tenant = t
		}
		next.ServeHTTP(w, r.WithContext(auth.WithTenant(r.Context(), tenant)))
	})
}

// requireTenantKey gates an endpoint on a real (non-public) tenant when
// MemoryRequireKey is set — i.e. a valid API key was supplied. Used for
// persistent memory/volumes so anonymous callers can't share/abuse the public
// tenant, while the rest of the API stays open.
func (s *Server) requireTenantKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.MemoryRequireKey {
			if t, _ := auth.TenantFrom(r.Context()); t == "" || t == auth.PublicTenant {
				writeJSON(w, http.StatusForbidden, map[string]any{
					"error":  "api_key_required",
					"detail": "persistent memory requires an API key (X-API-Key or Bearer); the rest of the API is open",
				})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func maxBody(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Session-Token, X-TTL-Seconds, If-None-Match")
		w.Header().Set("Access-Control-Expose-Headers", "ETag, X-Expires-At")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
