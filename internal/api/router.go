// Package api is the HTTP control plane: routing, validation, auth, rate
// limiting, the global concurrency gate, and the execute/runtimes/health
// endpoints. It is stateless — every execution is independent — so the binary
// scales horizontally behind a load balancer.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/siinghd/isobox/internal/executor"
	"github.com/siinghd/isobox/internal/registry"
	"github.com/siinghd/isobox/internal/sched"
	"github.com/siinghd/isobox/internal/web"
)

// Hard ceilings. Per-request overrides are clamped to these regardless of the
// language defaults — a caller can ask for less, never more.
const (
	maxMemoryBytes = 512 << 20 // 512 MiB
	maxOutputBytes = 256 << 10 // 256 KiB
	maxWallTimeMs  = 20_000     // 20 s
	maxPids        = 256
	maxCPUs        = 2.0
	maxBodyBytes   = 256 << 10 // 256 KiB request body
)

// Server holds the wired dependencies shared by all handlers.
type Server struct {
	Reg         *registry.Registry
	Exec        executor.Executor
	Sema        *sched.Limiter
	APIKey      string        // if non-empty, required via Bearer or X-API-Key
	AcquireWait time.Duration // max wait for a concurrency slot before 429
	ipLimiter   *ipLimiter
}

// Config parameterises Router construction.
type Config struct {
	APIKey         string
	AcquireWait    time.Duration
	RatePerMin     int
	RateBurst      int
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

	// Embedded playground UI.
	r.Get("/", web.Handler())

	// Unauthenticated, cheap endpoints.
	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)
	r.Get("/runtimes", s.handleRuntimes)

	// Execution endpoints: body cap -> rate limit -> auth.
	r.Group(func(r chi.Router) {
		r.Use(maxBody(maxBodyBytes))
		r.Use(s.ipLimiter.middleware)
		r.Use(s.authMiddleware)
		r.Post("/execute", s.handleExecute)
	})

	return r
}

// --- middleware & helpers --------------------------------------------------

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.APIKey == "" { // open mode (public demo) — rate limit still applies
			next.ServeHTTP(w, r)
			return
		}
		key := r.Header.Get("X-API-Key")
		if key == "" {
			if b := r.Header.Get("Authorization"); len(b) > 7 && b[:7] == "Bearer " {
				key = b[7:]
			}
		}
		if subtle.ConstantTimeCompare([]byte(key), []byte(s.APIKey)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
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
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
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
