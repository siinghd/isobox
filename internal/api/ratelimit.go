package api

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipLimiter is a per-client-IP token bucket. chi's RealIP middleware has already
// resolved r.RemoteAddr from X-Real-IP / CF-Connecting-IP (set by Caddy), so the
// key is the true client IP even behind Cloudflare.
type ipLimiter struct {
	mu      sync.Mutex
	clients map[string]*entry
	rate    rate.Limit
	burst   int
}

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

func newIPLimiter(perMin, burst int) *ipLimiter {
	if perMin <= 0 {
		perMin = 30
	}
	if burst <= 0 {
		burst = 10
	}
	l := &ipLimiter{
		clients: make(map[string]*entry),
		rate:    rate.Limit(float64(perMin) / 60.0),
		burst:   burst,
	}
	go l.janitor()
	return l
}

func (i *ipLimiter) get(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()
	e, ok := i.clients[ip]
	if !ok {
		e = &entry{lim: rate.NewLimiter(i.rate, i.burst)}
		i.clients[ip] = e
	}
	e.seen = time.Now()
	return e.lim
}

// janitor evicts idle buckets so memory does not grow with unique IPs.
func (i *ipLimiter) janitor() {
	t := time.NewTicker(10 * time.Minute)
	for range t.C {
		i.mu.Lock()
		for ip, e := range i.clients {
			if time.Since(e.seen) > 15*time.Minute {
				delete(i.clients, ip)
			}
		}
		i.mu.Unlock()
	}
}

func (i *ipLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !i.get(clientIP(r)).Allow() {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate_limited"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP resolves the rate-limit key WITHOUT trusting spoofable headers. The
// genuine TCP peer is authoritative; the proxy-set X-Real-IP is trusted ONLY
// when that peer is loopback (i.e. our co-located reverse proxy, which
// overwrites X-Real-IP from CF-Connecting-IP). This defeats the header-rotation
// bypass where a client forges True-Client-IP / X-Forwarded-For to get a fresh
// bucket per request. (chi's RealIP middleware is deliberately NOT used.)
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
			return xr
		}
	}
	return host
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"ip", clientIP(r),
			"ms", time.Since(start).Milliseconds(),
		)
	})
}
