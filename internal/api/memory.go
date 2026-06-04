package api

// HTTP control plane for tier-3 long-term STRUCTURED memory: an embedded,
// per-tenant bbolt key/value store with native TTL.
//
//	PUT    /v1/memory/{namespace}/{key}   write   (X-TTL-Seconds, Content-Type)
//	GET    /v1/memory/{namespace}/{key}   read    (-> ETag, X-Expires-At)
//	DELETE /v1/memory/{namespace}/{key}   delete
//	GET    /v1/memory/{namespace}?prefix=&limit=&cursor=   list keys (paginated)
//
// SECURITY: tenant is read ONLY from auth.TenantFrom(ctx) — never from a request
// field. The namespace and key come from the path and are validated INSIDE the
// store (validNamespace charset; key is opaque bytes within the tenant's bucket),
// so neither can traverse out of the tenant's <tenant>.bolt file.

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/siinghd/isobox/internal/memory"
)

const maxKVValue = 8 << 20 // mirrors memory.MaxValueLen; the route body cap

// PUT /v1/memory/{namespace}/{key}
func (s *Server) handleKVPut(w http.ResponseWriter, r *http.Request) {
	tenant, ok := reqTenant(w, r)
	if !ok {
		return
	}
	ns, key := chi.URLParam(r, "namespace"), chi.URLParam(r, "key")

	// Host free-disk floor: refuse new writes before the shared disk is exhausted
	// (the per-tenant 10MiB/10k caps bound one tenant; this bounds the aggregate).
	if s.Memory.DiskFull() {
		writeJSON(w, http.StatusInsufficientStorage, map[string]any{"error": "storage_full", "detail": "kv storage floor reached"})
		return
	}

	val, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxKVValue))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "too_large"})
		return
	}
	var ttl time.Duration
	if v := r.Header.Get("X-TTL-Seconds"); v != "" {
		secs, perr := strconv.Atoi(v)
		if perr != nil || secs < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_ttl"})
			return
		}
		ttl = time.Duration(secs) * time.Second
	}
	ct := r.Header.Get("Content-Type")
	if err := s.Memory.Put(tenant, ns, key, val, ct, ttl); err != nil {
		writeKVErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /v1/memory/{namespace}/{key}
func (s *Server) handleKVGet(w http.ResponseWriter, r *http.Request) {
	tenant, ok := reqTenant(w, r)
	if !ok {
		return
	}
	ns, key := chi.URLParam(r, "namespace"), chi.URLParam(r, "key")
	val, ct, expiresAt, etag, err := s.Memory.Get(tenant, ns, key)
	if err != nil {
		writeKVErr(w, err)
		return
	}
	if etag != "" {
		w.Header().Set("ETag", etag)
		// Conditional GET: if the caller already has this exact value, 304.
		if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	if !expiresAt.IsZero() {
		w.Header().Set("X-Expires-At", expiresAt.UTC().Format(time.RFC3339))
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	_, _ = w.Write(val)
}

// DELETE /v1/memory/{namespace}/{key}
func (s *Server) handleKVDelete(w http.ResponseWriter, r *http.Request) {
	tenant, ok := reqTenant(w, r)
	if !ok {
		return
	}
	ns, key := chi.URLParam(r, "namespace"), chi.URLParam(r, "key")
	if err := s.Memory.Delete(tenant, ns, key); err != nil {
		writeKVErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /v1/memory/{namespace}?prefix=&limit=&cursor=
func (s *Server) handleKVList(w http.ResponseWriter, r *http.Request) {
	tenant, ok := reqTenant(w, r)
	if !ok {
		return
	}
	ns := chi.URLParam(r, "namespace")
	q := r.URL.Query()
	limit := 0
	if v := q.Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v) // store clamps <=0 or >1000 to a sane default
	}
	keys, next, err := s.Memory.List(tenant, ns, q.Get("prefix"), limit, q.Get("cursor"))
	if err != nil {
		writeKVErr(w, err)
		return
	}
	if keys == nil {
		keys = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"namespace": ns, "keys": keys, "nextCursor": next})
}

// writeKVErr maps memory.Store errors to HTTP. ErrKVTenant is a server-derived
// invariant (the context tenant is always valid hex or "public") so it can only
// mean a bug -> 500.
func writeKVErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, memory.ErrKVNotFound):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not_found"})
	case errors.Is(err, memory.ErrKVQuota):
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "quota_exceeded", "detail": "tenant kv quota (10MiB / 10k keys) exceeded"})
	case errors.Is(err, memory.ErrKVValueSize):
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "value_too_large"})
	case errors.Is(err, memory.ErrKVNamespace):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_namespace"})
	case errors.Is(err, memory.ErrKVKey):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_key"})
	case errors.Is(err, memory.ErrKVTenant), errors.Is(err, memory.ErrKVClosed):
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal", "detail": err.Error()})
	}
}
