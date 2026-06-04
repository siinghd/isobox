package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/siinghd/isobox/internal/auth"
	"github.com/siinghd/isobox/internal/executor"
	"github.com/siinghd/isobox/internal/session"
)

const maxSessionUpload = 16 << 20 // 16 MiB per file upload (workspace quota bounds the total)

type createSessionRequest struct {
	Runtime  string `json:"runtime"`
	TTLSec   int    `json:"ttlSec"`
	VolumeID string `json:"volumeId"` // OPTIONAL: a memory volume to attach RW at /memory.
	// Type selects the session kind: "" / "filesystem" (default, zero-RAM at rest)
	// or "kernel" (Phase 4: a resident container with a persistent Python namespace
	// so variables/imports survive across exec steps). Defaulted server-side.
	Type string `json:"type"`
}

// reqTenant pulls the server-derived tenant from the context authMiddleware set.
// If it is absent the request bypassed authMiddleware — a routing bug — and we
// MUST fail closed (500) rather than silently default to "public". ok==false
// means the handler should 500 and stop.
func reqTenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenant, ok := auth.TenantFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "no_tenant", "detail": "request reached handler without a resolved tenant"})
		return "", false
	}
	return tenant, true
}

type createSessionResponse struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"` // capability token — required on every /v1/sessions/{id}/* call
	Runtime   string    `json:"runtime"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"createdAt"`
}

func sessionToken(r *http.Request) string { return r.Header.Get("X-Session-Token") }

// POST /v1/sessions
func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req createSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json", "detail": err.Error()})
		return
	}
	if req.Runtime == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "runtime_required", "detail": "see GET /runtimes"})
		return
	}
	tenant, ok := reqTenant(w, r)
	if !ok {
		return
	}

	stype := req.Type
	if stype == "" {
		stype = "filesystem"
	}

	// KERNEL sessions bake their /workspace + /memory binds into a LONG-LIVED
	// container at Create time, so a /memory volume must be attached BEFORE Create
	// (a post-Create attach would never appear in the already-running kernel).
	// We PRE-MINT the session id here so it is the RW-lock holder passed to Attach;
	// the holder MUST equal the final session id or OnDrop's ReleaseAll(id) could
	// never clear the lock. The id is passed via CreateOpts.ID (handler-set, never
	// from request JSON). On any failure before/at Create we release the hold so we
	// never leak a lock on a session we don't return.
	if stype == "kernel" {
		s.createKernelSession(w, r, tenant, req)
		return
	}

	// FILESYSTEM path (unchanged): mint the session FIRST so we have its id to use
	// as the RW lock holder, then attach the requested volume. volumeId from the
	// body is ONLY ever the `id` arg to Attach(tenant, ...) — it never derives or
	// overrides the tenant, so a volume of another tenant fails the key(tenant,id)
	// lookup with ErrVolNotFound (404), not a cross-tenant attach. On attach
	// failure we roll the session back.
	sess, err := s.Sessions.Create(req.Runtime, session.CreateOpts{
		TTL:    time.Duration(req.TTLSec) * time.Second,
		Tenant: tenant,
		Type:   stype,
	})
	if err != nil {
		writeCreateSessErr(w, err)
		return
	}

	if req.VolumeID != "" {
		if s.Volumes == nil {
			_ = s.Sessions.Destroy(sess.ID, sess.Token, tenant)
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "volumes_disabled"})
			return
		}
		hostPath, _, aerr := s.Volumes.Attach(tenant, req.VolumeID, sess.ID, true)
		if aerr != nil {
			_ = s.Sessions.Destroy(sess.ID, sess.Token, tenant) // roll back the just-created session
			writeVolErr(w, aerr)
			return
		}
		// Register the /memory mount so EVERY exec step replays it. If this fails
		// (e.g. the session vanished between Create and now), release the RW hold
		// and roll back so we never leak a lock on a session we don't return.
		if err := s.Sessions.SetMounts(sess.ID, sess.Token, tenant, []executor.Mount{
			{HostPath: hostPath, Target: "/memory", RW: true},
		}); err != nil {
			s.Volumes.Release(tenant, req.VolumeID, sess.ID)
			_ = s.Sessions.Destroy(sess.ID, sess.Token, tenant)
			writeSessErr(w, err)
			return
		}
	}

	writeJSON(w, http.StatusCreated, createSessionResponse{
		ID: sess.ID, Token: sess.Token, Runtime: sess.Runtime, Type: sess.Type, CreatedAt: sess.CreatedAt,
	})
}

// createKernelSession handles type="kernel" Create: it pre-mints the id, attaches
// any /memory volume RW under that id, then Creates the kernel with the /memory
// mount baked in via ExtraMounts. On any failure it releases the volume hold so a
// kernel we never return cannot leak the RW lock.
func (s *Server) createKernelSession(w http.ResponseWriter, _ *http.Request, tenant string, req createSessionRequest) {
	id := session.MintID()

	var extra []executor.Mount
	if req.VolumeID != "" {
		if s.Volumes == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "volumes_disabled"})
			return
		}
		hostPath, _, aerr := s.Volumes.Attach(tenant, req.VolumeID, id, true)
		if aerr != nil {
			writeVolErr(w, aerr)
			return
		}
		extra = []executor.Mount{{HostPath: hostPath, Target: "/memory", RW: true}}
	}

	sess, err := s.Sessions.Create(req.Runtime, session.CreateOpts{
		TTL:         time.Duration(req.TTLSec) * time.Second,
		Tenant:      tenant,
		Type:        "kernel",
		ID:          id,
		ExtraMounts: extra,
	})
	if err != nil {
		if req.VolumeID != "" && s.Volumes != nil {
			s.Volumes.Release(tenant, req.VolumeID, id) // never leak the RW hold on a kernel we don't return
		}
		writeCreateSessErr(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, createSessionResponse{
		ID: sess.ID, Token: sess.Token, Runtime: sess.Runtime, Type: sess.Type, CreatedAt: sess.CreatedAt,
	})
}

// writeCreateSessErr maps Create errors (filesystem + kernel) to HTTP responses.
func writeCreateSessErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, session.ErrTooMany):
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too_many_sessions"})
	case errors.Is(err, session.ErrDiskFull):
		writeJSON(w, http.StatusInsufficientStorage, map[string]any{"error": "storage_full", "detail": "session storage ceiling reached"})
	case errors.Is(err, session.ErrKernelDisabled):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "kernel_disabled", "detail": "kernel sessions are not available on this backend"})
	case errors.Is(err, session.ErrKernelBusy):
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "kernel_busy", "detail": "no free kernel slot"})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "create_failed", "detail": err.Error()})
	}
}

// POST /v1/sessions/{id}/exec — run one step sharing the session /workspace.
func (s *Server) handleSessionExec(w http.ResponseWriter, r *http.Request) {
	id, token := chi.URLParam(r, "id"), sessionToken(r)
	tenant, ok := reqTenant(w, r)
	if !ok {
		return
	}
	// IsKernel authes (token + tenant constant-time checked) and tells us whether to
	// route to the resident-kernel exec path (code framed over docker-attach into a
	// persistent namespace) instead of building a fresh-container spec.
	isK, err := s.Sessions.IsKernel(id, token, tenant)
	if err != nil {
		writeSessErr(w, err)
		return
	}
	// Decode the request body ONCE here; both paths read from it.
	var req execRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json", "detail": err.Error()})
		return
	}

	// KERNEL path: a kernel needs neither runtime Resolve nor buildSpec — code is
	// exec()'d into the live namespace. Variables/imports persist across steps.
	if isK {
		s.handleKernelExec(w, r, id, token, tenant, req)
		return
	}

	runtime, err := s.Sessions.Runtime(id, token, tenant) // token + tenant checked
	if err != nil {
		writeSessErr(w, err)
		return
	}
	lang, ok := s.Reg.Resolve(runtime, "") // the session's own runtime; caller cannot change it
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "runtime_gone"})
		return
	}
	spec, err := s.buildSpec(lang, req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no_source", "detail": "provide `code` or `files`"})
		return
	}

	if wantsSSE(r) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming_unsupported"})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		sink := &sseSink{w: w, flusher: flusher}
		res, err := s.Sessions.Exec(r.Context(), id, token, tenant, spec, sink)
		if err != nil {
			sink.event("error", map[string]any{"error": err.Error()})
			return
		}
		done := map[string]any{"language": lang.Name, "version": lang.Version, "backend": s.Exec.Name(), "run": toRunResult(res)}
		if spec.Network && !res.Network {
			done["warning"] = "network requested but currently unavailable (egress firewall not verified); ran with network OFF"
		}
		sink.event("done", done)
		return
	}

	res, err := s.Sessions.Exec(r.Context(), id, token, tenant, spec, nil)
	if err != nil {
		writeSessErr(w, err)
		return
	}
	resp := execResponse{Language: lang.Name, Version: lang.Version, Backend: s.Exec.Name(), Run: toRunResult(res)}
	if spec.Network && !res.Network {
		resp.Warning = "network requested but currently unavailable (egress firewall not verified); ran with network OFF"
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleKernelExec runs one step inside a resident kernel session: the snippet is
// framed over the docker-attach channel into the kernel's PERSISTENT namespace, so
// variables/imports survive across calls (Code-Interpreter parity). The request
// body has already been decoded (and the session token+tenant checked) by the
// caller. `code` comes from req.Code, falling back to the first file's content.
// stepMs is the caller's per-step wall deadline (clamped engine-side). Supports
// both SSE streaming and a buffered JSON result.
func (s *Server) handleKernelExec(w http.ResponseWriter, r *http.Request, id, token, tenant string, req execRequest) {
	code := req.Code
	if code == "" && len(req.Files) > 0 {
		code = req.Files[0].Content
	}
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no_source", "detail": "provide `code`"})
		return
	}
	stepMs := 0
	if req.Limits != nil && req.Limits.WallTimeMs != nil {
		stepMs = *req.Limits.WallTimeMs
	}

	if wantsSSE(r) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming_unsupported"})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		sink := &sseSink{w: w, flusher: flusher}
		res, err := s.Sessions.KernelExec(r.Context(), id, token, tenant, code, stepMs, sink)
		if err != nil {
			sink.event("error", map[string]any{"error": err.Error()})
			return
		}
		sink.event("done", map[string]any{"backend": s.Exec.Name(), "type": "kernel", "run": toRunResult(res)})
		return
	}

	res, err := s.Sessions.KernelExec(r.Context(), id, token, tenant, code, stepMs, nil)
	if err != nil {
		writeSessErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, execResponse{Backend: s.Exec.Name(), Run: toRunResult(res)})
}

// GET /v1/sessions/{id}/fs?path=...  — dir => JSON listing, file => raw bytes.
func (s *Server) handleSessionFSGet(w http.ResponseWriter, r *http.Request) {
	id, token := chi.URLParam(r, "id"), sessionToken(r)
	tenant, ok := reqTenant(w, r)
	if !ok {
		return
	}
	path := r.URL.Query().Get("path")
	fi, err := s.Sessions.Stat(id, token, tenant, path)
	if err != nil {
		writeSessErr(w, err)
		return
	}
	if fi.Dir {
		entries, err := s.Sessions.ListDir(id, token, tenant, path)
		if err != nil {
			writeSessErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"path": path, "dir": true, "entries": entries})
		return
	}
	data, err := s.Sessions.ReadFile(id, token, tenant, path)
	if err != nil {
		writeSessErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

// PUT /v1/sessions/{id}/fs?path=...  — upload a file (raw body), quota-checked.
func (s *Server) handleSessionFSPut(w http.ResponseWriter, r *http.Request) {
	id, token := chi.URLParam(r, "id"), sessionToken(r)
	tenant, ok := reqTenant(w, r)
	if !ok {
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "path_required"})
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSessionUpload))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "too_large", "detail": err.Error()})
		return
	}
	if err := s.Sessions.WriteFile(id, token, tenant, path, data); err != nil {
		writeSessErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": path, "bytes": len(data)})
}

// DELETE /v1/sessions/{id}/fs?path=...
func (s *Server) handleSessionFSDelete(w http.ResponseWriter, r *http.Request) {
	id, token := chi.URLParam(r, "id"), sessionToken(r)
	tenant, ok := reqTenant(w, r)
	if !ok {
		return
	}
	if err := s.Sessions.DeletePath(id, token, tenant, r.URL.Query().Get("path")); err != nil {
		writeSessErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DELETE /v1/sessions/{id}
func (s *Server) handleDestroySession(w http.ResponseWriter, r *http.Request) {
	tenant, ok := reqTenant(w, r)
	if !ok {
		return
	}
	if err := s.Sessions.Destroy(chi.URLParam(r, "id"), sessionToken(r), tenant); err != nil {
		writeSessErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeSessErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, session.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session_not_found"})
	case errors.Is(err, session.ErrForbidden):
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_session_token"})
	case errors.Is(err, session.ErrCapacity):
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "capacity"})
	case errors.Is(err, session.ErrQuota):
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "quota_exceeded", "detail": "workspace disk quota exceeded"})
	case errors.Is(err, session.ErrPath):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_path"})
	case errors.Is(err, session.ErrIsDir):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "is_a_directory"})
	case errors.Is(err, session.ErrKernelDisabled):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "kernel_disabled", "detail": "kernel sessions are not available on this backend"})
	case errors.Is(err, session.ErrKernelBusy):
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "kernel_busy", "detail": "no free kernel slot"})
	case errors.Is(err, session.ErrWrongType):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "wrong_session_type", "detail": "operation not valid for this session type"})
	case errors.Is(err, os.ErrNotExist):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not_found"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal", "detail": err.Error()})
	}
}
