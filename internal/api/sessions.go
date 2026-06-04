package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/siinghd/isobox/internal/session"
)

const maxSessionUpload = 16 << 20 // 16 MiB per file upload (workspace quota bounds the total)

type createSessionRequest struct {
	Runtime string `json:"runtime"`
	TTLSec  int    `json:"ttlSec"`
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
	sess, err := s.Sessions.Create(req.Runtime, session.CreateOpts{TTL: time.Duration(req.TTLSec) * time.Second})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "create_failed", "detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, createSessionResponse{
		ID: sess.ID, Token: sess.Token, Runtime: sess.Runtime, Type: sess.Type, CreatedAt: sess.CreatedAt,
	})
}

// POST /v1/sessions/{id}/exec — run one step sharing the session /workspace.
func (s *Server) handleSessionExec(w http.ResponseWriter, r *http.Request) {
	id, token := chi.URLParam(r, "id"), sessionToken(r)
	runtime, err := s.Sessions.Runtime(id, token) // token-checked
	if err != nil {
		writeSessErr(w, err)
		return
	}
	var req execRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json", "detail": err.Error()})
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
		res, err := s.Sessions.Exec(r.Context(), id, token, spec, sink)
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

	res, err := s.Sessions.Exec(r.Context(), id, token, spec, nil)
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

// GET /v1/sessions/{id}/fs?path=...  — dir => JSON listing, file => raw bytes.
func (s *Server) handleSessionFSGet(w http.ResponseWriter, r *http.Request) {
	id, token := chi.URLParam(r, "id"), sessionToken(r)
	path := r.URL.Query().Get("path")
	fi, err := s.Sessions.Stat(id, token, path)
	if err != nil {
		writeSessErr(w, err)
		return
	}
	if fi.Dir {
		entries, err := s.Sessions.ListDir(id, token, path)
		if err != nil {
			writeSessErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"path": path, "dir": true, "entries": entries})
		return
	}
	data, err := s.Sessions.ReadFile(id, token, path)
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
	if err := s.Sessions.WriteFile(id, token, path, data); err != nil {
		writeSessErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": path, "bytes": len(data)})
}

// DELETE /v1/sessions/{id}/fs?path=...
func (s *Server) handleSessionFSDelete(w http.ResponseWriter, r *http.Request) {
	id, token := chi.URLParam(r, "id"), sessionToken(r)
	if err := s.Sessions.DeletePath(id, token, r.URL.Query().Get("path")); err != nil {
		writeSessErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DELETE /v1/sessions/{id}
func (s *Server) handleDestroySession(w http.ResponseWriter, r *http.Request) {
	if err := s.Sessions.Destroy(chi.URLParam(r, "id"), sessionToken(r)); err != nil {
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
	case errors.Is(err, os.ErrNotExist):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not_found"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal", "detail": err.Error()})
	}
}
