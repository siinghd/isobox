package api

// HTTP control plane for tier-2 long-term FILESYSTEM memory: named, persistent
// volumes that survive sessions and re-attach as a RW bind-mount at /memory.
//
// SECURITY: the tenant is read ONLY from the request context (auth.TenantFrom,
// set by authMiddleware from the server-derived sha256(apiKey)). It is NEVER read
// from a body/query/path/header. volumeId from the request is only ever the `id`
// argument to the tenant-scoped manager — never a tenant source — so a volume of
// another tenant fails the tenant-scoped index lookup with ErrVolNotFound (404),
// not a cross-tenant attach.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/siinghd/isobox/internal/memory"
)

type createVolumeRequest struct {
	Name string `json:"name"` // display name; unique within the tenant; never a path component
}

// POST /v1/volumes — create a named volume for the caller's tenant.
func (s *Server) handleCreateVolume(w http.ResponseWriter, r *http.Request) {
	tenant, ok := reqTenant(w, r)
	if !ok {
		return
	}
	var req createVolumeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json", "detail": err.Error()})
		return
	}
	info, err := s.Volumes.Create(tenant, memory.CreateOpts{Name: req.Name})
	if err != nil {
		writeVolErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

// GET /v1/volumes — list the caller tenant's volumes.
func (s *Server) handleListVolumes(w http.ResponseWriter, r *http.Request) {
	tenant, ok := reqTenant(w, r)
	if !ok {
		return
	}
	vols, err := s.Volumes.List(tenant)
	if err != nil {
		writeVolErr(w, err)
		return
	}
	if vols == nil {
		vols = []memory.Info{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"volumes": vols})
}

// GET /v1/volumes/{id} — one volume, tenant-scoped.
func (s *Server) handleGetVolume(w http.ResponseWriter, r *http.Request) {
	tenant, ok := reqTenant(w, r)
	if !ok {
		return
	}
	info, err := s.Volumes.Get(tenant, chi.URLParam(r, "id"))
	if err != nil {
		writeVolErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// DELETE /v1/volumes/{id} — refuses while RW-attached (409). Tenant-scoped.
func (s *Server) handleDeleteVolume(w http.ResponseWriter, r *http.Request) {
	tenant, ok := reqTenant(w, r)
	if !ok {
		return
	}
	if err := s.Volumes.Delete(tenant, chi.URLParam(r, "id")); err != nil {
		writeVolErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeVolErr maps memory.Manager errors to HTTP status codes. Shared by the
// volume handlers and the volume-attach path inside handleCreateSession.
func writeVolErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, memory.ErrVolNotFound):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "volume_not_found"})
	case errors.Is(err, memory.ErrExists):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "volume_name_exists"})
	case errors.Is(err, memory.ErrVolumeLocked):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "volume_locked", "detail": "attached read-write by another session"})
	case errors.Is(err, memory.ErrBusy):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "volume_busy", "detail": "attached; detach or destroy the session first"})
	case errors.Is(err, memory.ErrVolQuota):
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "volume_quota_exceeded", "detail": "delete the volume or write a smaller replacement"})
	case errors.Is(err, memory.ErrDiskFull):
		writeJSON(w, http.StatusInsufficientStorage, map[string]any{"error": "storage_full", "detail": "volume storage ceiling reached"})
	case errors.Is(err, memory.ErrTooMany):
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too_many_volumes"})
	case errors.Is(err, memory.ErrBadName):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_name"})
	case errors.Is(err, memory.ErrBadID), errors.Is(err, memory.ErrBadTenant), errors.Is(err, memory.ErrContainment):
		// ErrBadTenant/ErrContainment are server-derived invariants; a caller can
		// only legitimately trip ErrBadID (malformed volumeId).
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal", "detail": err.Error()})
	}
}
