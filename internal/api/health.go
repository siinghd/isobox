package api

import (
	"net/http"
	"os"
	"strings"
)

// handleHealthz is a liveness probe: the process is up.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleReadyz is a readiness probe. It returns 200 only if the protective
// parent slice is actually memory-capped AND the isolation backend is healthy —
// refusing to serve untrusted code if the blast-radius ceiling is missing.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if !sliceCapped() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ready": false, "reason": "isobox.slice not memory-capped",
		})
		return
	}
	if err := s.Exec.HealthCheck(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ready": false, "reason": "backend: " + err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ready": true, "backend": s.Exec.Name()})
}

// sliceCapped reports whether isobox.slice has a finite memory.max. Reading the
// cgroup file directly avoids shelling out to systemctl.
func sliceCapped() bool {
	for _, p := range []string{
		"/sys/fs/cgroup/isobox.slice/memory.max",
		"/sys/fs/cgroup/system.slice/isobox.slice/memory.max",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		v := strings.TrimSpace(string(b))
		return v != "" && v != "max"
	}
	return false
}

type runtimeInfo struct {
	Language string   `json:"language"`
	Version  string   `json:"version"`
	Aliases  []string `json:"aliases"`
	Compiled bool     `json:"compiled"`
	Backend  string   `json:"backend"`
}

// handleRuntimes lists the available languages.
func (s *Server) handleRuntimes(w http.ResponseWriter, r *http.Request) {
	langs := s.Reg.All()
	out := make([]runtimeInfo, 0, len(langs))
	for _, l := range langs {
		out = append(out, runtimeInfo{
			Language: l.Name,
			Version:  l.Version,
			Aliases:  l.Aliases,
			Compiled: len(l.Compile) > 0,
			Backend:  s.Exec.Name(),
		})
	}
	writeJSON(w, http.StatusOK, out)
}
