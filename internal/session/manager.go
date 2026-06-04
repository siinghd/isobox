// Package session adds stateful sessions on top of the one-shot executor WITHOUT
// touching its verified hardening. A filesystem session is a per-session host
// directory bind-mounted RW at /workspace; each step is still a fresh hardened
// container (reusing executor.Execute via Spec.Mounts), so a session at rest
// costs zero RAM — only active steps consume a concurrency slot. Tenancy is an
// opaque per-session capability token, constant-time compared on every call;
// the control plane mounts only the matching session's directory.
package session

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/siinghd/isobox/internal/executor"
	"github.com/siinghd/isobox/internal/registry"
	"github.com/siinghd/isobox/internal/sched"
)

var (
	ErrNotFound  = errors.New("session not found")
	ErrForbidden = errors.New("invalid session token")
	ErrCapacity  = errors.New("no free execution slot")
	ErrQuota     = errors.New("workspace disk quota exceeded")
	ErrPath      = errors.New("invalid path")
	ErrIsDir     = errors.New("path is a directory")
	ErrDiskFull  = errors.New("session storage ceiling reached")
	ErrTooMany   = errors.New("too many sessions")
)

type Session struct {
	ID        string
	Token     string
	Runtime   string
	Type      string // "filesystem"
	Workspace string
	CreatedAt time.Time
	IdleTTL   time.Duration

	// Tenant is the SERVER-DERIVED tenant id (auth.TenantFrom at Create), pinned
	// for the life of the session. Every later op re-checks it (in addition to the
	// capability token) so a leaked/shared token alone cannot reach this session's
	// tenant-scoped /memory volume — the server-derived tenant, not just the
	// bearer token, is authoritative. Red-team RT2.
	Tenant string

	// ExtraMounts are mounts beyond /workspace that every Exec step must replay —
	// specifically an attached memory volume at /memory. Recording the attach is
	// not enough: Exec has to append these on each step or the mount never appears
	// in the sandbox. Set once at Create after a successful Attach. Advisor #2.
	ExtraMounts []executor.Mount

	mu           sync.Mutex
	lastActivity time.Time
}

func (s *Session) touch() { s.mu.Lock(); s.lastActivity = time.Now(); s.mu.Unlock() }
func (s *Session) idle() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastActivity)
}

// Info is a token-checked, safe-to-return view of a session.
type Info struct {
	ID        string    `json:"id"`
	Runtime   string    `json:"runtime"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"createdAt"`
	DiskBytes int64     `json:"diskBytes"`
}

type FileInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Dir     bool      `json:"dir"`
	ModTime time.Time `json:"modTime"`
}

// Manager owns session lifecycle. It is composed alongside the executor in the
// API server, never inside the Executor interface.
type Manager struct {
	Backend       executor.Executor
	Reg           *registry.Registry
	Sema          *sched.Limiter // shared global concurrency gate (same one /execute uses)
	Root          string
	AcquireWait   time.Duration
	DiskQuota     int64 // per-session workspace byte cap (enforced by the sweep, not just the API)
	GlobalDiskMax int64 // aggregate ceiling for ALL sessions — the disk blast-radius cap
	MaxSessions   int   // hard cap on concurrent sessions
	DefaultTTL    time.Duration

	// OnDrop, if set, is called with the session id whenever a session is removed
	// (Destroy OR sweep-drop). The API wires this to volume.Manager.ReleaseAll so a
	// crashed/swept session releases any RW volume hold instead of leaking the lock
	// until process restart. Must not block. Red-team RT2 hardening / advisor #3.
	OnDrop func(sessionID string)

	mu       sync.RWMutex
	sessions map[string]*Session
	used     int64 // aggregate workspace bytes, refreshed by Sweep (checked at Create)
}

// Config parameterises NewManager.
type Config struct {
	Root          string
	DiskQuota     int64 // per-session (default 512 MiB)
	GlobalDiskMax int64 // aggregate (default 10 GiB)
	MaxSessions   int   // default 200
	TTL           time.Duration
}

func NewManager(exec executor.Executor, reg *registry.Registry, sema *sched.Limiter, cfg Config) (*Manager, error) {
	if cfg.Root == "" {
		return nil, fmt.Errorf("session root required")
	}
	if err := os.MkdirAll(cfg.Root, 0o700); err != nil {
		return nil, fmt.Errorf("create session root: %w", err)
	}
	// Startup reconcile: the in-proc map is empty after a restart, so any
	// pre-existing session dirs are unreachable orphans — remove them so they
	// cannot accumulate and consume disk across restarts.
	if ents, err := os.ReadDir(cfg.Root); err == nil {
		for _, e := range ents {
			_ = os.RemoveAll(filepath.Join(cfg.Root, e.Name()))
		}
	}
	if cfg.DiskQuota <= 0 {
		cfg.DiskQuota = 512 << 20
	}
	if cfg.GlobalDiskMax <= 0 {
		cfg.GlobalDiskMax = 10 << 30
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 200
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 24 * time.Hour
	}
	return &Manager{
		Backend: exec, Reg: reg, Sema: sema, Root: cfg.Root,
		AcquireWait: 2 * time.Second, DiskQuota: cfg.DiskQuota,
		GlobalDiskMax: cfg.GlobalDiskMax, MaxSessions: cfg.MaxSessions, DefaultTTL: cfg.TTL,
		sessions: make(map[string]*Session),
	}, nil
}

type CreateOpts struct {
	TTL time.Duration

	// Tenant is the server-derived tenant id from auth.TenantFrom(ctx). REQUIRED:
	// it pins the session to a tenant. The API never reads it from a request field.
	Tenant string

	// ExtraMounts are non-/workspace mounts every step replays (the /memory volume).
	// The API populates this via volume.Manager.Attach(Tenant, volumeId, id, true).
	ExtraMounts []executor.Mount
}

// Create makes a new filesystem session: a workspace dir + a capability token.
// No container is started (filesystem sessions are zero-RAM at rest).
func (m *Manager) Create(runtime string, o CreateOpts) (*Session, error) {
	lang, ok := m.Reg.Resolve(runtime, "")
	if !ok {
		return nil, fmt.Errorf("unknown runtime %q", runtime)
	}
	m.mu.RLock()
	n, used := len(m.sessions), m.used
	m.mu.RUnlock()
	if n >= m.MaxSessions {
		return nil, ErrTooMany
	}
	if used >= m.GlobalDiskMax {
		return nil, ErrDiskFull
	}
	tok, err := mintToken()
	if err != nil {
		return nil, err
	}
	id := "sess_" + uuid.NewString()
	ws := filepath.Join(m.Root, id, "workspace")
	if err := os.MkdirAll(ws, 0o777); err != nil { // 0777 leaf so in-container nobody (65534) can write
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	_ = os.Chmod(ws, 0o777)
	ttl := o.TTL
	if ttl <= 0 {
		ttl = m.DefaultTTL
	}
	s := &Session{ID: id, Token: tok, Runtime: lang.Name, Type: "filesystem", Workspace: ws,
		CreatedAt: time.Now(), lastActivity: time.Now(), IdleTTL: ttl,
		Tenant: o.Tenant, ExtraMounts: o.ExtraMounts}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return s, nil
}

// authed is the single chokepoint for every per-session op. It requires BOTH a
// constant-time token match AND (when the caller passes a non-empty tenant) that
// the request's server-derived tenant equals the session's pinned tenant. The
// tenant compare is a plain == (the tenant id is not a secret; the token is the
// secret and is already constant-time compared) — this closes the red-team
// "token-only" door to a tenant's mounted /memory volume. Passing tenant=="" is
// reserved for internal callers that have no ctx (none today).
func (m *Manager) authed(id, token, tenant string) (*Session, error) {
	m.mu.RLock()
	s, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.Token)) != 1 {
		return nil, ErrForbidden
	}
	if tenant != "" && s.Tenant != tenant {
		return nil, ErrForbidden // token valid but wrong tenant — never reach another tenant's session
	}
	return s, nil
}

// SetMounts records the extra mounts (the /memory volume) every Exec step must
// replay. Called once by the API immediately after Create+Attach, BEFORE the
// session token is returned to the caller, so no concurrent Exec can race it.
// Token+tenant checked like every other op.
func (m *Manager) SetMounts(id, token, tenant string, mounts []executor.Mount) error {
	s, err := m.authed(id, token, tenant)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ExtraMounts = mounts
	s.mu.Unlock()
	return nil
}

// Runtime returns the session's language (token+tenant-checked) so the caller can build a Spec.
func (m *Manager) Runtime(id, token, tenant string) (string, error) {
	s, err := m.authed(id, token, tenant)
	if err != nil {
		return "", err
	}
	return s.Runtime, nil
}

func (m *Manager) Get(id, token, tenant string) (Info, error) {
	s, err := m.authed(id, token, tenant)
	if err != nil {
		return Info{}, err
	}
	return Info{ID: s.ID, Runtime: s.Runtime, Type: s.Type, CreatedAt: s.CreatedAt, DiskBytes: dirSize(s.Workspace)}, nil
}

// Exec runs one step in the session: the caller-built spec gets the session's
// /workspace mounted RW and Workdir=/workspace, then runs as a fresh hardened
// container. Shares the global concurrency gate. sink may be nil (buffered) or
// an SSE sink (streamed).
func (m *Manager) Exec(ctx context.Context, id, token, tenant string, spec executor.Spec, sink executor.OutputSink) (executor.Result, error) {
	s, err := m.authed(id, token, tenant)
	if err != nil {
		return executor.Result{}, err
	}
	spec.Workdir = "/workspace"
	spec.Mounts = append(spec.Mounts, executor.Mount{HostPath: s.Workspace, Target: "/workspace", RW: true})
	// Replay any attached memory volume (/memory) on EVERY step — recording the
	// attach at Create is not sufficient; the mount must be present each run.
	s.mu.Lock()
	extra := append([]executor.Mount(nil), s.ExtraMounts...)
	s.mu.Unlock()
	spec.Mounts = append(spec.Mounts, extra...)
	if !m.Sema.Acquire(ctx, m.AcquireWait) {
		return executor.Result{}, ErrCapacity
	}
	defer m.Sema.Release()
	res, err := m.Backend.Execute(ctx, spec, sink)
	s.touch()
	return res, err
}

func (m *Manager) Destroy(id, token, tenant string) error {
	s, err := m.authed(id, token, tenant)
	if err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
	if m.OnDrop != nil {
		m.OnDrop(s.ID) // release any RW volume hold this session held
	}
	return os.RemoveAll(filepath.Dir(s.Workspace)) // the per-session dir (parent of workspace)
}

// Sweep enforces the disk blast-radius bounds and idle TTLs against ACTUAL disk
// usage (not the API-tracked counter), so it catches code that writes directly
// to /workspace and bypasses the WriteFile quota. Order: reap idle/TTL; destroy
// any session over its per-session quota; then, if the aggregate is still over
// the global ceiling, destroy the largest sessions until under. Refreshes
// m.used for Create's fast-path check.
func (m *Manager) Sweep(_ context.Context) {
	m.mu.RLock()
	snap := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		snap = append(snap, s)
	}
	m.mu.RUnlock()

	type sized struct {
		s    *Session
		size int64
	}
	var live []sized
	var total int64
	for _, s := range snap {
		if s.idle() > s.IdleTTL {
			m.drop(s, "idle TTL")
			continue
		}
		sz := dirSize(s.Workspace)
		if sz > m.DiskQuota {
			m.drop(s, "over per-session disk quota")
			continue
		}
		total += sz
		live = append(live, sized{s, sz})
	}
	if total > m.GlobalDiskMax {
		sort.Slice(live, func(i, j int) bool { return live[i].size > live[j].size })
		for _, l := range live {
			if total <= m.GlobalDiskMax {
				break
			}
			m.drop(l.s, "global disk ceiling")
			total -= l.size
		}
	}
	m.mu.Lock()
	m.used = total
	m.mu.Unlock()
}

// drop removes a session and its workspace (used by Sweep).
func (m *Manager) drop(s *Session, reason string) {
	m.mu.Lock()
	delete(m.sessions, s.ID)
	m.mu.Unlock()
	if m.OnDrop != nil {
		m.OnDrop(s.ID) // release any RW volume hold so a swept session doesn't leak the lock
	}
	_ = os.RemoveAll(filepath.Dir(s.Workspace))
	slog.Warn("session destroyed by sweep", "id", s.ID, "reason", reason)
}

// Count reports the number of live sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// --- file operations (operate on the host workspace dir directly) ----------

func (m *Manager) Stat(id, token, tenant, rel string) (FileInfo, error) {
	s, err := m.authed(id, token, tenant)
	if err != nil {
		return FileInfo{}, err
	}
	p, err := m.safePath(s, rel)
	if err != nil {
		return FileInfo{}, err
	}
	fi, err := os.Stat(p)
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{Name: fi.Name(), Size: fi.Size(), Dir: fi.IsDir(), ModTime: fi.ModTime()}, nil
}

func (m *Manager) ReadFile(id, token, tenant, rel string) ([]byte, error) {
	s, err := m.authed(id, token, tenant)
	if err != nil {
		return nil, err
	}
	p, err := m.safePath(s, rel)
	if err != nil {
		return nil, err
	}
	if fi, e := os.Stat(p); e == nil && fi.IsDir() {
		return nil, ErrIsDir
	}
	return os.ReadFile(p)
}

func (m *Manager) ListDir(id, token, tenant, rel string) ([]FileInfo, error) {
	s, err := m.authed(id, token, tenant)
	if err != nil {
		return nil, err
	}
	p, err := m.safePath(s, rel)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	out := make([]FileInfo, 0, len(ents))
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, FileInfo{Name: e.Name(), Size: fi.Size(), Dir: e.IsDir(), ModTime: fi.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Manager) WriteFile(id, token, tenant, rel string, data []byte) error {
	s, err := m.authed(id, token, tenant)
	if err != nil {
		return err
	}
	p, err := m.safePath(s, rel)
	if err != nil {
		return err
	}
	var old int64
	if fi, e := os.Stat(p); e == nil {
		old = fi.Size()
	}
	if dirSize(s.Workspace)-old+int64(len(data)) > m.DiskQuota {
		return ErrQuota
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o777); err != nil {
		return err
	}
	if err := os.WriteFile(p, data, 0o666); err != nil { // 0666: in-container nobody can also rewrite it
		return err
	}
	s.touch()
	return nil
}

func (m *Manager) DeletePath(id, token, tenant, rel string) error {
	s, err := m.authed(id, token, tenant)
	if err != nil {
		return err
	}
	p, err := m.safePath(s, rel)
	if err != nil {
		return err
	}
	if p == s.Workspace {
		return ErrPath // never delete the workspace root via the file API
	}
	return os.RemoveAll(p)
}

// safePath resolves a caller-supplied relative path strictly within the session
// workspace, collapsing any traversal. Leading `..` segments resolve away
// because we Clean an absolute-rooted copy first.
func (m *Manager) safePath(s *Session, rel string) (string, error) {
	clean := filepath.Clean("/" + strings.TrimSpace(rel))
	p := filepath.Join(s.Workspace, clean)
	if p != s.Workspace && !strings.HasPrefix(p, s.Workspace+string(os.PathSeparator)) {
		return "", ErrPath
	}
	return p, nil
}

func mintToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "tok_" + hex.EncodeToString(b), nil
}

func dirSize(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if fi, e := d.Info(); e == nil {
			total += fi.Size()
		}
		return nil
	})
	return total
}
