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
)

type Session struct {
	ID           string
	Token        string
	Runtime      string
	Type         string // "filesystem"
	Workspace    string
	CreatedAt    time.Time
	IdleTTL      time.Duration
	mu           sync.Mutex
	lastActivity time.Time
}

func (s *Session) touch()              { s.mu.Lock(); s.lastActivity = time.Now(); s.mu.Unlock() }
func (s *Session) idle() time.Duration { s.mu.Lock(); defer s.mu.Unlock(); return time.Since(s.lastActivity) }

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
	Backend     executor.Executor
	Reg         *registry.Registry
	Sema        *sched.Limiter // shared global concurrency gate (same one /execute uses)
	Root        string
	AcquireWait time.Duration
	DiskQuota   int64 // per-session workspace byte cap
	DefaultTTL  time.Duration

	mu       sync.RWMutex
	sessions map[string]*Session
}

func NewManager(exec executor.Executor, reg *registry.Registry, sema *sched.Limiter, root string, diskQuota int64, ttl time.Duration) (*Manager, error) {
	if root == "" {
		return nil, fmt.Errorf("session root required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create session root: %w", err)
	}
	if diskQuota <= 0 {
		diskQuota = 512 << 20
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Manager{
		Backend: exec, Reg: reg, Sema: sema, Root: root,
		AcquireWait: 2 * time.Second, DiskQuota: diskQuota, DefaultTTL: ttl,
		sessions: make(map[string]*Session),
	}, nil
}

type CreateOpts struct{ TTL time.Duration }

// Create makes a new filesystem session: a workspace dir + a capability token.
// No container is started (filesystem sessions are zero-RAM at rest).
func (m *Manager) Create(runtime string, o CreateOpts) (*Session, error) {
	lang, ok := m.Reg.Resolve(runtime, "")
	if !ok {
		return nil, fmt.Errorf("unknown runtime %q", runtime)
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
		CreatedAt: time.Now(), lastActivity: time.Now(), IdleTTL: ttl}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return s, nil
}

func (m *Manager) authed(id, token string) (*Session, error) {
	m.mu.RLock()
	s, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.Token)) != 1 {
		return nil, ErrForbidden
	}
	return s, nil
}

// Runtime returns the session's language (token-checked) so the caller can build a Spec.
func (m *Manager) Runtime(id, token string) (string, error) {
	s, err := m.authed(id, token)
	if err != nil {
		return "", err
	}
	return s.Runtime, nil
}

func (m *Manager) Get(id, token string) (Info, error) {
	s, err := m.authed(id, token)
	if err != nil {
		return Info{}, err
	}
	return Info{ID: s.ID, Runtime: s.Runtime, Type: s.Type, CreatedAt: s.CreatedAt, DiskBytes: dirSize(s.Workspace)}, nil
}

// Exec runs one step in the session: the caller-built spec gets the session's
// /workspace mounted RW and Workdir=/workspace, then runs as a fresh hardened
// container. Shares the global concurrency gate. sink may be nil (buffered) or
// an SSE sink (streamed).
func (m *Manager) Exec(ctx context.Context, id, token string, spec executor.Spec, sink executor.OutputSink) (executor.Result, error) {
	s, err := m.authed(id, token)
	if err != nil {
		return executor.Result{}, err
	}
	spec.Workdir = "/workspace"
	spec.Mounts = append(spec.Mounts, executor.Mount{HostPath: s.Workspace, Target: "/workspace", RW: true})
	if !m.Sema.Acquire(ctx, m.AcquireWait) {
		return executor.Result{}, ErrCapacity
	}
	defer m.Sema.Release()
	res, err := m.Backend.Execute(ctx, spec, sink)
	s.touch()
	return res, err
}

func (m *Manager) Destroy(id, token string) error {
	s, err := m.authed(id, token)
	if err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
	return os.RemoveAll(filepath.Dir(s.Workspace)) // the per-session dir (parent of workspace)
}

// ReapIdle deletes sessions whose workspace has been idle past their TTL.
func (m *Manager) ReapIdle(ctx context.Context) {
	m.mu.Lock()
	var dead []*Session
	for id, s := range m.sessions {
		if s.idle() > s.IdleTTL {
			dead = append(dead, s)
			delete(m.sessions, id)
		}
	}
	m.mu.Unlock()
	for _, s := range dead {
		_ = os.RemoveAll(filepath.Dir(s.Workspace))
		slog.Info("session reaped (idle TTL)", "id", s.ID, "ttl", s.IdleTTL.String())
	}
}

// Count reports the number of live sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// --- file operations (operate on the host workspace dir directly) ----------

func (m *Manager) Stat(id, token, rel string) (FileInfo, error) {
	s, err := m.authed(id, token)
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

func (m *Manager) ReadFile(id, token, rel string) ([]byte, error) {
	s, err := m.authed(id, token)
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

func (m *Manager) ListDir(id, token, rel string) ([]FileInfo, error) {
	s, err := m.authed(id, token)
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

func (m *Manager) WriteFile(id, token, rel string, data []byte) error {
	s, err := m.authed(id, token)
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

func (m *Manager) DeletePath(id, token, rel string) error {
	s, err := m.authed(id, token)
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
