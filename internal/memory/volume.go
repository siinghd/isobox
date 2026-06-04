// Package memory implements Phase 3 long-term memory for isobox. This file is
// the VolumeManager: named, persistent filesystem volumes that survive sessions
// and re-attach as a RW bind-mount at /memory.
//
// Layout (under Root, default /var/lib/isobox/vol):
//
//	<tenant>/<id>/meta.json   server-owned metadata, 0600, OUTSIDE the mount
//	<tenant>/<id>/data/       the bind-mount target, 0777 leaf (guest uid 65534 writes here)
//
// Security model (this matches the rest of the control plane):
//   - tenant_id is derived SERVER-SIDE (sha256(apiKey) via a keystore) and passed
//     in by the caller of this package — it is NEVER a request field. The volume
//     root PATH is keyed by that tenant_id, so a volume is unreachable from any
//     other tenant.
//   - all volume ids are server-minted UUIDs. Caller-supplied ids (volumeId at
//     session create) are accepted ONLY at attach/Get/Delete time and are strictly
//     regex-validated to the minted shape before they ever touch a path, then the
//     resolved path is EvalSymlinks'd and HasPrefix-checked against the EvalSymlinks'd
//     tenant root. Raw caller strings never form a path component.
//
// Unlike sessions (ephemeral), volumes are durable, so two session-manager
// behaviours are deliberately INVERTED here:
//  1. startup does NOT wipe the root; it scans disk and rebuilds the in-proc
//     index from meta.json (the data is the whole point of the feature).
//  2. the quota sweep never deletes a healthy volume; it measures and GATES
//     (refuse RW attach / refuse Create over the ceiling). Only orphans — dirs
//     with no valid meta.json, or stray tenant entries — are GC'd.
package memory

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
)

var (
	// Note: this file shares package `memory` with kv.go, which already owns the
	// names ErrVolNotFound/ErrQuota/readVolMeta/writeVolMeta. Volume symbols are therefore
	// suffixed (ErrVol*, readVolMeta/writeVolMeta) to avoid redeclaration.
	ErrVolNotFound  = errors.New("volume not found")
	ErrExists       = errors.New("volume name already exists")
	ErrBadName      = errors.New("invalid volume name")
	ErrBadID        = errors.New("invalid volume id")
	ErrBadTenant    = errors.New("invalid tenant id")
	ErrVolQuota     = errors.New("volume disk quota exceeded") // -> HTTP 413; per-volume cap
	ErrDiskFull     = errors.New("volume storage ceiling reached")
	ErrTooMany      = errors.New("too many volumes")
	ErrVolumeLocked = errors.New("volume is attached read-write by another session") // -> HTTP 409
	ErrBusy         = errors.New("volume is attached and cannot be deleted")         // -> HTTP 409
	ErrContainment  = errors.New("resolved volume path escaped the tenant root")
)

// idRe is the exact shape of a server-minted volume id: the literal prefix
// "vol_" followed by a canonical lowercase UUID. Anything else is rejected
// before it can become a path component, so caller strings cannot traverse.
var idRe = regexp.MustCompile(`^vol_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// tenantRe bounds a server-derived tenant id (hex sha256, or the literal
// "public" for open mode). The tenant is server-side, but we still validate it
// defensively so a future keystore bug can't yield a path-traversing tenant.
var tenantRe = regexp.MustCompile(`^(public|[0-9a-f]{8,64})$`)

// nameRe bounds the human-facing display name. The name is metadata only — it
// is NEVER used in a path — but a tight charset keeps listings and logs clean.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// orphanGrace is how long an id-shaped, unindexed, meta-less dir must sit quiet
// before SweepOrphans removes it — the window that protects an in-flight Create
// (whose lock-free observation by the sweep would otherwise race meta.json).
const orphanGrace = 60 * time.Second

// meta is the server-owned, on-disk record. It lives at <id>/meta.json, OUTSIDE
// the data/ bind-mount, so the guest (uid 65534, which can write data/) can
// never forge or clobber it.
type meta struct {
	ID        string    `json:"id"`
	Tenant    string    `json:"tenant"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

// Volume is the in-proc handle. Lock state is held here (in-proc, single-node);
// see the package note on the multi-node Valkey path.
type Volume struct {
	ID        string
	Tenant    string
	Name      string
	CreatedAt time.Time

	// lock guards single-writer attach. rwHolder is the session id currently
	// holding the volume RW (empty => no RW holder). Set/cleared under
	// Manager.mu, so no separate mutex is needed on the Volume itself.
	rwHolder string
}

// Info is the safe-to-return, tenant-checked view (no host paths, no lock
// internals beyond the boolean the API needs).
type Info struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"createdAt"`
	DiskBytes  int64     `json:"diskBytes"`
	AttachedRW bool      `json:"attachedRw"`
}

// CreateOpts parameterises Create.
type CreateOpts struct {
	Name string // display name; must be unique within the tenant
}

// Manager owns the lifecycle of all tenants' volumes. It is composed alongside
// the session Manager in the API server.
type Manager struct {
	Root            string
	DiskQuota       int64 // per-volume byte cap, enforced by GATING (default 512 MiB)
	GlobalDiskMax   int64 // aggregate ceiling across ALL tenants/volumes (default 8 GiB)
	MaxVolPerTenant int   // hard cap on volumes per tenant (default 100)

	// MinFreeBytes is a host free-disk floor (red-team RT3 #2). The du-measured
	// `used` counter and GlobalDiskMax bound the LOGICAL aggregate, but on a 35G
	// disk shared with ~50 services the sum of session + volume + KV ceilings can
	// exceed physical free space. DiskFull() additionally consults statfs
	// (unprivileged) so Create/Attach refuse with 507 before the real disk is
	// exhausted, regardless of the configured logical ceiling. 0 disables it.
	MinFreeBytes int64

	mu   sync.RWMutex
	vols map[string]*Volume // key: tenant + "/" + id
	used int64              // aggregate bytes across all volumes, refreshed by Sweep
}

// Config parameterises NewManager.
type Config struct {
	Root            string
	DiskQuota       int64
	GlobalDiskMax   int64
	MaxVolPerTenant int
	MinFreeBytes    int64
}

func key(tenant, id string) string { return tenant + "/" + id }

// NewManager prepares the root and rebuilds the in-proc index from disk WITHOUT
// deleting anything durable. Partial/garbage dirs (no valid meta.json) are GC'd
// during the scan; everything with a valid meta is indexed and counted.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.Root == "" {
		return nil, fmt.Errorf("volume root required")
	}
	if err := os.MkdirAll(cfg.Root, 0o700); err != nil {
		return nil, fmt.Errorf("create volume root: %w", err)
	}
	if cfg.DiskQuota <= 0 {
		cfg.DiskQuota = 512 << 20
	}
	if cfg.GlobalDiskMax <= 0 {
		// Red-team RT3 #3: the old 50 GiB default OVERFLOWED a 35 GiB disk shared
		// with sessions (10 GiB) + KV + ~50 services. Default to a conservative 8
		// GiB logical ceiling; the statfs floor (MinFreeBytes) is the real backstop.
		cfg.GlobalDiskMax = 8 << 30
	}
	if cfg.MaxVolPerTenant <= 0 {
		cfg.MaxVolPerTenant = 100
	}
	m := &Manager{
		Root: cfg.Root, DiskQuota: cfg.DiskQuota,
		GlobalDiskMax: cfg.GlobalDiskMax, MaxVolPerTenant: cfg.MaxVolPerTenant,
		MinFreeBytes: cfg.MinFreeBytes,
		vols:         make(map[string]*Volume),
	}
	m.scan()
	return m, nil
}

// scan rebuilds the index from disk. Called once at startup. It tolerates and
// removes garbage (dirs that don't match the minted id shape, or lack a valid
// meta.json) but never touches a well-formed volume.
func (m *Manager) scan() {
	tents, err := os.ReadDir(m.Root)
	if err != nil {
		return
	}
	var total int64
	for _, te := range tents {
		if !te.IsDir() || !tenantRe.MatchString(te.Name()) {
			continue // ignore stray files / malformed tenant dirs (do not delete blindly)
		}
		tenant := te.Name()
		tdir := filepath.Join(m.Root, tenant)
		vents, err := os.ReadDir(tdir)
		if err != nil {
			continue
		}
		for _, ve := range vents {
			id := ve.Name()
			vdir := filepath.Join(tdir, id)
			if !ve.IsDir() || !idRe.MatchString(id) {
				_ = os.RemoveAll(vdir) // partial Create / stray entry — safe to GC
				continue
			}
			md, err := readVolMeta(vdir)
			if err != nil || md.ID != id || md.Tenant != tenant {
				// no/garbled meta, or meta disagrees with its own path -> orphan
				slog.Warn("volume: GC orphan (no/invalid meta)", "tenant", tenant, "id", id, "err", err)
				_ = os.RemoveAll(vdir)
				continue
			}
			m.vols[key(tenant, id)] = &Volume{
				ID: md.ID, Tenant: md.Tenant, Name: md.Name, CreatedAt: md.CreatedAt,
			}
			total += dirSize(filepath.Join(vdir, "data"))
		}
	}
	m.used = total
	slog.Info("volume index rebuilt", "volumes", len(m.vols), "bytes", total)
}

// Create mints a new volume for the tenant. The id is server-generated; the
// caller-supplied Name is metadata only (validated, never a path component).
func (m *Manager) Create(tenant string, o CreateOpts) (Info, error) {
	if !tenantRe.MatchString(tenant) {
		return Info{}, ErrBadTenant
	}
	name := strings.TrimSpace(o.Name)
	if name == "" {
		name = "memory"
	}
	if !nameRe.MatchString(name) {
		return Info{}, ErrBadName
	}
	// statfs floor (lock-free, fails open): refuse if host free disk is at/below
	// the floor regardless of the logical ceiling. The under-lock m.used check
	// below still enforces the logical aggregate ceiling.
	if m.MinFreeBytes > 0 && m.DiskFull() {
		return Info{}, ErrDiskFull
	}

	m.mu.Lock()
	// Per-tenant count + global ceiling are checked under the lock so concurrent
	// Creates can't both slip past.
	var n int
	for _, v := range m.vols {
		if v.Tenant != tenant {
			continue
		}
		n++
		if strings.EqualFold(v.Name, name) {
			m.mu.Unlock()
			return Info{}, ErrExists
		}
	}
	if n >= m.MaxVolPerTenant {
		m.mu.Unlock()
		return Info{}, ErrTooMany
	}
	if m.used >= m.GlobalDiskMax {
		m.mu.Unlock()
		return Info{}, ErrDiskFull
	}

	id := "vol_" + uuid.NewString()
	vdir := filepath.Join(m.Root, tenant, id)
	dataDir := filepath.Join(vdir, "data")
	// 0700 parent (server-owned), 0777 data leaf so in-guest nobody (65534) can write.
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		m.mu.Unlock()
		return Info{}, fmt.Errorf("create volume dir: %w", err)
	}
	if err := os.Chmod(dataDir, 0o777); err != nil {
		m.mu.Unlock()
		_ = os.RemoveAll(vdir)
		return Info{}, fmt.Errorf("chmod volume data: %w", err)
	}
	md := meta{ID: id, Tenant: tenant, Name: name, CreatedAt: time.Now().UTC()}
	if err := writeVolMeta(vdir, md); err != nil {
		m.mu.Unlock()
		_ = os.RemoveAll(vdir)
		return Info{}, fmt.Errorf("write meta: %w", err)
	}
	v := &Volume{ID: id, Tenant: tenant, Name: name, CreatedAt: md.CreatedAt}
	m.vols[key(tenant, id)] = v
	m.mu.Unlock()

	return Info{ID: v.ID, Name: v.Name, CreatedAt: v.CreatedAt}, nil
}

// lookup is the single tenant-scoped, id-validated index read. It NEVER falls
// back to another tenant — cross-tenant Get is impossible by construction.
func (m *Manager) lookup(tenant, id string) (*Volume, error) {
	if !tenantRe.MatchString(tenant) {
		return nil, ErrBadTenant
	}
	if !idRe.MatchString(id) {
		return nil, ErrBadID
	}
	m.mu.RLock()
	v, ok := m.vols[key(tenant, id)]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrVolNotFound
	}
	return v, nil
}

// Get returns the tenant-checked view of one volume.
func (m *Manager) Get(tenant, id string) (Info, error) {
	v, err := m.lookup(tenant, id)
	if err != nil {
		return Info{}, err
	}
	return m.infoOf(v), nil
}

// List returns every volume owned by the tenant, name-sorted.
func (m *Manager) List(tenant string) ([]Info, error) {
	if !tenantRe.MatchString(tenant) {
		return nil, ErrBadTenant
	}
	m.mu.RLock()
	var snap []*Volume
	for _, v := range m.vols {
		if v.Tenant == tenant {
			snap = append(snap, v)
		}
	}
	m.mu.RUnlock()
	out := make([]Info, 0, len(snap))
	for _, v := range snap {
		out = append(out, m.infoOf(v))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Manager) infoOf(v *Volume) Info {
	m.mu.RLock()
	rw := v.rwHolder != ""
	m.mu.RUnlock()
	return Info{
		ID: v.ID, Name: v.Name, CreatedAt: v.CreatedAt,
		DiskBytes: dirSize(m.dataDir(v.Tenant, v.ID)), AttachedRW: rw,
	}
}

// dataDir is the trusted, server-constructed path to a volume's data dir. It is
// only ever called with an id already proven to match idRe (via lookup), so it
// does not re-validate — HostPath is the public, defence-in-depth entry point.
func (m *Manager) dataDir(tenant, id string) string {
	return filepath.Join(m.Root, tenant, id, "data")
}

// HostPath returns the absolute directory to bind-mount at /memory, with full
// containment validation. This is THE security-critical method: its id arrives
// caller-supplied (volumeId at session create), so it must reject anything that
// isn't a server-minted volume of THIS tenant before returning a path, and the
// resolved path must EvalSymlinks+HasPrefix inside the EvalSymlinks'd tenant root.
//
// Order: (a) regex-validate tenant + id; (b) confirm the volume is in this
// tenant's index; (c) EvalSymlinks both the tenant root and the candidate, then
// HasPrefix. A passing result is safe to hand to executor.Mount as RW.
func (m *Manager) HostPath(tenant, id string) (string, error) {
	if _, err := m.lookup(tenant, id); err != nil { // (a)+(b): validate + tenant-scoped existence
		return "", err
	}

	tenantRoot := filepath.Join(m.Root, tenant)
	cand := filepath.Join(tenantRoot, id, "data")

	// (c) Resolve symlinks on BOTH sides. EvalSymlinks requires the path to
	// exist; for an indexed volume it does. If a tenant dir or volume dir were
	// ever swapped for a symlink pointing outside the root, the prefix check
	// below fails closed.
	realRoot, err := filepath.EvalSymlinks(tenantRoot)
	if err != nil {
		return "", fmt.Errorf("%w: tenant root: %v", ErrContainment, err)
	}
	realCand, err := filepath.EvalSymlinks(cand)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrContainment, err)
	}
	if realCand != realRoot && !strings.HasPrefix(realCand, realRoot+string(os.PathSeparator)) {
		return "", ErrContainment
	}
	return realCand, nil
}

// --- single-writer attach --------------------------------------------------

// Attach grants a session access to the volume and returns the host data dir
// plus the GRANTED mode. Only one session may hold a volume RW at a time:
//   - wantRW + over per-volume quota   -> ErrVolQuota (API: 413), before locking
//   - wantRW + no current holder       -> granted RW (this session becomes holder)
//   - wantRW + this session is holder  -> idempotent RW (re-attach is fine)
//   - wantRW + a different RW holder   -> ErrVolumeLocked (API: 409)
//   - !wantRW (read-only)              -> always granted RO, never locks or quota-checks
//
// The host path is produced via HostPath, so all containment checks apply.
// NOTE (multi-node): a single-node in-proc lock is authoritative only on this
// instance. Behind a load balancer, gate with Valkey SET NX EX
// iso:vol:<tenant>:<id>:lock <sessionID> EX <ttl> here, refreshed while attached
// and DEL'd on Release. Valkey holds ONLY this ephemeral lock (never durable
// data); if Valkey is down, degrade to the in-proc lock (correct on one node).
func (m *Manager) Attach(tenant, id, sessionID string, wantRW bool) (hostPath string, grantedRW bool, err error) {
	v, err := m.lookup(tenant, id)
	if err != nil {
		return "", false, err
	}
	hp, err := m.HostPath(tenant, id)
	if err != nil {
		return "", false, err
	}
	if !wantRW {
		return hp, false, nil // read-only attach never contends the lock or quota
	}
	// Per-volume quota gate. Like the session du-sweep, enforcement is at
	// attach-time (and the periodic Sweep), NEVER per-write — a live writer can
	// still overshoot mid-session; the next RW attach refuses until the agent
	// brings it back under. We HARD-REFUSE RW when over the cap rather than
	// silently downgrading to RO: a volume is reachable ONLY through the
	// in-sandbox /memory mount (there is no host-side file API as sessions have),
	// so a RO mount cannot prune. Recovery for an over-quota volume is therefore
	// Delete, or attaching while small enough to write a smaller replacement.
	if over, _, err := m.OverQuota(tenant, id); err != nil {
		return "", false, err
	} else if over {
		return "", false, ErrVolQuota
	}
	// Host free-disk floor (red-team RT3 #2): refuse a fresh RW attach when the
	// shared disk is critically low, since a RW mount is exactly the unbounded
	// in-session write path. A volume already RW-held by THIS session re-attaches
	// idempotently below regardless (it isn't new allocation pressure).
	if m.MinFreeBytes > 0 && v.rwHolder != sessionID && m.DiskFull() {
		return "", false, ErrDiskFull
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if v.rwHolder != "" && v.rwHolder != sessionID {
		return "", false, ErrVolumeLocked
	}
	v.rwHolder = sessionID
	return hp, true, nil
}

// Release drops a session's RW hold (no-op if it wasn't the holder). Call this
// when the owning session is destroyed/swept; otherwise the volume stays locked
// RW until restart. (Wiring this into session teardown lives outside this file.)
func (m *Manager) Release(tenant, id, sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.vols[key(tenant, id)]; ok && v.rwHolder == sessionID {
		v.rwHolder = ""
	}
}

// ReleaseAll drops every RW hold owned by a session across all volumes. Useful
// when a session is torn down without the caller tracking which volume it held.
func (m *Manager) ReleaseAll(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.vols {
		if v.rwHolder == sessionID {
			v.rwHolder = ""
		}
	}
}

// --- delete ----------------------------------------------------------------

// Delete removes a volume and all its data. It refuses while the volume is
// RW-attached (ErrBusy -> 409) so a delete can't pull the rug from a live
// session's bind-mount; detach/destroy the session first.
func (m *Manager) Delete(tenant, id string) error {
	v, err := m.lookup(tenant, id)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if v.rwHolder != "" {
		m.mu.Unlock()
		return ErrBusy
	}
	sz := dirSize(m.dataDir(tenant, id))
	delete(m.vols, key(tenant, id))
	m.used -= sz
	if m.used < 0 {
		m.used = 0
	}
	m.mu.Unlock()
	// Path is server-constructed from validated components; RemoveAll the whole
	// <id> dir (data + meta).
	return os.RemoveAll(filepath.Join(m.Root, tenant, id))
}

// --- sweep / quota ---------------------------------------------------------

// Sweep is the periodic du-based maintenance pass. Unlike the session sweep it
// NEVER deletes a healthy volume — it only:
//   - GCs orphans (dirs with no valid meta, stray non-volume entries, indexed
//     volumes whose dir vanished) via SweepOrphans, and
//   - refreshes the aggregate `used` counter so Create's ceiling check is current.
//
// Per-volume and aggregate quota are enforced by GATING (OverQuota / Attach /
// Create), never by destroying user data here.
func (m *Manager) Sweep() {
	m.SweepOrphans()

	m.mu.RLock()
	snap := make([]*Volume, 0, len(m.vols))
	for _, v := range m.vols {
		snap = append(snap, v)
	}
	m.mu.RUnlock()

	var total int64
	for _, v := range snap {
		total += dirSize(m.dataDir(v.Tenant, v.ID))
	}
	m.mu.Lock()
	m.used = total
	m.mu.Unlock()
}

// SweepOrphans GCs filesystem entries that are NOT healthy volumes:
//   - inside a known tenant dir: id-shaped dirs not in the index, or dirs that
//     are mis-shaped / lack a valid meta;
//   - index entries whose on-disk dir has disappeared (drop from the map).
//
// It deliberately leaves alone anything with a valid, index-matching meta. It is
// safe to call repeatedly and is also invoked by Sweep.
func (m *Manager) SweepOrphans() {
	// Snapshot the index so we can detect disk dirs that aren't indexed.
	m.mu.RLock()
	known := make(map[string]bool, len(m.vols))
	for k := range m.vols {
		known[k] = true
	}
	m.mu.RUnlock()

	tents, err := os.ReadDir(m.Root)
	if err != nil {
		return
	}
	for _, te := range tents {
		if !te.IsDir() || !tenantRe.MatchString(te.Name()) {
			continue
		}
		tenant := te.Name()
		tdir := filepath.Join(m.Root, tenant)
		vents, err := os.ReadDir(tdir)
		if err != nil {
			continue
		}
		for _, ve := range vents {
			id := ve.Name()
			vdir := filepath.Join(tdir, id)
			if !ve.IsDir() || !idRe.MatchString(id) {
				slog.Warn("volume: GC stray entry", "tenant", tenant, "path", vdir)
				_ = os.RemoveAll(vdir)
				continue
			}
			if known[key(tenant, id)] {
				continue // healthy, indexed volume — leave it
			}
			// id-shaped but not in the index: a failed Create or a half-finished
			// Delete. Confirm there's no valid meta before removing, to avoid a
			// race with a concurrent Create that just wrote meta but hasn't
			// indexed yet — if meta is valid, skip and let the next scan/Create
			// own it.
			if md, err := readVolMeta(vdir); err == nil && md.ID == id && md.Tenant == tenant {
				continue
			}
			// Grace period: Create does MkdirAll -> chmod -> writeVolMeta while
			// holding m.mu, but this walk runs lock-free, so it can observe a brand
			// new dir in the window before meta.json lands. Only GC dirs that have
			// been quiet longer than orphanGrace, so an in-flight Create is never
			// removed out from under itself.
			if fi, err := os.Stat(vdir); err == nil && time.Since(fi.ModTime()) < orphanGrace {
				continue
			}
			slog.Warn("volume: GC orphan dir (unindexed, no valid meta)", "tenant", tenant, "id", id)
			_ = os.RemoveAll(vdir)
		}
	}

	// Drop index entries whose data dir vanished underneath us (manual rm, disk
	// loss) so the map doesn't keep counting them.
	m.mu.Lock()
	for k, v := range m.vols {
		if _, err := os.Stat(m.dataDir(v.Tenant, v.ID)); errors.Is(err, fs.ErrNotExist) {
			slog.Warn("volume: dropping index entry, data dir gone", "key", k)
			delete(m.vols, k)
		}
	}
	m.mu.Unlock()
}

// OverQuota reports whether the volume currently exceeds its per-volume byte cap
// (du-measured). Attach consults this to HARD-REFUSE a fresh RW attach to an
// over-quota volume (ErrVolQuota -> 413). It is also exported so the API can
// surface usage. Writes land via the bind-mount and can't be intercepted
// per-write, so this is a boundary check, not a hard write barrier.
func (m *Manager) OverQuota(tenant, id string) (bool, int64, error) {
	if _, err := m.lookup(tenant, id); err != nil {
		return false, 0, err
	}
	sz := dirSize(m.dataDir(tenant, id))
	return sz > m.DiskQuota, sz, nil
}

// DiskFull reports whether NEW allocation must be refused: either the logical
// aggregate ceiling is reached, OR host free disk has dropped to/below the
// statfs floor. The Create gate and Attach (RW) both consult this so a tenant
// cannot push the shared 35G disk to exhaustion even if the logical ceilings
// were misconfigured above physical free space. statfs is unprivileged and fails
// OPEN (a transient stat error does not wedge the service).
func (m *Manager) DiskFull() bool {
	m.mu.RLock()
	over := m.used >= m.GlobalDiskMax
	m.mu.RUnlock()
	if over {
		return true
	}
	if m.MinFreeBytes <= 0 {
		return false
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(m.Root, &st); err != nil {
		return false
	}
	free := int64(st.Bavail) * int64(st.Bsize)
	return free < m.MinFreeBytes
}

// Count reports the total number of indexed volumes across all tenants.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.vols)
}

// --- meta + disk helpers ---------------------------------------------------

func metaPath(vdir string) string { return filepath.Join(vdir, "meta.json") }

func readVolMeta(vdir string) (meta, error) {
	b, err := os.ReadFile(metaPath(vdir))
	if err != nil {
		return meta{}, err
	}
	var md meta
	if err := json.Unmarshal(b, &md); err != nil {
		return meta{}, err
	}
	return md, nil
}

// writeVolMeta writes meta.json atomically (temp + rename) at 0600. It lives in the
// <id> dir, OUTSIDE data/, so the guest can never read or forge it.
func writeVolMeta(vdir string, md meta) error {
	b, err := json.MarshalIndent(md, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(vdir, ".meta.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, metaPath(vdir))
}

// dirSize sums the bytes of regular files under root. WalkDir does NOT follow
// symlinks, so a guest dropping symlinks in /memory can neither inflate the
// count nor escape the tree — the same "du-sweep" the session manager uses.
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
