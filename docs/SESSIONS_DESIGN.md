# isobox v2 — Stateful Session Architecture

Status: design. Integrates with the existing stateless one-shot `/execute` path;
does not replace it. All claims below were empirically verified on the target
host (ARM64, gVisor systrap, overlayfs, ext4 root, `isobox.slice` MemoryMax=2G /
MemorySwapMax=0 / CPUQuota=600%).

---

## 0. Empirically verified facts (load-bearing)

`docker exec` into a long-lived hardened container, tested on this host:

| Property at `docker run` (create) | Inherited by `docker exec`? | Notes |
|---|---|---|
| `--user 65534:65534` | YES (default) but **overridable** | `exec --user 0` regains uid 0. MUST pin `--user 65534:65534` on every exec. |
| `--read-only` rootfs | YES, **not overridable** | Write to `/` fails even as `exec --user 0`. |
| `--cap-drop=ALL` | YES, **not overridable** | `CapEff=0` even with `exec --privileged` (runsc ignores it). |
| `--network=none` (runsc-untrusted) | YES, **immutable** | Egress test failed in exec; network is fixed at create. |
| `--memory` / `--memory-swap` | YES, **immutable** | cgroup is per-container; cannot change after create. |
| `--cpus`, `--pids-limit` | YES, **immutable** | Same cgroup. |
| `--tmpfs /tmp` size/exec/noexec | YES, **immutable** | Mount set at create. |
| `-v <dir>:/workspace` | YES, **immutable** | Volume/bind set at create. |
| `--cgroup-parent=isobox.slice` | YES | Session nests in the slice like one-shots. |
| workdir | NO — defaults to image/create `-w` | Pass `-w /workspace` on every exec (registry default is `/box`). |

Consequence: **the entire security envelope, the resource limits, AND the
network mode are chosen at CreateSession and are immutable for the session's
life.** Per exec we only (re-)apply `--user 65534:65534` and `-w /workspace`.
`--privileged` and `--user 0` on exec are denied at the API layer regardless.

Other measured facts:
- gVisor (runsc) Sentry overhead: **~54 MB RSS per idle session**; slice
  `memory.current` ≈ 85 MB with one idle alpine session.
- Storage driver is **overlayfs** → `--storage-opt size=` is silently ignored;
  no per-container rootfs quota. Root FS is **ext4** (project quota possible only
  by remounting the shared root with `prjquota` — too disruptive on this
  50-tenant box). → du-poll soft quota now.
- Control plane (`isoboxd`) runs as **deploy** (in `docker` group, has sudo).
- A **deploy-owned, mode-0777 session dir under a 0700 parent** gives clean
  bidirectional FS I/O with no `docker cp` and no sudo: guest (nobody) writes are
  read directly by deploy; deploy writes (mode 0666) are read AND overwritten by
  the guest; `DestroySession` = `os.RemoveAll` (deploy owns the dir, unlinks
  guest-owned files, no sticky-bit problem).
- `du -sm <dir>` is the per-session disk-usage signal for soft quota.

---

## 1. What exec-per-step delivers — and what it does NOT

`sleep infinity` container + `docker exec` per step gives **filesystem-persistent
sessions**: `/workspace` survives across steps; uploaded files, build artifacts,
venvs, datasets persist. This covers goals #1 (shared `/workspace`) and #2 (file
I/O) fully.

It does NOT give **variable/interpreter state** ("like Code Interpreter"). Every
`exec python …` is a fresh interpreter; in-memory `df`, imports, and globals are
gone. True variable persistence needs a long-running kernel as the entrypoint
(see §8, Phase 2: Jupyter/IPython kernel per python session). Ship FS-persistent
sessions now; offer kernel-persistent variable state as a per-language opt-in
later. Do not silently imply Code-Interpreter semantics in the API copy.

Goal #3 (cross-session persistent memory) is a **separate durable store** from
`/workspace` (§6) — per-tenant, survives DestroySession.

---

## 2. Container lifecycle

CreateSession:
1. Allocate `sessID = uuid`. Pick a registry language (its image) at create — the
   session is pinned to one image (one-shot multi-language stays on `/execute`).
2. Make the workspace dir (host bind-mount, §3): `os.MkdirAll(sessDir, 0o700)`
   under a 0700 root, then `os.Chmod(sessDir, 0o777)`. Dir stays **deploy-owned**
   (NOT chowned to nobody — that is what lets deploy do direct FS I/O).
3. `docker run -d` the hardened **idle** container with entrypoint `sleep infinity`
   (busybox `sleep` is fine; the image already ships one). Full flag set = the
   existing `buildRunArgs` set, plus `-v sessDir:/workspace` and session labels,
   minus the per-job `-v jobdir:/box:ro` and minus the `sh -c <script>` command.
   Network mode (runsc-untrusted vs runsc-net + isobox-egress) is chosen here.
4. Record the session in the store (§5) with state=ready.

Exec (per step):
```
docker exec --user 65534:65534 -w /workspace <cid> \
    timeout -s KILL <wallSec> sh -c '<trusted launcher>' iso <argv...>
```
The launcher mirrors the one-shot `sh -c "set -e; [compile;] exec <run> \"$@\""`.
Wall-time is enforced by an **in-container `timeout`** (NOT by killing the
container — that would nuke the whole session). Output capture/cap reuses the
existing `capWriter`/`pump`/SSE `OutputSink` machinery unchanged.

DestroySession:
1. `docker rm -f <cid>` (label-scoped, like one-shots).
2. `os.RemoveAll(sessDir)`.
3. Delete the store entry.

Idle / crash: see reaper (§7).

---

## 3. /workspace storage decision

Three candidates on a 2G slice (tmpfs counts against memory!) + 35 GB disk:

| Option | Verdict |
|---|---|
| **tmpfs** | REJECT. RAM-backed → counts against the 2G slice and SwapMax=0; a few-hundred-MB dataset evaporates the session budget and triggers slice-wide OOM. Only `/tmp` stays tmpfs (small, RAM-scratch). |
| **docker named volume** | Workable but fresh volumes are `root:root 0755` → nobody can't write (verified); needs a chown step, and host-side FS I/O goes through `/var/lib/docker/volumes/...`. Keep as the **remote-daemon / multi-node** variant (with `docker cp` for I/O). |
| **host bind-mount dir** (deploy-owned 0777, 0700 parent) | **RECOMMEND for this box.** Direct `os.WriteFile/ReadFile/ReadDir/RemoveAll`, no docker cp, no sudo, both directions verified. `du` gives the quota signal. Lives on the 35 GB disk, not RAM. |

Layout: `/var/lib/isobox/sessions/<sessID>/` (0700 root, per-session 0777 dir).
Uploaded files written **mode 0666** so guest-as-nobody can overwrite them.

Disk quota (overlayfs ignores `--storage-opt size`): **du-poll soft quota**. A
background sweeper `du -sb` each session dir on the reap tick; on breach of
`DiskBytes` mark the session `state=disk_exceeded`, reject further WriteFile/exec
with 413, and (grace) destroy. Hard-quota upgrade path: per-session **ext4
loopback image** (`truncate -s 512M f.img; mkfs.ext4; mount -o loop`) mounted at
the bind path — real enforcement, ~1 loop dev per session, defer until needed.

---

## 4. Go interface: optional SessionExecutor (separate seam)

Keep `Executor` (one-shot) untouched. Add an **optional** interface the gVisor
backend also implements; non-session backends (firecracker-stub, runc) stay clean.

```go
// SessionExecutor is an optional capability: a backend that supports long-lived,
// filesystem-stateful sessions driven by exec-per-step. The control plane type-
// asserts for it; backends without it expose only one-shot Execute.
type SessionExecutor interface {
    CreateSession(ctx context.Context, spec SessionSpec) (*Session, error)
    Exec(ctx context.Context, sessID string, step ExecStep, sink OutputSink) (Result, error)
    WriteFile(ctx context.Context, sessID, path string, data []byte) error
    ReadFile(ctx context.Context, sessID, path string) ([]byte, error)
    ListFiles(ctx context.Context, sessID, dir string) ([]FileInfo, error)
    DestroySession(ctx context.Context, sessID string) error
    // ResolveSession returns the live session record (state, limits, lastActivity).
    ResolveSession(sessID string) (*Session, bool)
}

// SessionSpec is the immutable create-time envelope. Everything here is fixed for
// the session's life (see §0); Limits map 1:1 to create-time cgroup/mount flags.
type SessionSpec struct {
    Image     string            // digest-pinned, from registry (one language)
    Lang      Language          // identity for the envelope
    Workdir   string            // always "/workspace" for sessions
    Env       map[string]string // HOME=/workspace added
    ScratchMB int               // /tmp tmpfs size (RAM!) — small, default 64
    Network   bool              // runsc-net+egress if true, else runsc-untrusted; IMMUTABLE
    Limits    Limits            // MemoryBytes/CPUs/Pids -> immutable cgroup caps
    DiskBytes int64             // du-poll soft quota on the workspace dir
    IdleTTL   time.Duration     // reaped after this much inactivity (default 15m)
    Tenant    string            // for persistent-memory mount + fair-share accounting
}

// Session is the live record (also persisted to the store, §5).
type Session struct {
    ID           string    `json:"id"`
    ContainerID  string    `json:"-"`
    Lang         Language  `json:"language"`
    Image        string    `json:"-"`
    Workdir      string    `json:"workdir"`
    Network      bool      `json:"network"`
    Limits       Limits    `json:"limits"`
    DiskBytes    int64     `json:"diskBytes"`
    DiskUsed     int64     `json:"diskUsed"`     // last du sample
    Tenant       string    `json:"tenant,omitempty"`
    State        string    `json:"state"`        // ready|running|idle|disk_exceeded|dead
    CreatedAt    time.Time `json:"createdAt"`
    LastActivity time.Time `json:"lastActivity"` // bumped on every exec/file op
    Node         string    `json:"node,omitempty"` // owning control-plane node (multi-node)
}

// ExecStep is one step. Argv is NEVER interpolated into the shell (passed as "$@").
type ExecStep struct {
    Compile    []string // usually nil for sessions (interpreted langs)
    Run        []string // trusted run argv from registry, e.g. ["python","-"] or ["python","main.py"]
    Files      []File   // optional: write these into /workspace before running
    Stdin      string
    Argv       []string
    WallTimeMs int      // per-step deadline -> in-container `timeout`, clamped to ceiling
    OutputBytes int64
}

type FileInfo struct {
    Name    string `json:"name"`
    Size    int64  `json:"size"`
    Mode    string `json:"mode"`
    ModTime string `json:"modTime"`
    IsDir   bool   `json:"isDir"`
}
```

Implementation notes (gVisor backend):
- `WriteFile`/`ReadFile`/`ListFiles` are `os.WriteFile(…,0o666)` / `os.ReadFile` /
  `os.ReadDir` on `sessDir + sanitize(path)`. Reuse `sanitizeName`; for nested
  paths add a `filepath.Clean` + `..` rejection + ensure the result stays under
  `sessDir` (`strings.HasPrefix(filepath.Clean(p), sessDir)`).
- `Exec` builds the `docker exec --user 65534:65534 -w /workspace <cid> timeout …`
  argv and reuses `pump`/`capWriter`/`OutputSink`. It MUST re-pin `--user` and
  reject any caller attempt to set user/privileged.
- `ResolveSession` reads the in-mem store (§5).

---

## 5. Session state store

Phase 1 (this box): **in-memory map** `map[string]*Session` behind a `sync.RWMutex`
in a new `internal/session` package, with **container labels as the
reconstructable source of truth**. Labels on the idle container:
`isobox.managed=true`, `isobox.session=<id>`, `isobox.tenant=<t>`,
`isobox.memlimit=<bytes>`. On startup, reconcile: `docker ps -a --filter
label=isobox.session` → rebuild the map (or `rm -f` containers whose workspace dir
is gone). This makes a control-plane restart non-fatal: sessions survive, the map
is rebuilt.

Phase 2 (multi-node): **Valkey** (already on host). Hash `session:<id>` →
{node, state, limits, lastActivity}; the API gateway routes `/sessions/:id/*` to
the owning node (sessions are **node-affine** — the container and bind dir live on
one box). This is a real departure from today's stateless design and is the main
new operational property. Use the existing planned Valkey-Streams work for the
queue; reuse the same client for session routing.

---

## 6. Persistent memory (goal #3) — distinct from /workspace

Two layers, both per-tenant, both surviving DestroySession:

1. **Per-tenant scratch dir** `/var/lib/isobox/memory/<tenant>/` bind-mounted
   **read-write at `/memory`** into every session of that tenant (separate from
   the per-session 0777 `/workspace`). Own du-poll quota (`MemoryBytes` per
   tenant, e.g. 1 GB). Files an agent drops in `/memory` are visible to its next
   session.
2. **Valkey KV** (already running) for small structured recall: a thin
   `POST /memory/:key` / `GET /memory/:key` scoped by tenant + API key, TTL
   optional. This is the "store a fact, recall it later" path that doesn't warrant
   a file. Caps: value size + per-tenant key count.

Keep `/workspace` (ephemeral-ish, per-session) and `/memory` (durable, per-tenant)
clearly separate in docs and mounts.

---

## 7. Idle-TTL reaping (extend the existing reaper)

Today's reaper removes only `status=exited` label-matched containers — it would
never reap a healthy `sleep infinity` session (good) but WOULD `rm -f` a *crashed*
session's container while **leaking its workspace dir + store entry** (bad). Make
it session-aware:

- New tick path: for each session in the store, if `now - LastActivity > IdleTTL`
  → `DestroySession` (rm container, RemoveAll dir, delete entry).
- Crash path: a session whose container is gone (`docker inspect` fails) but whose
  store entry/dir remains → full cleanup (dir + entry).
- Disk path: `du -sb` each session dir; on `> DiskBytes` set `state=disk_exceeded`
  and (after grace) destroy.
- Startup reconcile: `docker ps -a --filter label=isobox.session` vs store; adopt
  or sweep mismatches.
- Keep the existing orphan sweep (one-shot `status=exited`) unchanged.

`LastActivity` is bumped in the store on every Exec/WriteFile/ReadFile; TTL default
**15 min**, configurable via `ISOBOX_SESSION_IDLE_TTL`.

---

## 8. Concurrency model & quota numbers (the core constraint)

**Memory admission IS the session concurrency model — and it is NOT the existing
`sched.Limiter`.** Because `MemorySwapMax=0`, a simultaneous burst across sessions
cannot spill to swap; it triggers **slice-wide OOM kills that cross session
boundaries**. Therefore admit on the **sum of per-session `--memory` *limits***
(fixed at create, immutable), not on idle footprint.

Two distinct controls:

1. **Session memory budget (new, at CreateSession).** Reserve `Limits.MemoryBytes`
   from a slice-wide budget = `2G − headroom`. With ~256 MB default session
   memory and ~256 MB headroom: **≈ 5–6 concurrent live sessions**. CreateSession
   returns **429** when the budget is exhausted. (Idle sessions still cost the
   ~54 MB Sentry each, which fits inside their own 256 MB reservation — no
   double-counting.)
2. **Exec gate (existing `sched.Limiter`, unchanged).** Bounds how many steps RUN
   simultaneously (CPU-bound). Keep ≈ 4 to fit `CPUQuota=600%`. A 6th session can
   exist (idle) while only 4 execs run at once.

So: up to ~6 sessions can be *alive*; at most ~4 can be *executing* a step at any
instant. State both numbers and that they are separate knobs
(`ISOBOX_MAX_SESSIONS`, `ISOBOX_CONCURRENCY`).

Per-session caps (all create-time except disk):
- memory: `--memory == --memory-swap` (swap OFF), default 256 MB, ceiling 512 MB.
- cpus: `--cpus`, default 1.0, ceiling 2.0.
- pids: `--pids-limit`, default 128, ceiling 256.
- disk: `DiskBytes` du-poll soft quota, default 512 MB.
- `/tmp` tmpfs: small (default 64 MB, **counts against `--memory`**).

Nesting in `isobox.slice`: identical to one-shots — every session container passes
`--cgroup-parent=isobox.slice`, so the 2G/600% hard caps bound sessions +
one-shots **together**. The session memory budget (control 1) is the admission
layer that keeps the *sum of reservations* under the slice cap so the kernel OOM
killer is a backstop, not the primary control.

---

## 9. REST API

All under the existing auth + rate-limit + body-cap middleware. New routes:

```
POST   /sessions
       body: {language, version?, network?, limits?{memoryBytes,cpus,pids,diskBytes},
              idleTtlSec?, tenant?}
       201:  {id, language, version, backend, network, limits, workdir:"/workspace",
              createdAt, expiresAt}
       429:  session memory budget exhausted (Retry-After)

GET    /sessions/:id            -> Session JSON (state, limits, diskUsed, lastActivity)
DELETE /sessions/:id            -> 204 (rm container + dir + entry)

POST   /sessions/:id/exec
       body: {code? | run?, files?, stdin?, args?, wallTimeMs?, outputBytes?}
       sync JSON  -> {run:{stdout,stderr,exitCode,timedOut,oomKilled,truncated,durationMs}}
       SSE (Accept: text/event-stream | ?stream=1) -> stdout/stderr/done events
       (reuses the exact /execute streaming machinery)
       409 if state != ready|idle ; 413 if disk_exceeded

PUT    /sessions/:id/files/*path   body=raw bytes (or {content,encoding})  -> 204 (mode 0666)
GET    /sessions/:id/files/*path   -> raw bytes (download)
GET    /sessions/:id/files         ?dir=  -> [{name,size,mode,modTime,isDir}]
DELETE /sessions/:id/files/*path   -> 204

POST   /memory/:key   (tenant-scoped Valkey KV; body=value, ?ttl=)  -> 204
GET    /memory/:key   -> value | 404
```

Path-traversal: `*path` is `filepath.Clean`ed and rejected unless it stays under
`sessDir`. Network is read-only after create (immutable). Per-step `wallTimeMs`,
`outputBytes` clamp to the same ceilings as `/execute`.

---

## 10. Scalability — build now vs later

Build **now** (this box):
- FS-persistent sessions (this doc), in-mem store + label reconciliation.
- du-poll disk quota; session memory-budget admission (the real density control).
- Idle-TTL reaper; startup reconcile.

Build **soon / cheap wins**:
- **Warm pool**: keep N pre-created idle session containers per hot language
  (python pre-warm already costs ~2 s) so CreateSession is instant. Bounded by the
  session memory budget — a warm idle session still reserves its 256 MB.
- **Valkey Streams queue + session→node routing** (Valkey already runs here):
  turns the single-box session map into a multi-node, node-affine fleet.

Build **later / other hosts**:
- **Multi-node workers** behind the gateway; node-affine session routing via Valkey.
- **Kernel-persistent variable state** (Jupyter/IPython kernel as entrypoint, send
  cells via the kernel protocol) — the true Code-Interpreter upgrade.
- **Snapshots / checkpoint-restore**: gVisor `runsc checkpoint`/`restore` to
  hibernate idle sessions to disk and free their memory reservation (directly
  attacks the 5–6 session ceiling). Prototype on this box; productionize later.
- **Firecracker backend** for KVM hosts only (impossible here: no /dev/kvm),
  already a planned `Executor` implementation — gives microVM snapshots/clones for
  fast session fork.
- **Autoscaling** the worker fleet on session-budget pressure.
