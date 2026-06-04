// Kernel sessions (Phase 4): Code-Interpreter parity — VARIABLES PERSIST across
// exec steps. Unlike a filesystem session (zero RAM at rest, a fresh hardened
// container per step), a kernel session is ONE long-lived, fully-sandboxed
// container running a persistent Python REPL harness. The harness holds a single
// namespace dict and exec()s each submitted snippet into it, so `x=5` then
// `print(x)` -> 5.
//
// TRANSPORT is `docker attach` (NOT `docker exec`: exec spawns a NEW process and
// would lose the namespace). Code is submitted as framed JSON-lines over the
// container's stdin; framed JSON-lines come back on its stdout. Concurrent
// submissions to ONE kernel are serialised by a per-session mutex (one in-flight
// exec per kernel). A runaway step is interrupted with `docker kill -s INT`,
// which the harness translates into a KeyboardInterrupt on its worker thread —
// the namespace survives and the container keeps running.
//
// HARDENING is identical to the one-shot executor and filesystem sessions: the
// same flags this manager mirrors from executor.Gvisor.buildRunArgs (runsc
// runtime forcing --network=none, --read-only rootfs, noexec tmpfs scratch,
// --memory/--memory-swap equal => swap off, --cpus, --pids-limit, --cap-drop=ALL,
// no-new-privileges, --user nobody, --cgroup-parent=isobox.slice). The container
// is long-lived but no less sandboxed.
//
// DENSITY is bounded by a SECOND limiter (KernelSlots) independent of the exec
// Sema, plus idle-TTL and max-lifetime reaping. Resident kernels cost RAM, so the
// default is the minimal python-slim image, capped to a small per-kernel memory
// budget.
package session

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "embed"

	"github.com/google/uuid"
	"github.com/siinghd/isobox/internal/executor"
	"github.com/siinghd/isobox/internal/sched"
)

// harnessPy is the REPL harness shipped to every kernel via `python -c`. Embedding
// keeps the single static binary (no file to install on the host).
//
//go:embed harness.py
var harnessPy string

// KernelConfig parameterises kernel-session behaviour. Zero values get safe
// defaults in NewKernelEngine.
type KernelConfig struct {
	Slots         int           // max RESIDENT kernels (independent of the exec Sema). Default 6.
	MemoryBytes   int64         // per-kernel --memory (and --memory-swap). Default 128 MiB.
	CPUs          float64       // per-kernel --cpus. Default 1.0.
	Pids          int           // per-kernel --pids-limit. Default 128.
	OutputBytes   int64         // per-step stdout+stderr cap (passed to the harness). Default 64 KiB.
	StartTimeout  time.Duration // max wait for the harness "ready" banner. Default 30s.
	DefaultStepMs int           // per-step wall-clock deadline when the caller sets none. Default 20s.
	MaxStepMs     int           // hard ceiling on a per-step deadline. Default 60s.
	IdleTTL       time.Duration // reap a kernel idle this long. Default 30m.
	MaxLifetime   time.Duration // reap a kernel older than this regardless of use. Default 4h.
	AcquireWait   time.Duration // max wait for a kernel slot at Create. Default 2s.
}

func (c *KernelConfig) applyDefaults() {
	if c.Slots <= 0 {
		c.Slots = 6
	}
	if c.MemoryBytes <= 0 {
		c.MemoryBytes = 128 << 20
	}
	if c.CPUs <= 0 {
		c.CPUs = 1.0
	}
	if c.Pids <= 0 {
		c.Pids = 128
	}
	if c.OutputBytes <= 0 {
		c.OutputBytes = 64 << 10
	}
	if c.StartTimeout <= 0 {
		c.StartTimeout = 30 * time.Second
	}
	if c.DefaultStepMs <= 0 {
		c.DefaultStepMs = 20_000
	}
	if c.MaxStepMs <= 0 {
		c.MaxStepMs = 60_000
	}
	if c.IdleTTL <= 0 {
		c.IdleTTL = 30 * time.Minute
	}
	if c.MaxLifetime <= 0 {
		c.MaxLifetime = 4 * time.Hour
	}
	if c.AcquireWait <= 0 {
		c.AcquireWait = 2 * time.Second
	}
}

// KernelEngine owns the lifecycle of long-lived kernel containers. It is composed
// into the session Manager (Manager.Kernels) and shares nothing with the exec
// Sema; KernelSlots bounds resident kernels on its own. It mirrors the hardened
// docker-run argv from the Gvisor executor so a kernel container is sandboxed
// exactly like a one-shot job.
type KernelEngine struct {
	cfg   KernelConfig
	Slots *sched.Limiter // bounds RESIDENT kernels (separate from the exec Sema)
	gv    *executor.Gvisor

	mu      sync.Mutex
	kernels map[string]*kernel // by session id
}

// NewKernelEngine builds the engine. gv supplies the verified hardening config
// (runtime, slice, user) so kernel containers match one-shot jobs flag-for-flag.
// Returns (nil, false) if the backend is not the gVisor executor (kernel sessions
// require the docker/runsc transport this engine drives directly).
func NewKernelEngine(backend executor.Executor, cfg KernelConfig) (*KernelEngine, bool) {
	gv, ok := backend.(*executor.Gvisor)
	if !ok {
		return nil, false
	}
	cfg.applyDefaults()
	// Startup reconcile: the kernel map is empty after a restart, so any RUNNING
	// kernel container from a previous process is an unreachable orphan holding
	// RAM. The label-based reaper only sweeps EXITED containers, so these would
	// leak forever — force-remove them here, exactly as the session manager
	// removes orphan workspace dirs on startup.
	sweepOrphanKernels()
	return &KernelEngine{
		cfg:     cfg,
		Slots:   sched.New(cfg.Slots),
		gv:      gv,
		kernels: make(map[string]*kernel),
	}, true
}

// sweepOrphanKernels force-removes every isobox kernel container (running or
// exited). Called once at engine construction, when no kernel can legitimately
// be alive yet.
func sweepOrphanKernels() {
	out, err := exec.Command("docker", "ps", "-aq", "--filter", "label=isobox.kernel=true").Output()
	if err != nil {
		return
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return
	}
	_ = exec.Command("docker", append([]string{"rm", "-f"}, ids...)...).Run()
	slog.Info("removed orphan kernel containers on startup", "count", len(ids))
}

// kernel is one resident container + its attach pipes. The mutex serialises exec
// submissions: exactly one step is in flight at a time, which is what lets a
// SIGINT unambiguously target the current step.
type kernel struct {
	id        string // session id, also the container name suffix
	container string // docker container name (iso-kernel-<uuid>)
	image     string
	createdAt time.Time

	cancel context.CancelFunc // cancels the long-lived `docker attach` process ctx
	stdin  io.WriteCloser     // attach -> container stdin (request frames)
	stdout *bufio.Reader      // container stdout -> attach (response frames)
	attach *exec.Cmd

	mu sync.Mutex // serialises Exec: one in-flight step per kernel

	// lastUsed (UnixNano) and dead are touched from Exec (under mu) AND from
	// Destroy/Reap/DestroyAll (which intentionally do NOT take mu so they can't be
	// blocked by a long-running step). They are therefore atomics, not mu-guarded
	// fields — go vet won't flag the cross-goroutine access but `-race` would.
	lastUsed atomic.Int64 // wall-clock UnixNano of the last completed step
	dead     atomic.Bool  // set once the container is gone; further Exec fails fast
}

// --- request / response frames (the JSON-lines protocol) -------------------

type kReq struct {
	ID   string `json:"id"`
	Op   string `json:"op"`             // "exec" | "ping" | "shutdown"
	Code string `json:"code,omitempty"` // for op=exec
}

type kResp struct {
	ID         string `json:"id"`
	Type       string `json:"type"`   // "ready" | "stream" | "result" | "pong" | "fatal"
	Stream     string `json:"stream"` // "stdout" | "stderr" (type=stream)
	Data       string `json:"data"`   // chunk (type=stream)
	OK         bool   `json:"ok"`     // type=result
	Error      string `json:"error"`  // type=result/fatal
	Exc        string `json:"exc"`    // type=result: exception class name
	DurationMs int64  `json:"durationMs"`
	Truncated  bool   `json:"truncated"`
	Proto      int    `json:"proto"`  // type=ready
	Python     string `json:"python"` // type=ready
}

// NewKernel starts a long-lived, hardened container running the REPL harness and
// attaches to it. workspaceMounts (the session /workspace, plus any /memory
// volume) are bind-mounted RW so the filesystem persists alongside the namespace.
// Caller MUST already hold a kernel slot — Manager.Create acquires it before this.
func (e *KernelEngine) NewKernel(parent context.Context, id, image string, mounts []executor.Mount, network bool) (*kernel, error) {
	name := "iso-kernel-" + uuid.NewString()

	// 1. Start the container detached, with stdin kept OPEN (-i) and NO TTY (so
	//    stdout/stderr are not merged and our JSON frames stay byte-clean). The
	//    command is the harness, fed inline via `python -c` so no file install is
	//    needed. python -u => unbuffered (we also line-buffer inside the harness).
	runArgs := e.buildKernelRunArgs(name, id, image, mounts, network)
	runArgs = append(runArgs, "python", "-u", "-c", harnessPy)
	if out, err := exec.CommandContext(parent, "docker", append([]string{"run"}, runArgs...)...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("docker run kernel: %w: %s", err, string(out))
	}

	// 2. Attach a long-lived process to the running container's stdio. A dedicated
	//    context (NOT the request ctx) keeps the attach alive across many steps;
	//    Destroy cancels it. --sig-proxy=false so signals to isoboxd are NOT
	//    forwarded to the container (we interrupt explicitly via `docker kill`).
	attachCtx, cancel := context.WithCancel(context.Background())
	attach := exec.CommandContext(attachCtx, "docker", "attach", "--sig-proxy=false", name)
	stdin, err := attach.StdinPipe()
	if err != nil {
		cancel()
		_ = forceRemove(name)
		return nil, fmt.Errorf("attach stdin: %w", err)
	}
	stdoutPipe, err := attach.StdoutPipe()
	if err != nil {
		cancel()
		_ = forceRemove(name)
		return nil, fmt.Errorf("attach stdout: %w", err)
	}
	// Drain stderr (container stderr is harness-internal; protocol is on stdout).
	attach.Stderr = io.Discard
	if err := attach.Start(); err != nil {
		cancel()
		_ = forceRemove(name)
		return nil, fmt.Errorf("attach start: %w", err)
	}

	k := &kernel{
		id: id, container: name, image: image,
		createdAt: time.Now(),
		cancel:    cancel, stdin: stdin,
		stdout: bufio.NewReaderSize(stdoutPipe, 64<<10),
		attach: attach,
	}
	k.lastUsed.Store(time.Now().UnixNano())

	// 3. Wait for the harness "ready" banner so we never accept a step before the
	//    namespace is live. Bounded by StartTimeout.
	if err := k.awaitReady(e.cfg.StartTimeout); err != nil {
		cancel()
		_ = forceRemove(name)
		return nil, fmt.Errorf("kernel never became ready: %w", err)
	}

	e.mu.Lock()
	e.kernels[id] = k
	e.mu.Unlock()
	return k, nil
}

// awaitReady reads frames until the "ready" banner or the timeout. A read goroutine
// feeds a channel so we can race it against a timer.
func (k *kernel) awaitReady(timeout time.Duration) error {
	type rr struct {
		line []byte
		err  error
	}
	ch := make(chan rr, 1)
	go func() {
		line, err := k.stdout.ReadBytes('\n')
		ch <- rr{line, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-timer.C:
		return fmt.Errorf("timeout after %s", timeout)
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		var resp kResp
		if err := json.Unmarshal(r.line, &resp); err != nil {
			return fmt.Errorf("garbled ready frame: %w", err)
		}
		if resp.Type != "ready" {
			return fmt.Errorf("expected ready, got %q", resp.Type)
		}
		return nil
	}
}

// Exec submits one step to a kernel, streams stdout/stderr deltas to sink (if
// non-nil), and returns the terminal Result. It SERIALISES via the kernel mutex:
// one in-flight step per kernel, so a SIGINT can only ever interrupt the current
// step. The per-step deadline is enforced with `docker kill -s INT` (soft, the
// namespace survives) escalating to container removal on a stuck kernel.
func (e *KernelEngine) Exec(ctx context.Context, k *kernel, code string, stepMs int, sink executor.OutputSink) (executor.Result, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.isDead() {
		return executor.Result{}, fmt.Errorf("kernel is dead")
	}

	stepID := uuid.NewString()
	req := kReq{ID: stepID, Op: "exec", Code: code}
	frame, _ := json.Marshal(req)
	frame = append(frame, '\n')

	// Per-step deadline: caller value clamped to [1s, MaxStepMs], default if zero.
	if stepMs <= 0 {
		stepMs = e.cfg.DefaultStepMs
	}
	if stepMs > e.cfg.MaxStepMs {
		stepMs = e.cfg.MaxStepMs
	}
	if stepMs < 1000 {
		stepMs = 1000
	}
	wall := time.Duration(stepMs) * time.Millisecond

	start := time.Now()
	if _, err := k.stdin.Write(frame); err != nil {
		k.markDead()
		return executor.Result{}, fmt.Errorf("write step: %w", err)
	}

	// Soft interrupt on deadline: SIGINT -> KeyboardInterrupt in the harness worker.
	// The harness still emits a terminal result frame (exc=KeyboardInterrupt), so
	// the read loop below returns normally and the kernel survives. A second timer
	// hard-kills the container if the harness doesn't yield to the interrupt.
	// timedOut is set in the timer goroutine and read in the read loop below, so it
	// must be atomic (matches executor.Gvisor.Execute's timedOut).
	var timedOut atomic.Bool
	softTimer := time.AfterFunc(wall, func() {
		timedOut.Store(true)
		_ = exec.Command("docker", "kill", "-s", "INT", k.container).Run()
	})
	defer softTimer.Stop()
	hardTimer := time.AfterFunc(wall+5*time.Second, func() {
		_ = exec.Command("docker", "kill", k.container).Run() // SIGKILL the container; read loop will EOF
	})
	defer hardTimer.Stop()

	var res executor.Result
	out := &capBuf{limit: e.cfg.OutputBytes}
	errb := &capBuf{limit: e.cfg.OutputBytes}

	// If the request ctx is cancelled (client disconnect), interrupt the step so we
	// don't block forever holding the kernel mutex.
	stopCtx := make(chan struct{})
	defer close(stopCtx)
	go func() {
		select {
		case <-ctx.Done():
			_ = exec.Command("docker", "kill", "-s", "INT", k.container).Run()
		case <-stopCtx:
		}
	}()

	// Read frames for THIS step id until the terminal "result". Stream deltas are
	// forwarded live and also buffered (capped) into the Result.
	for {
		line, err := k.stdout.ReadBytes('\n')
		if err != nil {
			// EOF/broken pipe => the kernel process is gone (hard kill or crash).
			k.markDead()
			res.Stdout = out.String()
			res.Stderr = errb.String()
			res.DurationMs = time.Since(start).Milliseconds()
			res.TimedOut = timedOut.Load()
			res.ExitCode = 137
			if timedOut.Load() {
				return res, nil
			}
			return res, fmt.Errorf("kernel stream closed mid-step: %w", err)
		}
		if len(line) == 0 {
			continue
		}
		var resp kResp
		if e := json.Unmarshal(line, &resp); e != nil {
			continue // ignore any non-JSON noise; protocol is line-framed JSON
		}
		// SECURITY: only frames whose id EXACTLY matches this step are honoured.
		// User code shares the container and can write raw bytes to fd 1/2 (or
		// spawn a subprocess that inherits them), so it could try to inject a
		// FORGED terminal frame onto the protocol channel — e.g. an early
		// {"type":"result"} (which JSON-decodes with id=="") to make us return
		// before the real step finishes, evading the wall-clock deadline while the
		// worker keeps burning CPU. Requiring an exact id match (NOT `id != ""`)
		// turns every such forged/stale frame into ignored noise: only the harness
		// knows the freshly-minted per-step uuid. The harness ALSO redirects fd 1/2
		// to /dev/null around user code (defence in depth); this is the control-plane
		// half of that pair. The harness's own fatal frame uses id=="" and is now
		// surfaced via the EOF path (markDead) instead of the fatal branch — a
		// coarser but still-safe error.
		if resp.ID != stepID {
			continue
		}
		switch resp.Type {
		case "stream":
			b := []byte(resp.Data)
			if resp.Stream == "stderr" {
				errb.Write(b)
				if sink != nil {
					sink.Stderr(clip(b, errb))
				}
			} else {
				out.Write(b)
				if sink != nil {
					sink.Stdout(clip(b, out))
				}
			}
		case "result":
			res.Stdout = out.String()
			res.Stderr = errb.String()
			res.DurationMs = resp.DurationMs
			if res.DurationMs == 0 {
				res.DurationMs = time.Since(start).Milliseconds()
			}
			res.Truncated = resp.Truncated || out.truncated || errb.truncated
			res.TimedOut = timedOut.Load()
			if !resp.OK {
				res.ExitCode = 1 // a step that raised (incl. KeyboardInterrupt) is "nonzero"
			}
			if timedOut.Load() {
				res.ExitCode = 137
			}
			k.touch()
			return res, nil
		case "fatal":
			k.markDead()
			res.Stderr = out.String() + resp.Error
			res.ExitCode = 1
			res.DurationMs = time.Since(start).Milliseconds()
			return res, fmt.Errorf("kernel fatal: %s", resp.Error)
		default:
			// ready/pong mid-step shouldn't happen; ignore.
		}
	}
}

// Destroy force-removes a kernel container and cancels its attach. Idempotent.
func (e *KernelEngine) Destroy(id string) {
	e.mu.Lock()
	k := e.kernels[id]
	delete(e.kernels, id)
	e.mu.Unlock()
	if k == nil {
		return
	}
	k.cancel() // tear down the attach process
	_ = forceRemove(k.container)
	k.markDead()
}

// Reap culls kernels that are idle past IdleTTL or older than MaxLifetime. It
// NEVER treats a running kernel as an orphan (a resident kernel is status=running
// by design); culling is by our own bookkeeping (idle / lifetime), and Destroy
// releases the slot via the Manager. Returns the ids it removed so the Manager can
// drop them and release slots/volumes.
func (e *KernelEngine) Reap() []string {
	now := time.Now()
	// Snapshot the kernels under e.mu, then RELEASE e.mu before inspecting any of
	// them. We must never hold the engine lock while touching a kernel that might
	// be mid-step: Exec holds k.mu for the whole step (up to MaxStepMs+5s), so
	// locking k.mu under e.mu would stall Create/Destroy/Count/DestroyAll for up to
	// ~65s behind one busy kernel. idle/dead are atomics (no k.mu needed); a kernel
	// that IS mid-step is by definition not idle, so skipping it is correct anyway.
	e.mu.Lock()
	snap := make([]*kernel, 0, len(e.kernels))
	for _, k := range e.kernels {
		snap = append(snap, k)
	}
	e.mu.Unlock()

	var doomed []*kernel
	for _, k := range snap {
		idle := now.Sub(time.Unix(0, k.lastUsed.Load()))
		age := now.Sub(k.createdAt)
		if k.isDead() || idle > e.cfg.IdleTTL || age > e.cfg.MaxLifetime {
			doomed = append(doomed, k)
		}
	}

	if len(doomed) > 0 {
		e.mu.Lock()
		for _, k := range doomed {
			delete(e.kernels, k.id)
		}
		e.mu.Unlock()
	}

	ids := make([]string, 0, len(doomed))
	for _, k := range doomed {
		k.cancel()
		_ = forceRemove(k.container)
		k.markDead()
		ids = append(ids, k.id)
		slog.Info("kernel reaped", "id", k.id, "container", k.container)
	}
	return ids
}

// Count reports the number of resident kernels.
func (e *KernelEngine) Count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.kernels)
}

// DestroyAll tears every kernel down (graceful shutdown).
func (e *KernelEngine) DestroyAll() {
	e.mu.Lock()
	ks := make([]*kernel, 0, len(e.kernels))
	for _, k := range e.kernels {
		ks = append(ks, k)
	}
	e.kernels = make(map[string]*kernel)
	e.mu.Unlock()
	for _, k := range ks {
		k.cancel()
		_ = forceRemove(k.container)
		k.markDead()
	}
}

func (k *kernel) touch()    { k.lastUsed.Store(time.Now().UnixNano()) }
func (k *kernel) markDead() { k.dead.Store(true) }
func (k *kernel) isDead() bool {
	return k.dead.Load()
}

// buildKernelRunArgs mirrors executor.Gvisor.buildRunArgs for a LONG-LIVED
// container: same runtime (forces --network=none), read-only rootfs, noexec
// tmpfs, swap-off memory cap, cpu/pids caps, cap-drop, no-new-privs, nobody user,
// slice nesting. Differences from a one-shot job: -d -i (detached, stdin open),
// no source bind (code arrives over stdin), an extra isobox.session=<id> label so
// the Manager's reaper can find it by session, and HOME=/tmp + the harness output
// budget passed via env.
func (e *KernelEngine) buildKernelRunArgs(name, sessionID, image string, mounts []executor.Mount, network bool) []string {
	mem := e.cfg.MemoryBytes
	// Default: no network (runsc-untrusted forces --network=none). When the kernel
	// is created with network on AND the egress firewall is live, use the net
	// runtime + the filtered egress bridge + public resolv.conf — same posture as a
	// one-shot networked job. A running container's network can't change, so this
	// is decided once at create time.
	runtime, netFlag := e.gv.Runtime, "--network=none"
	var resolvMount []string
	if network {
		if rt, net, resolv, ok := e.gv.NetMode(); ok {
			runtime, netFlag = rt, "--network="+net
			if resolv != "" {
				resolvMount = []string{"-v", resolv + ":/etc/resolv.conf:ro"}
			}
		}
	}
	a := []string{
		"-d", "-i", // detached, stdin OPEN for the attach channel. NO -t (keep streams unmerged).
		"--name", name,
		"--runtime", runtime,
		netFlag,
		"--read-only",
		"--tmpfs", fmt.Sprintf("/tmp:rw,noexec,nosuid,nodev,size=%dm,nr_inodes=%d", 64, 64*64),
		"-w", "/workspace",
		"--memory", strconv.FormatInt(mem, 10),
		"--memory-swap", strconv.FormatInt(mem, 10), // equal => swap OFF
		"--cpus", strconv.FormatFloat(e.cfg.CPUs, 'f', 2, 64),
		"--pids-limit", strconv.Itoa(e.cfg.Pids),
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--user=" + e.gv.User,
		"--cgroup-parent=" + e.gv.Slice,
		"--hostname=sandbox",
		"--label", "isobox.managed=true",
		"--label", "isobox.kernel=true",
		"--label", "isobox.session=" + sessionID,
		"--env", "HOME=/tmp",
		"--env", "ISOBOX_KERNEL_OUTPUT_BYTES=" + strconv.FormatInt(e.cfg.OutputBytes, 10),
		"--env", "PYTHONDONTWRITEBYTECODE=1",
	}
	a = append(a, resolvMount...)
	// Bind the session /workspace (RW) and any /memory volume so the FILESYSTEM
	// persists across steps alongside the in-memory namespace. Rootfs stays
	// read-only; every other control is unchanged from a one-shot job.
	for _, m := range mounts {
		mode := "ro"
		if m.RW {
			mode = "rw"
		}
		a = append(a, "-v", m.HostPath+":"+m.Target+":"+mode)
	}
	a = append(a, image)
	return a
}

// forceRemove deletes a container, ignoring "no such container".
func forceRemove(name string) error {
	return exec.Command("docker", "rm", "-f", name).Run()
}

// --- capped buffer (same contract as the executor's capWriter) -------------

type capBuf struct {
	b         []byte
	limit     int64
	n         int64
	truncated bool
}

func (w *capBuf) Write(p []byte) (int, error) {
	if w.n >= w.limit {
		w.truncated = true
		return len(p), nil
	}
	if room := w.limit - w.n; int64(len(p)) > room {
		w.b = append(w.b, p[:room]...)
		w.n = w.limit
		w.truncated = true
		return len(p), nil
	}
	w.b = append(w.b, p...)
	w.n += int64(len(p))
	return len(p), nil
}

func (w *capBuf) String() string { return string(w.b) }

// clip returns the portion of b that fit under the cap, so the live sink can
// never exceed OutputBytes either. Call AFTER w.Write(b).
func clip(b []byte, w *capBuf) []byte {
	// w.n already reflects the post-write count; the bytes that fit are the tail of
	// b up to whatever room remained. Simplest safe behaviour: forward nothing once
	// truncated, else the whole chunk.
	if w.truncated {
		return nil
	}
	return b
}
