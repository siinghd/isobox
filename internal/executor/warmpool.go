package executor

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// WarmPool is an OPTIONAL latency optimisation that WRAPS *Gvisor. It is NOT a new
// Executor type: it embeds the verified backend and, for poolable one-shot jobs,
// serves them by `docker exec`-ing into a pre-booted, fully-hardened container
// instead of paying the ~0.5s cold start of a fresh `docker run`.
//
// SINGLE-USE EPHEMERALITY IS PRESERVED. A pooled container runs `sleep infinity`
// (no user code at rest). A job `docker exec`s a FRESH process into it, and the
// container is then UNCONDITIONALLY `docker rm -f`d and asynchronously replaced —
// so no container is ever reused across two executions. `docker exec` is correct
// here precisely because each job is a brand-new process by design.
//
// DEFAULT-OFF: with Size == 0 the pool pre-boots nothing and Execute is literally
// `wp.gv.Execute(...)` — byte-for-byte the current behaviour. Only when Size > 0
// AND a spec is poolable (the pre-booted image, no extra mounts, network off) does
// the fast path engage; everything else falls straight through to the normal path.
//
// HARDENING is identical to a one-shot job: the warm containers are booted with the
// exact same flag set as Gvisor.buildRunArgs (runsc runtime forcing --network=none,
// --read-only rootfs, noexec tmpfs scratch, swap-off memory cap, cpu/pids caps,
// --cap-drop=ALL, no-new-privileges, nobody user, --cgroup-parent=isobox.slice so
// the pool RAM accounts against the slice). The only fixed difference vs a one-shot
// container is that per-request --memory/--cpus/--pids overrides cannot be applied
// to an already-running container — so a spec is only poolable when its limits match
// the pool's boot limits closely enough (we boot at the global ceiling and let the
// job's wall-time + output cap, both enforced Go-side, do the per-request bounding).
type WarmPool struct {
	gv   *Gvisor
	size int

	// Image / boot limits the pool is pre-booted with. A spec is poolable only when
	// it targets this image (and carries no extra mounts / no network).
	image     string
	memBytes  int64
	cpus      float64
	pids      int
	scratchMB int

	mu      sync.Mutex
	ready   []string // container names of booted, idle warm containers
	closed  bool
	booting atomic.Int64 // in-flight replenish count (observability only)
	jobRoot string
}

// WarmPoolConfig parameterises the pool. Image/limits should mirror the language
// the pool warms (python).
type WarmPoolConfig struct {
	Size      int
	Image     string
	MemBytes  int64
	CPUs      float64
	Pids      int
	ScratchMB int
	JobRoot   string
}

// NewWarmPool wraps gv. If cfg.Size <= 0 the pool is a no-op passthrough: Execute
// always falls through to gv.Execute and no containers are pre-booted.
func NewWarmPool(gv *Gvisor, cfg WarmPoolConfig) *WarmPool {
	wp := &WarmPool{
		gv:        gv,
		size:      cfg.Size,
		image:     cfg.Image,
		memBytes:  cfg.MemBytes,
		cpus:      cfg.CPUs,
		pids:      cfg.Pids,
		scratchMB: cfg.ScratchMB,
		jobRoot:   cfg.JobRoot,
	}
	if wp.memBytes <= 0 {
		wp.memBytes = 384 << 20
	}
	if wp.cpus <= 0 {
		wp.cpus = 1.5
	}
	if wp.pids <= 0 {
		wp.pids = 128
	}
	if wp.scratchMB <= 0 {
		wp.scratchMB = 64
	}
	return wp
}

// Enabled reports whether the fast path is active.
func (wp *WarmPool) Enabled() bool { return wp != nil && wp.size > 0 }

// Size reports the configured pool target (for metrics). Zero => disabled.
func (wp *WarmPool) Size() int {
	if wp == nil {
		return 0
	}
	return wp.size
}

// Ready reports how many warm containers are currently booted and idle (metrics).
func (wp *WarmPool) Ready() int {
	if wp == nil {
		return 0
	}
	wp.mu.Lock()
	defer wp.mu.Unlock()
	return len(wp.ready)
}

// Name and HealthCheck DELEGATE to the wrapped backend so the /execute response
// `backend` field and /readyz are unchanged whether or not the pool is enabled.
func (wp *WarmPool) Name() string { return wp.gv.Name() }
func (wp *WarmPool) HealthCheck(ctx context.Context) error {
	return wp.gv.HealthCheck(ctx)
}

// Prime pre-boots the pool up to Size. Safe to call once at startup; a no-op when
// disabled. Boot failures are logged and tolerated (a missing warm container just
// means that job falls back to a cold run).
func (wp *WarmPool) Prime(ctx context.Context) {
	if !wp.Enabled() {
		return
	}
	for i := 0; i < wp.size; i++ {
		name, err := wp.boot(ctx)
		if err != nil {
			slog.Warn("warmpool: boot failed at prime (will fall back to cold runs)", "err", err)
			continue
		}
		wp.mu.Lock()
		wp.ready = append(wp.ready, name)
		wp.mu.Unlock()
	}
	slog.Info("warmpool primed", "image", wp.image, "ready", wp.Ready(), "target", wp.size)
}

// Close tears down every warm container (graceful shutdown).
func (wp *WarmPool) Close() {
	if wp == nil {
		return
	}
	wp.mu.Lock()
	wp.closed = true
	names := wp.ready
	wp.ready = nil
	wp.mu.Unlock()
	for _, n := range names {
		dockerRmTimeout(n)
	}
}

// poolable reports whether spec can be served by a pre-booted warm container. It
// must match the pool's image, carry no extra mounts (sessions/volumes bind dirs
// the warm container doesn't have), request no network, and have no compile step.
func (wp *WarmPool) poolable(s Spec) bool {
	return wp.Enabled() &&
		s.Image == wp.image &&
		len(s.Mounts) == 0 &&
		len(s.Compile) == 0 &&
		!s.Network
}

// Execute serves a poolable one-shot job from the warm pool when enabled; in EVERY
// other case it falls straight through to the wrapped backend's verified path —
// which is exactly today's behaviour when Size == 0.
//
// The fast path is taken ONLY for buffered jobs (sink == nil). A streaming (SSE)
// job keeps the verified cold path: the warm path's infra-failure fallback re-runs
// cold, but `docker exec`'s OCI error first arrives on stderr and would be forwarded
// to a live sink before the re-run — so to keep the fallback airtight we never warm
// a streaming job. (In practice the buffered /execute path is what benefits from the
// pool; SSE callers already accept streaming overheads.)
func (wp *WarmPool) Execute(ctx context.Context, s Spec, sink OutputSink) (Result, error) {
	if sink != nil || !wp.poolable(s) {
		return wp.gv.Execute(ctx, s, sink)
	}
	name, ok := wp.take()
	if !ok {
		// Pool momentarily empty (all leased / boot failing) — never block a request
		// on the pool; serve it cold.
		return wp.gv.Execute(ctx, s, sink)
	}
	// UNCONDITIONAL teardown + async replenish: the container is single-use, removed
	// after this job whether it succeeds, errors, or the ctx is cancelled.
	defer wp.retire(name)

	res, err := wp.execInto(ctx, name, s, sink)
	if errors.Is(err, errExecStartFailed) {
		// The docker exec never got the user's process running (infra-level failure,
		// e.g. the container died). The job is idempotent (network off, no mounts) and
		// nothing was streamed to the sink yet, so serve it cold instead of surfacing
		// an infra error as user output. The leased container is still retired above.
		slog.Warn("warmpool: exec start failed; falling back to a cold run", "err", err)
		return wp.gv.Execute(ctx, s, sink)
	}
	return res, err
}

// errExecStartFailed signals that `docker exec` could not start the user process in
// the warm container (the process never ran), so Execute may safely retry cold.
var errExecStartFailed = errors.New("warm exec failed to start")

// take leases an idle warm container, or returns ok=false if none is ready.
func (wp *WarmPool) take() (string, bool) {
	wp.mu.Lock()
	defer wp.mu.Unlock()
	if wp.closed || len(wp.ready) == 0 {
		return "", false
	}
	n := wp.ready[len(wp.ready)-1]
	wp.ready = wp.ready[:len(wp.ready)-1]
	return n, true
}

// retire force-removes a used container and asynchronously boots a replacement to
// keep the pool topped up. Removal is unconditional (single-use guarantee).
func (wp *WarmPool) retire(name string) {
	dockerRmTimeout(name)
	wp.mu.Lock()
	closed := wp.closed
	wp.mu.Unlock()
	if closed {
		return
	}
	wp.booting.Add(1)
	go func() {
		defer wp.booting.Add(-1)
		repl, err := wp.boot(context.Background())
		if err != nil {
			slog.Warn("warmpool: replenish failed (pool runs below target until next retire)", "err", err)
			return
		}
		wp.mu.Lock()
		if wp.closed {
			wp.mu.Unlock()
			dockerRmTimeout(repl)
			return
		}
		wp.ready = append(wp.ready, repl)
		wp.mu.Unlock()
	}()
}

// dockerRmTimeout / dockerKillTimeout run best-effort container teardown with a
// hard deadline, so a wedged docker daemon can't block pool replenishment or
// graceful shutdown indefinitely (bare exec.Command.Run() has no timeout).
func dockerRmTimeout(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", name).Run()
}

func dockerKillTimeout(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "docker", "kill", name).Run()
}

// boot starts one hardened, idle warm container running `sleep infinity`. It mirrors
// Gvisor.buildRunArgs flag-for-flag (minus the per-job source bind, which arrives
// later via `docker exec`). Returns the container name.
func (wp *WarmPool) boot(ctx context.Context) (string, error) {
	name := "iso-warm-" + uuid.NewString()
	tmpfs := fmt.Sprintf("/tmp:rw,noexec,nosuid,nodev,size=%dm,nr_inodes=%d", wp.scratchMB, wp.scratchMB*64)
	a := []string{
		"run", "-d",
		"--name", name,
		"--runtime", wp.gv.Runtime, // runsc-untrusted: forces --network=none
		"--network=none",
		"--read-only",
		"--tmpfs", tmpfs,
		"--memory", strconv.FormatInt(wp.memBytes, 10),
		"--memory-swap", strconv.FormatInt(wp.memBytes, 10), // equal => swap OFF
		"--cpus", strconv.FormatFloat(wp.cpus, 'f', 2, 64),
		"--pids-limit", strconv.Itoa(wp.pids),
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--user=" + wp.gv.User,
		"--cgroup-parent=" + wp.gv.Slice, // pool RAM accounts against isobox.slice
		"--hostname=sandbox",
		"--label", "isobox.managed=true",
		"--label", "isobox.warm=true",
		"--env", "HOME=/tmp",
		wp.image,
		"sleep", "infinity",
	}
	if out, err := exec.CommandContext(ctx, "docker", a...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("docker run warm: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return name, nil
}

// execInto runs the job as a FRESH process inside the leased warm container via
// `docker exec -i`. The user's source files are staged in a world-readable host dir
// and streamed in over stdin to a tiny shell launcher that writes them under /tmp,
// then execs the trusted run argv — keeping the rootfs read-only and never touching
// the container across jobs except for this one ephemeral exec.
//
// Limits note: --memory/--cpus/--pids are fixed at boot and CANNOT be overridden per
// exec; the per-request wall-time (Go-side timer) and output cap (Go-side capWriter)
// still apply exactly as on the cold path. OOMKilled cannot be read back from the
// persistent container's State, so the OOM signal is best-effort false here.
func (wp *WarmPool) execInto(ctx context.Context, name string, s Spec, sink OutputSink) (Result, error) {
	var res Result
	res.Network = false // poolable => network off by construction

	// 1. Stage source files in a world-readable host dir, then base64 them into the
	//    in-container launcher so we never depend on a bind mount (the warm container
	//    has none) and never interpolate user bytes into a shell.
	jobDir, err := os.MkdirTemp(wp.jobRoot, "iso-warm-job-")
	if err != nil {
		return res, fmt.Errorf("create job dir: %w", err)
	}
	defer os.RemoveAll(jobDir)

	// Build a here-doc-free launcher: read each file's bytes from stdin via a length
	// header. Simpler + injection-proof: write files into a fresh /tmp/box dir using
	// printf of base64 piped to base64 -d. The run argv is trusted (registry only).
	var script strings.Builder
	script.WriteString("set -e; mkdir -p /tmp/box; cd /tmp/box; ")
	for _, f := range s.Files {
		nm := sanitizeName(f.Name)
		if nm == "" {
			continue
		}
		data, derr := decodeFile(f)
		if derr != nil {
			return res, fmt.Errorf("decode file %q: %w", f.Name, derr)
		}
		// Stage on host too (defensive; not bind-mounted) and embed base64 inline.
		_ = os.WriteFile(filepath.Join(jobDir, nm), data, 0o644)
		b64 := base64.StdEncoding.EncodeToString(data)
		script.WriteString("printf %s " + shQuote(b64) + " | base64 -d > " + shQuote(nm) + "; ")
	}
	// Run argv comes from the trusted registry; rewrite a leading /box path to the
	// warm container's /tmp/box staging dir. User Argv is passed safely as "$@".
	run := rewriteBoxPaths(s.Run)
	script.WriteString("exec " + shJoin(run) + ` "$@"`)

	args := []string{"exec", "-i"}
	// Re-assert HOME and any spec env on the exec (the boot env is inherited, but a
	// per-spec env override must win for this process).
	args = append(args, "-e", "HOME=/tmp")
	for k, v := range s.Env {
		args = append(args, "-e", k+"="+v)
	}
	// -w MUST point at a dir that already exists: `docker exec --workdir` (unlike
	// `docker run -w`) does NOT create it, and /tmp/box is made by the script below.
	// Use /tmp (always present) and let the script `cd /tmp/box`; the run argv was
	// rewritten to absolute /tmp/box paths so cwd doesn't matter for it.
	args = append(args, "-w", "/tmp", name, "sh", "-c", script.String(), "iso")
	args = append(args, s.Argv...)

	wall := time.Duration(s.Limits.WallTimeMs) * time.Millisecond
	if wall <= 0 {
		wall = 10 * time.Second
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "docker", args...)
	if s.Stdin != "" {
		cmd.Stdin = strings.NewReader(s.Stdin)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return res, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return res, err
	}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return res, fmt.Errorf("docker exec: %w", err)
	}

	limit := s.Limits.OutputBytes
	if limit <= 0 {
		limit = 64 << 10
	}
	outW := &capWriter{limit: limit}
	errW := &capWriter{limit: limit}
	var wg sync.WaitGroup
	wg.Add(2)
	go pump(&wg, stdoutPipe, outW, sinkFn(sink, false))
	go pump(&wg, stderrPipe, errW, sinkFn(sink, true))

	// Wall-time enforcement: on deadline, kill the exec'd process tree. Killing the
	// warm container would defeat single-use replenish accounting, but the container
	// is force-removed unconditionally by retire() right after, so killing it on
	// timeout is fine and guarantees the runaway process dies.
	var timedOut atomic.Bool
	timer := time.AfterFunc(wall, func() {
		timedOut.Store(true)
		dockerKillTimeout(name)
	})

	waitErr := cmd.Wait()
	timer.Stop()
	wg.Wait()
	res.DurationMs = time.Since(start).Milliseconds()

	res.Stdout = outW.String()
	res.Stderr = errW.String()
	res.Truncated = outW.truncated || errW.truncated
	res.TimedOut = timedOut.Load()

	// Exit code from the `docker exec` client (it propagates the exec'd process exit
	// code). OOMKilled is not observable on a persistent container, so it stays false.
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if res.TimedOut {
		res.ExitCode = 137
	}
	_ = waitErr // nonzero exit is carried in the structured Result

	// INFRA-FAILURE detection: when `docker exec` cannot start the user process (the
	// container died, a runtime hiccup), it exits 126/127 with an "OCI runtime exec
	// failed" banner on stderr and produces NO program stdout. The user's process
	// never ran, so this is not a real result — signal Execute to retry cold. Guarded
	// on empty stdout so a real run that legitimately exits 126/127 (or an SSE run
	// that already streamed bytes) is never misclassified.
	if !res.TimedOut && outW.String() == "" && (res.ExitCode == 125 || res.ExitCode == 126 || res.ExitCode == 127) &&
		strings.Contains(res.Stderr, "OCI runtime exec failed") {
		return res, errExecStartFailed
	}
	return res, nil
}

// rewriteBoxPaths rewrites a trusted run argv's /box prefix to /tmp/box (the warm
// container's staging dir). The cold path mounts source at /box; the warm path
// stages it under the tmpfs at /tmp/box.
func rewriteBoxPaths(run []string) []string {
	out := make([]string, len(run))
	for i, p := range run {
		if strings.HasPrefix(p, "/box/") {
			out[i] = "/tmp/box/" + strings.TrimPrefix(p, "/box/")
		} else if p == "/box" {
			out[i] = "/tmp/box"
		} else {
			out[i] = p
		}
	}
	return out
}
