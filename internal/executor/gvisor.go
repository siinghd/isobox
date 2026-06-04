package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
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

// Gvisor runs each execution as a hardened, single-shot Docker container under
// the gVisor (runsc) runtime, nested in a hard-capped parent cgroup slice.
//
// Implementation note: this backend drives the `docker` CLI rather than the
// Docker SDK. The exact argv it builds was empirically verified end-to-end on
// the target host (stdout capture, exit-code propagation, read-only rootfs,
// tmpfs scratch, network-off, non-root, slice nesting, OOM detection). Driving
// the CLI keeps the dependency surface tiny and the behaviour identical to what
// was verified by hand. Swapping to the SDK (or Firecracker) is a drop-in behind
// the Executor interface.
type Gvisor struct {
	Runtime       string // no-network runtime (forces --network=none), e.g. "runsc-untrusted"
	NetRuntime    string // runtime used for opt-in network mode, e.g. "runsc-net"
	Slice         string // systemd cgroup parent, e.g. "isobox.slice"
	JobRoot       string // base dir for ephemeral per-job dirs ("" => os.TempDir)
	User          string // uid:gid inside the sandbox (default 65534:65534 = nobody)
	AllowNetwork  bool   // master switch for opt-in egress
	EgressNetwork string // docker network with the egress firewall, e.g. "isobox-egress"
	ResolvConf    string // host file with public resolvers, bind-mounted in network mode

	// Fail-closed heartbeat: a privileged timer re-asserts the egress firewall and
	// refreshes this sentinel file. isoboxd (unprivileged) cannot read iptables, so
	// it gates network on the sentinel being present AND fresh. If the firewall is
	// ever torn down (e.g. a docker restart flushes DOCKER-USER), the sentinel goes
	// stale and network mode automatically disables — instead of failing open.
	Sentinel       string        // "" disables the check (operator manages the firewall)
	SentinelMaxAge time.Duration // max sentinel age before network is refused
}

// NewGvisor returns a backend with safe defaults for the verified host setup.
func NewGvisor() *Gvisor {
	return &Gvisor{
		Runtime:        "runsc-untrusted",
		NetRuntime:     "runsc-net",
		Slice:          "isobox.slice",
		User:           "65534:65534",
		AllowNetwork:   true,
		EgressNetwork:  "isobox-egress",
		ResolvConf:     "/etc/isobox/resolv.conf",
		Sentinel:       "/etc/isobox/egress-ok",
		SentinelMaxAge: 240 * time.Second, // ~5 missed 45s heartbeats before fail-closed
	}
}

// networkEnabled reports whether this spec should get filtered egress. It fails
// CLOSED: even with network requested and allowed, egress is refused unless the
// firewall heartbeat sentinel is present and fresh.
func (g *Gvisor) networkEnabled(s Spec) bool {
	return s.Network && g.AllowNetwork && g.EgressNetwork != "" && g.egressFirewallFresh()
}

// egressFirewallFresh reports whether the privileged re-assert timer has recently
// confirmed the egress firewall is in place. An empty Sentinel disables the check
// (operator-managed firewall).
func (g *Gvisor) egressFirewallFresh() bool {
	if g.Sentinel == "" {
		return true
	}
	fi, err := os.Stat(g.Sentinel)
	if err != nil {
		return false
	}
	return time.Since(fi.ModTime()) < g.SentinelMaxAge
}

func (g *Gvisor) Name() string { return "gvisor" }

// HealthCheck confirms docker is reachable and the hardened runtime is registered.
func (g *Gvisor) HealthCheck(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{json .Runtimes}}").Output()
	if err != nil {
		return fmt.Errorf("docker info: %w", err)
	}
	if !strings.Contains(string(out), g.Runtime) {
		return fmt.Errorf("docker runtime %q not registered", g.Runtime)
	}
	return nil
}

// Execute runs one Spec to completion and always reaps the sandbox.
func (g *Gvisor) Execute(ctx context.Context, s Spec, sink OutputSink) (Result, error) {
	var res Result
	res.Network = g.networkEnabled(s) // false if requested but fail-closed

	// 1. Ephemeral, world-readable job dir so uid 65534 (nobody) inside the
	//    sandbox can read the source files (they are the caller's own code).
	jobDir, err := os.MkdirTemp(g.JobRoot, "iso-job-")
	if err != nil {
		return res, fmt.Errorf("create job dir: %w", err)
	}
	defer os.RemoveAll(jobDir)
	if err := os.Chmod(jobDir, 0o755); err != nil {
		return res, fmt.Errorf("chmod job dir: %w", err)
	}
	for _, f := range s.Files {
		name := sanitizeName(f.Name)
		if name == "" {
			continue
		}
		data, derr := decodeFile(f)
		if derr != nil {
			return res, fmt.Errorf("decode file %q: %w", f.Name, derr)
		}
		if err := os.WriteFile(filepath.Join(jobDir, name), data, 0o644); err != nil {
			return res, fmt.Errorf("write file %q: %w", name, err)
		}
	}

	// 2. Trusted in-container launcher: optional compile, then exec the run argv
	//    with the user's arguments passed safely as positional params ("$@").
	//    Compile/Run come from the trusted registry, never from the caller, so
	//    interpolating them into `sh -c` is safe; user Argv is NOT interpolated.
	var script strings.Builder
	script.WriteString("set -e; ")
	if len(s.Compile) > 0 {
		script.WriteString(shJoin(s.Compile) + "; ")
	}
	script.WriteString("exec " + shJoin(s.Run) + ` "$@"`)

	name := "iso-" + uuid.NewString()
	args := g.buildRunArgs(name, jobDir, s)
	args = append(args, "sh", "-c", script.String(), "iso")
	args = append(args, s.Argv...)

	// 3. Launch. No --rm: we inspect for OOMKilled/ExitCode before removing.
	//    The deferred force-remove guarantees teardown even on panic/cancel; the
	//    label-based reaper sweeps any orphan a crash leaves behind.
	wall := time.Duration(s.Limits.WallTimeMs) * time.Millisecond
	if wall <= 0 {
		wall = 10 * time.Second
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "docker", append([]string{"run"}, args...)...)
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
	defer func() { _ = exec.Command("docker", "rm", "-f", name).Run() }()

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return res, fmt.Errorf("docker run: %w", err)
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

	// Wall-time enforcement: on deadline, kill the container by name (killing the
	// docker client alone would orphan it). Records the timeout signal.
	var timedOut atomic.Bool
	timer := time.AfterFunc(wall, func() {
		timedOut.Store(true)
		_ = exec.Command("docker", "kill", name).Run()
	})

	waitErr := cmd.Wait()
	timer.Stop()
	wg.Wait()
	res.DurationMs = time.Since(start).Milliseconds()

	res.Stdout = outW.String()
	res.Stderr = errW.String()
	res.Truncated = outW.truncated || errW.truncated
	res.TimedOut = timedOut.Load()

	// Authoritative exit code + OOM signal from the container state, captured
	// before the deferred remove runs.
	if oom, code, ok := inspectState(name); ok {
		res.OOMKilled = oom
		res.ExitCode = code
	} else if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if res.TimedOut {
		res.ExitCode = 137
		res.OOMKilled = false
	}
	_ = waitErr // non-nil for any nonzero exit; the structured Result is the source of truth
	return res, nil
}

// buildRunArgs assembles the verified hardened `docker run` flag set (everything
// up to the image). The trailing command (sh -c …) is appended by the caller.
func (g *Gvisor) buildRunArgs(name, jobDir string, s Spec) []string {
	mem := s.Limits.MemoryBytes
	if mem <= 0 {
		mem = 256 << 20
	}
	pids := s.Limits.Pids
	if pids <= 0 {
		pids = 128
	}
	cpus := s.Limits.CPUs
	if cpus <= 0 {
		cpus = 1.0
	}
	workdir := s.Workdir
	if workdir == "" {
		workdir = "/box"
	}
	// /tmp is the only writable surface: RAM-backed, size- and inode-bounded.
	// Docker mounts --tmpfs noexec by default, so compiled languages must pass an
	// EXPLICIT `exec` option (scratch_exec) — otherwise a built binary cannot run
	// even with the executable bit set. (tmpfs usage counts against --memory.)
	scratchMB := s.ScratchMB
	if scratchMB <= 0 {
		scratchMB = 64
	}
	execOpt := "noexec"
	if s.ScratchExec {
		execOpt = "exec"
	}
	tmpfs := fmt.Sprintf("/tmp:rw,%s,nosuid,nodev,size=%dm,nr_inodes=%d", execOpt, scratchMB, scratchMB*64)

	// Default: no network at all, via the runtime that *forces* --network=none.
	// Opt-in: the hardened net runtime + the FILTERED egress bridge (public
	// internet only — metadata/private/host/SMTP are firewalled at the host) +
	// a public resolv.conf, since gVisor's netstack can't use Docker's embedded
	// DNS resolver at 127.0.0.11.
	runtime := g.Runtime
	netArgs := []string{"--network=none"}
	if g.networkEnabled(s) {
		runtime = g.NetRuntime
		netArgs = []string{"--network=" + g.EgressNetwork}
	}

	a := []string{
		"--name", name,
		"--runtime", runtime,
	}
	a = append(a, netArgs...)
	if g.networkEnabled(s) && g.ResolvConf != "" {
		a = append(a, "-v", g.ResolvConf+":/etc/resolv.conf:ro")
	}
	a = append(a,
		"--read-only",
		"--tmpfs", tmpfs,
		"-v", jobDir+":/box:ro",
		"-w", workdir,
		"--memory", strconv.FormatInt(mem, 10),
		"--memory-swap", strconv.FormatInt(mem, 10), // equal => swap OFF
		"--cpus", strconv.FormatFloat(cpus, 'f', 2, 64),
		"--pids-limit", strconv.Itoa(pids),
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--user=" + g.User,
		"--cgroup-parent=" + g.Slice,
		"--hostname=sandbox",
		"--label", "isobox.managed=true",
	)

	// Extra binds: a session's persistent /workspace (RW) and any memory volume.
	// These survive across steps; the rootfs stays --read-only and every other
	// control (gVisor, cap-drop, no-new-privs, nobody, network) is unchanged.
	for _, m := range s.Mounts {
		mode := "ro"
		if m.RW {
			mode = "rw"
		}
		a = append(a, "-v", m.HostPath+":"+m.Target+":"+mode)
	}

	// HOME must be writable under --read-only + nobody; point it at the tmpfs.
	env := map[string]string{"HOME": "/tmp"}
	for k, v := range s.Env {
		env[k] = v
	}
	for k, v := range env {
		a = append(a, "--env", k+"="+v)
	}
	a = append(a, s.Image)
	return a
}

// --- helpers ---------------------------------------------------------------

func sinkFn(sink OutputSink, isErr bool) func([]byte) {
	if sink == nil {
		return nil
	}
	if isErr {
		return sink.Stderr
	}
	return sink.Stdout
}

// inspectState reads the container's terminal state. Returns ok=false if the
// container is already gone.
func inspectState(name string) (oom bool, code int, ok bool) {
	out, err := exec.Command("docker", "inspect", name,
		"--format", "{{.State.OOMKilled}}|{{.State.ExitCode}}").Output()
	if err != nil {
		return false, 0, false
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	if len(parts) != 2 {
		return false, 0, false
	}
	code, _ = strconv.Atoi(parts[1])
	return parts[0] == "true", code, true
}

func decodeFile(f File) ([]byte, error) {
	switch strings.ToLower(f.Encoding) {
	case "", "utf8", "utf-8":
		return []byte(f.Content), nil
	case "base64":
		return base64.StdEncoding.DecodeString(f.Content)
	case "hex":
		return hex.DecodeString(f.Content)
	default:
		return nil, fmt.Errorf("unsupported encoding %q", f.Encoding)
	}
}

// sanitizeName reduces a caller-supplied file name to a safe flat base name,
// rejecting path traversal. (Subdirectories are a deliberate v1 non-feature.)
func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	base := filepath.Base(name)
	if base == "." || base == ".." || strings.ContainsAny(base, "/\\") {
		return ""
	}
	return base
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func shJoin(parts []string) string {
	q := make([]string, len(parts))
	for i, p := range parts {
		q[i] = shQuote(p)
	}
	return strings.Join(q, " ")
}

// capWriter buffers up to limit bytes, flagging truncation past the cap.
type capWriter struct {
	buf       bytes.Buffer
	limit     int64
	n         int64
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if w.n >= w.limit {
		w.truncated = true
		return len(p), nil
	}
	if room := w.limit - w.n; int64(len(p)) > room {
		w.buf.Write(p[:room])
		w.n = w.limit
		w.truncated = true
		return len(p), nil
	}
	w.buf.Write(p)
	w.n += int64(len(p))
	return len(p), nil
}

func (w *capWriter) String() string { return w.buf.String() }

// pump copies a sandbox output stream into the capped buffer and, if a live
// sink is present, forwards a private copy of each chunk.
func pump(wg *sync.WaitGroup, r io.Reader, w *capWriter, sink func([]byte)) {
	defer wg.Done()
	buf := make([]byte, 16<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			// Forward to the live sink only up to the SAME cap as the buffered
			// output, so the SSE stream cannot exceed OutputBytes either. (Read
			// w.n before w.Write; pump is the sole writer of this capWriter.)
			if sink != nil {
				if room := w.limit - w.n; room > 0 {
					k := n
					if int64(k) > room {
						k = int(room)
					}
					c := make([]byte, k)
					copy(c, buf[:k])
					sink(c)
				}
			}
			_, _ = w.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}
