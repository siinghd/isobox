// Package executor defines the pluggable isolation backend for isobox.
//
// The Executor interface is the seam that keeps isobox portable: the gVisor
// (runsc) backend runs on hosts without hardware virtualization (no /dev/kvm),
// a Firecracker backend can run on KVM hosts, and a hardened-runc backend is
// the lowest-common-denominator fallback. The control plane talks only to this
// interface, never to a specific runtime.
package executor

import "context"

// Language identifies a runtime by name and version (e.g. python / 3.14.5).
type Language struct {
	Name    string `json:"language"`
	Version string `json:"version"`
}

// File is one source file written into the sandbox working directory.
type File struct {
	Name     string `json:"name"`
	Content  string `json:"content"`
	Encoding string `json:"encoding,omitempty"` // utf8 (default) | base64 | hex
}

// Limits are the per-execution resource bounds. They are enforced by the host
// kernel (cgroup v2) and by the worker (wall-time, output size), never trusted
// to the guest.
type Limits struct {
	MemoryBytes   int64   `json:"memoryBytes"`   // --memory AND --memory-swap (equal => swap OFF)
	CPUs          float64 `json:"cpus"`          // --cpus (cgroup cpu.max)
	Pids          int     `json:"pids"`          // --pids-limit (fork-bomb guard)
	OutputBytes   int64   `json:"outputBytes"`   // stdout+stderr truncation ceiling
	WallTimeMs    int     `json:"wallTimeMs"`    // worker-enforced deadline -> kill
	CompileTimeMs int     `json:"compileTimeMs"` // compile-phase deadline (compiled langs)
}

// Spec is a fully-resolved execution request. The control plane fills Image,
// Compile, Run, Workdir, Env and ScratchExec from the trusted language registry;
// Files, Stdin, Argv and Limits come (validated/clamped) from the caller.
type Spec struct {
	Lang        Language          // language identity (for the result envelope)
	Image       string            // digest-pinned OCI image
	Compile     []string          // trusted compile argv (nil => interpreted)
	Run         []string          // trusted run argv (user Argv appended after)
	Workdir     string            // container workdir (default /box)
	Env         map[string]string // extra env (HOME=/tmp is always added)
	ScratchExec bool              // true => /tmp mounted exec (compiled langs)
	ScratchMB   int               // size of the /tmp tmpfs in MiB (default 64)
	Files       []File            // source files written into the job dir
	Stdin       string            // fed to the program's stdin
	Argv        []string          // user program arguments (passed safely as "$@")
	Limits      Limits            // resource bounds
	Network     bool              // default false => --network=none
}

// Result is the outcome of one execution. The boolean signals are authoritative:
// TimedOut and OOMKilled disambiguate the otherwise-ambiguous exit code 137.
type Result struct {
	Stdout        string `json:"stdout"`
	Stderr        string `json:"stderr"`
	ExitCode      int    `json:"exitCode"`
	TimedOut      bool   `json:"timedOut"`
	OOMKilled     bool   `json:"oomKilled"`
	Truncated     bool   `json:"truncated"`
	DurationMs    int64  `json:"durationMs"`
	CompileOutput string `json:"compileOutput,omitempty"`
}

// OutputSink receives stdout/stderr chunks as they are produced. It is optional:
// when nil the executor still buffers output into Result. When non-nil (SSE) the
// executor forwards each chunk live. Implementations must be safe for concurrent
// Stdout/Stderr calls.
type OutputSink interface {
	Stdout([]byte)
	Stderr([]byte)
}

// Executor is the pluggable isolation backend.
type Executor interface {
	// Name reports the backend identity: "gvisor" | "firecracker" | "runc".
	Name() string
	// HealthCheck verifies the backend can run sandboxes (e.g. runtime present).
	HealthCheck(ctx context.Context) error
	// Execute runs one Spec to completion. ctx may carry a deadline / be cancelled
	// (client disconnect); the executor must always reap the sandbox.
	Execute(ctx context.Context, s Spec, sink OutputSink) (Result, error)
}
