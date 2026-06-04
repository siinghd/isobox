// Package integration exercises the real gVisor backend end-to-end. It requires
// docker + the runsc-untrusted runtime + the isobox.slice cgroup, so it is
// skipped automatically where those are absent (e.g. CI without gVisor).
//
//	go test ./test/integration -run TestGvisor -v
package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/siinghd/isobox/internal/executor"
	"github.com/siinghd/isobox/internal/registry"
)

const registryPath = "../../internal/registry/registry.yaml"

func newPythonSpec(t *testing.T, code string, limits executor.Limits) executor.Spec {
	t.Helper()
	reg, err := registry.Load(registryPath)
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	lang, ok := reg.Resolve("python", "")
	if !ok {
		t.Fatal("python not in registry")
	}
	def := lang.DefaultLimits()
	if limits.MemoryBytes != 0 {
		def.MemoryBytes = limits.MemoryBytes
	}
	if limits.WallTimeMs != 0 {
		def.WallTimeMs = limits.WallTimeMs
	}
	if limits.OutputBytes != 0 {
		def.OutputBytes = limits.OutputBytes
	}
	if limits.Pids != 0 {
		def.Pids = limits.Pids
	}
	return lang.BuildSpec(
		[]executor.File{{Name: "main.py", Content: code}},
		"", nil, def, false,
	)
}

func gvisorOrSkip(t *testing.T) *executor.Gvisor {
	t.Helper()
	g := executor.NewGvisor()
	if err := g.HealthCheck(context.Background()); err != nil {
		t.Skipf("gVisor backend unavailable: %v", err)
	}
	return g
}

func run(t *testing.T, g *executor.Gvisor, spec executor.Spec) executor.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := g.Execute(ctx, spec, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	return res
}

func TestGvisorHelloWorld(t *testing.T) {
	g := gvisorOrSkip(t)
	res := run(t, g, newPythonSpec(t, `print("hello"); print(sum(range(10)))`, executor.Limits{}))
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "hello") || !strings.Contains(res.Stdout, "45") {
		t.Fatalf("unexpected stdout: %q", res.Stdout)
	}
}

func TestGvisorExitCodePropagation(t *testing.T) {
	g := gvisorOrSkip(t)
	res := run(t, g, newPythonSpec(t, `import sys; sys.exit(7)`, executor.Limits{}))
	if res.ExitCode != 7 {
		t.Fatalf("want exit 7, got %d", res.ExitCode)
	}
	if res.TimedOut || res.OOMKilled {
		t.Fatalf("clean exit misclassified: timedOut=%v oom=%v", res.TimedOut, res.OOMKilled)
	}
}

// The disambiguation that is easiest to get wrong: a wall-time kill and an OOM
// both surface as host exit 137. They must be told apart.
func TestGvisorTimeoutVsOOM(t *testing.T) {
	g := gvisorOrSkip(t)

	t.Run("timeout", func(t *testing.T) {
		res := run(t, g, newPythonSpec(t, `import time; time.sleep(30)`, executor.Limits{WallTimeMs: 1200}))
		if !res.TimedOut {
			t.Fatalf("want timedOut=true, got exit=%d oom=%v", res.ExitCode, res.OOMKilled)
		}
		if res.OOMKilled {
			t.Fatal("timeout must not be reported as OOM")
		}
	})

	t.Run("oom", func(t *testing.T) {
		res := run(t, g, newPythonSpec(t, `x = bytearray(400*1024*1024)`, executor.Limits{MemoryBytes: 128 << 20, WallTimeMs: 8000}))
		if !res.OOMKilled {
			t.Fatalf("want oomKilled=true, got exit=%d timedOut=%v", res.ExitCode, res.TimedOut)
		}
		if res.TimedOut {
			t.Fatal("OOM must not be reported as timeout")
		}
	})
}

func TestGvisorNetworkOff(t *testing.T) {
	g := gvisorOrSkip(t)
	code := `import socket; socket.setdefaulttimeout(3); socket.create_connection(("1.1.1.1",53)); print("LEAK")`
	res := run(t, g, newPythonSpec(t, code, executor.Limits{}))
	if res.ExitCode == 0 || strings.Contains(res.Stdout, "LEAK") {
		t.Fatalf("network egress was NOT blocked: exit=%d stdout=%q", res.ExitCode, res.Stdout)
	}
}

func TestGvisorReadOnlyRoot(t *testing.T) {
	g := gvisorOrSkip(t)
	res := run(t, g, newPythonSpec(t, `open("/etc/pwned","w").write("x"); print("WROTE")`, executor.Limits{}))
	if res.ExitCode == 0 || strings.Contains(res.Stdout, "WROTE") {
		t.Fatalf("rootfs was writable: exit=%d stdout=%q", res.ExitCode, res.Stdout)
	}
}

func TestGvisorOutputTruncation(t *testing.T) {
	g := gvisorOrSkip(t)
	res := run(t, g, newPythonSpec(t, `print("A"*2_000_000)`, executor.Limits{OutputBytes: 4096}))
	if !res.Truncated {
		t.Fatal("want truncated=true")
	}
	if len(res.Stdout) > 8192 {
		t.Fatalf("output not capped: %d bytes", len(res.Stdout))
	}
}
