package executor

import "os"

// Detect picks the strongest isolation backend the host supports.
//
//   - /dev/kvm present  => Firecracker microVMs (hardware isolation) — not yet
//     implemented; falls through to gVisor for now.
//   - otherwise          => gVisor (runsc, systrap) — a userspace kernel that
//     needs no hardware virtualization. This is the path on the verified host.
//
// A hardened-runc fallback is the lowest tier (shared host kernel) and must be
// opted into explicitly; it is never auto-selected for untrusted code.
func Detect() Executor {
	if hasKVM() {
		// TODO(firecracker): return NewFirecracker() once implemented.
		return NewGvisor()
	}
	return NewGvisor()
}

func hasKVM() bool {
	_, err := os.Stat("/dev/kvm")
	return err == nil
}
