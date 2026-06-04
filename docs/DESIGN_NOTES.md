# isobox — Architecture (v1)

Self-hostable, security-first sandbox for running untrusted / AI-generated code.
Isolation: gVisor (runsc, systrap) on this no-KVM ARM64 box; pluggable Firecracker / hardened-runc backends.

## Verified ground truth (this host, 2026-06-04)
- aarch64 Neoverse-N1, 8 cores. RAM 277MB free / 4.7G available; **swap 3.3G/4G already used**.
- No `/dev/kvm` → KVM/Firecracker impossible here. `runsc release-20260525.0`, platform=systrap, kernel `4.19.0-gvisor`. Docker 29.1.3, cgroup v2, systemd 255.
- `isobox.slice` is loaded but UNCONFIGURED (`MemoryMax=infinity`) → must be written.
- Only bare `runsc` runtime in daemon.json → must add `runsc-untrusted`.
- Port **8090 free**. Caddy already trusts CF IPs + reads `CF-Connecting-IP` (so `{remote_host}` = real client IP).
- `python:3-slim@sha256:c845af9399020c7e562969a13689e929074a10fd057acd1b1fad06a2fb068e97` pulled (arm64).

## Empirically verified (combined, this session)
1. Full hardened invocation as a UNIT works: `--runtime=runsc --network=none --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m -v JOBDIR:/box:ro --memory=256m --memory-swap=256m --cpus=1.0 --pids-limit=128 --cap-drop=ALL --security-opt=no-new-privileges --user=65534:65534 --cgroup-parent=isobox.slice --env HOME=/tmp`. stdout captured, `sys.exit(7)` → host exit 7 propagated. **`HOME=/tmp` is required** (RO rootfs + nobody has no writable home).
2. Deliberate OOM (alloc>memory): host exit **137** AND `docker inspect .State.OOMKilled == true` under gVisor. → Use `ContainerInspect().State.OOMKilled` as the OOM signal (more robust than parsing gVisor-nested `memory.events`).

## Verification status (honest)
- VERIFIED this session: exit-7 propagation path; OOM path (137 + OOMKilled=true) — both with **bare `runsc` + per-exec docker-run flags**.
- NOT yet verified: (a) the `runsc-untrusted` daemon.json runtime as a unit (must add it + `systemctl reload docker` + re-run smoke test — daemon.json is a prod change, out of scope for the design phase); (b) the timeout branch (context deadline → docker kill → 137 + OOMKilled=**false**) — disambiguation logic is sound but one-sided in evidence; covered by a buildSequence integration test.
- `runsc-untrusted` earns its place as **centralization** (a caller physically cannot omit `--network=none`), NOT new isolation: `--host-uds=none/--host-fifo=none/--file-access=exclusive` are runsc defaults, and `--overlay2=all:memory` is moot under `--read-only` (no writable overlay upper; only writable surface is the RAM-backed tmpfs `/tmp`, charged to the 256m).

## Resolved cross-dimension conflicts (decided, not averaged)
1. **Code transport** = RO bind-mount of a per-job control-plane temp dir at `/box` (codapi/Piston shape; supports multi-file `files[]`). Dim 2's "no bind mounts" = no *host system* paths; an ephemeral RO job dir is safe (rootfs stays `--read-only`, `/tmp` tmpfs RW).
2. **/tmp exec** = `noexec,nosuid,nodev` for Python milestone. NOT hardcoded in the executor — `scratch_exec` is a per-language registry flag so compiled langs (go build → /tmp/prog) flip to `exec` at fan-out.
3. **Slice MemoryMax = 2G** (grounded in verified swap 3.3/4G used, not stale "5GB free"). `MemorySwapMax=0`, `memory.oom.group=1`, concurrency **6** (6×~300m ≈ 1.8G < 2G).
4. **Numeric defaults** (per-request overridable): cpus 1.0, pids 128, output 64KB default / 256KB hard max, wall-time 10s.
5. **Two Limits structs kept distinct**: registry `Limits` (YAML defaults) vs runtime `executor.Limits` (Spec); map between them, don't conflate.

## Honesty flag (security-first project)
`import origin_tls` is the Cloudflare **origin cert only** — NOT Authenticated Origin Pull (mTLS). The threat model's "origin lock prevents Turnstile/rate-limit bypass" is therefore **not yet true**. Real residual: an attacker hitting Caddy:443 by IP skips Cloudflare. Milestone-1 mitigation: Go binds `127.0.0.1:8090` (origin only reachable via Caddy) + recommend a 443 firewall allowing only Cloudflare IP ranges. Full fix (deferred): add `tls { client_auth { mode require_and_verify; trusted_ca_cert_file <cloudflare-origin-pull-ca> } }`. Do NOT claim AOP until configured.
