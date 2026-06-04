# Security audit — round 1

An adversarial red-team audit was run against the **live** isobox sandbox: five independent agents attacking by category (sandbox escape, resource exhaustion, network exfiltration, information disclosure, white-box source review), with every claimed exploit independently re-verified before being accepted.

**Verdict: PASS WITH FIXES.** Containment held under live adversarial testing; the defects found were in the orchestration layer (availability / control-gap), none broke isolation. All confirmed issues below are **fixed**.

## Controls that held (verified live)

- **Privilege:** `CapEff=0` (`--cap-drop=ALL`), `no_new_privs=1`, runs as `nobody` (65534).
- **Filesystem:** read-only rootfs (writes to `/etc`, `/box` → `EPERM`); `/box` mounted `:ro`; only the `noexec` `/tmp` tmpfs is writable; `noexec` enforced against both `execve` and `PROT_EXEC` mmap for interpreted languages.
- **gVisor boundary:** guest kernel `4.19.0-gvisor`; `/proc` & `/sys` synthesized (no host PIDs, host RAM shows the cgroup cap).
- **Path traversal:** `files[].name` collapsed to a flat basename (no `..`/escape).
- **Env scrub:** only `HOME=/tmp` + trusted image/registry env; no host env inheritance.
- **Resource caps + clamping:** requests for `memoryBytes` ~900GB / `cpus` 64 / `pids` 99999 / huge wall-time are clamped to the ceilings; memory bomb → `OOMKilled`, fork bomb → pids-cap contained, each correctly disambiguated from timeout.
- **Aggregate containment:** every sandbox nested under `isobox.slice` (`MemoryMax`, `TasksMax`).
- **Network:** default `network:false` → all egress blocked; opt-in `network:true` → metadata/private/host/SMTP firewalled (see [THREAT_MODEL](THREAT_MODEL.md#network-egress-opt-in)).
- **Buffered output truncation** held exactly.

## Confirmed issues — all fixed

| # | Severity | Issue | Fix |
|---|---|---|---|
| 1 | medium | **Per-IP rate-limit bypass.** chi `middleware.RealIP` ranked spoofable headers (`True-Client-IP` > `X-Real-IP` > `X-Forwarded-For`); rotating `True-Client-IP` gave a fresh bucket per request. | Removed `middleware.RealIP`. `clientIP()` now trusts the proxy-set `X-Real-IP` **only when the TCP peer is loopback** (our reverse proxy, which overwrites it from `CF-Connecting-IP`), else the genuine peer. Caddy also strips `True-Client-IP`. *Verified: rotation now collapses to one bucket → `rate_limited`.* |
| 2 | low | **SSE output cap not enforced.** `pump()` forwarded chunks to the live sink unbounded; only the buffered result was capped. | `pump()` forwards to the sink only up to `OutputBytes`. *Verified: a 2 MB write with `outputBytes=2048` streams exactly 2048 bytes.* |
| 3 | info | **Non-constant-time API-key compare** (`key != s.APIKey`). | `crypto/subtle.ConstantTimeCompare`. |
| 4 | hardening | Slice had no CPU ceiling (`CPUQuota=infinity`); 4 concurrent CPU-bound runs could starve neighbors. | `CPUQuota=600%` on `isobox.slice` (6 of 8 cores). |

## Known low-priority notes (no security impact)

- `compileTimeMs` is parsed/clamped but not enforced as a *separate* deadline — the single wall-time timer covers compile+run. Tracked.
- `inspectState` vs the reaper has a tiny TOCTOU window (≤ ms between `wait` and `inspect`) that could degrade OOM/exit *reporting* (not containment); the executor removes its own container, the reaper only sweeps already-exited orphans.
- Egress host-IP block lists the host's current public IP; multi-IP hosts should extend it (the private/metadata/INPUT rules already cover the host regardless).
