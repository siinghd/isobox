# isobox threat model

isobox runs **untrusted, possibly adversarial code** (AI-generated or user-submitted) and is often exposed to the public internet. This document enumerates the attack surface (STRIDE) and maps every class to a concrete, enforced control. It is deliberately honest about residual risk.

## Trust boundary

The guest code is the adversary. The boundary on a **no-KVM host is gVisor's `Sentry`** — a userspace reimplementation of the Linux kernel in memory-safe Go that intercepts guest syscalls, so the host kernel only ever sees a small seccomp-permitted set from the Sentry itself. This is strong defense-in-depth, **but it is a software boundary, strictly weaker than a hardware VM.** For fully-hostile multi-tenant workloads, run the Firecracker backend on KVM hardware. We do not pretend gVisor equals a microVM.

## Defense-in-depth layers

1. **Isolation** — gVisor (`runsc`, systrap): guest syscalls never reach the host kernel directly.
2. **Least privilege** — non-root (`--user=65534`), `--cap-drop=ALL`, `--security-opt=no-new-privileges`, never `--privileged`.
3. **No network** — `--network=none` by default *and* baked into the `runsc-untrusted` runtime so a caller cannot omit it.
4. **Immutable filesystem** — `--read-only` rootfs; the only writable surface is a size+inode-bounded `tmpfs /tmp`; source is a **read-only** bind mount.
5. **Resource caps (cgroup v2)** — memory (swap off), cpu, pids; enforced by the host kernel, not trusted to the guest.
6. **Blast-radius ceiling** — every sandbox nests under `isobox.slice` (`MemoryMax`, `MemorySwapMax=0`): the *aggregate* of all sandboxes is hard-capped, protecting neighbouring services.
7. **Time & output bounds** — worker-enforced wall-time kill; stdout/stderr truncated at a byte ceiling.
8. **Ephemerality** — unique container per run, scrubbed env, force-removed on exit; a label-based reaper sweeps orphans.
9. **Edge controls** — per-IP rate limit, request-body cap, global concurrency shed (429).

## Threat → mitigation

| # | Threat (STRIDE) | Mitigation (enforced) |
|---|---|---|
| 1 | **Sandbox escape** (E) | gVisor systrap (syscalls in userspace Sentry); non-root; all caps dropped; `no-new-privileges`; pinned `runsc` version; track gVisor advisories. **Residual accepted:** software boundary — see above. |
| 2 | **Memory exhaustion / OOM neighbours** (D) | `--memory` = `--memory-swap` (swap off); parent `isobox.slice MemoryMax`+`MemorySwapMax=0`; `--cgroup-parent`. *Verified: OOM ⇒ exit 137 + `inspect.State.OOMKilled=true`, killed inside the slice.* |
| 3 | **CPU exhaustion / crypto-mining** (D) | `--cpus` (cgroup `cpu.max`); global concurrency cap; wall-time kill; `--network=none` (mining pool unreachable); per-IP limit. |
| 4 | **Fork bomb** (D) | `--pids-limit` (cgroup `pids.max`). |
| 5 | **Disk / inode exhaustion** (D) | `--read-only` + `tmpfs /tmp` with `size=` and `nr_inodes=`. *(`--storage-opt size=` is silently ignored on overlayfs — verified; not relied upon.)* |
| 6 | **Wall-clock hang** (D) | Control-plane `context` deadline ⇒ `docker kill`. Disambiguated from OOM: timeout ⇒ `timedOut=true, oomKilled=false`. *Both branches covered by integration tests.* |
| 7 | **Network exfil / SSRF to `169.254.169.254`** (I) | `--network=none` by default (egress moot). Opt-in network is gated and, when added, drops cloud-metadata + RFC1918 + loopback ranges. |
| 8 | **Symlink / path traversal on inputs** (T) | Read-only rootfs; read-only `/box` mount; control plane writes the job dir with sanitized flat names (rejects `..`, `/`), regular files only (Judge0 CVE-2024-28185 class). |
| 9 | **Env / secret leakage** (I) | Scrubbed container env — only an explicit allowlist (`HOME=/tmp`). Secrets live only in the control-plane process, never as container env. |
| 10 | **/proc & /sys info leak** (I) | gVisor synthetic masked `/proc` & `/sys`; no host bind mounts except the RO job dir; `--hostname=sandbox`. |
| 11 | **Output flooding** (D) | Output capped at `OutputBytes` (64 KiB default, 256 KiB hard max); `Truncated` flag. |
| 12 | **Name / log injection** (S/R) | UUID container names (never user input); structured JSON logs; stdin/stdout not logged by default. |
| 13 | **Supply chain of language images** (T→E) | Images pinned by `sha256:` digest (never `:latest`); arm64-verified; trivy scan in CI recommended; private mirror recommended. |
| 14 | **Public-demo abuse** (D) | Per-IP token bucket on the real client IP (Cloudflare `CF-Connecting-IP`); body cap; global concurrency ⇒ 429. Cloudflare Turnstile recommended. |
| 15 | **Direct-origin bypass** (D) — *partial, honest* | Control plane binds `127.0.0.1`; origin reachable only via Caddy. **But** `import origin_tls` is the CF origin **cert** only, **not** Authenticated Origin Pull — an attacker hitting the origin IP:443 still skips Cloudflare controls. Mitigation: firewall 443 to Cloudflare ranges; full fix is Caddy `client_auth` with the CF origin-pull CA. We do **not** claim AOP is in place. |
| 16 | **Side channels** (I) — *residual* | Reduced by cpu throttle + short wall-time + no cross-tenant sharing; cannot be fully closed on a shared SMT host without core pinning. Accepted residual. |

## Network egress (opt-in)

By default sandboxes have **no network**. Because AI agents need to fetch and scrape, isobox offers an **opt-in, firewalled egress** (`"network": true`): the sandbox can reach the **public internet only**. It is built so that turning egress on does *not* open a path to anything sensitive.

How it is contained (verified on the live host):

- Network-mode sandboxes join a dedicated bridge (`isobox-egress`, a fixed private subnet) under the `runsc-net` runtime, **not** the default isolated runtime.
- **FORWARD filtering** (`DOCKER-USER`, scoped to the sandbox subnet) drops traffic to: cloud-metadata / link-local `169.254.0.0/16`, and all RFC1918 private ranges (`10/8`, `172.16/12`, `192.168/16`).
- **INPUT filtering** drops *all* traffic from the sandbox bridge to the **host itself**. This is essential: a host's own IPs (bridge gateways, and crucially any VPN like a WireGuard `10.x`) are reached via the kernel's INPUT path, **not** FORWARD — so FORWARD rules alone would miss them. The sandbox never needs to talk to the host (DNS uses public resolvers; routing is L2), so this is a clean, total block.
- **No SMTP** — outbound `25/465/587` dropped (anti-spam).
- **DNS** is a bind-mounted `resolv.conf` pointing at public resolvers (`1.1.1.1`, `8.8.8.8`), because gVisor's userspace netstack cannot use Docker's embedded resolver at `127.0.0.11`. This also means no internal name resolution.
- **No raw sockets** (`--net-raw=false`) — no packet crafting / spoofing / ICMP scanning.
- IPv6 is disabled on the bridge (no v6 egress to bypass the v4 rules).
- **No sandbox-to-sandbox traffic** — inter-container communication is disabled on the bridge (`enable_icc=false`) *and* the FORWARD private-range DROP covers the bridge subnet. Verified: a connector sandbox cannot reach a real listener sandbox on the same bridge.
- **Fails closed, self-heals.** The firewall rules live outside Docker's managed state, so a `docker restart` (which rebuilds `DOCKER-USER`) could flush them while the bridge persists. To prevent a silent fail-open: a privileged systemd timer re-asserts the rules every 60s and refreshes a heartbeat sentinel (`/etc/isobox/egress-ok`), and isoboxd **refuses `network:true` whenever that sentinel is missing or stale** — egress disables itself rather than running unfiltered. Verified: removing the sentinel makes `network:true` runs fall back to no-network.

Verified blocked from inside a network-mode sandbox: cloud metadata, the host's WireGuard VPN (`10.0.0.1`) and peers, every bridge gateway, the host's public IP, all private ranges, and outbound mail — while public HTTPS and DNS work.

**Residual risks (honest):**
- **Abuse of the egress IP.** Code can make requests to arbitrary *public* hosts, which appear to come from the server's IP (scraping, light request floods). Mitigated by per-IP rate limiting, short wall-time, the CPU cap, and the global concurrency cap; for a fully-open public endpoint, gate `network:true` behind an API key (`ISOBOX_API_KEY`) or disable it (`ISOBOX_ALLOW_NETWORK=0`).
- **DNS rebinding** cannot reach internal hosts here because the *IP-level* firewall blocks private/metadata destinations regardless of what a name resolves to — the block is on the resolved address, not the name.
- Egress is **off by default**; operators opt in per host and callers opt in per request.

## Reporting

Found a way out? Please open a private security advisory on GitHub rather than a public issue.
