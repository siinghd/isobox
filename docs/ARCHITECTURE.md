# isobox architecture

> Design-phase verification log (what was empirically confirmed on the first host) lives in [DESIGN_NOTES.md](DESIGN_NOTES.md).

```
        Cloudflare ──▶ Caddy (TLS, body cap, SSE flush) ──▶ 127.0.0.1:8090
                                                                  │
        ┌─────────────────────────────────────────────────────────────────────┐
        │  isoboxd (single static Go binary, stateless)                         │
        │                                                                       │
        │  api/      chi router · auth · per-IP rate limit · body cap · CORS     │
        │              ├─ GET  /            embedded playground UI               │
        │              ├─ POST /execute     sync JSON  or  live SSE              │
        │              ├─ GET  /runtimes /healthz /readyz                        │
        │  sched/    global semaphore  ── the single true concurrency cap        │
        │  registry/ registry.yaml ▶ trusted launch recipe (image, run, limits)  │
        │  executor/ Executor interface ──┐                                      │
        │  reaper/   orphan sweep (label) │                                      │
        └─────────────────────────────────┼─────────────────────────────────────┘
                                          ▼
                    ┌─────────────┬───────────────┬──────────────┐
                  gVisor      Firecracker      hardened-runc   (auto-select
                 (no KVM)      (KVM hosts)      (fallback)       via /dev/kvm)
                    │
                    ▼  docker run --runtime=runsc-untrusted (hardened argv)
        ┌───────────────────────────────────────────────────────────┐
        │ sandbox: read-only rootfs · tmpfs /tmp · --network=none     │
        │ --user=65534 · --cap-drop=ALL · no-new-privileges          │
        │ --memory(=swap) · --cpus · --pids-limit                    │
        │ nested under  isobox.slice  (hard aggregate memory cap)     │
        └───────────────────────────────────────────────────────────┘
```

## Components

| Package | Responsibility |
|---|---|
| `cmd/isoboxd` | Entry point: load config + registry, select backend, wire server, run reaper, graceful shutdown. |
| `internal/api` | HTTP control plane — routing, validation, auth, rate limit, body cap, the execute handler (JSON + SSE), health/readiness, runtimes. |
| `internal/executor` | The pluggable isolation backend: `Executor` interface + `Spec`/`Result`/`Limits` types; the gVisor implementation; backend auto-select. |
| `internal/registry` | Loads `registry.yaml` into trusted launch recipes; resolves language/alias/version; maps default + clamped limits. |
| `internal/sched` | Global counting semaphore (the one true concurrency cap). |
| `internal/reaper` | Periodic sweep of orphaned sandboxes by the `isobox.managed=true` label. |
| `internal/web` | Embedded single-page playground. |
| `internal/obs` | Structured JSON logging. |

## The Executor interface

The seam that keeps isobox portable. The control plane talks only to this; it never knows whether the backend is gVisor, Firecracker, or runc.

```go
type Executor interface {
    Name() string
    HealthCheck(ctx context.Context) error
    Execute(ctx context.Context, s Spec, sink OutputSink) (Result, error)
}
```

`Spec` carries the *trusted* recipe (image, compile/run argv, env, scratch-exec) from the registry plus the *validated/clamped* caller inputs (files, stdin, argv, limits). `Result` carries authoritative signals — `ExitCode`, `TimedOut`, `OOMKilled`, `Truncated`, `DurationMs` — that disambiguate the otherwise-ambiguous exit 137. `OutputSink` is optional live streaming (SSE); when nil the executor still buffers a capped result.

### gVisor backend

Drives the `docker` CLI with the exact hardened argv that was empirically verified on the target host. Key behaviours:

- **No `--rm`**: the container is inspected for `State.OOMKilled` / `State.ExitCode` *before* a deferred force-remove. (`OOMKilled` from inspect is more robust under gVisor than parsing nested cgroup `memory.events`.)
- **Wall-time** is enforced by the worker (a timer that `docker kill`s by name), not trusted to the guest — killing only the docker client would orphan the container.
- **Compiled languages** run compile-then-exec in one container via a trusted shell launcher; the caller's argv is passed as positional params (`"$@"`), never interpolated into the shell string.
- **Cleanup** is guaranteed by `defer docker rm -f`; the reaper is the backstop for crash orphans.

## Request lifecycle (`POST /execute`)

1. Body cap → per-IP rate limit → auth.
2. Decode, validate, resolve language from the registry.
3. Compute limits = language defaults ⊕ caller overrides, **clamped to hard ceilings**.
4. Acquire a global semaphore slot (bounded wait → `429 + Retry-After` if saturated).
5. Executor writes source to an ephemeral world-readable job dir, launches the hardened sandbox, streams/collects output, enforces wall-time, inspects terminal state, reaps.
6. Respond: buffered JSON, or a stream of SSE `stdout`/`stderr` chunks then a `done` event.

## Scalability

**Single node (default):** stateless gateway + in-process buffered-channel queue gated by one semaphore. No external dependencies. Backpressure is explicit (429), never unbounded queueing. The binding constraint on a small host is *memory* (gVisor Sentry overhead per sandbox), not CPU — which is why warm pools are opt-in, not default.

**Horizontal:** the gateway stays 100% stateless. The same `Queue` interface targets Valkey/Redis Streams (`XADD`/`XREADGROUP`/`XACK` + `XAUTOCLAIM` reaper); job state lives in Valkey keyed by id with a TTL so any replica serves any id. At-least-once delivery is safe because executions are idempotent (`--network=none` ⇒ no external side effects). Per-host concurrency stays local so each host protects its own slice.

See [DEPLOY.md](DEPLOY.md) for host setup.
