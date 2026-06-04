<div align="center">

# isobox

**Run untrusted code safely, on your own box — no KVM required.**

Open-source, self-hostable sandbox for executing untrusted / AI-generated code in isolated, resource-capped, ephemeral environments. Isolated by [gVisor](https://gvisor.dev). Security-first: every default is the safe one.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
&nbsp;·&nbsp; [Live demo](https://isobox.hsingh.app) &nbsp;·&nbsp; [Architecture](docs/ARCHITECTURE.md) &nbsp;·&nbsp; [Threat model](docs/THREAT_MODEL.md)

</div>

---

## Why

AI agents generate code that has to run *somewhere*. Running it on the host is reckless; spinning up a full VM per call is slow and needs hardware virtualization you may not have. **isobox** is the middle path: a userspace kernel (gVisor) gives you a real syscall boundary without `/dev/kvm`, wrapped in a hardened, horizontally-scalable HTTP service you can self-host.

What makes it different from Piston / Judge0 / E2B:

- **Built for AI agents.** Real work needs to fetch, scrape, and crunch data — so isobox ships a batteries-included Python (requests/httpx, BeautifulSoup/lxml, pandas/numpy…) and an **opt-in, firewalled network egress**: code can reach the public internet but **cannot** touch cloud metadata, private/VPN ranges, the host, or send mail. Verified, not asserted.
- **Hardened by default.** Network off, read-only rootfs, non-root, all caps dropped, swap off, pids/memory/cpu/wall-time capped, output truncated, digest-pinned images — *together*, verified on a real shared box. (The Judge0 escape CVEs came straight from unsafe defaults.)
- **No KVM needed.** Runs on plain cloud VMs via gVisor's `systrap` platform, where Firecracker-based tools (E2B) physically cannot.
- **Blast-radius ceiling.** The entire sandbox subsystem runs under one hard-capped cgroup slice, so a runaway can never OOM its neighbours.
- **Honest about the boundary.** On no-KVM hosts the trust boundary is gVisor's software Sentry (excellent defense-in-depth, *not* a hardware VM). For fully-hostile multi-tenant on KVM hardware, flip to the Firecracker backend. We document the line instead of hiding it.
- **One static binary.** API + playground UI embedded. `scp` it and run.

## Quickstart

```bash
# Prereqs: Docker + gVisor (runsc). One-time host setup:
sudo bash deploy/setup.sh          # installs runsc, the runsc-untrusted runtime, and isobox.slice

# Build & run
go build -o bin/isoboxd ./cmd/isoboxd
ISOBOX_REGISTRY=internal/registry/registry.yaml ./bin/isoboxd
# -> playground on http://127.0.0.1:8090
```

Run some code:

```bash
curl -s localhost:8090/execute -H 'content-type: application/json' -d '{
  "language": "python",
  "code": "print(sum(range(100)))"
}'
# {"language":"python","version":"3.14.5","backend":"gvisor",
#  "run":{"stdout":"4950\n","stderr":"","exitCode":0,"timedOut":false,"oomKilled":false,"truncated":false,"durationMs":214}}
```

Stream output live (Server-Sent Events):

```bash
curl -N localhost:8090/execute -H 'accept: text/event-stream' -H 'content-type: application/json' \
  -d '{"language":"python","code":"import time\nfor i in range(3):\n  print(i,flush=True); time.sleep(0.5)"}'
```

Let an agent fetch + scrape + analyze (opt-in `network: true`, firewalled to the public internet):

```bash
curl -s localhost:8090/execute -H 'content-type: application/json' -d '{
  "language": "python",
  "network": true,
  "code": "import requests, pandas as pd, io\n csv = requests.get(\"https://raw.githubusercontent.com/mwaskom/seaborn-data/master/iris.csv\").text\n df = pd.read_csv(io.StringIO(csv))\n print(df.groupby(\"species\")[\"sepal_length\"].mean())"
}'
```

## API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/execute` | Run code, return stdout/stderr/exit. Send `Accept: text/event-stream` for live SSE. |
| `GET` | `/runtimes` | List available languages + versions. |
| `GET` | `/healthz` | Liveness. |
| `GET` | `/readyz` | Readiness — **503 unless the protective slice is actually capped**. |
| `GET` | `/` | Embedded playground UI. |

**Request:**

```jsonc
{
  "language": "python",          // name or alias (py, py3, …)
  "version": "3.14.5",           // optional, pins a version
  "code": "print(1)",            // single-file convenience…
  "files": [{"name":"main.py","content":"…"}],  // …or multi-file
  "stdin": "",
  "args": [],
  "limits": {                    // all optional, clamped to hard ceilings
    "memoryBytes": 268435456,    // ≤ 512 MiB
    "cpus": 1.0,                 // ≤ 2.0
    "pids": 128,                 // ≤ 256
    "outputBytes": 65536,        // ≤ 256 KiB
    "wallTimeMs": 10000          // ≤ 20 000
  },
  "network": false               // default false
}
```

**Result signals** are authoritative and disambiguate the otherwise-ambiguous exit 137:
`exitCode`, `timedOut`, `oomKilled`, `truncated`, `durationMs`.

## Languages

Live today: **Python, JavaScript, TypeScript, Ruby, Go, Rust** — all start fast: Python/JS/TS/Ruby ≈0.6–1.1s, Rust ≈1.4s, Go ≈2s (a pre-warmed stdlib cache cuts Go from ~14s). The default **Python is batteries-included** for agent work; `python-slim` is the minimal zero-build fallback. Languages are declared in [`internal/registry/registry.yaml`](internal/registry/registry.yaml) — adding one is a config entry (digest-pinned image, run command, default limits), no code change, hot-reloadable with `SIGHUP`.

## Clients

Dependency-free clients in [`clients/`](clients): [`python/isobox.py`](clients/python/isobox.py) and [`js/isobox.mjs`](clients/js/isobox.mjs) — both support `execute()`, live `stream()` (SSE), and `runtimes()`.

```python
from isobox import Isobox
box = Isobox("https://isobox.hsingh.app")
print(box.execute("python", code="print(40+2)")["run"]["stdout"])  # 42
```

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `ISOBOX_ADDR` | `127.0.0.1:8090` | Listen address |
| `ISOBOX_REGISTRY` | `internal/registry/registry.yaml` | Language catalogue path |
| `ISOBOX_CONCURRENCY` | `4` | Global max concurrent sandboxes |
| `ISOBOX_API_KEY` | *(empty)* | If set, required via `X-API-Key` / `Bearer` |
| `ISOBOX_RATE_PER_MIN` | `30` | Per-IP rate limit |
| `ISOBOX_RATE_BURST` | `10` | Per-IP burst |
| `ISOBOX_ALLOW_NETWORK` | `1` | Allow opt-in `network:true` (filtered egress). `0` disables it host-wide |
| `ISOBOX_EGRESS_NETWORK` | `isobox-egress` | Docker network carrying the egress firewall |

## Security

Read the [**threat model**](docs/THREAT_MODEL.md) and the [**adversarial audit**](docs/SECURITY_AUDIT.md) (live red-team; verdict *pass with fixes* — isolation held, found-and-fixed defects documented). Short version: defense-in-depth — gVisor syscall boundary, `--network=none`, read-only rootfs, `--user=nobody`, `--cap-drop=ALL`, `no-new-privileges`, swap-off memory cap, pids cap, cpu cap, worker-enforced wall-time kill, output truncation, ephemeral per-run filesystem, scrubbed env, digest-pinned images, and a hard-capped parent cgroup slice. **Residual risk:** on no-KVM hosts the boundary is software (gVisor Sentry), strictly weaker than a microVM — use the Firecracker backend for hostile multi-tenant on KVM hardware.

## Self-hosting & scaling

Single binary, stateless gateway. Single node uses an in-process semaphore-gated queue (no external dependencies). For multi-node, the same `Queue` interface targets Valkey/Redis Streams (at-least-once; executions are idempotent because the network is off). See [ARCHITECTURE.md](docs/ARCHITECTURE.md) and [DEPLOY.md](docs/DEPLOY.md).

## Roadmap

- [x] gVisor backend, sync + SSE, hardened-by-default, hard-capped slice
- [x] Languages: Python, JavaScript, TypeScript, Ruby, Go, Rust
- [x] **Firewalled network egress** for agents (public-only; metadata/private/host/SMTP blocked)
- [x] **Batteries-included Python** (requests/httpx, BeautifulSoup/lxml, pandas/numpy…)
- [x] Pre-warmed Go image (≈14s → ≈2s)
- [x] Dependency-free Python + JS clients
- [ ] Warm single-use sandbox pool to shave interpreted cold-start
- [ ] More languages (C/C++, Bash, Java) + Piston-compatible `/api/v2/execute` shim
- [ ] Valkey queue + multi-node workers, Prometheus metrics
- [ ] Firecracker and hardened-runc backends
- [ ] Cloudflare Turnstile + Authenticated Origin Pull for the public demo

## License

[Apache-2.0](LICENSE).
