# isobox API reference

Base URL — live: `https://isobox.hsingh.app` · self-host default: `http://127.0.0.1:8090`

Machine-readable: [`openapi.yaml`](../internal/web/openapi.yaml) (also served at `/openapi.yaml`) · agent-readable: [`llms.txt`](../internal/web/llms.txt) (served at `/llms.txt`).

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Playground UI |
| `GET` | `/healthz` | Liveness → `200 ok` |
| `GET` | `/readyz` | Readiness → `200 {ready:true,backend}` or `503` |
| `GET` | `/runtimes` | List languages |
| `POST` | `/execute` | Run code (JSON, or SSE stream) |
| `GET` | `/llms.txt`, `/openapi.yaml` | Docs |

## Authentication

Optional. If the server is started with an API key, send `X-API-Key: <key>` **or** `Authorization: Bearer <key>`; otherwise the endpoint is open (rate-limited). A wrong/missing key when one is required → `401 {"error":"unauthorized"}`.

## Rate limits & capacity

- **Per-IP** token bucket (default 30/min, burst 10) → `429 {"error":"rate_limited"}` + `Retry-After`.
- **Global concurrency** cap (default 4 sandboxes) → `429 {"error":"capacity","detail":"no free execution slot"}` + `Retry-After`.

## `POST /execute`

`Content-Type: application/json`. Body cap **256 KiB**.

### Request

| Field | Type | Notes |
|---|---|---|
| `language` | string | **required** — name or alias (see `/runtimes`) |
| `version` | string | optional — pins a version |
| `code` | string | single-file source — provide `code` **or** `files` (≥1 required) |
| `files` | `[{name, content, encoding}]` | multi-file; `encoding` = `utf8` (default) \| `base64` \| `hex` |
| `stdin` | string | fed to the program's stdin |
| `args` | string[] | program argv (passed safely as positional params) |
| `limits` | object | optional, each field **clamped** to the bounds below |
| `network` | bool | default `false`; `true` = filtered public egress |

**Limits (clamped to bounds; per-language defaults apply when omitted):**

| Field | Min | Max | Default |
|---|---|---|---|
| `memoryBytes` | 8 MiB | 512 MiB | 256–512 MiB by language |
| `cpus` | 0.1 | 2.0 | 1.0–2.0 by language |
| `pids` | 1 | 256 | 128 |
| `outputBytes` | 1 KiB | 256 KiB | 64 KiB (per stream) |
| `wallTimeMs` | 100 | 20000 | 10000–20000 by language |

```bash
curl -s https://isobox.hsingh.app/execute -H 'content-type: application/json' -d '{
  "language": "python",
  "code": "print(40+2)",
  "limits": {"wallTimeMs": 5000, "memoryBytes": 134217728}
}'
```

### Response `200`

```json
{
  "language": "python", "version": "3.14-agent", "backend": "gvisor",
  "run": {
    "stdout": "42\n", "stderr": "",
    "exitCode": 0, "timedOut": false, "oomKilled": false,
    "truncated": false, "durationMs": 214, "network": false
  }
}
```

| `run.*` | Meaning |
|---|---|
| `exitCode` | process exit code (a wall-time or memory kill → `137`) |
| `timedOut` | killed by the wall-time cap |
| `oomKilled` | killed by the memory cap — disambiguates the `137` |
| `truncated` | output hit the `outputBytes` cap |
| `durationMs` | wall-clock ms |
| `network` | whether filtered egress was **actually** applied |

A top-level `warning` appears only when `network:true` was requested but denied (fail-closed). Always check `run.network`.

## Streaming (SSE)

Send `Accept: text/event-stream` (or `?stream=1`). HTTP status is always `200`; the outcome is in the `done` event.

```
event: stdout
data: {"chunk":"hel"}

event: stderr
data: {"chunk":"oops\n"}

event: done
data: {"language":"python","version":"...","backend":"gvisor","run":{...}}
```

`error` events (`data: {"error":"..."}`) are emitted only on internal failure.

```bash
curl -N https://isobox.hsingh.app/execute \
  -H 'accept: text/event-stream' -H 'content-type: application/json' \
  -d '{"language":"python","code":"import time\nfor i in range(3):\n print(i,flush=True);time.sleep(.3)"}'
```

## Languages

`GET /runtimes` for the live list.

| Language | Aliases | Compiled | Notes |
|---|---|---|---|
| `python` | py, py3, python3 | no | batteries: requests, httpx, beautifulsoup4, lxml, pandas, numpy |
| `python-slim` | pyslim | no | minimal, no bundled libs |
| `javascript` | js, node, nodejs | no | Node 26 (global `fetch`) |
| `typescript` | ts | no | native type-stripping |
| `ruby` | rb | no | |
| `go` | golang | yes | pre-warmed (~2s) |
| `rust` | rs | yes | |

## Network mode

`"network": true` opts into **filtered egress** — the **public internet only**. Firewalled off: cloud metadata (`169.254.169.254`), all private/RFC1918, the host (incl. VPN), outbound SMTP, IPv6, and other sandboxes. It **fails closed**: if the egress firewall isn't currently verified, the run executes with network **off**, `run.network` is `false`, and a `warning` is returned. Operators can disable it host-wide with `ISOBOX_ALLOW_NETWORK=0`.

```bash
curl -s https://isobox.hsingh.app/execute -H 'content-type: application/json' -d '{
  "language":"python","network":true,
  "code":"import requests; print(requests.get(\"https://api.github.com\").status_code)"
}'
```

## Errors

| Status | Body | When |
|---|---|---|
| 400 | `{"error":"invalid_json"}` | malformed body / > 256 KiB |
| 400 | `{"error":"language_required"}` | `language` missing |
| 400 | `{"error":"unknown_language"}` | not a known runtime |
| 400 | `{"error":"no_source"}` | neither `code` nor `files` |
| 401 | `{"error":"unauthorized"}` | bad/missing key (when required) |
| 429 | `{"error":"rate_limited"}` | per-IP limit (+ `Retry-After`) |
| 429 | `{"error":"capacity"}` | global concurrency (+ `Retry-After`) |

## Client libraries

Dependency-free: [`clients/python/isobox.py`](../clients/python/isobox.py) and [`clients/js/isobox.mjs`](../clients/js/isobox.mjs) — `execute()`, `stream()` (SSE), `runtimes()`.

## Stateful sessions (`/v1`)

For multi-step / agent workflows that share state. A **filesystem session** is a persistent `/workspace` shared across steps; each step still runs in a fresh hardened sandbox, so a session at rest costs **no RAM**. Every `/v1/sessions/{id}/*` call requires the capability token from create, as `X-Session-Token: <token>`.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/sessions` | Create. Body `{"runtime","ttlSec"}` → `201 {id, token, runtime, type, createdAt}` |
| `POST` | `/v1/sessions/{id}/exec` | Run a step (body = `/execute` body minus `language`); `/workspace` is RW + the cwd. Sync or SSE. |
| `GET` | `/v1/sessions/{id}/fs?path=` | Dir → JSON listing; file → raw bytes |
| `PUT` | `/v1/sessions/{id}/fs?path=` | Upload a file (raw body, ≤16 MiB) → `{path, bytes}` |
| `DELETE` | `/v1/sessions/{id}/fs?path=` | Delete a file/subtree → `204` |
| `DELETE` | `/v1/sessions/{id}` | End session + delete workspace → `204` |

Errors: `401 invalid_session_token`, `404 session_not_found`, `413 quota_exceeded`, `400 invalid_path`; at create, `429 too_many_sessions` / `507 storage_full`. Per-session disk quota (default 512 MiB) is enforced against **actual** usage by a sweep (so direct writes to `/workspace` can't bypass it); a global disk ceiling + max-session count bound aggregate blast radius; idle sessions are reaped after their TTL (default 24h).

```bash
S=$(curl -s -X POST https://isobox.hsingh.app/v1/sessions -d '{"runtime":"python"}')
ID=$(echo "$S"|jq -r .id); TOK=$(echo "$S"|jq -r .token)
curl -s -X POST https://isobox.hsingh.app/v1/sessions/$ID/exec -H "X-Session-Token: $TOK" \
  -d '{"code":"open(\"/workspace/x\",\"w\").write(\"42\")"}'
curl -s -X POST https://isobox.hsingh.app/v1/sessions/$ID/exec -H "X-Session-Token: $TOK" \
  -d '{"code":"print(open(\"/workspace/x\").read())"}'   # -> 42  (state shared across steps)
```

## Persistent memory (`/v1/memory`, `/v1/volumes`)

Durable storage an agent recalls across sessions. Open/demo mode = one shared **public** tenant; set `ISOBOX_API_KEYS` for one isolated tenant per key (derived server-side from the key, never from the request).

**Structured KV** — per-tenant, opaque keys, optional TTL, quota 10 MiB / 10k keys:

| Method | Path | Notes |
|---|---|---|
| `PUT` | `/v1/memory/{namespace}/{key}` | body = value; `X-TTL-Seconds` optional → `204` |
| `GET` | `/v1/memory/{namespace}/{key}` | value + `ETag`/`X-Expires-At`, or `404` |
| `DELETE` | `/v1/memory/{namespace}/{key}` | `204` |
| `GET` | `/v1/memory/{namespace}?prefix=&limit=&cursor=` | list keys |

**Filesystem volumes** — a named dir that survives sessions and re-attaches at `/memory` (RW, single-writer, quota 512 MiB):

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/volumes` | `{"name"}` → `{id,...}` |
| `GET`/`DELETE` | `/v1/volumes`, `/v1/volumes/{id}` | list / get / delete (tenant-scoped) |

Attach via `"volumeId"` at `POST /v1/sessions` → mounted RW at `/memory` for every step. Tenant isolation verified: cross-tenant read/attach all `404`.

## Live-kernel sessions (persistent variables)

`POST /v1/sessions` with `"type":"kernel"` (default `"filesystem"`) keeps a long-lived interpreter so **variables/imports persist across `exec` steps** (Code-Interpreter style), and steps are near-instant. Same hardening, same exec/fs/DELETE endpoints, `/workspace` + attached `/memory` still work. Kernels are pool-capped (`ISOBOX_KERNEL_SLOTS`, default 3) → `429` past the cap; idle-reaped (~30 min). A step that *blocks* past its wall-time ends the kernel (bounded; keep waits short).
