# isobox API Reference

**isobox** is an open-source sandbox that runs untrusted / AI-generated code in
[gVisor](https://gvisor.dev)-isolated, resource-capped, ephemeral containers.
It is security-first and built for AI agents: every default is the safe one.

You hand it a language and some code; it runs the code in a throwaway container
and returns stdout, stderr, the exit code, and timing — either as a single JSON
response or as a live stream.

## Base URL

| Environment | Base URL |
| --- | --- |
| Live (hosted) | `https://isobox.hsingh.app` |
| Self-host (default) | `http://127.0.0.1:8090` |

All endpoint paths below are relative to the base URL. Request and response
bodies are JSON unless noted otherwise.

### Endpoint map

| Method & path | Purpose |
| --- | --- |
| `GET /` | Playground UI (HTML) |
| `GET /healthz` | Liveness probe |
| `GET /readyz` | Readiness probe |
| `GET /runtimes` | List available language runtimes |
| `POST /execute` | Run code (sync JSON, or live SSE) |
| `GET /llms.txt` | LLM-oriented documentation (`text/plain`) |
| `GET /openapi.yaml` | OpenAPI spec (`application/yaml`) |

---

## Authentication

Authentication is **optional** and only enforced when the server is configured
with an API key. If no key is configured, all endpoints are open.

When a key **is** configured, send it on every request using either header:

```
X-API-Key: <key>
```

or

```
Authorization: Bearer <key>
```

A missing or incorrect key returns `401`:

```json
{ "error": "unauthorized" }
```

---

## Rate limits & capacity

isobox protects itself with two independent limiters. Both reply with HTTP
`429` and a `Retry-After` header (seconds) telling you how long to wait.

| Limit | Scope | Default | Status & body |
| --- | --- | --- | --- |
| Rate limit | Per IP (token bucket) | 30 / min, burst 10 | `429 {"error":"rate_limited"}` |
| Capacity | Global concurrency cap | 4 concurrent runs | `429 {"error":"capacity","detail":"no free execution slot"}` |

The **rate limit** is a per-IP token bucket — a sustained rate of 30 requests
per minute with a burst allowance of 10. The **capacity** limit is global: it
caps how many executions can run at once across all clients. When every
execution slot is busy, new runs are rejected rather than queued.

On any `429`, honor `Retry-After` before retrying.

```json
{ "error": "rate_limited" }
```

```json
{ "error": "capacity", "detail": "no free execution slot" }
```

---

## Endpoint reference

### GET /healthz

Liveness probe. Always returns plain text.

| | |
| --- | --- |
| Auth | Not required |
| Success | `200` `text/plain` |

```
ok
```

---

### GET /readyz

Readiness probe. Reports ready **only** if the protective cgroup slice is
memory-capped **and** the backend is healthy.

| Field | Type | Description |
| --- | --- | --- |
| `ready` | bool | Whether the service is ready to accept executions |
| `backend` | string | Execution backend (e.g. `gvisor`) — present when ready |
| `reason` | string | Why the service is not ready — present when not ready |

**Ready — `200`:**

```json
{ "ready": true, "backend": "gvisor" }
```

**Not ready — `503`:**

```json
{ "ready": false, "reason": "..." }
```

---

### GET /runtimes

Lists the language runtimes the server can execute. Use this to discover live
language names, aliases, versions, and which languages are compiled.

| Field | Type | Description |
| --- | --- | --- |
| `language` | string | Canonical language name |
| `version` | string | Runtime version |
| `aliases` | string[] | Alternate names accepted by `POST /execute` |
| `compiled` | bool | Whether the language is compiled before running |
| `backend` | string | Execution backend (e.g. `gvisor`) |

**Success — `200`:**

```json
[
  {
    "language": "python",
    "version": "3.14-agent",
    "aliases": ["py", "py3", "python3"],
    "compiled": false,
    "backend": "gvisor"
  }
]
```

---

### POST /execute

Runs code in an isolated, ephemeral container. Returns a single JSON response by
default, or a live [Server-Sent Events](#streaming-sse) stream when the request
asks for one.

| | |
| --- | --- |
| Content-Type | `application/json` |
| Request body hard cap | 256 KiB |
| Streaming | Send `Accept: text/event-stream` (see [Streaming](#streaming-sse)) |

#### Request body

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `language` | string | **Yes** | Language name or alias (see `GET /runtimes`) |
| `version` | string | No | Pins a specific runtime version |
| `code` | string | One of `code`/`files` | Single-file convenience source |
| `files` | object[] | One of `code`/`files` | Multi-file source (see below) |
| `stdin` | string | No | Fed to the program's standard input |
| `args` | string[] | No | Program argv, passed safely as positional parameters |
| `limits` | object | No | Resource limits, each **clamped** to a hard ceiling (see [Limits & clamps](#limits--clamps)) |
| `network` | bool | No | Opt-in filtered egress. Default `false` (see [Network mode](#network-mode)) |

At least one of `code` or `files` must be provided.

**`files[]` entries:**

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | Yes | File name |
| `content` | string | Yes | File contents, decoded per `encoding` |
| `encoding` | string | No | `utf8` (default), `base64`, or `hex` |

**`limits` object:**

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `memoryBytes` | int | — | Memory cap in bytes |
| `cpus` | float | — | CPU cores |
| `pids` | int | — | Max process/thread count |
| `outputBytes` | int | 65536 (64 KiB) | Combined stdout/stderr byte cap |
| `wallTimeMs` | int | — | Wall-clock time limit in milliseconds |

All `limits` fields are optional and **clamped** to the hard ceilings in the
[Limits & clamps](#limits--clamps) table — values outside the range are pulled
to the nearest allowed value rather than rejected.

**Example request:**

```json
{
  "language": "python",
  "version": "3.14-agent",
  "code": "print(40 + 2)",
  "stdin": "",
  "args": [],
  "limits": {
    "memoryBytes": 268435456,
    "cpus": 1.0,
    "pids": 128,
    "outputBytes": 65536,
    "wallTimeMs": 10000
  },
  "network": false
}
```

#### Response — `200`

| Field | Type | Description |
| --- | --- | --- |
| `language` | string | Resolved language |
| `version` | string | Resolved runtime version |
| `backend` | string | Execution backend (e.g. `gvisor`) |
| `run` | object | Execution result (see below) |
| `warning` | string | Present **only** when network was requested but denied (fail-closed) |

**`run` object:**

| Field | Type | Description |
| --- | --- | --- |
| `stdout` | string | Captured standard output |
| `stderr` | string | Captured standard error |
| `exitCode` | int | Process exit code |
| `timedOut` | bool | Killed by the wall-time cap (exit code 137) |
| `oomKilled` | bool | Killed by the memory cap (exit code 137) — disambiguates from a timeout |
| `truncated` | bool | Output hit the `outputBytes` cap and was cut off |
| `durationMs` | int | Wall-clock execution time in milliseconds |
| `network` | bool | Whether filtered egress was **actually** applied |

`timedOut` and `oomKilled` both correspond to exit code 137; check these flags
to tell a wall-time kill apart from a memory kill.

**Example response:**

```json
{
  "language": "python",
  "version": "3.14-agent",
  "backend": "gvisor",
  "run": {
    "stdout": "42\n",
    "stderr": "",
    "exitCode": 0,
    "timedOut": false,
    "oomKilled": false,
    "truncated": false,
    "durationMs": 214,
    "network": false
  }
}
```

**Quick curl:**

```bash
curl -s https://isobox.hsingh.app/execute \
  -H 'content-type: application/json' \
  -d '{"language":"python","code":"print(40+2)"}'
```

---

## Streaming (SSE)

To receive output as it is produced, add the header
`Accept: text/event-stream` to a `POST /execute` request. The response is a
[Server-Sent Events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)
stream instead of a single JSON body.

Each event has an `event:` type and a `data:` JSON payload:

| Event | Payload | Meaning |
| --- | --- | --- |
| `stdout` | `{"chunk":"..."}` | A chunk of standard output |
| `stderr` | `{"chunk":"..."}` | A chunk of standard error |
| `done` | Full execute response object | Run finished; carries `run` and optional `warning` |
| `error` | `{"error":"..."}` | Internal failure (only emitted on internal error) |

**Example stream:**

```
event: stdout
data: {"chunk":"he"}

event: stderr
data: {"chunk":"oops\n"}

event: done
data: {"language":"python","version":"3.14-agent","backend":"gvisor","run":{"stdout":"...","stderr":"...","exitCode":0,"timedOut":false,"oomKilled":false,"truncated":false,"durationMs":214,"network":false}}
```

The terminal `done` event carries the same object as a non-streaming `200`
response (including `warning` when applicable), so you can rely on it for the
final status.

**Streaming curl:**

```bash
curl -N https://isobox.hsingh.app/execute \
  -H 'accept: text/event-stream' \
  -H 'content-type: application/json' \
  -d '{"language":"python","code":"import time\nfor i in range(3):\n print(i,flush=True);time.sleep(.3)"}'
```

---

## Limits & clamps

Every `limits` field is optional. Values you send are **clamped** to the hard
ceilings below — anything outside the range is moved to the nearest allowed
value, not rejected.

| Limit | Default | Minimum | Maximum |
| --- | --- | --- | --- |
| `memoryBytes` | — | 8 MiB (8388608) | 512 MiB (536870912) |
| `cpus` | — | 0.1 | 2.0 |
| `pids` | — | 1 | 256 |
| `outputBytes` | 64 KiB (65536) | 1 KiB (1024) | 256 KiB (262144) |
| `wallTimeMs` | — | 100 | 20000 |

Separately, the entire `POST /execute` request body is capped at **256 KiB**;
larger bodies are rejected with `400 invalid_json`.

---

## Languages

Call `GET /runtimes` for the authoritative live list. The languages below ship
by default.

| Language | Aliases | Compiled? | Notes |
| --- | --- | --- | --- |
| `python` | `py`, `py3`, `python3` | No | Batteries-included: requests, httpx, beautifulsoup4, lxml, pandas, numpy |
| `python-slim` | `pyslim` | No | Minimal Python without the bundled libraries |
| `javascript` | `js`, `node`, `nodejs` | No | Node.js |
| `typescript` | `ts` | No | TypeScript |
| `ruby` | `rb` | No | |
| `go` | `golang` | Yes | Compiled, pre-warmed |
| `rust` | `rs` | Yes | Compiled |

---

## Network mode

Network access is **off by default**. Set `"network": true` to opt into
**filtered egress**.

When enabled, code can reach the **public internet only**. The following are
firewalled off:

- Cloud metadata endpoints (`169.254.169.254`)
- All private / RFC1918 ranges
- The host (including any VPN)
- Outbound SMTP (mail)
- IPv6
- Other sandboxes

**Fail-closed behavior.** If the egress firewall is not currently verified, the
run executes with network **OFF**. In that case the response carries
`run.network = false` and a top-level `warning`:

```json
{
  "run": { "network": false, "...": "..." },
  "warning": "network requested but currently unavailable ..."
}
```

Always check `run.network` to confirm whether filtered egress was actually
applied, rather than assuming your `network: true` request was honored.

**Network curl (fetch + scrape):**

```bash
curl -s https://isobox.hsingh.app/execute \
  -H 'content-type: application/json' \
  -d '{"language":"python","network":true,"code":"import requests;print(requests.get(\"https://api.github.com\").status_code)"}'
```

---

## Error reference

All errors are returned as JSON with a non-2xx status.

| Status | Body | Meaning |
| --- | --- | --- |
| `400` | `{"error":"invalid_json","detail":"..."}` | Malformed body, or body over the 256 KiB cap |
| `400` | `{"error":"language_required"}` | `language` was omitted |
| `400` | `{"error":"unknown_language","detail":"..."}` | Language/alias is not a known runtime; see `GET /runtimes` |
| `400` | ``{"error":"no_source","detail":"provide `code` or `files`"}`` | Neither `code` nor `files` was provided |
| `401` | `{"error":"unauthorized"}` | Missing/invalid API key (only when a key is configured) |
| `429` | `{"error":"rate_limited"}` | Per-IP rate limit exceeded; honor `Retry-After` |
| `429` | `{"error":"capacity","detail":"no free execution slot"}` | Global concurrency cap reached; honor `Retry-After` |

Both `429` responses include a `Retry-After` header (seconds).

---

## Client libraries

Lightweight, dependency-free clients live in the repository:

| Language | Path |
| --- | --- |
| Python | [`clients/python/isobox.py`](../clients/python/isobox.py) |
| JavaScript | [`clients/js/isobox.mjs`](../clients/js/isobox.mjs) |

Both wrap `POST /execute` (sync and streaming) and handle the request/response
shapes documented above.
