"""isobox — minimal Python client (stdlib only, no dependencies).

    from isobox import Isobox
    box = Isobox("https://isobox.hsingh.app")
    r = box.execute("python", code="print(40+2)")
    print(r["run"]["stdout"])          # "42\n"

    for ev, data in box.stream("python", code="import time\nfor i in range(3):\n print(i,flush=True);time.sleep(.3)"):
        if ev == "stdout": print(data["chunk"], end="")
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Iterator


class IsoboxError(Exception):
    def __init__(self, status: int, body: Any):
        super().__init__(f"isobox HTTP {status}: {body}")
        self.status = status
        self.body = body


class Isobox:
    def __init__(self, base_url: str = "http://127.0.0.1:8090", api_key: str | None = None, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self, extra: dict | None = None) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["X-API-Key"] = self.api_key
        if extra:
            h.update(extra)
        return h

    def _body(self, language, code, files, stdin, args, limits, network) -> bytes:
        payload: dict[str, Any] = {"language": language, "stdin": stdin or "", "network": bool(network)}
        if code is not None:
            payload["code"] = code
        if files:
            payload["files"] = files
        if args:
            payload["args"] = args
        if limits:
            payload["limits"] = limits
        return json.dumps(payload).encode()

    def execute(self, language: str, *, code: str | None = None, files: list | None = None,
                stdin: str = "", args: list | None = None, limits: dict | None = None,
                network: bool = False) -> dict:
        """Run code synchronously and return the full result envelope."""
        req = urllib.request.Request(
            f"{self.base_url}/execute",
            data=self._body(language, code, files, stdin, args, limits, network),
            headers=self._headers(), method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise IsoboxError(e.code, _safe_json(e.read())) from None

    def stream(self, language: str, **kwargs) -> Iterator[tuple[str, Any]]:
        """Run code and yield (event, data) tuples live via SSE: ('stdout'|'stderr', {'chunk':...}), then ('done', {...})."""
        req = urllib.request.Request(
            f"{self.base_url}/execute",
            data=self._body(language, kwargs.get("code"), kwargs.get("files"), kwargs.get("stdin", ""),
                            kwargs.get("args"), kwargs.get("limits"), kwargs.get("network", False)),
            headers=self._headers({"Accept": "text/event-stream"}), method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            event = None
            for raw in resp:
                line = raw.decode("utf-8", "replace").rstrip("\n")
                if line.startswith("event: "):
                    event = line[7:]
                elif line.startswith("data: ") and event:
                    yield event, json.loads(line[6:])
                    event = None

    def runtimes(self) -> list:
        with urllib.request.urlopen(f"{self.base_url}/runtimes", timeout=self.timeout) as resp:
            return json.loads(resp.read())


def _safe_json(b: bytes) -> Any:
    try:
        return json.loads(b)
    except Exception:
        return b.decode("utf-8", "replace")


if __name__ == "__main__":
    box = Isobox()
    print(box.execute("python", code="print('hello from the isobox python client')")["run"]["stdout"], end="")
