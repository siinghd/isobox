// isobox — minimal JavaScript/TypeScript client (uses fetch; Node 18+ or browser).
//
//   import { Isobox } from "./isobox.mjs";
//   const box = new Isobox({ baseUrl: "https://isobox.hsingh.app" });
//   const r = await box.execute({ language: "javascript", code: "console.log(40+2)" });
//   console.log(r.run.stdout); // "42\n"
//
//   for await (const [ev, data] of box.stream({ language: "python", code: "print(1)" })) {
//     if (ev === "stdout") process.stdout.write(data.chunk);
//   }

export class IsoboxError extends Error {
  constructor(status, body) {
    super(`isobox HTTP ${status}: ${typeof body === "string" ? body : JSON.stringify(body)}`);
    this.status = status;
    this.body = body;
  }
}

export class Isobox {
  constructor({ baseUrl = "http://127.0.0.1:8090", apiKey = null } = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
  }

  _headers(extra = {}) {
    const h = { "Content-Type": "application/json", ...extra };
    if (this.apiKey) h["X-API-Key"] = this.apiKey;
    return h;
  }

  _body({ language, code, files, stdin = "", args, limits, network = false }) {
    const p = { language, stdin, network };
    if (code != null) p.code = code;
    if (files) p.files = files;
    if (args) p.args = args;
    if (limits) p.limits = limits;
    return JSON.stringify(p);
  }

  /** Run code synchronously; resolves to the full result envelope. */
  async execute(opts) {
    const res = await fetch(`${this.baseUrl}/execute`, {
      method: "POST", headers: this._headers(), body: this._body(opts),
    });
    if (!res.ok) throw new IsoboxError(res.status, await safeJson(res));
    return res.json();
  }

  /** Async-iterate live output: yields ["stdout"|"stderr", {chunk}], then ["done", {...}]. */
  async *stream(opts) {
    const res = await fetch(`${this.baseUrl}/execute`, {
      method: "POST",
      headers: this._headers({ Accept: "text/event-stream" }),
      body: this._body(opts),
    });
    if (!res.ok) throw new IsoboxError(res.status, await safeJson(res));
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const block = buf.slice(0, i);
        buf = buf.slice(i + 2);
        const ev = /event: (\w+)/.exec(block);
        const dt = /data: (.*)/s.exec(block);
        if (ev && dt) yield [ev[1], JSON.parse(dt[1])];
      }
    }
  }

  async runtimes() {
    const res = await fetch(`${this.baseUrl}/runtimes`);
    if (!res.ok) throw new IsoboxError(res.status, await safeJson(res));
    return res.json();
  }
}

async function safeJson(res) {
  try {
    return await res.json();
  } catch {
    return res.statusText;
  }
}
