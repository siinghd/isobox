#!/usr/bin/env python3
# isobox live-kernel REPL harness.
#
# Runs as PID 1-ish inside a long-lived, fully-sandboxed python-slim container
# started with `docker run -d -i`. It owns ONE persistent namespace dict and
# exec()s every submitted snippet into it, so variables/imports/defs survive
# across exec steps (Code-Interpreter parity).
#
# TRANSPORT: framed JSON-lines.
#   stdin  (one JSON object per line):  {"id": "...", "op": "exec", "code": "..."}
#                                       {"id": "...", "op": "ping"}
#   stdout (one JSON object per line):  stream deltas then exactly ONE result:
#       {"id","type":"stream","stream":"stdout"|"stderr","data":"..."}
#       {"id","type":"result","ok":bool,"error":"","exc":"","durationMs":N,"truncated":bool}
#       {"id","type":"pong"}                          (reply to ping)
#       {"type":"ready","proto":1,"python":"3.x.y"}   (one banner at startup)
#
# All protocol frames go to fd 1 (stdout). The harness DUPS the real stdout/stderr
# away before running any user code and rebinds sys.stdout/sys.stderr to capturing
# shims, so a user `print()` can never corrupt the frame stream — it is captured
# and re-emitted as a framed "stream" delta on the protocol channel instead.
#
# INTERRUPTIBILITY: each exec runs on a WORKER THREAD. The control plane interrupts
# a runaway step with `docker kill -s INT <name>`; the default SIGINT handler in
# the MAIN thread raises KeyboardInterrupt, which we re-raise INTO the worker via
# PyThreadState_SetAsyncExc. The worker unwinds, the namespace survives, and the
# container keeps running for the next step. The container is NEVER recreated.
#
# No third-party deps: stdlib only. Buffers are flushed per-line so the Go side
# sees deltas live.

import sys
import io
import os
import json
import time
import ctypes
import signal
import threading
import traceback

PROTO = 1

# Frames are written ONLY through a PRIVATE duplicate of the original fd 1 — the
# single protocol channel. We dup fd 1 to a high, non-inheritable fd, then point
# the real fds 1 and 2 at /dev/null. After this, user code (which runs in the SAME
# process and could otherwise os.write(1, ...), use sys.__stdout__, or spawn a
# subprocess that inherits fd 1/2) has NO writable handle on the protocol channel:
# a forged {"type":"result"} frame can never reach the Go control plane. This is
# the harness half of a two-layer defence; the Go side additionally honours only
# frames whose id matches the freshly-minted per-step uuid. SECURITY-CRITICAL.
_proto_fd = os.dup(1)
os.set_inheritable(_proto_fd, False)  # subprocesses must NOT inherit the proto fd
_devnull_fd = os.open(os.devnull, os.O_WRONLY)
os.dup2(_devnull_fd, 1)  # user prints / os.write(1) / sys.__stdout__ -> /dev/null
os.dup2(_devnull_fd, 2)  # user os.write(2) / sys.__stderr__         -> /dev/null
os.close(_devnull_fd)
_raw_stdout = os.fdopen(_proto_fd, "w", encoding="utf-8", newline="\n", buffering=1)
_emit_lock = threading.Lock()


def _emit(obj):
    # One JSON object per line. Holds a lock because stream deltas from the worker
    # and the terminal result from the main thread can race on the channel.
    line = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    with _emit_lock:
        _raw_stdout.write(line)
        _raw_stdout.write("\n")
        _raw_stdout.flush()


# Per-step output budget. Mirrors the one-shot executor's OutputBytes cap so a
# single chatty step can't flood the attach pipe. Tunable via env at container
# launch (Go sets ISOBOX_KERNEL_OUTPUT_BYTES).
MAX_OUTPUT = int(os.environ.get("ISOBOX_KERNEL_OUTPUT_BYTES", str(64 * 1024)))


class _StreamShim(io.TextIOBase):
    """Replaces sys.stdout / sys.stderr during exec. Forwards writes as framed
    'stream' deltas tagged with the current step id, coalescing small writes and
    enforcing a per-step byte budget (then silently drops, flagging truncation)."""

    def __init__(self, name):
        self._name = name          # "stdout" | "stderr"
        self.step_id = None
        self.count = 0
        self.truncated = False

    def writable(self):
        return True

    def write(self, s):
        if not isinstance(s, str):
            s = str(s)
        if not s:
            return 0
        n = len(s)
        if self.step_id is None:
            return n  # nothing running (shouldn't happen); swallow
        if self.count >= MAX_OUTPUT:
            self.truncated = True
            return n
        room = MAX_OUTPUT - self.count
        chunk = s if n <= room else s[:room]
        self.count += len(chunk)
        if n > room:
            self.truncated = True
        _emit({"id": self.step_id, "type": "stream", "stream": self._name, "data": chunk})
        return n

    def flush(self):
        pass

    def reset(self, step_id):
        self.step_id = step_id
        self.count = 0
        self.truncated = False


_out_shim = _StreamShim("stdout")
_err_shim = _StreamShim("stderr")

# The ONE persistent namespace. Survives across every exec step.
NS = {"__name__": "__main__", "__builtins__": __builtins__}

# Neutralise the interactive `exit`/`quit` builtins. These are _sitebuiltins.Quitter
# objects whose __call__ does `sys.stdin.close()` BEFORE raising SystemExit — which
# would close the harness's request channel and tear the kernel down, defeating the
# "exit() is a handled step result" contract below. We replace them with a plain
# sys.exit (raises SystemExit, no stdin side effect), which _run_step catches so the
# namespace and the container survive. (Only affects these two REPL conveniences;
# sys.exit / raising SystemExit directly already worked.)
def _safe_exit(code=None):
    raise SystemExit(code)


try:
    _bi = NS["__builtins__"]
    _bid = _bi if isinstance(_bi, dict) else _bi.__dict__
    _bid["exit"] = _safe_exit
    _bid["quit"] = _safe_exit
except Exception:
    pass


# --- worker-thread interrupt plumbing --------------------------------------
# The main thread receives SIGINT (from `docker kill -s INT`). We translate that
# into an async exception delivered to the worker thread running user code, so the
# KeyboardInterrupt lands in the user's stack frame, not in our I/O loop.
_worker_tid = None          # ctypes-visible thread id of the in-flight worker
_worker_lock = threading.Lock()


def _raise_in_thread(tid, exc_type):
    if tid is None:
        return
    ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(tid), ctypes.py_object(exc_type)
    )


def _on_sigint(signum, frame):
    with _worker_lock:
        tid = _worker_tid
    _raise_in_thread(tid, KeyboardInterrupt)


signal.signal(signal.SIGINT, _on_sigint)
# SIGTERM => clean exit (container stop). Let default handling end the process.


def _user_traceback():
    """Format the current exception, hiding the harness's own frames so the user
    sees a clean traceback rooted at their <step> code (Code-Interpreter quality).
    We drop leading frames until the first one whose filename is "<step>"."""
    etype, evalue, tb = sys.exc_info()
    frames = traceback.extract_tb(tb)
    keep = frames
    for i, fr in enumerate(frames):
        if fr.filename == "<step>":
            keep = frames[i:]
            break
    out = ["Traceback (most recent call last):\n"]
    out += traceback.format_list(keep)
    out += traceback.format_exception_only(etype, evalue)
    return "".join(out)


def _run_step(step_id, code):
    """Compile+exec one snippet into NS on the worker thread, capturing output
    and any exception. Emits the terminal result frame from THIS thread."""
    global _worker_tid
    with _worker_lock:
        _worker_tid = threading.get_ident()
    _out_shim.reset(step_id)
    _err_shim.reset(step_id)
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = _out_shim, _err_shim
    start = time.monotonic()
    ok = True
    err = ""
    exc = ""
    try:
        try:
            compiled = compile(code, "<step>", "exec")
        except SyntaxError:
            ok = False
            exc = "SyntaxError"
            err = "".join(traceback.format_exc(limit=0)).rstrip("\n")
        else:
            try:
                exec(compiled, NS)
            except KeyboardInterrupt:
                ok = False
                exc = "KeyboardInterrupt"
                err = "KeyboardInterrupt"
            except SystemExit:
                # User called exit()/sys.exit(): treat as a handled step result,
                # do NOT let it tear the kernel process down.
                ok = False
                exc = "SystemExit"
                err = "SystemExit"
            except BaseException:
                ok = False
                exc = type(sys.exc_info()[1]).__name__
                err = _user_traceback().rstrip("\n")
    finally:
        sys.stdout, sys.stderr = old_out, old_err
        with _worker_lock:
            _worker_tid = None
    dur_ms = int((time.monotonic() - start) * 1000)
    _emit({
        "id": step_id, "type": "result",
        "ok": ok, "error": err, "exc": exc,
        "durationMs": dur_ms,
        "truncated": _out_shim.truncated or _err_shim.truncated,
    })


def main():
    _emit({"type": "ready", "proto": PROTO, "python": ".".join(map(str, sys.version_info[:3]))})
    # Read framed requests off stdin, one JSON object per line. One exec is in
    # flight at a time (the Go side serialises with a per-session mutex, but we
    # also enforce it here: we run the worker and JOIN before reading the next
    # line, so SIGINT can only ever target the current step).
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
        except Exception:
            _emit({"id": "", "type": "result", "ok": False, "error": "bad request frame", "exc": "ProtocolError", "durationMs": 0, "truncated": False})
            continue
        op = req.get("op", "exec")
        step_id = req.get("id", "")
        if op == "ping":
            _emit({"id": step_id, "type": "pong"})
            continue
        if op == "shutdown":
            _emit({"id": step_id, "type": "result", "ok": True, "error": "", "exc": "", "durationMs": 0, "truncated": False})
            break
        if op != "exec":
            _emit({"id": step_id, "type": "result", "ok": False, "error": "unknown op " + repr(op), "exc": "ProtocolError", "durationMs": 0, "truncated": False})
            continue
        code = req.get("code", "")
        # Run user code on a worker thread so a main-thread SIGINT can be injected
        # into it as KeyboardInterrupt without killing the harness.
        t = threading.Thread(target=_run_step, args=(step_id, code), daemon=True)
        t.start()
        # Join WITHOUT a wall-clock timeout here: the control plane owns the
        # deadline and enforces it via `docker kill -s INT` (soft) then container
        # rm (hard). We just wait for the worker to finish or be interrupted.
        t.join()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception:
        # Last-resort: surface a fatal harness error on the channel before dying.
        try:
            _emit({"id": "", "type": "fatal", "error": traceback.format_exc()})
        except Exception:
            pass
        sys.exit(1)
