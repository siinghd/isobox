#!/usr/bin/env bash
# isobox host setup — installs gVisor, registers the hardened `runsc-untrusted`
# Docker runtime, and creates the hard-capped isobox.slice cgroup. Idempotent.
# Requires: Docker (with cgroup v2 + systemd), root (sudo).
#
#   sudo bash deploy/setup.sh
set -euo pipefail

SLICE_MAX="${ISOBOX_SLICE_MEMORY_MAX:-2G}"
SLICE_HIGH="${ISOBOX_SLICE_MEMORY_HIGH:-1700M}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "FATAL: '$1' not found"; exit 1; }; }
need docker
[ "$(id -u)" = 0 ] || { echo "FATAL: run as root (sudo)"; exit 1; }

echo "==> 1/3 Installing gVisor (runsc)…"
if command -v runsc >/dev/null 2>&1; then
  echo "    runsc already installed: $(runsc --version | head -1)"
else
  ARCH=$(uname -m)
  URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"
  tmp=$(mktemp -d); pushd "$tmp" >/dev/null
  wget -q "${URL}/runsc" "${URL}/runsc.sha512" \
          "${URL}/containerd-shim-runsc-v1" "${URL}/containerd-shim-runsc-v1.sha512"
  sha512sum -c runsc.sha512 containerd-shim-runsc-v1.sha512
  chmod a+rx runsc containerd-shim-runsc-v1
  cp runsc containerd-shim-runsc-v1 /usr/local/bin/
  popd >/dev/null; rm -rf "$tmp"
  echo "    installed: $(runsc --version | head -1)"
fi

echo "==> 2/3 Registering the runsc-untrusted runtime in /etc/docker/daemon.json…"
# Merge a hardened runtime (systrap + network off + no host IPC) without clobbering
# existing daemon config. Requires python3 (present wherever Docker dev tools are);
# falls back to a manual note if absent.
if python3 - "$SLICE_MAX" <<'PY'
import json, os, sys
path = "/etc/docker/daemon.json"
cfg = {}
if os.path.exists(path):
    with open(path) as f:
        try: cfg = json.load(f)
        except Exception: cfg = {}
        import shutil; shutil.copy(path, path + ".bak.isobox")
rt = cfg.setdefault("runtimes", {})
rt["runsc-untrusted"] = {
    "path": "/usr/local/bin/runsc",
    "runtimeArgs": ["--platform=systrap","--network=none","--host-uds=none",
                    "--host-fifo=none","--file-access=exclusive","--net-raw=false"],
}
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
print("    daemon.json updated (backup: daemon.json.bak.isobox)")
PY
then
  systemctl reload docker || systemctl restart docker
  docker info --format '{{.Runtimes}}' | grep -q runsc-untrusted && echo "    runtime registered."
else
  echo "    !! could not edit daemon.json automatically; add the runsc-untrusted block from deploy/daemon.json.runsc-untrusted manually, then: systemctl reload docker"
fi

echo "==> 3/3 Creating the hard-capped isobox.slice (MemoryMax=${SLICE_MAX})…"
cat > /etc/systemd/system/isobox.slice <<EOF
[Unit]
Description=isobox sandbox subsystem (hard-capped aggregate cgroup)
Before=slices.target

[Slice]
MemoryAccounting=yes
MemoryMax=${SLICE_MAX}
MemoryHigh=${SLICE_HIGH}
MemorySwapMax=0
CPUAccounting=yes
CPUWeight=200
TasksAccounting=yes
TasksMax=512
EOF
systemctl daemon-reload
systemctl start isobox.slice
got=$(systemctl show isobox.slice -p MemoryMax --value)
echo "    isobox.slice MemoryMax=${got}"

echo
echo "Done. Verify a sandbox runs:"
echo "  docker run --rm --runtime=runsc-untrusted --cgroup-parent=isobox.slice alpine echo ok"
echo "Then build & start isoboxd (see deploy/isoboxd.service)."
