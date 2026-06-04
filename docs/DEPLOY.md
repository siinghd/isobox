# Deploying isobox

## Prerequisites

- Linux with **cgroup v2** and **systemd**.
- **Docker** (the daemon uses the systemd cgroup driver).
- No `/dev/kvm` is fine — that's the point. (With KVM you may later prefer the Firecracker backend.)
- A non-root user in the `docker` group to run the control plane.

## 1. Host setup (one-time)

```bash
sudo bash deploy/setup.sh
```

This is idempotent and does three things:

1. **Installs gVisor** (`runsc` + the containerd shim), checksum-verified, to `/usr/local/bin`.
2. **Registers the `runsc-untrusted` runtime** in `/etc/docker/daemon.json` (systrap platform, `--network=none`, no host IPC) and reloads Docker. A backup is written to `daemon.json.bak.isobox`.
3. **Creates `isobox.slice`** — the hard-capped parent cgroup (`MemoryMax=2G`, `MemorySwapMax=0` by default; override with `ISOBOX_SLICE_MEMORY_MAX`).

Verify:

```bash
docker run --rm --runtime=runsc-untrusted --cgroup-parent=isobox.slice alpine uname -r
# -> 4.19.0-gvisor   (gVisor's kernel, not the host's)
systemctl show isobox.slice -p MemoryMax --value   # -> 2G  (not "infinity")
```

> **Sizing `isobox.slice`.** The cap is the aggregate ceiling for *all* concurrent sandboxes. Budget `concurrency × (per-exec memory + ~40–60 MB gVisor Sentry/Gofer overhead)` and keep it comfortably below the cap. On a busy shared host, watch for swap-in spikes on neighbours under load and lower `ISOBOX_CONCURRENCY` or the slice cap if you see them.

## 2. Build & install the binary

```bash
go build -o bin/isoboxd ./cmd/isoboxd
sudo cp deploy/isoboxd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now isoboxd
curl -s localhost:8090/readyz   # {"ready":true,"backend":"gvisor"}
```

Tune via the `Environment=` lines in the unit (or a drop-in): `ISOBOX_CONCURRENCY`, `ISOBOX_RATE_PER_MIN`, `ISOBOX_API_KEY` (set to require auth), etc.

## 3. Expose it (Caddy example)

```bash
sudo cp deploy/isobox.caddy /etc/caddy/sites.d/
sudo systemctl reload caddy
```

The site config sets two non-obvious essentials:

- `flush_interval -1` — **required** for SSE; without it the proxy buffers and the live token stream is withheld until EOF.
- `header_up X-Real-IP {http.request.header.CF-Connecting-IP}` — so per-IP rate limiting keys on the true client behind Cloudflare.

### Public-demo hardening

The control plane binds `127.0.0.1` (reachable only via the proxy) and rate-limits per IP. For a public endpoint also:

- **Firewall 443 to Cloudflare IP ranges** (so the origin can't be hit directly), or configure Caddy **Authenticated Origin Pull** with the Cloudflare origin-pull CA.
- Add a **Cloudflare Turnstile** gate in front of `/execute`.
- Consider setting `ISOBOX_API_KEY` and issuing keys instead of running fully open.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full control list and the honest residual-risk notes.

## 4. (Optional) agent runtimes + network egress

For AI-agent workloads (fetch / scrape / data):

```bash
# Batteries-included Python + pre-warmed Go images (referenced by registry.yaml)
docker build -t isobox/python-agent:1 deploy/images/python-agent
docker build -t isobox/go-agent:1     deploy/images/go-agent

# Filtered egress network + firewall (adds the runsc-net runtime use; idempotent)
sudo cp deploy/isobox-egress.service /etc/systemd/system/
sudo systemctl enable --now isobox-egress.service   # runs deploy/egress-setup.sh
```

`egress-setup.sh` creates the `isobox-egress` bridge and installs the firewall that lets `network:true` sandboxes reach the **public internet only** — cloud metadata, all RFC1918/private ranges, the host itself (incl. VPNs), and outbound mail are dropped (see [THREAT_MODEL.md](THREAT_MODEL.md#network-egress-opt-in)). It also needs the `runsc-net` runtime in `daemon.json` (added by `setup.sh`, or from `deploy/daemon.json.runtimes`).

Disable egress entirely with `ISOBOX_ALLOW_NETWORK=0`. For a fully-open public endpoint, consider gating `network:true` behind an API key.

> If you skip this, everything still works — sandboxes simply stay network-off, and `python` falls back to `python-slim` if you don't build the agent image (edit `registry.yaml` to point `python` at `python:3-slim`).

## Uninstall

```bash
sudo systemctl disable --now isoboxd
sudo systemctl stop isobox.slice && sudo rm /etc/systemd/system/isobox.slice
sudo rm /etc/caddy/sites.d/isobox.caddy && sudo systemctl reload caddy
# (optional) remove the runsc-untrusted block from /etc/docker/daemon.json
```
