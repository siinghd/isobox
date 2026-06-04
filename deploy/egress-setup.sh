#!/usr/bin/env bash
# isobox egress setup — creates the FILTERED network used by opt-in `network:true`
# sandboxes, so AI-agent code can reach the PUBLIC internet but NOT cloud
# metadata, private/RFC1918 ranges, the host itself (incl. any VPN), or outbound
# mail. Idempotent; run on boot via isobox-egress.service.
#
#   sudo bash deploy/egress-setup.sh
set -euo pipefail

NET="${ISOBOX_EGRESS_NETWORK:-isobox-egress}"
BRIDGE="${ISOBOX_EGRESS_BRIDGE:-iso-egress0}"
SUBNET="${ISOBOX_EGRESS_SUBNET:-172.28.218.0/24}"
GATEWAY="${ISOBOX_EGRESS_GATEWAY:-172.28.218.1}"
RESOLV="${ISOBOX_RESOLV:-/etc/isobox/resolv.conf}"

[ "$(id -u)" = 0 ] || { echo "FATAL: run as root (sudo)"; exit 1; }

echo "==> public-resolver resolv.conf at ${RESOLV} (bypasses Docker's embedded DNS, unreachable from gVisor's netstack)"
mkdir -p "$(dirname "$RESOLV")"
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions timeout:3 attempts:2\n' > "$RESOLV"

echo "==> docker network ${NET} (${SUBNET}, IPv4-only)"
if ! docker network inspect "$NET" >/dev/null 2>&1; then
  docker network create --driver bridge --subnet "$SUBNET" --gateway "$GATEWAY" \
    --opt com.docker.network.bridge.name="$BRIDGE" \
    --opt com.docker.network.bridge.enable_icc=false "$NET"  # no sandbox-to-sandbox traffic
fi

echo "==> egress firewall (idempotent)"
add() { iptables -C "$@" 2>/dev/null || iptables -I "$@"; }

# FORWARD (DOCKER-USER): sandbox -> elsewhere. Drop dangerous destinations; the
# rest (public internet) is allowed to flow through Docker's own ACCEPT rules.
add DOCKER-USER -s "$SUBNET" -d 169.254.0.0/16 -j DROP   # cloud metadata / link-local
add DOCKER-USER -s "$SUBNET" -d 10.0.0.0/8     -j DROP   # private
add DOCKER-USER -s "$SUBNET" -d 172.16.0.0/12  -j DROP   # private (incl. docker nets + host gw)
add DOCKER-USER -s "$SUBNET" -d 192.168.0.0/16 -j DROP   # private
add DOCKER-USER -s "$SUBNET" -p tcp -m multiport --dports 25,465,587 -j DROP  # anti-spam (outbound mail)

# INPUT: sandbox -> the HOST itself. The sandbox never needs to talk to the host
# (DNS goes to public resolvers; routing is L2), so drop it all. This is what
# stops access to host-LOCAL IPs (e.g. a WireGuard 10.x VPN, bridge gateways)
# which travel via INPUT, NOT FORWARD/DOCKER-USER.
add INPUT -i "$BRIDGE" -j DROP

echo "==> verify + heartbeat sentinel (fail-closed gate for isoboxd)"
# isoboxd is unprivileged and cannot read iptables, so it trusts this sentinel:
# it is (re)touched ONLY when every load-bearing rule is confirmed present. A
# systemd timer re-runs this script every 60s, so if the firewall is ever torn
# down (e.g. a docker restart flushes DOCKER-USER), the sentinel goes stale and
# isoboxd disables network mode instead of failing open.
SENTINEL="${ISOBOX_EGRESS_SENTINEL:-/etc/isobox/egress-ok}"
ok=1
for d in 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
  iptables -C DOCKER-USER -s "$SUBNET" -d "$d" -j DROP 2>/dev/null || ok=0
done
iptables -C INPUT -i "$BRIDGE" -j DROP 2>/dev/null || ok=0
if [ "$ok" = 1 ]; then
  touch "$SENTINEL"
  echo "    OK — egress firewall verified, sentinel refreshed ($SENTINEL)"
else
  rm -f "$SENTINEL"
  echo "    WARNING — egress rules incomplete; sentinel removed; network mode will fail closed"
  exit 1
fi
