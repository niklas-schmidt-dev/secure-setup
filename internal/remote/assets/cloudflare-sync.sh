#!/bin/sh
# secure-setup-cloudflare-sync: refresh the Cloudflare IP ranges in the
# nftables sets. Installed by secure-setup, run daily by
# secure-setup-cloudflare-sync.timer. Safe to run by hand.
set -eu

ELEMENTS=/etc/secure-setup/cloudflare.nft
V4_URL=https://www.cloudflare.com/ips-v4
V6_URL=https://www.cloudflare.com/ips-v6

tmp=$(mktemp)
live=$(mktemp)
trap 'rm -f "$tmp" "$live"' EXIT

fetch() {
	curl -fsSL --max-time 30 --retry 3 --retry-delay 5 "$1"
}

v4=$(fetch "$V4_URL") || { echo "secure-setup-cloudflare-sync: could not fetch $V4_URL" >&2; exit 1; }
v6=$(fetch "$V6_URL") || { echo "secure-setup-cloudflare-sync: could not fetch $V6_URL" >&2; exit 1; }

# Keep only well-formed prefixes and refuse suspiciously short lists.
v4=$(printf '%s\n' "$v4" | tr -d '\r' | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$' || true)
v6=$(printf '%s\n' "$v6" | tr -d '\r' | grep -Ei '^[0-9a-f:]+/[0-9]{1,3}$' || true)
n4=$(printf '%s\n' "$v4" | grep -c . || true)
n6=$(printf '%s\n' "$v6" | grep -c . || true)
if [ "$n4" -lt 5 ] || [ "$n6" -lt 3 ]; then
	echo "secure-setup-cloudflare-sync: unexpected response ($n4 IPv4, $n6 IPv6 prefixes); keeping the current sets" >&2
	exit 1
fi

list4=$(printf '%s\n' "$v4" | paste -sd, -)
list6=$(printf '%s\n' "$v6" | paste -sd, -)

{
	echo "# Cloudflare IP ranges - managed by secure-setup-cloudflare-sync, refreshed daily. Do not edit."
	echo "add element inet secure_setup cloudflare_v4 { $list4 }"
	echo "add element inet secure_setup cloudflare_v6 { $list6 }"
} > "$tmp"

{
	echo "flush set inet secure_setup cloudflare_v4"
	echo "flush set inet secure_setup cloudflare_v6"
	echo "add element inet secure_setup cloudflare_v4 { $list4 }"
	echo "add element inet secure_setup cloudflare_v6 { $list6 }"
} > "$live"

nft -c -f "$live"
nft -f "$live"
install -m 0644 "$tmp" "$ELEMENTS"
echo "secure-setup-cloudflare-sync: $n4 IPv4 and $n6 IPv6 Cloudflare prefixes active"
