#!/bin/sh
# Validates the generated nftables rulesets, the Cloudflare sync script and the
# rollback script against a real nft binary inside a throwaway Debian container.
# Usage: scripts/validate-ruleset.sh   (uses DOCKER_CONTEXT, default nas-docker)
set -eu
cd "$(dirname "$0")/.."
ctx=${DOCKER_CONTEXT:-nas-docker}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/goldens" "$tmp/assets"
cp internal/nftgen/testdata/*.nft "$tmp/goldens/"
cp internal/remote/assets/* "$tmp/assets/"
cat > "$tmp/run.sh" <<'INNER'
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
apt-get install -y -q --no-install-recommends nftables curl ca-certificates iproute2 >/dev/null 2>&1
echo "nft $(nft --version)"
mkdir -p /etc/secure-setup /var/lib/secure-setup
: > /etc/secure-setup/cloudflare.nft
for f in /t/goldens/*.nft; do nft -c -f "$f" && echo "syntax ok: $(basename "$f")"; done
nft -f /t/goldens/default.nft
nft list chain inet secure_setup input | grep -q 'policy drop' && echo "default ruleset applied, input policy drop"
install -m 0755 /t/assets/cloudflare-sync.sh /usr/local/sbin/secure-setup-cloudflare-sync
secure-setup-cloudflare-sync
n=$(nft -j list set inet secure_setup cloudflare_v4 | grep -o '"prefix"' | wc -l)
echo "live cloudflare_v4 set holds $n prefixes"
[ "$n" -ge 5 ]
nft -f /t/goldens/default.nft
nft list set inet secure_setup cloudflare_v4 | grep -q '173.245.48.0/20' && echo "elements survive a full reload via the include"
{ echo "table inet secure_setup"; echo "delete table inet secure_setup"; nft list table inet secure_setup; } > /var/lib/secure-setup/previous.nft
nft -f /t/goldens/web-both.nft
nft list chain inet secure_setup input | grep -q 'dport { 80, 443 }' && echo "web-both ruleset applied"
sh /t/assets/rollback.sh
nft list chain inet secure_setup input | grep -q 'dport { 443 } accept' && echo "rollback restored the previous table"
rm -f /var/lib/secure-setup/previous.nft
sh /t/assets/rollback.sh
if nft list table inet secure_setup >/dev/null 2>&1; then echo "FAIL: table still present"; exit 1; fi
echo "rollback without previous state removed the table"
echo "ALL CHECKS PASSED"
INNER
COPYFILE_DISABLE=1 tar --no-xattrs -C "$tmp" -cf - . | docker --context "$ctx" run --rm -i --cap-add NET_ADMIN debian:bookworm-slim \
	sh -c 'mkdir -p /t && tar -C /t -xf - && sh /t/run.sh'
