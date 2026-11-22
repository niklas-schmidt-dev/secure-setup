#!/bin/sh
# Validates the generated nftables rulesets, the Cloudflare sync script, the
# rollback script and the forward chain (in a routed lab of network namespaces,
# hence --privileged) against a real nft binary inside a throwaway Debian
# container.
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
apt-get install -y -q --no-install-recommends nftables curl ca-certificates iproute2 netcat-openbsd >/dev/null 2>&1
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

# Forward chain: a routed lab with two uplinks (upa, upb) and one workload (wl).
# The workload listens on 8080; every uplink must be filtered like the internet.
for n in a b c; do ip netns add "$n"; done
ip link add upa type veth peer name a0 netns a
ip link add upb type veth peer name b0 netns b
ip link add wl type veth peer name c0 netns c
i=1
for pair in upa:a wl:c upb:b; do
	dev=${pair%:*}; ns=${pair#*:}
	case $dev in upa) i=1 ;; upb) i=2 ;; wl) i=3 ;; esac
	ip addr add 10.91.$i.1/24 dev "$dev"; ip link set "$dev" up
	ip -n "$ns" addr add 10.91.$i.2/24 dev "${ns}0"; ip -n "$ns" link set "${ns}0" up; ip -n "$ns" link set lo up
	ip -n "$ns" route add default via 10.91.$i.1
done
echo 1 > /proc/sys/net/ipv4/ip_forward
ip netns exec c nc -lk 8080 </dev/null >/dev/null 2>&1 &
ip netns exec b nc -lk 9090 </dev/null >/dev/null 2>&1 &
sleep 1
reach() { ip netns exec "$1" nc -z -w 2 "$2" "$3" 2>/dev/null; }
sed 's/"eth0"/"upa"/g' /t/goldens/default.nft > /tmp/one-uplink.nft
sed 's/"eth0"/"upa"/g; s/"he-ipv6"/"upb"/g' /t/goldens/two-uplinks.nft > /tmp/two-uplinks.nft
nft -f /tmp/one-uplink.nft
if reach a 10.91.3.2 8080; then echo "FAIL: the default-route uplink reaches the workload"; exit 1; fi
if reach b 10.91.3.2 8080; then echo "one uplink named: the second uplink still reaches the workload on 8080"; else echo "FAIL: control did not reproduce"; exit 1; fi
nft -f /tmp/two-uplinks.nft
if reach a 10.91.3.2 8080 || reach b 10.91.3.2 8080; then echo "FAIL: an uplink reaches the workload"; exit 1; fi
reach c 10.91.2.2 9090 || { echo "FAIL: the workload cannot reach out"; exit 1; }
echo "both uplinks named: neither reaches the workload, its outbound traffic still works"

# Existing private network on upa, which also carries a public address
# (10.91.4.1): SSH only to the admin address, and upa is filtered like the
# internet for forwarding. The tailnet-style rule trusts every address on it.
ip addr add 10.91.4.1/24 dev upa
ip -n a addr add 10.91.4.2/24 dev a0
nc -lk 22 </dev/null >/dev/null 2>&1 &
sleep 1
sed 's/"tailscale0"/"upa"/g; s/"eth0"/"upb"/g' /t/goldens/default.nft > /tmp/interface-wide.nft
nft -f /tmp/interface-wide.nft
if reach a 10.91.4.1 22; then echo "interface-wide admin rule: the other address on upa reaches SSH"; else echo "FAIL: control did not reproduce"; exit 1; fi
sed 's/"eth1"/"upa"/g; s/"eth0"/"upb"/g; s/10\.0\.0\.5/10.91.1.1/g' /t/goldens/existing-network.nft > /tmp/existing-network.nft
nft -f /tmp/existing-network.nft
reach a 10.91.1.1 22 || { echo "FAIL: the admin address is not reachable"; exit 1; }
if reach a 10.91.4.1 22; then echo "FAIL: another address on the admin interface reaches SSH"; exit 1; fi
if reach a 10.91.3.2 8080; then echo "FAIL: the internet-facing admin interface reaches the workload"; exit 1; fi
echo "existing network: SSH only to the admin address; its interface is filtered like the internet"

# Public ports: what the plan opens to everyone is reachable from an uplink,
# on the host and as a published container port; nothing else is, SSH least
# of all.
nc -lk 2525 </dev/null >/dev/null 2>&1 &
sleep 1
sed 's/"eth0"/"upa"/g' /t/goldens/default.nft > /tmp/no-public.nft
nft -f /tmp/no-public.nft
if reach a 10.91.1.1 2525 || reach a 10.91.3.2 8080; then echo "FAIL: control did not reproduce"; exit 1; fi
sed -e 's/"eth0"/"upa"/g' -e 's/{ 25, 587 }/{ 2525, 8080 }/g' /t/goldens/public-ports.nft > /tmp/public.nft
nft -f /tmp/public.nft
reach a 10.91.1.1 2525 || { echo "FAIL: a public port on the host is not reachable"; exit 1; }
reach a 10.91.3.2 8080 || { echo "FAIL: a public port published by the workload is not reachable"; exit 1; }
if reach a 10.91.1.1 22; then echo "FAIL: public ports opened SSH"; exit 1; fi
if reach a 10.91.2.2 9090; then echo "FAIL: public ports let the uplink reach another port"; exit 1; fi
echo "public ports: reachable from the internet on the host and on the workload, and nothing else"

# DHCPv6: the reply to a lease request comes from the router's link-local
# address, port 547, to this host's port 546. It answers a multicast, so it is
# not "established" traffic; dropped, the IPv6 address is lost when the lease
# runs out. Nothing else from that port gets in.
v6on='for f in /proc/sys/net/ipv6/conf/all/disable_ipv6 /proc/sys/net/ipv6/conf/default/disable_ipv6; do echo 0 > $f; done'
sh -c "$v6on"
ip netns add r
ip netns exec r sh -c "$v6on"
ip link add upr type veth peer name r0 netns r
ip link set upr up; ip -n r link set r0 up
for i in 1 2 3 4 5 6; do
	ll=$(ip -6 -o addr show dev upr scope link -tentative | awk '{print $4}' | cut -d/ -f1)
	[ -n "$ll" ] && [ -n "$(ip -n r -6 -o addr show dev r0 scope link -tentative)" ] && break
	sleep 1
done
[ -n "$ll" ] || { echo "FAIL: no link-local address in the lab"; exit 1; }
from547() {
	: > /tmp/got
	timeout 4 nc -6 -u -l "$1" > /tmp/got 2>/dev/null &
	sleep 1
	ip netns exec r sh -c "echo lease | nc -6 -u -w 1 -p 547 '$ll%r0' $1" >/dev/null 2>&1 || true
	sleep 1
	grep -q lease /tmp/got
}
sed -e 's/"eth0"/"upr"/g' -e '/udp sport 547/d' /t/goldens/default.nft > /tmp/no-dhcp6.nft
nft -f /tmp/no-dhcp6.nft
if from547 546; then echo "FAIL: control did not reproduce"; exit 1; fi
echo "without the rule: a DHCPv6 reply is dropped"
sed 's/"eth0"/"upr"/g' /t/goldens/default.nft > /tmp/dhcp6.nft
nft -f /tmp/dhcp6.nft
from547 546 || { echo "FAIL: a DHCPv6 reply is dropped"; exit 1; }
if from547 5000; then echo "FAIL: the DHCPv6 rule lets another port in"; exit 1; fi
echo "DHCPv6 replies reach the client port, and only that port"
echo "ALL CHECKS PASSED"
INNER
COPYFILE_DISABLE=1 tar --no-xattrs -C "$tmp" -cf - . | docker --context "$ctx" run --rm -i --privileged debian:bookworm-slim \
	sh -c 'mkdir -p /t && tar -C /t -xf - && sh /t/run.sh'
