#!/bin/sh
# End-to-end test on a Docker host (the NAS, or the runner in CI): a throwaway
# systemd "VPS" with two networks (eth0 = "internet", eth1 = "private network")
# and a client container that runs secure-setup against it. Covers: detection,
# nftables install, sshd hardening, Cloudflare ranges, apply + confirm,
# verification that the public port is closed, the automatic rollback, and
# undo.
# Usage: test/e2e/run.sh          (DOCKER_CONTEXT defaults to nas-docker)
set -eu
cd "$(dirname "$0")/../.."
ctx=${DOCKER_CONTEXT:-nas-docker}
d() { docker --context "$ctx" "$@"; }
id="ss-e2e-$$"
srv="$id-server"; cli="$id-client"; pub="$id-a-public"; prv="$id-b-private"
cleanup() {
	d rm -f "$srv" "$cli" >/dev/null 2>&1 || true
	d network rm "$pub" "$prv" >/dev/null 2>&1 || true
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

echo "== build linux binary"
bin=${E2E_BINARY:-/tmp/secure-setup-linux-amd64}
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$bin" .

echo "== start server and client"
d network create --subnet "${E2E_SUBNET_PUBLIC:-10.250.100.0/24}" "$pub" >/dev/null
d network create --subnet "${E2E_SUBNET_PRIVATE:-10.250.101.0/24}" "$prv" >/dev/null
d run -d --name "$srv" --restart unless-stopped --privileged --hostname e2e-vps --network "$pub" secure-setup-e2e-server >/dev/null
d network connect "$prv" "$srv"
d run -d --name "$cli" --network "$pub" secure-setup-e2e-client >/dev/null
d network connect "$prv" "$cli"
d cp "$bin" "$cli:/usr/local/bin/secure-setup"
d exec "$cli" sh -c 'mkdir -p /root/.ssh && chmod 700 /root/.ssh && ssh-keygen -q -t ed25519 -N "" -f /root/.ssh/id_ed25519'
pubkey=$(d exec "$cli" cat /root/.ssh/id_ed25519.pub)
d exec "$srv" sh -c "mkdir -p /root/.ssh && printf '%s\n' '$pubkey' > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"
pubip=$(d inspect -f "{{(index .NetworkSettings.Networks \"$pub\").IPAddress}}" "$srv")
prvip=$(d inspect -f "{{(index .NetworkSettings.Networks \"$prv\").IPAddress}}" "$srv")
echo "   server public $pubip (eth0), private $prvip (eth1)"
for i in $(seq 1 30); do
	if d exec "$srv" systemctl is-active --quiet ssh 2>/dev/null; then break; fi
	sleep 1
done
d exec "$srv" systemctl is-active --quiet ssh || fail "sshd did not start in the server container"
d exec "$cli" nc -z -w 5 "$pubip" 22 || fail "public ssh not reachable before the run"
d exec "$cli" nc -z -w 5 "$prvip" 22 || fail "private ssh not reachable before the run"

echo "== run 1: apply (existing private network stands in for the tailnet)"
d exec -i "$cli" sh -c 'cat > /root/plan.json' <<JSON
{
  "update_system": true,
  "reboot": true,
  "server": {"host": "$pubip", "port": 22, "user": "root", "key_path": "/root/.ssh/id_ed25519"},
  "tailscale": {"admin_interface": "eth1", "udp_port": 41641, "use_existing_network": true, "admin_address": "$prvip"},
  "firewall": {"web_ports": [443], "allow_ping": true, "tailnet_ports": [22, 8080], "rollback_seconds": 30, "cloudflare_sync": true},
  "ssh": {"harden": true, "add_local_key": true}
}
JSON
d exec "$cli" secure-setup apply -f /root/plan.json --yes 2>&1 | tee /tmp/e2e-run1.log
grep -q "The server is locked down" /tmp/e2e-run1.log || fail "run 1 did not report success"
grep -q "==> Update the system" /tmp/e2e-run1.log && ! grep -q "Update the system: skipped" /tmp/e2e-run1.log || fail "run 1 did not update the system first"
grep -q "the server rebooted and is reachable over the private network again" /tmp/e2e-run1.log || fail "run 1 did not reboot"
grep -q "after the reboot: rules loaded, nftables enabled at boot" /tmp/e2e-run1.log || fail "run 1 did not check the server after the reboot"
echo "   rebooted (container restart) and the lockdown came back on its own"

echo "== assertions after run 1"
if d exec "$cli" nc -z -w 5 "$pubip" 22; then fail "public ssh still open"; else echo "   public ssh blocked"; fi
d exec "$cli" nc -z -w 5 "$prvip" 22 && echo "   private ssh open"
d exec "$cli" nc -z -w 5 "$prvip" 8080 2>/dev/null && fail "nothing listens on 8080, nc should not connect" || true
d exec "$srv" nft list chain inet secure_setup input | grep -Eq 'iifname "eth1" tcp dport \{ 22, 8080 \} counter packets [0-9]+ bytes [0-9]+ accept' && echo "   tailnet rule present"
d exec "$srv" nft list set inet secure_setup cloudflare_v4 | grep -q '173.245.48.0/20' && echo "   cloudflare set populated"
d exec "$srv" sh -c 'systemctl is-enabled nftables' | grep -q enabled && echo "   nftables.service enabled"
d exec "$srv" systemctl is-active --quiet secure-setup-cloudflare-sync.timer && echo "   cloudflare sync timer active"
d exec "$srv" systemctl is-active --quiet secure-setup-rollback.timer && fail "rollback timer still armed" || echo "   rollback timer cancelled"
d exec "$srv" test -f /etc/ssh/sshd_config.d/00-secure-setup.conf && echo "   sshd drop-in present"
d exec "$srv" sh -c 'sshd -T | grep -q "^passwordauthentication no"' && echo "   sshd password auth off"
d exec "$srv" grep -q 'Managed by secure-setup' /etc/nftables.conf && echo "   /etc/nftables.conf persisted"
d exec "$srv" test -f /etc/nftables.conf.secure-setup.bak && echo "   previous nftables.conf backed up"

echo "== run 2: rules that would lock us out must roll back"
d exec -i "$cli" sh -c 'cat > /root/plan-bad.json' <<JSON
{
  "server": {"host": "$prvip", "port": 22, "user": "root", "key_path": "/root/.ssh/id_ed25519"},
  "update_system": false,
  "reboot": false,
  "tailscale": {"admin_interface": "eth0", "udp_port": 41641, "use_existing_network": true, "admin_address": "$prvip"},
  "firewall": {"web_ports": [443], "allow_ping": true, "tailnet_ports": [22], "rollback_seconds": 30, "cloudflare_sync": true, "wan_interface": "eth1", "wan_interface_override": true},
  "ssh": {"harden": false, "add_local_key": false}
}
JSON
if d exec "$cli" secure-setup apply -f /root/plan-bad.json --yes >/tmp/e2e-run2.log 2>&1; then
	cat /tmp/e2e-run2.log; fail "run 2 should have failed"
fi
tail -8 /tmp/e2e-run2.log
grep -q "rolled back" /tmp/e2e-run2.log || fail "run 2 did not report the rollback"
d exec "$cli" nc -z -w 5 "$prvip" 22 && echo "   private ssh open again after rollback"
d exec "$srv" nft list chain inet secure_setup input | grep -Eq 'iifname "eth1" tcp dport \{ 22, 8080 \} counter packets [0-9]+ bytes [0-9]+ accept' && echo "   previous (run 1) rules restored"
if d exec "$cli" nc -z -w 5 "$pubip" 22; then fail "public ssh open after rollback"; else echo "   public ssh still blocked"; fi
d exec "$srv" test -f /var/lib/secure-setup/rolled-back && echo "   rollback marker written"

echo "== undo"
d exec "$cli" secure-setup undo --host "$prvip" --user root --key /root/.ssh/id_ed25519 --yes 2>&1 | sed 's/^/   /'
d exec "$srv" nft list table inet secure_setup >/dev/null 2>&1 && fail "table still present after undo" || echo "   table removed"
d exec "$cli" nc -z -w 5 "$pubip" 22 && echo "   public ssh open again"
d exec "$srv" test -f /etc/ssh/sshd_config.d/00-secure-setup.conf && fail "sshd drop-in still present" || echo "   sshd drop-in removed"
d exec "$srv" systemctl is-enabled secure-setup-cloudflare-sync.timer >/dev/null 2>&1 && fail "sync timer still enabled" || echo "   sync timer removed"
echo
echo "E2E PASSED"
