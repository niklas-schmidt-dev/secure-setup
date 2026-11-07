#!/bin/sh
# End-to-end test of `secure-setup here` on a Docker host (the NAS, or the
# runner in CI): the binary runs INSIDE the throwaway systemd "VPS" (eth0 =
# internet, eth1 = private network standing in for the tailnet). A client
# container logs in over the private network to confirm. Covers: login
# confirmation (automatic and via `secure-setup confirm`), self-check
# confirmation, the rollback when no login arrives, sshd hardening
# preconditions, the TUI, and `undo --here`.
# Usage: test/e2e/run-here.sh       (DOCKER_CONTEXT defaults to nas-docker)
set -eu
cd "$(dirname "$0")/../.."
ctx=${DOCKER_CONTEXT:-nas-docker}
d() { docker --context "$ctx" "$@"; }
id="ss-here-$$"
srv="$id-server"; cli="$id-client"; pub="$id-a-public"; prv="$id-b-private"
cleanup() {
	d rm -f "$srv" "$cli" >/dev/null 2>&1 || true
	d network rm "$pub" "$prv" >/dev/null 2>&1 || true
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
# wait_log FILE PATTERN SECONDS: wait until the server-side log matches
wait_log() {
	for i in $(seq 1 "$3"); do
		if d exec "$srv" grep -q "$2" "$1" 2>/dev/null; then return 0; fi
		sleep 1
	done
	d exec "$srv" cat "$1" 2>/dev/null | tail -20
	fail "timeout waiting for '$2' in $1"
}

echo "== build linux binary"
bin=${E2E_BINARY:-/tmp/secure-setup-linux-amd64}
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$bin" .

echo "== start server and client"
d network create --subnet "${E2E_SUBNET_PUBLIC:-10.250.100.0/24}" "$pub" >/dev/null
d network create --subnet "${E2E_SUBNET_PRIVATE:-10.250.101.0/24}" "$prv" >/dev/null
# Pinned names: a container restarted by its policy (the simulated reboot) can
# otherwise get its two cards in the other order (Docker 28 or newer).
ifname=com.docker.network.endpoint.ifname
d run -d --name "$srv" --restart unless-stopped --privileged --hostname here-vps --network "name=$pub,driver-opt=$ifname=eth0" secure-setup-e2e-server >/dev/null
d network connect --driver-opt "$ifname=eth1" "$prv" "$srv"
d run -d --name "$cli" --network "$pub" secure-setup-e2e-client >/dev/null
d network connect "$prv" "$cli"
d cp "$bin" "$srv:/usr/local/bin/secure-setup"
d exec "$cli" sh -c 'mkdir -p /root/.ssh && chmod 700 /root/.ssh && ssh-keygen -q -t ed25519 -N "" -f /root/.ssh/id_ed25519'
pubkey=$(d exec "$cli" cat /root/.ssh/id_ed25519.pub)
pubip=$(d inspect -f "{{(index .NetworkSettings.Networks \"$pub\").IPAddress}}" "$srv")
prvip=$(d inspect -f "{{(index .NetworkSettings.Networks \"$prv\").IPAddress}}" "$srv")
cliprv=$(d inspect -f "{{(index .NetworkSettings.Networks \"$prv\").IPAddress}}" "$cli")
echo "   server public $pubip (eth0), private $prvip (eth1)"
for i in $(seq 1 30); do
	if d exec "$srv" systemctl is-active --quiet ssh 2>/dev/null; then break; fi
	sleep 1
done
d exec "$srv" systemctl is-active --quiet ssh || fail "sshd did not start in the server container"
login() { d exec "$cli" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR -i /root/.ssh/id_ed25519 "root@$1" "$2"; }

plan() {
	d exec -i "$srv" sh -c "cat > $1" <<JSON
{
  "local": true,
  "update_system": false,
  "reboot": false,
  "tailscale": {"admin_interface": "eth1", "udp_port": 41641, "use_existing_network": true, "admin_address": "$prvip"},
  "firewall": {"web_ports": [443], "allow_ping": true, "tailnet_ports": [22, 8080], "rollback_seconds": 30, "cloudflare_sync": true, "confirm_by": "$2"},
  "ssh": {"harden": true, "add_local_key": true}
}
JSON
}

echo "== run 0: hardening must be skipped without an authorized key (nothing to log in with)"
plan /root/plan-login.json login
d exec -d "$srv" sh -c 'secure-setup here -f /root/plan-login.json --yes > /root/run0.log 2>&1; echo "EXIT=$?" >> /root/run0.log'
wait_log /root/run0.log "Now prove the new rules" 60
d exec "$srv" grep -q "Harden SSH (keys only): skipped (no usable public key" /root/run0.log || { d exec "$srv" cat /root/run0.log; fail "hardening not skipped"; }
echo "   hardening skipped as expected; letting it roll back (no login)"
wait_log /root/run0.log "EXIT=" 70
d exec "$srv" grep -q "rolled back to its previous rules" /root/run0.log || { d exec "$srv" cat /root/run0.log; fail "run 0 did not report the rollback"; }
d exec "$srv" grep -q "EXIT=1" /root/run0.log || fail "run 0 should exit 1"
d exec "$srv" nft list table inet secure_setup >/dev/null 2>&1 && fail "table present after rollback with no previous state" || echo "   rolled back: table removed, public ssh open"
d exec "$cli" nc -z -w 5 "$pubip" 22 || fail "public ssh not open after rollback"

echo "== install the client's key on the server"
d exec "$srv" sh -c "mkdir -p /root/.ssh && printf '%s\n' '$pubkey' > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"
login "$pubip" true || fail "key login over public address failed before the run"

echo "== run 1: confirm by a login over the private network"
d exec -d "$srv" sh -c 'SSH_CONNECTION="10.250.100.3 50000 '"$pubip"' 22" secure-setup here -f /root/plan-login.json --yes > /root/run1.log 2>&1; echo "EXIT=$?" >> /root/run1.log'
wait_log /root/run1.log "Now prove the new rules" 90
d exec "$srv" grep -q "this SSH session: 10.250.100.3 -> $pubip over eth0 (the public interface)" /root/run1.log || { d exec "$srv" grep "SSH session" /root/run1.log; fail "session note missing"; }
sleep 2
if d exec "$cli" nc -z -w 3 "$pubip" 22; then fail "public ssh still open while confirmation pending"; fi
echo "   rules live, public ssh blocked; logging in over the private network"
login "$prvip" "echo hello-from-client" | grep -q hello-from-client || fail "private login failed"
wait_log /root/run1.log "EXIT=" 60
d exec "$srv" grep -Eq "new SSH session from .* through the eth1 rule: the rules let you in|sshd accepted a login by root from $cliprv after the rules went live" /root/run1.log || { d exec "$srv" tail -30 /root/run1.log; fail "login not detected"; }
# Both lines need the eth1 rule's counter above zero; which one appears depends
# on whether a poll still saw the short session open.
d exec "$srv" grep -Eq "a connection arrived over eth1 through the new rule|new SSH session from .* through the eth1 rule" /root/run1.log || { d exec "$srv" tail -30 /root/run1.log; fail "rule counter did not register the login"; }
d exec "$srv" grep -q "This machine is locked down" /root/run1.log || { d exec "$srv" tail -30 /root/run1.log; fail "run 1 did not report success"; }
d exec "$srv" grep -q "EXIT=0" /root/run1.log || fail "run 1 should exit 0"

echo "== assertions after run 1"
if d exec "$cli" nc -z -w 5 "$pubip" 22; then fail "public ssh still open"; else echo "   public ssh blocked"; fi
login "$prvip" true && echo "   private ssh open"
d exec "$srv" nft list chain inet secure_setup input | grep -Eq 'iifname "eth1" tcp dport \{ 22, 8080 \} counter packets [0-9]+ bytes [0-9]+ accept' && echo "   tailnet rule present"
d exec "$srv" nft list set inet secure_setup cloudflare_v4 | grep -q '173.245.48.0/20' && echo "   cloudflare set populated"
d exec "$srv" sh -c 'systemctl is-enabled nftables' | grep -q enabled && echo "   nftables.service enabled"
d exec "$srv" systemctl is-active --quiet secure-setup-cloudflare-sync.timer && echo "   cloudflare sync timer active"
d exec "$srv" systemctl is-active --quiet secure-setup-rollback.timer && fail "rollback timer still armed" || echo "   rollback timer cancelled"
d exec "$srv" sh -c 'sshd -T | grep -q "^passwordauthentication no"' && echo "   sshd password auth off"
d exec "$srv" grep -q 'Managed by secure-setup' /etc/nftables.conf && echo "   /etc/nftables.conf persisted"
d exec "$srv" test -f /var/lib/secure-setup/confirm-expect && fail "confirm-expect left behind" || echo "   confirm markers cleaned"
d exec "$srv" grep -q 'Confirmed by.*login from' /root/run1.log && echo "   summary names the confirming login"

echo "== run 2: a session from BEFORE the apply must not count; \`secure-setup confirm\` in it must"
# ControlMaster: one TCP connection opened before the apply, reused for the
# confirm command, so no new session appears to the automatic detection.
d exec -d "$cli" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i /root/.ssh/id_ed25519 -M -S /tmp/cm -N "root@$prvip"
for i in $(seq 1 10); do d exec "$cli" ssh -S /tmp/cm -O check "root@$prvip" >/dev/null 2>&1 && break; sleep 1; done
d exec "$cli" ssh -S /tmp/cm -O check "root@$prvip" >/dev/null 2>&1 || fail "control master did not come up"
d exec -d "$srv" sh -c 'secure-setup here -f /root/plan-login.json --yes > /root/run2.log 2>&1; echo "EXIT=$?" >> /root/run2.log'
wait_log /root/run2.log "Now prove the new rules" 90
sleep 7
d exec "$srv" grep -q "EXIT=" /root/run2.log && { d exec "$srv" tail -20 /root/run2.log; fail "the old session was counted as a confirmation"; }
d exec "$srv" test -f /var/lib/secure-setup/confirm-expect || fail "confirm-expect missing while waiting"
echo "   old session correctly ignored"
out=$(d exec "$srv" sh -c "SSH_CONNECTION='10.250.100.3 50001 $pubip 22' secure-setup confirm 2>&1 || true")
echo "$out" | grep -q "came in over $pubip, not $prvip" || fail "confirm accepted a public-address session: $out"
echo "   confirm refused a session over the public address"
d exec "$cli" ssh -S /tmp/cm "root@$prvip" secure-setup confirm | grep -q "confirmed: this session arrived over $prvip" || fail "secure-setup confirm failed in the private session"
wait_log /root/run2.log "EXIT=" 60
d exec "$cli" ssh -S /tmp/cm -O exit "root@$prvip" >/dev/null 2>&1 || true
d exec "$srv" grep -q 'confirmed by `secure-setup confirm`' /root/run2.log || { d exec "$srv" tail -20 /root/run2.log; fail "explicit confirm not honoured"; }
d exec "$srv" grep -q "EXIT=0" /root/run2.log || fail "run 2 should exit 0"
echo "   explicit confirm accepted"

echo "== run 3: self-check confirmation (unattended), no login at all"
plan /root/plan-self.json self
d exec "$srv" sh -c 'secure-setup here -f /root/plan-self.json --yes > /root/run3.log 2>&1; echo "EXIT=$?" >> /root/run3.log' || true
d exec "$srv" grep -q "EXIT=0" /root/run3.log || { d exec "$srv" tail -30 /root/run3.log; fail "run 3 failed"; }
d exec "$srv" grep -q "check: rule for eth1 loaded" /root/run3.log || fail "self-check missing"
d exec "$srv" grep -q "check: sshd listens on $prvip:22" /root/run3.log || fail "listener check missing"
d exec "$srv" grep -q "Confirmed by.*self-checks" /root/run3.log || fail "summary does not name self-checks"
d exec "$srv" systemctl is-active --quiet secure-setup-rollback.timer && fail "rollback timer still armed after self-confirm" || echo "   self-confirmed; timer cancelled"
if d exec "$cli" nc -z -w 5 "$pubip" 22; then fail "public ssh open after self-confirm"; else echo "   public ssh still blocked"; fi

echo "== run 4: apply -f with a local plan takes the same path"
d exec "$srv" sh -c 'secure-setup apply -f /root/plan-self.json --yes > /root/run4.log 2>&1; echo "EXIT=$?" >> /root/run4.log' || true
d exec "$srv" grep -q "EXIT=0" /root/run4.log || { d exec "$srv" tail -20 /root/run4.log; fail "apply with local plan failed"; }
echo "   ok"

echo "== run 5: the wizard (TUI) on the server, driven by expect, confirmed by a login"
d cp test/e2e/here-tui.exp "$srv:/root/here-tui.exp"
d exec -d -e E2E_PRIVATE_IP="$prvip" "$srv" sh -c 'HOME=/root TERM=xterm expect -f /root/here-tui.exp > /root/run5.log 2>&1; echo "EXIT=$?" >> /root/run5.log'
wait_log /root/run5.log "WALK: waiting for login" 120
sleep 2
login "$prvip" true || fail "private login during TUI run failed"
wait_log /root/run5.log "EXIT=" 90
d exec "$srv" grep -q "WALK: done screen" /root/run5.log || { d exec "$srv" tail -40 /root/run5.log; fail "TUI did not reach the done screen"; }
d exec "$srv" grep -q "EXIT=0" /root/run5.log || { d exec "$srv" tail -40 /root/run5.log; fail "TUI run failed"; }
d exec "$srv" grep -q '"confirm_by": "login"' /etc/secure-setup/plan.json || fail "TUI did not save the local plan"
d exec "$srv" grep -q '"local": true' /etc/secure-setup/plan.json || fail "saved plan is not marked local"
echo "   TUI walked all screens, saved /etc/secure-setup/plan.json, confirmed by login"

echo "== run 6: reboot at the end; the boot check reports after the restart"
d exec "$srv" sh -c 'sed "s/\"reboot\": false/\"reboot\": true/" /root/plan-self.json > /root/plan-reboot.json'
d exec "$srv" rm -f /var/log/secure-setup-bootcheck.log
d exec -d "$srv" sh -c 'secure-setup here -f /root/plan-reboot.json --yes > /root/run6.log 2>&1'
wait_log /root/run6.log "reboots in 15 seconds" 90
d exec "$srv" grep -q "This machine is locked down" /root/run6.log || fail "run 6 did not finish before the reboot"
wait_log /var/log/secure-setup-bootcheck.log "secure-setup: after the reboot" 240
d exec "$srv" grep -q "all checks passed" /var/log/secure-setup-bootcheck.log || { d exec "$srv" cat /var/log/secure-setup-bootcheck.log; fail "boot check found problems"; }
d exec "$srv" grep -q "all checks passed" /etc/motd.d/secure-setup || fail "login message missing"
d exec "$srv" systemctl is-enabled --quiet secure-setup-bootcheck.service && fail "boot check still enabled"
d exec "$srv" nft list table inet secure_setup >/dev/null || fail "rules not loaded after the reboot"
echo "   rebooted; the boot check passed, wrote the log and the login message, and disabled itself"

echo "== undo --here"
d exec "$srv" secure-setup undo --here --yes 2>&1 | sed 's/^/   /'
d exec "$srv" nft list table inet secure_setup >/dev/null 2>&1 && fail "table still present after undo" || echo "   table removed"
d exec "$cli" nc -z -w 5 "$pubip" 22 && echo "   public ssh open again"
d exec "$srv" test -f /etc/ssh/sshd_config.d/00-secure-setup.conf && fail "sshd drop-in still present" || echo "   sshd drop-in removed"

echo "== run 7: ctrl+c in the wizard while it waits for the login; it stays until the run has cleaned up"
d cp test/e2e/here-tui-abort.exp "$srv:/root/here-tui-abort.exp"
d exec -d -e E2E_PRIVATE_IP="$prvip" "$srv" sh -c 'HOME=/root TERM=xterm expect -f /root/here-tui-abort.exp > /root/run7.log 2>&1; echo "EXIT=$?" >> /root/run7.log'
wait_log /root/run7.log "EXIT=" 180
d exec "$srv" grep -q "WALK: cleanup ran" /root/run7.log || { d exec "$srv" tail -40 /root/run7.log; fail "the wizard did not wait for the cleanup"; }
d exec "$srv" grep -q "WALK: exit 130" /root/run7.log || { d exec "$srv" grep -a WALK /root/run7.log; fail "an aborted wizard should exit 130"; }
d exec "$srv" test -f /etc/ssh/sshd_config.d/00-secure-setup.conf && fail "sshd drop-in left behind after ctrl+c" || true
d exec "$srv" sh -c 'sshd -T | grep -q "^passwordauthentication yes"' || fail "password login not restored after ctrl+c"
echo "   the wizard waited: password login restored, exit 130"
for i in $(seq 1 90); do
	d exec "$srv" nft list table inet secure_setup >/dev/null 2>&1 || break
	sleep 1
done
d exec "$srv" nft list table inet secure_setup >/dev/null 2>&1 && fail "the rollback timer did not restore the firewall after ctrl+c" || echo "   the rollback timer restored the previous firewall"
echo
echo "E2E HERE PASSED"
