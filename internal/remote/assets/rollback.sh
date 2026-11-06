#!/bin/sh
# secure-setup: restore the firewall state from before the last apply.
# Fired by the secure-setup-rollback timer when the new rules were not
# confirmed over the tailnet in time. Safe to run by hand.
set -u
STATE=/var/lib/secure-setup

if [ -s "$STATE/previous.nft" ] && nft -f "$STATE/previous.nft"; then
	msg="firewall rolled back to the previous state"
else
	nft delete table inet secure_setup 2>/dev/null || true
	msg="firewall table removed (no previous state to restore)"
fi
if [ -e "$STATE/ufw-was-active" ]; then
	# The apply only stopped ufw's rules (ufw-init stop); it is still enabled.
	ufw_init=; for p in /lib/ufw/ufw-init /usr/lib/ufw/ufw-init; do if [ -x "$p" ]; then ufw_init=$p; break; fi; done
	if [ -n "$ufw_init" ] && "$ufw_init" start >/dev/null 2>&1; then msg="$msg; ufw re-enabled"
	elif ufw --force enable >/dev/null 2>&1; then msg="$msg; ufw re-enabled"
	else msg="$msg; ufw could NOT be re-enabled"; fi
fi
if [ -e "$STATE/firewalld-was-active" ]; then
	if systemctl start firewalld >/dev/null 2>&1; then msg="$msg; firewalld restarted"; else msg="$msg; firewalld could NOT be restarted"; fi
fi
date -u +%Y-%m-%dT%H:%M:%SZ > "$STATE/rolled-back"
echo "secure-setup: $msg"
logger -t secure-setup "$msg: the new rules were not confirmed in time" 2>/dev/null || true
