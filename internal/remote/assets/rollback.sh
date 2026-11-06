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
date -u +%Y-%m-%dT%H:%M:%SZ > "$STATE/rolled-back"
echo "secure-setup: $msg"
logger -t secure-setup "$msg: the new rules were not confirmed in time" 2>/dev/null || true
