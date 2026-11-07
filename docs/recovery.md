# Confirmation, rollback and recovery

[Back to the README](../README.md) · [Networking](networking.md) · [Reference](reference.md)

## How access is confirmed

Remote and server-local setup perform the same work under a rollback timer.
They differ in how they confirm that the new rules let you in:

- **From your computer**, secure-setup opens a brand-new SSH connection over
  the tailnet after the rules go live, and afterwards checks from the outside
  that a new connection to the public port is refused or times out; if it
  still succeeds, the run fails. If the run reached the server at its private
  address, or your computer cannot resolve or route the public address, the
  result says public SSH was not tested. Your key is installed and tested
  before password login is turned off. No separate server-side confirmation
  command is needed.
- **On the server** (`here`), it asks you to log in once more from another
  device over the tailnet while the timer runs. The new admin rule's packet
  counter must move, and sshd must write an "Accepted" line to the journal
  for a login from a machine other than this one, over a connection that
  opened after the rules went live. A TCP connection that never logs in does
  not count. With Tailscale SSH, run `secure-setup confirm` in the new
  session. Password login is only turned
  off when `authorized_keys` holds a key sshd would accept for your account
  (read as that account, no restricting options), or when this run turns
  Tailscale SSH on; if the run then fails or rolls back, password login is
  turned back on. It cannot test its own public port from inside, so do that
  once from outside: `nc -zv <public ip> 22` must fail.
- **Unattended** (`here --yes`, cloud-init), nobody can log in during the
  run, so it confirms itself: the admin rule is loaded, a root-owned sshd
  socket listens on the tailnet address, Tailscale is running and online, and
  an online tailnet peer, if there is one, answers a `tailscale ping`. The
  ping is an outbound probe; it does not exercise the admin rule. What it
  cannot see is your tailnet ACL. If that blocks SSH to the new node, fix the
  ACL; the server is intact and the provider console remains the back door.

The reboot at the end is the real test of what was made permanent. From your
computer secure-setup waits for the server to come back over the tailnet and
checks it again; on the server itself it cannot watch its own reboot, so a
one-shot service does the same checks after the boot and leaves the result in
the log and the login message. The rollback timer no longer covers this
step: if something did not come back, use the provider console.

## How rollback works

1. The new ruleset is validated with `nft -c` and the current table is saved.
2. A transient systemd timer is armed: `secure-setup-rollback` fires after your
   chosen window (60 s to 5 min).
3. The rules are loaded atomically.
4. secure-setup opens a brand-new SSH connection over the tailnet. New, because
   the old connection would survive anyway as an established flow. (On the
   server, it waits for your login from another device instead, or runs the
   self-checks in unattended mode.)
5. Over that connection it claims the outcome, cancels the timer, persists
   the ruleset and enables the services. The claim is an atomic `mkdir` that
   the timer's rollback makes too: whichever comes first decides. A
   confirmation that arrives after the rollback started fails as rolled back
   and leaves the rollback to finish.

If step 4 fails, the timer runs `/var/lib/secure-setup/rollback.sh`, which
restores the saved table (or removes the new one) and writes
`/var/lib/secure-setup/rolled-back`. secure-setup reports that and exits
non-zero. The previous firewall state is restored; this is not a rollback
of every change made during setup.

The wizard offers 60 seconds, 2 minutes or 5 minutes. A saved plan can
choose a window from 30 to 900 seconds. Package upgrades are not undone.
Once the confirmation cancels the timer, later failures—including boot
failures—need their own recovery path. If persisting the rules fails at that
point, the confirmed rules stay live, the run reports the error, and a host
firewall that was running before (ufw, firewalld) is still enabled for the
next boot.

## Check the result

From another machine, open a new private SSH connection using the address
shown by the wizard:

```sh
ssh YOUR_USER@YOUR_TAILNET_IP
```

Then test a new connection to public SSH:

```sh
nc -zv YOUR_PUBLIC_IP 22
```

Replace the placeholders and port. Private SSH must succeed and public SSH
must fail. A failure on the public port alone is not proof that your private
access works.

For `secure-setup here`, log in over the tailnet from another device while
the confirmation timer is running. With Tailscale SSH, explicitly confirm
from the new session:

```sh
secure-setup confirm
```

If sudo drops the session metadata, use:

```sh
sudo --preserve-env=SSH_CONNECTION secure-setup confirm
```

## When setup or a reboot fails

| Situation | What to inspect or do |
| --- | --- |
| The new private connection cannot be confirmed | Let the active rollback timer restore the previous firewall. Read the reported error before retrying. |
| A rollback was reported | `/var/lib/secure-setup/rolled-back` records that rollback fired. Confirm access and correct the plan before rerunning. |
| A local run rebooted the server | Inspect `/var/log/secure-setup-bootcheck.log` and the login message in `/etc/motd.d/secure-setup`. |
| Cloud-init failed or did not finish | Inspect `/var/log/secure-setup-firstboot.log` and test access from another machine. The server retains its provider-image exposure until setup succeeds. |
| Private SSH fails after reboot or unattended setup | Use the provider console to inspect Tailscale, sshd, nftables and the tailnet policy. Self-checks cannot validate your inbound ACL. |

Keep the provider console available. For first boot, combine setup with a
provider firewall when public access must be restricted before the installer
finishes. The reboot phase is outside the rollback window.

## Undo

From your computer, use the server's reachable private address:

```sh
secure-setup undo --host YOUR_TAILNET_IP --user YOUR_USER
```

On the server itself, as root or with passwordless sudo:

```sh
secure-setup undo --here
```

Both commands ask before continuing. Remote undo supports `--port` and
`--key` if your connection needs them. Undo removes secure-setup's firewall,
timers and SSH hardening changes and leaves Tailscale installed. It can make
the server publicly reachable again; review the prompt and the restored
policy before relying on it.

A retired ufw is re-enabled. firewalld is unmasked, but must be started
manually because it conflicts with `nftables.service`. Undo does not revert
package upgrades or remove every package installed by setup.
