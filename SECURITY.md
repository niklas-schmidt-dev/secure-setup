# Security

secure-setup rewrites the firewall and the SSH daemon configuration of a
server you point it at. Read this before trusting it with a machine you care
about.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(Security tab, "Report a vulnerability"). Please do not open a public issue
for anything that could lock people out of their servers or let others in.

## What the tool does, and does not do

It is a single static binary, run either on your machine or on the server
(`secure-setup here`). It makes outbound connections to:

- the server you name, over SSH (when run from your machine)
- `www.cloudflare.com`, to fetch the published IP ranges
- `github.com`, only through `install.sh`, to download a release

It sends no telemetry and writes only the plan (never secrets) to
`~/.config/secure-setup/<host>.json` or `/etc/secure-setup/plan.json`, and
`~/.ssh/known_hosts` after you accepted a host key. Only a host with no
entry in known_hosts counts as a first contact (which `--yes` accepts); a
different, revoked or certificate key, or a known_hosts file that cannot be
parsed, is refused before any credential is sent.

On the server it installs `nftables` and, unless you chose an existing private
network, Tailscale through `https://tailscale.com/install.sh`. Every file it
writes is listed in the README under "What ends up on the server". It never
removes your SSH keys, never changes your password, and leaves Tailscale
installed on `undo`.

## Lockout protection

Firewall rules are applied under a transient systemd timer that restores the
previous ruleset if secure-setup cannot confirm the new one within your chosen
window. From your machine the confirmation is a brand-new SSH connection over
the tailnet. On the server it is a new login from another device: the admin
rule's packet counter must move, and then either a session from a machine
other than this one is visible on the tailnet address, or sshd (journal
entries with _UID=0) logged an accepted login; `secure-setup confirm` in that
session is the explicit form. In unattended mode (`here --yes`) it is a
self-check: admin rule loaded, a root-owned sshd socket on the tailnet
address, Tailscale running and online, and an optional ping to a tailnet
peer. Self-checks cannot see your tailnet ACL. The host firewall that was
running before (ufw, firewalld) is stopped only under the same timer, stays
enabled at boot until the confirmation, and comes back with a rollback. The
rules are kept only when `nftables.service` loads a file that includes them.
`test/e2e/run.sh` and `test/e2e/run-here.sh` exercise all of these paths,
including forced lockouts, and check that the server comes back.

## Threat model, in short

- The server is reachable by anyone on the internet before the run, and stays
  so if the run fails, including the unattended first-boot path. The run
  itself happens over SSH with the credentials you provide.
- A login link is completed by whoever opens it. Over SSH, a server that
  joined through one must be reachable from your computer over the tailnet,
  or it logs out again; on the server, you confirm the tailnet's name. Only
  then is Tailscale SSH switched on. Unattended runs refuse the login link.
- Secrets written to the server (the Tailscale auth key) are created mode
  0600 in a 0700 directory before any byte is written. Text the server
  returns is stripped of terminal control characters before it is shown.
- Cloudflare's IP ranges are shared by every Cloudflare customer. Enable
  Authenticated Origin Pulls or use Cloudflare Tunnel if that matters to you.
- UDP 41641 is open to the world for direct Tailscale connections. That port
  only speaks authenticated WireGuard.
- Your existing SSH session survives the firewall change (conntrack). That is
  by design and does not weaken the result; the final step proves a fresh
  connection to the public port is blocked.
