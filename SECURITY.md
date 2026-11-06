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
`~/.ssh/known_hosts` after you accepted a host key.

On the server it installs `nftables` and, unless you chose an existing private
network, Tailscale through `https://tailscale.com/install.sh`. Every file it
writes is listed in the README under "What ends up on the server". It never
removes your SSH keys, never changes your password, and leaves Tailscale
installed on `undo`.

## Lockout protection

Firewall rules are applied under a transient systemd timer that restores the
previous ruleset if secure-setup cannot confirm the new one within your chosen
window. From your machine the confirmation is a brand-new SSH connection over
the tailnet. On the server it is a new login from another device, detected as
a new session on the tailnet address or as a hit on the admin rule's packet
counter together with an "Accepted" line in sshd's journal; `secure-setup
confirm` in that session is the explicit form. In unattended mode (`here
--yes`) it is a self-check: admin rule loaded, sshd listening on the tailnet
address, Tailscale running and online, a tailnet peer answering a ping
through the new rules. Self-checks cannot see your tailnet ACL.
`test/e2e/run.sh` and `test/e2e/run-here.sh` exercise all of these paths,
including forced lockouts, and check that the server comes back.

## Threat model, in short

- The server is reachable by anyone on the internet before the run. The run
  itself happens over SSH with the credentials you provide; secure-setup does
  not weaken anything before the new rules are confirmed.
- Cloudflare's IP ranges are shared by every Cloudflare customer. Enable
  Authenticated Origin Pulls or use Cloudflare Tunnel if that matters to you.
- UDP 41641 is open to the world for direct Tailscale connections. That port
  only speaks authenticated WireGuard.
- Your existing SSH session survives the firewall change (conntrack). That is
  by design and does not weaken the result; the final step proves a fresh
  connection to the public port is blocked.
