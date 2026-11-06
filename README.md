# secure-setup

One command that turns a fresh Linux server into one only you can reach.

```
secure-setup
```

The guided wizard connects to the server over its public address once, then:

1. installs Tailscale and joins your tailnet (auth key or login link)
2. switches SSH to keys only, after installing and verifying your key
3. installs an nftables firewall: SSH only over the tailnet, HTTPS only from
   Cloudflare's published ranges, everything else dropped
4. applies the rules with a rollback timer, confirms them over a fresh
   tailnet connection, and only then makes them permanent
5. verifies from your machine that a new connection to the public SSH port is
   blocked

If the new rules cannot be confirmed in time (typo in an interface name, tailnet
down, anything), the server restores its previous firewall by itself. You are
never locked out.

Works on any VPS or cloud machine running a systemd distribution with
apt, dnf, yum, pacman or zypper: Hetzner, DigitalOcean, Vultr, Linode, OVH,
AWS, GCP and so on. Debian, Ubuntu, Fedora, Rocky, Alma, Arch and openSUSE.

## Install

One command on your Mac or Linux machine (not on the server). It installs the
tool and starts the wizard:

```
sh -c "$(curl -fsSL https://raw.githubusercontent.com/niklas-schmidt-dev/secure-setup/main/install.sh)"
```

The script downloads the release for your OS and architecture from GitHub
Releases, checks its SHA-256 against `checksums.txt`, puts one static binary
in `~/.local/bin`, and runs it. Read it first if you like: it is about 100 lines
of POSIX sh. Knobs: `SECURE_SETUP_NO_RUN=1` installs without starting the
wizard, `SECURE_SETUP_VERSION=v0.1.0` pins a release,
`SECURE_SETUP_INSTALL_DIR` picks another directory.

Other ways:

```
go install github.com/niklas-schmidt-dev/secure-setup@latest   # needs Go 1.27+
```

or download an archive from the Releases page. Windows: use WSL.

Your machine must be on the same tailnet as the server for the final checks
(the Tailscale app or `tailscale up`).

## Use

```
secure-setup                       guided setup (TUI)
secure-setup apply -f plan.json    replay a saved plan, no questions asked with --yes
secure-setup render -f plan.json   print the nftables ruleset a plan produces
secure-setup undo --host ADDR      remove the firewall, timers and sshd change again
```

The wizard saves its answers (without secrets) to `~/.config/secure-setup/<host>.json`.
Replaying that file sets up the next server the same way:

```
TS_AUTHKEY=tskey-auth-... secure-setup apply -f ~/.config/secure-setup/vps.json --yes
```

Secrets come from the environment in non-interactive mode:
`SECURE_SETUP_PASSWORD`, `SECURE_SETUP_PASSPHRASE`, `TS_AUTHKEY`.

## What ends up on the server

| Path | Purpose |
|---|---|
| `/etc/nftables.conf` | the ruleset, loaded by `nftables.service` at boot (a previous file is kept as `.secure-setup.bak`) |
| `/etc/secure-setup/cloudflare.nft` | Cloudflare IPv4 and IPv6 ranges, included by the ruleset |
| `/usr/local/sbin/secure-setup-cloudflare-sync` | refreshes the ranges; run daily by `secure-setup-cloudflare-sync.timer` |
| `/etc/ssh/sshd_config.d/00-secure-setup.conf` | password login off, root login with keys only |
| `/var/lib/secure-setup/` | rollback script and the previous ruleset; `rolled-back` appears if a rollback ever fired |

ufw or firewalld, when active, are disabled: nftables takes over.

The ruleset in words:

- inbound default: drop
- loopback, established and related connections, the ICMP types networks need, DHCP replies: accept
- ping: accept with a rate limit (optional)
- UDP 41641 from anywhere: accept (direct Tailscale connections; authenticated WireGuard)
- SSH and any extra ports you chose, only on `tailscale0`: accept
- TCP 443 (and 80 if chosen), only from Cloudflare's ranges: accept
- forwarded traffic (Docker, VMs): allowed from inside, allowed from the internet only through Cloudflare on the web ports
- outbound: allowed

See it for yourself before applying: `secure-setup render`.

## How the rollback works

1. The new ruleset is validated with `nft -c` and the current table is saved.
2. A transient systemd timer is armed: `secure-setup-rollback` fires after your
   chosen window (60 s to 5 min).
3. The rules are loaded atomically.
4. secure-setup opens a brand-new SSH connection over the tailnet. New, because
   the old connection would survive anyway as an established flow.
5. Over that connection it cancels the timer, persists the ruleset and enables
   the services.

If step 4 fails, the timer runs `/var/lib/secure-setup/rollback.sh`, which
restores the saved table (or removes the new one) and writes
`/var/lib/secure-setup/rolled-back`. secure-setup reports that and exits
non-zero. The server is in its previous state.

## Things worth knowing

- **Your existing SSH session stays up** while the firewall changes. That is
  conntrack keeping an established flow. A new connection to the public port
  is what gets blocked, and that is what the final step tests.
- **Web traffic**: Cloudflare must proxy your DNS record (orange cloud). Set the
  SSL mode to Full (strict) and consider Cloudflare's Authenticated Origin
  Pulls so only your zone's traffic, not any Cloudflare customer's, reaches the
  origin. Cloudflare Tunnel is an alternative that needs no open port at all.
- **Docker**: containers can reach out as usual. Published ports are reachable
  from the tailnet and, from the internet, only through Cloudflare on the web
  ports. Docker's own iptables rules stay; both rulesets must accept a packet.
- **Tailscale SSH** (optional): logs you in with your tailnet identity instead
  of keys. Your keys keep working too.
- **Non-Tailscale private networks**: set `use_existing_network`,
  `admin_address` and `admin_interface` in the plan file to use a provider
  private network or a WireGuard peer instead. Tailscale is then not installed.
- **Undo** restores the old state but leaves Tailscale installed.
- Debian's `nftables.service` flushes the ruleset when stopped. Reload with
  `nft -f /etc/nftables.conf`; do not stop the service on a live box.

## Development

```
go test ./...                    unit tests (ruleset generator, parsers, plan)
scripts/validate-ruleset.sh      rulesets and scripts against a real nft binary (Docker)
test/e2e/run.sh                  full run against a throwaway systemd server (Docker)
```

The end-to-end test builds a Debian container with systemd and sshd on two
networks, lets secure-setup lock it down over the "private" one, then proves
the public port is closed, forces a lockout to watch the rollback fire, and
runs `undo`. Docker commands use `DOCKER_CONTEXT` (default `nas-docker`).
The e2e networks use `10.250.100.0/24` and `10.250.101.0/24`; override with
`E2E_SUBNET_PUBLIC` and `E2E_SUBNET_PRIVATE`.

Layout:

```
main.go                 commands: wizard, apply, render, undo
internal/tui            the wizard (bubbletea + huh)
internal/textui         plain-text reporter and prompts for apply/undo
internal/runner         the steps, shared by both UIs
internal/remote         what runs on the server, with the embedded scripts and units
internal/sshx           SSH client: keys, agent, password, known_hosts
internal/nftgen         nftables ruleset template and renderer
internal/cloudflare     fetches and validates Cloudflare's ranges
internal/plan           the plan file
```
