# secure-setup

One command that turns a fresh Linux server into one only you can reach.

Run it on the server:

```
curl -fsSL https://raw.githubusercontent.com/niklas-schmidt-dev/secure-setup/main/install.sh | sh -s -- here
```

or on your computer, pointing it at the server:

```
sh -c "$(curl -fsSL https://raw.githubusercontent.com/niklas-schmidt-dev/secure-setup/main/install.sh)"
```

Either way the guided wizard:

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

The install script downloads the release for your OS and architecture from
GitHub Releases, checks its SHA-256 against `checksums.txt`, puts one static
binary in `/usr/local/bin` (as root) or `~/.local/bin`, and runs it with the
arguments you pass. Read it first if you like: it is about 110 lines of POSIX
sh. Knobs: `SECURE_SETUP_NO_RUN=1` installs without starting anything,
`SECURE_SETUP_VERSION=v0.2.0` pins a release, `SECURE_SETUP_INSTALL_DIR`
picks another directory.

**On the server** (as root, in your first SSH session):

```
curl -fsSL https://raw.githubusercontent.com/niklas-schmidt-dev/secure-setup/main/install.sh | sh -s -- here
```

**On your computer**, to set a server up over SSH:

```
sh -c "$(curl -fsSL https://raw.githubusercontent.com/niklas-schmidt-dev/secure-setup/main/install.sh)"
```

**Unattended at first boot**, so the server is never reachable from the
internet at all: see [examples/cloud-init.yaml](examples/cloud-init.yaml).
With a Tailscale auth key it is one line of user data:

```
TS_AUTHKEY=tskey-auth-... sh -c "$(curl -fsSL https://raw.githubusercontent.com/niklas-schmidt-dev/secure-setup/main/install.sh)" -- here --yes
```

Other ways:

```
go install github.com/niklas-schmidt-dev/secure-setup@latest   # needs Go 1.27+
```

or download an archive from the Releases page. Windows: use WSL.

Other ways: `go install github.com/niklas-schmidt-dev/secure-setup@latest`
(Go 1.27+), or an archive from the Releases page. Windows: use WSL.

## Use

On the server itself:

```
secure-setup here                  guided setup of this machine (TUI)
secure-setup here --yes            no questions: defaults, confirmed by self-checks
secure-setup here -f plan.json     run a saved plan on this machine
secure-setup confirm               in a new tailnet session: confirm a waiting setup
secure-setup undo --here           remove it from this machine again
```

From your computer:

```
secure-setup                       guided setup of a server over SSH (TUI)
secure-setup apply -f plan.json    replay a saved plan, no questions asked with --yes
secure-setup undo --host ADDR      remove the firewall, timers and sshd change again
secure-setup render -f plan.json   print the nftables ruleset a plan produces
```

The wizard saves its answers (without secrets) to
`~/.config/secure-setup/<host>.json`, or `/etc/secure-setup/plan.json` on the
server. Replaying that file sets up the next server the same way:

```
TS_AUTHKEY=tskey-auth-... secure-setup apply -f ~/.config/secure-setup/vps.json --yes
```

Secrets come from the environment in non-interactive mode:
`SECURE_SETUP_PASSWORD`, `SECURE_SETUP_PASSPHRASE`, `TS_AUTHKEY`.

### On the server or from your computer?

Both do the same work and both are protected by the rollback timer. They
differ in who proves that the new rules let you in:

- **From your computer**, secure-setup opens a brand-new SSH connection over
  the tailnet after the rules go live, and afterwards proves from the outside
  that the public port is closed. Your key is installed and tested before
  password login is turned off. The strongest proof, and nothing to type on
  the server.
- **On the server** (`here`), it asks you to log in once more from another
  device over the tailnet while the timer runs. That login is detected (a new
  session on the tailnet address, the rule's packet counter plus sshd's
  journal) and confirms the rules; with Tailscale SSH, run
  `secure-setup confirm` in the new session. Password login is only turned
  off when a public key is already authorized or Tailscale SSH is on. It
  cannot test its own public port from inside, so do that once from outside:
  `nc -zv <public ip> 22` must fail.
- **Unattended** (`here --yes`, cloud-init), nobody can log in during the
  run, so it confirms itself: the admin rule is loaded, sshd listens on the
  tailnet address, Tailscale is running and online, and an online tailnet peer
  answers a `tailscale ping` through the new rules. What it cannot see is your
  tailnet ACL. If that blocks SSH to the new node, fix the ACL; the server is
  intact and the provider console remains the back door.

## What ends up on the server

| Path | Purpose |
|---|---|
| `/etc/nftables.conf` | the ruleset, loaded by `nftables.service` at boot (a previous file is kept as `.secure-setup.bak`) |
| `/etc/secure-setup/cloudflare.nft` | Cloudflare IPv4 and IPv6 ranges, included by the ruleset |
| `/usr/local/sbin/secure-setup-cloudflare-sync` | refreshes the ranges; run daily by `secure-setup-cloudflare-sync.timer` |
| `/etc/ssh/sshd_config.d/00-secure-setup.conf` | password login off, root login with keys only |
| `/var/lib/secure-setup/` | rollback script and the previous ruleset; `rolled-back` appears if a rollback ever fired |
| `/etc/secure-setup/plan.json` | the answers of a `here` run, for `secure-setup here -f` next time |

ufw or firewalld, when active, are disabled: nftables takes over.

The ruleset in words:

- inbound default: drop
- loopback, established and related connections, the ICMP types networks need, DHCP replies: accept
- ping: accept with a rate limit (optional)
- UDP 41641 from anywhere: accept (direct Tailscale connections; authenticated WireGuard)
- SSH and any extra ports you chose, only on `tailscale0`: accept (with a counter: `nft list chain inet secure_setup input` shows how many connections came in this way)
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
   the old connection would survive anyway as an established flow. (On the
   server, it waits for your login from another device instead, or runs the
   self-checks in unattended mode.)
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
go test ./...                    unit tests (ruleset generator, parsers, plan, sessions)
scripts/validate-ruleset.sh      rulesets and scripts against a real nft binary (Docker)
test/e2e/run.sh                  full run from a client container against a throwaway systemd server (Docker)
test/e2e/run-here.sh             full run of `here` inside that server: login, confirm, self-check, rollback, TUI, undo
```

The end-to-end tests build a Debian container with systemd and sshd on two
networks (a "public" and a "private" one standing in for the tailnet), lock
it down, prove the public port is closed, force a lockout to watch the
rollback fire, and run `undo`. Docker commands use `DOCKER_CONTEXT` (default
`nas-docker`). The e2e networks use `10.250.100.0/24` and `10.250.101.0/24`;
override with `E2E_SUBNET_PUBLIC` and `E2E_SUBNET_PRIVATE`. Build the images
first:

```
docker build -t secure-setup-e2e-server -f test/e2e/Dockerfile.server test/e2e
docker build -t secure-setup-e2e-client -f test/e2e/Dockerfile.client test/e2e
```

Layout:

```
main.go                 commands: wizard, here, confirm, apply, render, undo
internal/tui            the wizard (bubbletea + huh)
internal/textui         plain-text reporter and prompts for apply/undo
internal/runner         the steps: over SSH (runner.go) and on the machine itself (here.go)
internal/remote         what runs on the server, with the embedded scripts and units
internal/localhost      runs those steps on this machine (`here`)
internal/sshx           SSH client: keys, agent, password, known_hosts
internal/nftgen         nftables ruleset template and renderer
internal/cloudflare     fetches and validates Cloudflare's ranges
internal/plan           the plan file
```
