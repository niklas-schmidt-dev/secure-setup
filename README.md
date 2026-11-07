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

1. updates the system packages first (`apt-get upgrade`, `dnf upgrade`, ...;
   the wizard asks, yes by default, and says when a reboot is needed)
2. installs Tailscale and joins your tailnet (auth key or login link; after a
   login link it checks that the tailnet is yours before going on)
3. switches SSH to keys only, after installing and verifying your key
4. installs an nftables firewall: SSH only over the tailnet, HTTPS only from
   Cloudflare's published ranges (or, for stronger protection, no web port at
   all behind a Cloudflare Tunnel), everything else dropped
5. applies the rules with a rollback timer, confirms them over a fresh
   tailnet connection, and only then makes them permanent
6. verifies from your machine that a new connection to the public SSH port is
   blocked
7. reboots and checks that everything came back on its own: rules loaded,
   nftables enabled at boot, Tailscale running, sshd keys only, public SSH
   still blocked (the wizard asks, yes by default; `"reboot": false` in a
   plan skips it)

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

**Unattended at first boot**: see [examples/cloud-init.yaml](examples/cloud-init.yaml).
It runs as soon as cloud-init reaches its final stage and needs a Tailscale
auth key: an unattended run refuses the login link, because nobody is there
to open it and anyone who reads the pending link could claim the server. Until the new rules are live (a few minutes) the server is as
reachable as the provider image makes it, and if the run fails it stays
that way, so check `/var/log/secure-setup-firstboot.log` or test the public
port from outside before you rely on it. Pair it with a provider firewall
if the server must never be reachable at all.

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
server. Replaying that file sets up the next server the same way. The
internet interface is detected on each server and not saved; a
`wan_interface` you put in a plan must exist on the target, and if it differs
from the interface of the default route the run stops unless the plan also
sets `"wan_interface_override": true`:

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
  device over the tailnet while the timer runs. Only a connection that came
  in through the new admin rule counts (its packet counter must move), from
  a machine other than this one, either as a visible session or as an
  "Accepted" line sshd itself wrote to the journal; with Tailscale SSH, run
  `secure-setup confirm` in the new session. Password login is only turned
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

## What ends up on the server

| Path | Purpose |
|---|---|
| `/etc/nftables.conf` | the ruleset, loaded by `nftables.service` at boot (a previous file is kept as `.secure-setup.bak`); where the unit loads another file, such as `/etc/sysconfig/nftables.conf` on Fedora and RHEL, that file gets an `include` of it. A system whose `nftables.service` loads no file is refused before any rule goes live |
| `/etc/secure-setup/cloudflare.nft` | Cloudflare IPv4 and IPv6 ranges, included by the ruleset |
| `/usr/local/sbin/secure-setup-cloudflare-sync` | refreshes the ranges; run daily by `secure-setup-cloudflare-sync.timer` |
| `/etc/ssh/sshd_config.d/00-secure-setup.conf` | password login off, root login with keys only |
| `/var/lib/secure-setup/` | rollback script and the previous ruleset; `rolled-back` appears if a rollback ever fired |
| `/etc/secure-setup/plan.json` | the answers of a `here` run, for `secure-setup here -f` next time |
| `secure-setup-bootcheck.service` | after a `here` run's reboot: checks the lockdown once, writes `/var/log/secure-setup-bootcheck.log` and `/etc/motd.d/secure-setup` (shown at login), then disables itself |

ufw or firewalld, when active, keep running until the new rules go live under
the rollback timer; a rollback starts them again. ufw's rules are only
stopped then (`ufw-init stop`), so it stays enabled at boot until the
confirmation. Only after confirmation is ufw disabled and firewalld disabled
and masked (also when it was enabled at
boot but not running, so it cannot replace the rules at the next boot).
sshd hardening never loosens a stricter `PermitRootLogin` (`no`,
`forced-commands-only`), and is reverted when sshd's effective policy, Match
blocks included, still allows passwords.

The ruleset in words:

- inbound default: drop
- loopback, established and related connections, the ICMP types networks need, DHCP replies: accept
- ping: accept with a rate limit (optional)
- UDP 41641 from anywhere: accept (direct Tailscale connections; authenticated WireGuard)
- SSH and any extra ports you chose, only on `tailscale0`: accept (with a counter: `nft list chain inet secure_setup input` shows how many connections came in this way)
- TCP 443 (and 80 if chosen), only from Cloudflare's ranges: accept
- forwarded traffic (Docker, VMs): allowed from inside, allowed from the internet only through Cloudflare on the web ports. "The internet" is every interface with a default route, IPv4 or IPv6, and every network card with a public address, such as a second public NIC without a default route; traffic arriving on anything else (Docker and VM bridges, VPN and tunnel devices, private networks) counts as inside
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
- **Web traffic, two levels**:
  - *Cloudflare's IP ranges* (default): TCP 443 (and 80 if chosen) is open
    only to Cloudflare. Cloudflare must proxy your DNS record (orange cloud);
    set the SSL mode to Full (strict). The ranges are shared by every
    Cloudflare customer, so consider Authenticated Origin Pulls so only your
    zone's traffic reaches the origin.
  - *Cloudflare Tunnel* (stronger protection): no web port is opened at all.
    cloudflared connects out to Cloudflare and brings your traffic in through
    that connection. Create a tunnel in the Cloudflare dashboard (Networks >
    Tunnels), route your hostname to the local service there (for example
    `http://localhost:8080`), and give secure-setup the token from its
    install command: in the wizard, or as `CLOUDFLARE_TUNNEL_TOKEN` with
    `"cloudflare_tunnel": true` in a plan. secure-setup installs cloudflared
    from Cloudflare's package repository, keeps the token in
    `/etc/secure-setup/cloudflared.token` (mode 0600, read with
    `--token-file`, never on a command line) and runs
    `secure-setup-cloudflared.service`. The run only goes on to the firewall
    once the tunnel is connected, and the reboot check expects it to
    reconnect.
- **Docker**: containers can reach out as usual. Published ports are reachable
  from the tailnet and, from the internet, only through Cloudflare on the web
  ports. Docker's own iptables rules stay; both rulesets must accept a packet.
- **Tailscale SSH** (optional): logs you in with your tailnet identity instead
  of keys. While it is on, tailscaled answers port 22 on the tailnet address
  instead of sshd, so logins there follow your tailnet policy. It is switched
  on with `tailscale set --ssh` only once the tailnet is known to be yours.
  From your computer it is the last step, after every check against sshd,
  and a fresh login through it must work (a browser check your policy asks
  for is shown); otherwise it is switched off again and sshd with your key
  stays in charge. On a rerun it is paused during the run.
- **Non-Tailscale private networks**: set `use_existing_network`,
  `admin_address` and `admin_interface` in the plan file to use a provider
  private network or a WireGuard peer instead. Tailscale is then not installed.
- **Undo** restores the old state but leaves Tailscale installed. It
  re-enables a ufw that secure-setup retired and unmasks firewalld (start it
  again yourself, it conflicts with `nftables.service`).
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
