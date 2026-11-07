# Configuration and server reference

[Back to the README](../README.md) · [Networking](networking.md) · [Recovery](recovery.md)

## Saved plans

The wizard saves its answers (without secrets) to
`~/.config/secure-setup/<host>.json`, or `/etc/secure-setup/plan.json` on the
server. Edit the target address before replaying a remote plan on another
server. The internet interface is detected on each server and not saved; a
`wan_interface` you put in a plan must exist on the target, and if it differs
from the interface of the default route the run stops unless the plan also
sets `"wan_interface_override": true`. Further internet-facing interfaces
that detection cannot recognise go into `extra_wan_interfaces` (see
[Docker and forwarded traffic](networking.md#docker-and-forwarded-traffic)).
Replay a saved plan with:

```sh
secure-setup apply -f ~/.config/secure-setup/vps.json --yes
```

Secrets come from the environment in non-interactive mode:
`SECURE_SETUP_PASSWORD`, `SECURE_SETUP_PASSPHRASE`, `TS_AUTHKEY`,
`CLOUDFLARE_TUNNEL_TOKEN`. Set these in the process environment; do not put
secrets in saved plans or commit them to the repository.

### Plan defaults and confirmation

The default plan enables package updates, a final reboot, SSH hardening,
HTTPS from Cloudflare, rate-limited ping and daily Cloudflare range refresh.
SSH uses `tailscale0`; Tailscale SSH is opt-in. The default rollback window
is 120 seconds. The wizard offers 60, 120 and 300 seconds; a saved plan can
specify 30–900 seconds.

`secure-setup apply -f plan.json` prompts before applying. Add `--yes` for
unattended use; on a remote run it also accepts first-seen SSH host keys.
Changed, revoked, certificate or unparseable known host keys are refused
before credentials are sent. Remote runs still verify a fresh private
connection; `--yes` does not replace that with local self-checks.

On the server, `secure-setup here -f plan.json` applies the local plan.
`here --yes` uses self-checks by default. A plan's `firewall.confirm_by` or
the `--confirm login|self` flag can choose the local confirmation mode
explicitly. `--no-tui` uses plain text. See [the confirmation requirements](recovery.md#how-access-is-confirmed)
before choosing unattended setup.

Set `"update_system": false` or `"reboot": false` in a saved plan to skip
those steps. `cloudflare_tunnel` replaces `web_ports`: leave `web_ports`
empty when enabling a tunnel. The token comes from the environment or the
wizard, not from the JSON file.

## What ends up on the server

| Path | Purpose |
|---|---|
| `/etc/nftables.conf` | the ruleset, loaded by `nftables.service` at boot (a previous file is kept as `.secure-setup.bak`); where the unit loads another file, such as `/etc/sysconfig/nftables.conf` on Fedora and RHEL, that file gets an `include` of it. A system whose `nftables.service` loads no file is refused before any rule goes live |
| `/etc/secure-setup/cloudflare.nft` | Cloudflare IPv4 and IPv6 ranges, included by the ruleset |
| `/usr/local/sbin/secure-setup-cloudflare-sync` | refreshes the ranges; run daily by `secure-setup-cloudflare-sync.timer` |
| `/etc/ssh/sshd_config.d/00-secure-setup.conf` | password login off, root login with keys only |
| `/var/lib/secure-setup/` | rollback script and the previous ruleset; `decided` once the confirmation or the rollback timer claimed an apply's outcome; `rolled-back` appears if a rollback ever fired |
| `/etc/secure-setup/plan.json` | the answers of a `here` run, for `secure-setup here -f` next time |
| `/etc/secure-setup/cloudflared.token` | optional Cloudflare Tunnel token, mode 0600, read by cloudflared through `--token-file` |
| `secure-setup-cloudflared.service` | optional outbound tunnel; connects before the firewall is applied and is checked again after reboot |
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

## Supported platforms

| Component | Requirements |
| --- | --- |
| Server | Linux with systemd and apt-get, dnf, yum, pacman or zypper; root or passwordless sudo. |
| Release binaries | Linux and macOS, amd64 and arm64. On Windows use WSL with working private-network connectivity. |
| Source build | The Go version in [go.mod](https://github.com/niklas-schmidt-dev/secure-setup/blob/main/go.mod). |
| E2E test environment | A disposable Debian systemd server with public/private test networks. |

The package-manager paths cover distributions such as Debian, Ubuntu,
Fedora, Rocky, Alma, Arch and openSUSE. Setup is independent of the VPS or
cloud provider, but this is not a claim that every image or provider is
tested. For Cloudflare Tunnel, automatic cloudflared installation supports
apt-get, dnf, yum and pacman; on other systems, install cloudflared first.

## Installer options

| Variable | Effect |
| --- | --- |
| `SECURE_SETUP_NO_RUN=1` | Install the binary without starting the wizard. |
| `SECURE_SETUP_VERSION` | Pin a release tag; the default is the latest release. |
| `SECURE_SETUP_INSTALL_DIR` | Override `/usr/local/bin` for root or `~/.local/bin` otherwise. |
| `SECURE_SETUP_NO_PROVENANCE=1` | Explicitly skip signed provenance verification, including for releases through v0.4.0. |

The installer checks SHA-256 for each archive. A compatible GitHub CLI is
also required for its provenance check; the installer reports when that
check did not run. See [installation details](../README.md#installation-details)
for the trust distinction and manual verification.
