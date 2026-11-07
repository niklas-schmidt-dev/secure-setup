// Package remote runs the server-side steps on a Host: an SSH connection
// (sshx.Client) or the machine itself (localhost.Host).
package remote

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// Host runs shell on the server. sshx.Client and localhost.Host implement it.
type Host interface {
	// Output runs cmd with /bin/sh and returns its trimmed stdout.
	Output(ctx context.Context, cmd string) (string, error)
	// Script runs a multi-line script with set -eu, streaming output lines.
	Script(ctx context.Context, script string, onLine func(string)) error
	// WriteFile writes data to path atomically with the given octal mode.
	WriteFile(ctx context.Context, path string, data []byte, mode string) error
}

// exitStatus returns the exit code of a failed Script, or -1.
func exitStatus(err error) int {
	var se *ssh.ExitError
	if errors.As(err, &se) {
		return se.ExitStatus()
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

//go:embed assets/*
var assets embed.FS

func asset(name string) string {
	data, err := assets.ReadFile("assets/" + name)
	if err != nil {
		panic("missing embedded asset " + name)
	}
	return string(data)
}

// Facts is what Detect learns about a server.
type Facts struct {
	ID         string
	IDLike     string
	Codename   string
	PrettyName string
	Hostname   string
	PkgMgr     string // apt-get, dnf, yum, pacman, zypper, apk or ""
	Systemd    bool
	NFT        bool
	SSHPort    int
	WANIface   string
	WANIfaces  []string // every device with a default route (IPv4 and IPv6), WANIface first
	PublicNICs []string // network cards with a public address, with or without a default route
	WANIPv4    string   // first IPv4 address on WANIface, when known
	Docker     bool

	Tailscale      bool   // CLI installed
	TailscaleState string // Running, NeedsLogin, Stopped, NoState, "" when not running
	TailscaleIPv4  string

	UFWActive        bool
	FirewalldActive  bool
	FirewalldEnabled bool   // enabled at boot, even if not running now
	SecureSetupTable bool   // our nftables table is already loaded
	RolledBack       string // timestamp of a previous rollback, if any
	RollbackArmed    bool   // a rollback timer from an earlier run is still active

	aptUpdated bool
}

const detectScript = `
if [ -r /etc/os-release ]; then . /etc/os-release; fi
printf 'ID=%s\n' "${ID:-}"
printf 'ID_LIKE=%s\n' "${ID_LIKE:-}"
printf 'CODENAME=%s\n' "${VERSION_CODENAME:-}"
printf 'PRETTY=%s\n' "${PRETTY_NAME:-}"
printf 'HOSTNAME=%s\n' "$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || true)"
if [ -d /run/systemd/system ]; then echo SYSTEMD=1; else echo SYSTEMD=0; fi
for m in apt-get dnf yum pacman zypper apk; do
	if command -v "$m" >/dev/null 2>&1; then printf 'PKG=%s\n' "$m"; break; fi
done
if command -v nft >/dev/null 2>&1; then echo NFT=1; else echo NFT=0; fi
if command -v tailscale >/dev/null 2>&1; then echo TAILSCALE=1; else echo TAILSCALE=0; fi
if command -v docker >/dev/null 2>&1; then echo DOCKER=1; else echo DOCKER=0; fi
sshd_bin=$(command -v sshd || echo /usr/sbin/sshd)
printf 'SSHPORT=%s\n' "$("$sshd_bin" -T 2>/dev/null | awk '$1=="port"{print $2; exit}')"
printf 'WAN=%s\n' "$(ip -o -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
printf 'WAN6=%s\n' "$(ip -o -6 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
printf 'WANS=%s\n' "$({ ip -o -4 route show default; ip -o -6 route show default; } 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); break}}' | tr '\n' ' ')"
wan=$(ip -o -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
if [ -n "$wan" ]; then printf 'WANIP=%s\n' "$(ip -o -4 addr show dev "$wan" 2>/dev/null | awk '{print $4; exit}' | cut -d/ -f1)"; fi
sysnet=/sys/class/net
` + onCardScript + `printf 'NICADDRS=%s\n' "$(ip -o addr show scope global 2>/dev/null | while read -r _ dev _ addr _; do dev=${dev%%@*}; if oncard "$dev" 0; then printf '%s %s ' "$dev" "$addr"; fi; done)"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then echo UFW=1; else echo UFW=0; fi
if systemctl is-active --quiet firewalld 2>/dev/null; then echo FIREWALLD=1; else echo FIREWALLD=0; fi
if systemctl is-enabled --quiet firewalld 2>/dev/null; then echo FIREWALLD_ENABLED=1; else echo FIREWALLD_ENABLED=0; fi
if command -v nft >/dev/null 2>&1 && nft list table inet secure_setup >/dev/null 2>&1; then echo SS_TABLE=1; else echo SS_TABLE=0; fi
if [ -f /var/lib/secure-setup/rolled-back ]; then printf 'ROLLED_BACK=%s\n' "$(cat /var/lib/secure-setup/rolled-back)"; fi
if systemctl is-active --quiet secure-setup-rollback.timer 2>/dev/null; then echo ROLLBACK_ARMED=1; fi
`

// onCardScript defines `oncard DEV DEPTH`: true when DEV is a network card
// (it has $sysnet/DEV/device) or sits on one, such as a VLAN, bond, bridge or
// macvlan over a card, followed through its lower_* links up to four levels.
// Docker and VM bridges sit on veth and tap devices, which are not cards.
const onCardScript = `oncard() {
	[ -e "$sysnet/$1/device" ] && return 0
	[ "$2" -lt 4 ] || return 1
	for l in "$sysnet/$1"/lower_*; do
		[ -e "$l" ] && oncard "${l##*/lower_}" $(($2 + 1)) && return 0
	done
	return 1
}
`

// detectKeys are the facts detectScript prints. Other lines are ignored, so
// a server cannot fill the map with keys of its own.
var detectKeys = []string{"ID", "ID_LIKE", "CODENAME", "PRETTY", "HOSTNAME", "SYSTEMD", "PKG", "NFT", "TAILSCALE", "DOCKER", "SSHPORT", "WAN", "WAN6", "WANS", "WANIP", "NICADDRS", "UFW", "FIREWALLD", "FIREWALLD_ENABLED", "SS_TABLE", "ROLLED_BACK", "ROLLBACK_ARMED"}

// Detect gathers Facts about the server. Their text is shown in the wizard's
// forms, so control characters are replaced (see Printable).
func Detect(ctx context.Context, c Host) (*Facts, error) {
	kv := map[string]string{}
	err := c.Script(ctx, detectScript, func(line string) {
		if k, v, ok := strings.Cut(line, "="); ok && slices.Contains(detectKeys, k) {
			kv[k] = Printable(v)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("detect server facts: %w", err)
	}
	f := &Facts{
		ID:               kv["ID"],
		IDLike:           kv["ID_LIKE"],
		Codename:         kv["CODENAME"],
		PrettyName:       kv["PRETTY"],
		Hostname:         kv["HOSTNAME"],
		PkgMgr:           kv["PKG"],
		Systemd:          kv["SYSTEMD"] == "1",
		NFT:              kv["NFT"] == "1",
		Tailscale:        kv["TAILSCALE"] == "1",
		Docker:           kv["DOCKER"] == "1",
		UFWActive:        kv["UFW"] == "1",
		FirewalldActive:  kv["FIREWALLD"] == "1",
		FirewalldEnabled: kv["FIREWALLD_ENABLED"] == "1",
		SecureSetupTable: kv["SS_TABLE"] == "1",
		RolledBack:       kv["ROLLED_BACK"],
		RollbackArmed:    kv["ROLLBACK_ARMED"] == "1",
		WANIface:         kv["WAN"],
		WANIPv4:          kv["WANIP"],
	}
	if f.WANIface == "" {
		f.WANIface = kv["WAN6"]
	}
	for _, n := range append([]string{f.WANIface}, strings.Fields(kv["WANS"])...) {
		if n != "" && !slices.Contains(f.WANIfaces, n) {
			f.WANIfaces = append(f.WANIfaces, n)
		}
	}
	f.PublicNICs = publicNICs(strings.Fields(kv["NICADDRS"]))
	if f.PrettyName == "" {
		f.PrettyName = "unknown Linux"
	}
	f.SSHPort, _ = strconv.Atoi(kv["SSHPORT"])
	if f.SSHPort == 0 {
		f.SSHPort = 22
	}
	if f.Tailscale {
		if st, err := TailscaleStatus(ctx, c); err == nil {
			f.TailscaleState = Printable(st.BackendState)
			for _, ip := range st.Self.TailscaleIPs {
				if !strings.Contains(ip, ":") {
					f.TailscaleIPv4 = Printable(ip)
					break
				}
			}
		}
	}
	return f, nil
}

// publicNICs picks the network cards that carry a public address from pairs
// of device and address (detect lists cards and the VLANs, bonds and bridges
// on top of them). A second uplink without a default route is still on the
// internet. Docker and VM bridges, veths, VPN and tunnel devices are not on a
// card, so container and VM traffic stays inside even on a public prefix.
func publicNICs(pairs []string) []string {
	var out []string
	for i := 0; i+1 < len(pairs); i += 2 {
		dev, addr := pairs[i], pairs[i+1]
		p, err := netip.ParsePrefix(addr)
		if err != nil || !publicAddr(p.Addr()) || slices.Contains(out, dev) {
			continue
		}
		out = append(out, dev)
	}
	return out
}

// Printable replaces control characters other than newline and tab, so text
// that came from the server cannot drive the operator's terminal.
func Printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || !unicode.IsControl(r) {
			return r
		}
		return '?'
	}, s)
}

// sharedSpace is 100.64.0.0/10: carrier-grade NAT, and Tailscale's IPv4 range.
var sharedSpace = netip.MustParsePrefix("100.64.0.0/10")

func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsGlobalUnicast() && !a.IsPrivate() && !sharedSpace.Contains(a)
}

// InstallPackages installs packages with the detected package manager.
// UpdateSystem installs pending package updates (apt-get upgrade, dnf
// upgrade, ...). It reports whether a reboot is needed to finish them.
func UpdateSystem(ctx context.Context, c Host, f *Facts, onLine func(string)) (reboot bool, err error) {
	var script string
	switch f.PkgMgr {
	case "apt-get":
		script = "export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a\napt-get update -q\n" +
			"apt-get upgrade -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
	case "dnf":
		script = "dnf upgrade -y -q"
	case "yum":
		script = "yum update -y -q"
	case "pacman":
		script = "pacman -Syu --noconfirm"
	case "zypper":
		script = "zypper --non-interactive update"
	case "apk":
		script = "apk upgrade"
	default:
		return false, fmt.Errorf("no supported package manager found (need apt-get, dnf, yum, pacman or zypper)")
	}
	script += "\nif [ -f /var/run/reboot-required ] || { command -v needs-restarting >/dev/null 2>&1 && ! needs-restarting -r >/dev/null 2>&1; }; then echo REBOOT_REQUIRED; fi\n"
	err = c.Script(ctx, script, func(line string) {
		if line == "REBOOT_REQUIRED" {
			reboot = true
		} else if onLine != nil {
			onLine(line)
		}
	})
	if err != nil {
		return false, fmt.Errorf("update the system: %w", err)
	}
	if f.PkgMgr == "apt-get" {
		f.aptUpdated = true
	}
	return reboot, nil
}

func InstallPackages(ctx context.Context, c Host, f *Facts, onLine func(string), pkgs ...string) error {
	if len(pkgs) == 0 {
		return nil
	}
	list := strings.Join(pkgs, " ")
	var script string
	switch f.PkgMgr {
	case "apt-get":
		update := ""
		if !f.aptUpdated {
			update = "apt-get update -q\n"
		}
		script = "export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a\n" + update +
			"apt-get install -y -q --no-install-recommends " + list
	case "dnf":
		script = "dnf install -y -q " + list
	case "yum":
		script = "yum install -y -q " + list
	case "pacman":
		script = "pacman -Sy --noconfirm --needed " + list
	case "zypper":
		script = "zypper --non-interactive install " + list
	case "apk":
		script = "apk add " + list
	default:
		return fmt.Errorf("no supported package manager found (need apt-get, dnf, yum, pacman or zypper)")
	}
	if err := c.Script(ctx, script, onLine); err != nil {
		return fmt.Errorf("install %s: %w", list, err)
	}
	if f.PkgMgr == "apt-get" {
		f.aptUpdated = true
	}
	return nil
}
