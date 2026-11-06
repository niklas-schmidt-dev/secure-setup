// Package remote runs the server-side steps over an sshx.Client.
package remote

import (
	"context"
	"embed"
	"fmt"
	"strconv"
	"strings"

	"github.com/niklas-schmidt-dev/secure-setup/internal/sshx"
)

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
	Docker     bool

	Tailscale      bool   // CLI installed
	TailscaleState string // Running, NeedsLogin, Stopped, NoState, "" when not running
	TailscaleIPv4  string

	UFWActive        bool
	FirewalldActive  bool
	SecureSetupTable bool   // our nftables table is already loaded
	RolledBack       string // timestamp of a previous rollback, if any
	RollbackArmed    bool   // a rollback timer from an earlier run is still active

	aptUpdated bool
}

// Family groups distributions by package tooling.
func (f *Facts) Family() string {
	id := strings.ToLower(f.ID + " " + f.IDLike)
	switch {
	case strings.Contains(id, "debian") || strings.Contains(id, "ubuntu"):
		return "debian"
	case strings.Contains(id, "fedora") || strings.Contains(id, "rhel") || strings.Contains(id, "centos") || strings.Contains(id, "rocky") || strings.Contains(id, "almalinux"):
		return "rhel"
	case strings.Contains(id, "arch"):
		return "arch"
	case strings.Contains(id, "suse"):
		return "suse"
	case strings.Contains(id, "alpine"):
		return "alpine"
	}
	return ""
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
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then echo UFW=1; else echo UFW=0; fi
if systemctl is-active --quiet firewalld 2>/dev/null; then echo FIREWALLD=1; else echo FIREWALLD=0; fi
if command -v nft >/dev/null 2>&1 && nft list table inet secure_setup >/dev/null 2>&1; then echo SS_TABLE=1; else echo SS_TABLE=0; fi
if [ -f /var/lib/secure-setup/rolled-back ]; then printf 'ROLLED_BACK=%s\n' "$(cat /var/lib/secure-setup/rolled-back)"; fi
if systemctl is-active --quiet secure-setup-rollback.timer 2>/dev/null; then echo ROLLBACK_ARMED=1; fi
`

// Detect gathers Facts about the server.
func Detect(ctx context.Context, c *sshx.Client) (*Facts, error) {
	kv := map[string]string{}
	err := c.Script(ctx, detectScript, func(line string) {
		if k, v, ok := strings.Cut(line, "="); ok {
			kv[k] = v
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
		SecureSetupTable: kv["SS_TABLE"] == "1",
		RolledBack:       kv["ROLLED_BACK"],
		RollbackArmed:    kv["ROLLBACK_ARMED"] == "1",
		WANIface:         kv["WAN"],
	}
	if f.WANIface == "" {
		f.WANIface = kv["WAN6"]
	}
	if f.PrettyName == "" {
		f.PrettyName = "unknown Linux"
	}
	f.SSHPort, _ = strconv.Atoi(kv["SSHPORT"])
	if f.SSHPort == 0 {
		f.SSHPort = 22
	}
	if f.Tailscale {
		if st, err := TailscaleStatus(ctx, c); err == nil {
			f.TailscaleState = st.BackendState
			for _, ip := range st.Self.TailscaleIPs {
				if !strings.Contains(ip, ":") {
					f.TailscaleIPv4 = ip
					break
				}
			}
		}
	}
	return f, nil
}

// InstallPackages installs packages with the detected package manager.
func InstallPackages(ctx context.Context, c *sshx.Client, f *Facts, onLine func(string), pkgs ...string) error {
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
