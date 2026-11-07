package remote

import (
	"context"
	"fmt"
	"strings"
)

// Cloudflare Tunnel: cloudflared keeps an outbound connection to Cloudflare,
// so the server needs no inbound web port at all.
const (
	TunnelUnit      = "secure-setup-cloudflared"
	TunnelTokenPath = "/etc/secure-setup/cloudflared.token"
	// Outside cloudflared's default metrics ports (20241-20245), which
	// another cloudflared on the machine may hold.
	tunnelPort    = "20290"
	tunnelMetrics = "127.0.0.1:" + tunnelPort
)

// tunnelReady is a shell function that succeeds when this unit's cloudflared
// has a connection to Cloudflare: /ready answers, and the listener belongs to
// the unit's main process rather than to another cloudflared.
var tunnelReady = fmt.Sprintf(`tunnel_ready() {
	pid=$(systemctl show -p MainPID --value %[1]s.service 2>/dev/null)
	[ -n "$pid" ] && [ "$pid" != 0 ] || return 1
	ss -Htlnp 'sport = :%[2]s' 2>/dev/null | grep -q "pid=$pid," || return 1
	curl -fsS -o /dev/null http://%[3]s/ready 2>/dev/null
}
`, TunnelUnit, tunnelPort, tunnelMetrics)

// ensureCurl installs curl, which the repository setup and the readiness
// check need, when it is missing.
func ensureCurl(ctx context.Context, c Host, f *Facts, onLine func(string)) error {
	if _, err := c.Output(ctx, "command -v curl"); err == nil {
		return nil
	}
	pkgs := []string{"curl"}
	if f.PkgMgr == "apt-get" {
		pkgs = append(pkgs, "ca-certificates")
	}
	return InstallPackages(ctx, c, f, onLine, pkgs...)
}

// InstallCloudflared installs cloudflared from Cloudflare's signed package
// repository, unless it is already installed.
func InstallCloudflared(ctx context.Context, c Host, f *Facts, onLine func(string)) error {
	if err := ensureCurl(ctx, c, f, onLine); err != nil {
		return err
	}
	if _, err := c.Output(ctx, "command -v cloudflared"); err == nil {
		onLine("cloudflared already installed")
		return nil
	}
	var script string
	switch f.PkgMgr {
	case "apt-get":
		// The repository is fetched over HTTPS; curl may be there without
		// the CA bundle it only recommends.
		if err := InstallPackages(ctx, c, f, onLine, "ca-certificates"); err != nil {
			return err
		}
		script = `export DEBIAN_FRONTEND=noninteractive
mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL --proto '=https' https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' > /etc/apt/sources.list.d/cloudflared.list
apt-get update -q
apt-get install -y -q -o DPkg::Lock::Timeout=300 cloudflared`
	case "dnf", "yum":
		script = fmt.Sprintf(`curl -fsSL --proto '=https' https://pkg.cloudflare.com/cloudflared.repo -o /etc/yum.repos.d/cloudflared.repo
%s install -y -q cloudflared`, f.PkgMgr)
	case "pacman":
		script = "pacman -S --noconfirm --needed cloudflared"
	default:
		return fmt.Errorf("no cloudflared package for %s here; install cloudflared yourself and run again", orNone(f.PkgMgr))
	}
	if err := c.Script(ctx, script+"\necho \"installed $(cloudflared --version)\"", onLine); err != nil {
		return fmt.Errorf("install cloudflared: %w", err)
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "this system"
	}
	return s
}

// SetupTunnel runs cloudflared as a systemd service for the tunnel whose token
// is given (or already stored, on a rerun) and waits until it has a
// connection to Cloudflare. The token only ever lives in a 0600 file that
// cloudflared reads with --token-file, never on a command line.
func SetupTunnel(ctx context.Context, c Host, token string, onLine func(string)) error {
	if token != "" {
		if err := c.WriteFile(ctx, TunnelTokenPath, []byte(strings.TrimSpace(token)+"\n"), "0600"); err != nil {
			return err
		}
		onLine("stored the tunnel token in " + TunnelTokenPath + " (mode 0600)")
	} else if _, err := c.Output(ctx, "test -s "+TunnelTokenPath); err != nil {
		return fmt.Errorf("no Cloudflare Tunnel token: set CLOUDFLARE_TUNNEL_TOKEN to the \"Install as service\" command of your tunnel (Cloudflare dashboard > Networks > Tunnels), as it is or just its token")
	}
	bin, err := c.Output(ctx, "command -v cloudflared")
	bin = strings.TrimSpace(bin)
	if err != nil || !exePathRe.MatchString(bin) {
		return fmt.Errorf("cloudflared not found at a usable path (%q)", bin)
	}
	unit := fmt.Sprintf(`[Unit]
Description=secure-setup: Cloudflare Tunnel
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=%s --no-autoupdate tunnel --metrics %s run --token-file %s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
`, bin, tunnelMetrics, TunnelTokenPath)
	if err := c.WriteFile(ctx, unitDir+TunnelUnit+".service", []byte(unit), "0644"); err != nil {
		return err
	}
	script := tunnelReady + fmt.Sprintf(`systemctl daemon-reload
systemctl enable %[1]s.service >/dev/null 2>&1
systemctl restart %[1]s.service
for i in $(seq 1 30); do
	if tunnel_ready; then echo "Cloudflare Tunnel connected"; exit 0; fi
	sleep 2
done
echo "the tunnel did not connect to Cloudflare within 60 seconds:" >&2
journalctl -u %[1]s.service -n 6 --no-pager -o cat >&2 || true
systemctl disable --now %[1]s.service >/dev/null 2>&1 || true
echo "stopped and disabled %[1]s.service; check the token and run again" >&2
exit 1
`, TunnelUnit)
	if err := c.Script(ctx, script, onLine); err != nil {
		return fmt.Errorf("start Cloudflare Tunnel: %w", err)
	}
	return nil
}

// TunnelReady reports whether this unit's cloudflared has a connection to
// Cloudflare.
func TunnelReady(ctx context.Context, c Host) bool {
	_, err := c.Output(ctx, tunnelReady+"tunnel_ready")
	return err == nil
}

// RemoveTunnel takes down the tunnel service of an earlier run when the plan
// no longer uses one, so the web is not reachable through it any more.
func RemoveTunnel(ctx context.Context, c Host, onLine func(string)) error {
	script := fmt.Sprintf(`if [ -f %[1]s ]; then
	systemctl disable --now %[2]s.service >/dev/null 2>&1 || true
	rm -f %[1]s %[3]s
	systemctl daemon-reload
	echo "removed the Cloudflare Tunnel of an earlier run: this plan does not use one"
else
	echo "not requested"
fi
`, unitDir+TunnelUnit+".service", TunnelUnit, TunnelTokenPath)
	if err := c.Script(ctx, script, onLine); err != nil {
		return fmt.Errorf("remove the earlier Cloudflare Tunnel: %w", err)
	}
	return nil
}
