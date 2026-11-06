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
	tunnelMetrics   = "127.0.0.1:20241"
)

// InstallCloudflared installs cloudflared from Cloudflare's signed package
// repository, unless it is already installed.
func InstallCloudflared(ctx context.Context, c Host, f *Facts, onLine func(string)) error {
	if _, err := c.Output(ctx, "command -v cloudflared"); err == nil {
		onLine("cloudflared already installed")
		return nil
	}
	var script string
	switch f.PkgMgr {
	case "apt-get":
		if err := InstallPackages(ctx, c, f, onLine, "curl", "ca-certificates"); err != nil {
			return err
		}
		script = `export DEBIAN_FRONTEND=noninteractive
mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL --proto '=https' https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' > /etc/apt/sources.list.d/cloudflared.list
apt-get update -q
apt-get install -y -q -o DPkg::Lock::Timeout=300 cloudflared`
	case "dnf", "yum":
		if err := InstallPackages(ctx, c, f, onLine, "curl"); err != nil {
			return err
		}
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
		return fmt.Errorf("no Cloudflare Tunnel token: set CLOUDFLARE_TUNNEL_TOKEN (Cloudflare dashboard > Networks > Tunnels > your tunnel > install command)")
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
	script := fmt.Sprintf(`systemctl daemon-reload
systemctl enable %[1]s.service >/dev/null 2>&1
systemctl restart %[1]s.service
for i in $(seq 1 30); do
	if curl -fsS -o /dev/null http://%[2]s/ready 2>/dev/null; then echo "Cloudflare Tunnel connected"; exit 0; fi
	sleep 2
done
echo "the tunnel did not connect to Cloudflare within 60 seconds:" >&2
journalctl -u %[1]s.service -n 6 --no-pager -o cat >&2 || true
systemctl disable --now %[1]s.service >/dev/null 2>&1 || true
echo "stopped and disabled %[1]s.service; check the token and run again" >&2
exit 1
`, TunnelUnit, tunnelMetrics)
	if err := c.Script(ctx, script, onLine); err != nil {
		return fmt.Errorf("start Cloudflare Tunnel: %w", err)
	}
	return nil
}

// TunnelReady reports whether cloudflared has a connection to Cloudflare.
func TunnelReady(ctx context.Context, c Host) bool {
	_, err := c.Output(ctx, "curl -fsS -o /dev/null http://"+tunnelMetrics+"/ready")
	return err == nil
}
