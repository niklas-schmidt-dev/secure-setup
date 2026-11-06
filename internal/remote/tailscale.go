package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/niklas-schmidt-dev/secure-setup/internal/sshx"
)

// TSStatus is the subset of `tailscale status --json` we read.
type TSStatus struct {
	BackendState   string `json:"BackendState"`
	MagicDNSSuffix string `json:"MagicDNSSuffix"`
	Self           struct {
		HostName     string   `json:"HostName"`
		DNSName      string   `json:"DNSName"`
		TailscaleIPs []string `json:"TailscaleIPs"`
		Online       bool     `json:"Online"`
	} `json:"Self"`
}

// TailscaleStatus reads the node state. It fails when tailscaled is not running.
func TailscaleStatus(ctx context.Context, c *sshx.Client) (*TSStatus, error) {
	out, err := c.Output(ctx, "tailscale status --json")
	if err != nil {
		return nil, err
	}
	var st TSStatus
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		return nil, fmt.Errorf("parse tailscale status: %w", err)
	}
	return &st, nil
}

// TailscaleIPv4 returns the node's 100.x address.
func TailscaleIPv4(ctx context.Context, c *sshx.Client) (string, error) {
	out, err := c.Output(ctx, "tailscale ip -4")
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if !strings.HasPrefix(ip, "100.") {
		return "", fmt.Errorf("unexpected tailscale IPv4 %q", ip)
	}
	return ip, nil
}

// InterfaceExists checks for a network interface by name.
func InterfaceExists(ctx context.Context, c *sshx.Client, name string) bool {
	_, err := c.Output(ctx, "ip -o link show "+sshx.Quote(name))
	return err == nil
}

const installTailscaleScript = `
if command -v tailscale >/dev/null 2>&1; then
	echo "tailscale already installed: $(tailscale version | head -1)"
else
	tmp=$(mktemp)
	curl -fsSL https://tailscale.com/install.sh -o "$tmp"
	head -c 2 "$tmp" | grep -q '#!' || { echo "unexpected installer content" >&2; exit 1; }
	grep -q tailscale "$tmp" || { echo "unexpected installer content" >&2; exit 1; }
	sh "$tmp"
	rm -f "$tmp"
fi
systemctl enable --now tailscaled
echo "tailscaled: $(systemctl is-active tailscaled)"
`

// InstallTailscale installs the package via Tailscale's official installer
// and starts tailscaled.
func InstallTailscale(ctx context.Context, c *sshx.Client, f *Facts, onLine func(string)) error {
	if err := InstallPackages(ctx, c, f, onLine, "curl", "ca-certificates"); err != nil {
		return err
	}
	if err := c.Script(ctx, installTailscaleScript, onLine); err != nil {
		return fmt.Errorf("install tailscale: %w", err)
	}
	f.Tailscale = true
	return nil
}

// UpOptions configure `tailscale up`.
type UpOptions struct {
	AuthKey  string
	Hostname string
	SSH      bool
}

var loginURLRe = regexp.MustCompile(`https://login\.tailscale\.com/\S+`)

// TailscaleUp connects the node. Without an auth key it reports the login URL
// through onURL and waits until the user has authenticated.
func TailscaleUp(ctx context.Context, c *sshx.Client, o UpOptions, onLine func(string), onURL func(string)) error {
	args := []string{"tailscale", "up", "--timeout=15m"}
	if o.Hostname != "" {
		args = append(args, "--hostname="+sshx.Quote(o.Hostname))
	}
	if o.SSH {
		args = append(args, "--ssh")
	}
	script := ""
	if o.AuthKey != "" {
		keyPath := StateDir + "/tailscale.authkey"
		if err := c.WriteFile(ctx, keyPath, []byte(o.AuthKey+"\n"), "0600"); err != nil {
			return err
		}
		args = append(args, "--auth-key=file:"+keyPath)
		script = "trap 'rm -f " + sshx.Quote(keyPath) + "' EXIT\n"
	}
	script += strings.Join(args, " ")
	seen := false
	err := c.Script(ctx, script, func(line string) {
		if onLine != nil {
			onLine(line)
		}
		if url := loginURLRe.FindString(line); url != "" && !seen {
			seen = true
			if onURL != nil {
				onURL(url)
			}
		}
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return err
		}
		return fmt.Errorf("tailscale up: %w", err)
	}
	return nil
}
