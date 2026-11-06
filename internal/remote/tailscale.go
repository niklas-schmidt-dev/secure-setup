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
	CurrentTailnet *struct {
		Name string `json:"Name"`
	} `json:"CurrentTailnet"`
	Health []string          `json:"Health"`
	Self   TSNode            `json:"Self"`
	Peer   map[string]TSNode `json:"Peer"`
}

// TSNode is one node in `tailscale status --json`.
type TSNode struct {
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
}

// TailscaleStatus reads the node state. It fails when tailscaled is not running.
func TailscaleStatus(ctx context.Context, c Host) (*TSStatus, error) {
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

// Tailnet names the tailnet the node is in, as far as the status shows it.
func (s *TSStatus) Tailnet() string {
	suffix := strings.TrimSuffix(s.MagicDNSSuffix, ".")
	if suffix == "" {
		if _, rest, ok := strings.Cut(strings.TrimSuffix(s.Self.DNSName, "."), "."); ok {
			suffix = rest
		}
	}
	switch {
	case s.CurrentTailnet != nil && s.CurrentTailnet.Name != "" && suffix != "":
		return s.CurrentTailnet.Name + " (" + suffix + ")"
	case s.CurrentTailnet != nil && s.CurrentTailnet.Name != "":
		return s.CurrentTailnet.Name
	case suffix != "":
		return suffix
	}
	return "unknown"
}

// TailscaleSetSSH turns Tailscale SSH on or off. secure-setup turns it on
// only once the node is known to be in the operator's tailnet, never in
// `tailscale up`. While it is on, tailscaled answers port 22 on the tailnet
// address instead of sshd.
func TailscaleSetSSH(ctx context.Context, c Host, on bool, onLine func(string)) error {
	state := map[bool]string{true: "enabled", false: "disabled"}[on]
	if err := c.Script(ctx, fmt.Sprintf("tailscale set --ssh=%t\necho \"Tailscale SSH %s\"", on, state), onLine); err != nil {
		return fmt.Errorf("set Tailscale SSH %s: %w", state, err)
	}
	return nil
}

// TailscaleSSHOn reports whether Tailscale SSH is on (false when unknown).
func TailscaleSSHOn(ctx context.Context, c Host) bool {
	out, err := c.Output(ctx, "tailscale debug prefs")
	if err != nil {
		return false
	}
	var prefs struct {
		RunSSH bool `json:"RunSSH"`
	}
	return json.Unmarshal([]byte(out), &prefs) == nil && prefs.RunSSH
}

// TailscaleLogout takes the node off the tailnet it joined.
func TailscaleLogout(ctx context.Context, c Host, onLine func(string)) error {
	if err := c.Script(ctx, "tailscale logout\necho \"logged this machine out of the tailnet\"", onLine); err != nil {
		return fmt.Errorf("tailscale logout: %w", err)
	}
	return nil
}

// TailscaleIPv4 returns the node's 100.x address.
func TailscaleIPv4(ctx context.Context, c Host) (string, error) {
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
func InterfaceExists(ctx context.Context, c Host, name string) bool {
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
func InstallTailscale(ctx context.Context, c Host, f *Facts, onLine func(string)) error {
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
}

var loginURLRe = regexp.MustCompile(`https://login\.tailscale\.com/\S+`)

// TailscaleUp connects the node. Without an auth key it reports the login URL
// through onURL and waits until the user has authenticated.
func TailscaleUp(ctx context.Context, c Host, o UpOptions, onLine func(string), onURL func(string)) error {
	args := []string{"tailscale", "up", "--timeout=15m"}
	if o.Hostname != "" {
		args = append(args, "--hostname="+sshx.Quote(o.Hostname))
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

// TailscalePingPeer pings one online peer over the tailnet and reports the
// path it took. It returns ok=false with a reason when no online peer exists.
func TailscalePingPeer(ctx context.Context, c Host, st *TSStatus) (ok bool, detail string, err error) {
	var peer *TSNode
	for _, n := range st.Peer {
		if n.Online && len(n.TailscaleIPs) > 0 {
			n := n
			if peer == nil || n.HostName < peer.HostName {
				peer = &n
			}
		}
	}
	if peer == nil {
		return false, "no other tailnet device is online to ping", nil
	}
	ip := ""
	for _, a := range peer.TailscaleIPs {
		if !strings.Contains(a, ":") {
			ip = a
			break
		}
	}
	if ip == "" {
		ip = peer.TailscaleIPs[0]
	}
	out, err := c.Output(ctx, "tailscale ping --c 3 --timeout 5s --until-direct=false "+sshx.Quote(ip))
	if err != nil {
		return false, "", fmt.Errorf("tailscale ping %s (%s): %w", peer.HostName, ip, err)
	}
	last := out
	if i := strings.LastIndexByte(strings.TrimSpace(out), '\n'); i >= 0 {
		last = strings.TrimSpace(out)[i+1:]
	}
	return true, peer.HostName + ": " + strings.TrimSpace(last), nil
}
