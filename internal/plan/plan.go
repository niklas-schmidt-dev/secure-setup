// Package plan holds everything secure-setup needs to know about one server.
// A plan can be saved as JSON and replayed with `secure-setup apply -f`.
// Secrets (password, passphrase, Tailscale auth key) are never written.
package plan

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Plan is the full answer set of the wizard.
type Plan struct {
	// Local means the plan is applied on the machine secure-setup runs on
	// (`secure-setup here`); Server is then unused.
	Local     bool      `json:"local,omitempty"`
	Server    Server    `json:"server"`
	Tailscale Tailscale `json:"tailscale"`
	Firewall  Firewall  `json:"firewall"`
	SSH       SSH       `json:"ssh"`
}

// Confirmation modes for a local run.
const (
	// ConfirmLogin waits for a new SSH login over the private network (or
	// `secure-setup confirm` in such a session) before the rules are kept.
	ConfirmLogin = "login"
	// ConfirmSelf keeps the rules after self-checks: tailscale is running,
	// the interface and listener exist, a tailnet peer answers a ping.
	// For unattended runs (cloud-init) where nobody can log in.
	ConfirmSelf = "self"
)

// Server is how we reach the machine today, over its public address.
type Server struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	KeyPath    string `json:"key_path,omitempty"`
	Password   string `json:"-"`
	Passphrase string `json:"-"`
}

// Tailscale configures the tailnet join. When UseExisting is set, Tailscale is
// not installed and AdminAddress (an address on AdminInterface, e.g. a private
// network or WireGuard peer) is used instead.
type Tailscale struct {
	Hostname       string `json:"hostname,omitempty"`
	AuthKey        string `json:"-"`
	SSH            bool   `json:"tailscale_ssh"`
	AdminInterface string `json:"admin_interface"`
	UDPPort        int    `json:"udp_port"`
	UseExisting    bool   `json:"use_existing_network,omitempty"`
	AdminAddress   string `json:"admin_address,omitempty"`
}

// Firewall is the inbound policy.
type Firewall struct {
	WebPorts        []int  `json:"web_ports"`
	AllowPing       bool   `json:"allow_ping"`
	TailnetPorts    []int  `json:"tailnet_ports"`
	TailnetAll      bool   `json:"tailnet_all"`
	RollbackSeconds int    `json:"rollback_seconds"`
	WANInterface    string `json:"wan_interface,omitempty"`
	// WANOverride confirms that WANInterface deliberately differs from the
	// interface of the server's default route.
	WANOverride    bool `json:"wan_interface_override,omitempty"`
	CloudflareSync bool `json:"cloudflare_sync"`
	// ConfirmBy applies to local runs only: "login" (default) or "self".
	ConfirmBy string `json:"confirm_by,omitempty"`
}

// SSH covers sshd hardening and key handling.
type SSH struct {
	Harden        bool   `json:"harden"`
	AddLocalKey   bool   `json:"add_local_key"`
	PublicKeyPath string `json:"public_key_path,omitempty"`
}

// Default returns the recommended plan: SSH only over the tailnet, HTTPS only
// from Cloudflare, ping allowed, key-only sshd.
func Default() Plan {
	return Plan{
		Server:    Server{Port: 22, User: "root"},
		Tailscale: Tailscale{AdminInterface: "tailscale0", UDPPort: 41641},
		Firewall: Firewall{
			WebPorts:        []int{443},
			AllowPing:       true,
			TailnetPorts:    []int{22},
			RollbackSeconds: 120,
			CloudflareSync:  true,
		},
		SSH: SSH{Harden: true, AddLocalKey: true},
	}
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)

// Validate checks the plan for mistakes that would make the run fail or lock
// the user out.
func (p *Plan) Validate() error {
	var errs []error
	if p.Local {
		switch p.Firewall.ConfirmBy {
		case "", ConfirmLogin, ConfirmSelf:
		default:
			errs = append(errs, fmt.Errorf("confirm_by must be %q or %q, got %q", ConfirmLogin, ConfirmSelf, p.Firewall.ConfirmBy))
		}
	} else {
		if p.Server.Host == "" {
			errs = append(errs, errors.New("server host is required"))
		} else if net.ParseIP(p.Server.Host) == nil && !hostRe.MatchString(p.Server.Host) {
			errs = append(errs, fmt.Errorf("server host %q is not a hostname or IP address", p.Server.Host))
		}
		if p.Server.Port < 1 || p.Server.Port > 65535 {
			errs = append(errs, fmt.Errorf("server port %d is out of range", p.Server.Port))
		}
		if p.Server.User == "" {
			errs = append(errs, errors.New("server user is required"))
		}
	}
	if p.Tailscale.AdminInterface == "" {
		errs = append(errs, errors.New("admin interface is required"))
	}
	if p.Tailscale.UseExisting && p.Tailscale.AdminAddress == "" {
		errs = append(errs, errors.New("admin address is required when using an existing private network"))
	}
	if p.Tailscale.UDPPort < 1 || p.Tailscale.UDPPort > 65535 {
		errs = append(errs, fmt.Errorf("tailscale UDP port %d is out of range", p.Tailscale.UDPPort))
	}
	for _, port := range append(append([]int{}, p.Firewall.WebPorts...), p.Firewall.TailnetPorts...) {
		if port < 1 || port > 65535 {
			errs = append(errs, fmt.Errorf("port %d is out of range", port))
		}
	}
	if p.Firewall.RollbackSeconds < 30 || p.Firewall.RollbackSeconds > 900 {
		errs = append(errs, fmt.Errorf("rollback window must be between 30 and 900 seconds, got %d", p.Firewall.RollbackSeconds))
	}
	if len(p.Firewall.WebPorts) == 0 && p.Firewall.CloudflareSync {
		p.Firewall.CloudflareSync = false
	}
	return errors.Join(errs...)
}

// Address is host:port of the public SSH endpoint.
func (p Plan) Address() string {
	return net.JoinHostPort(p.Server.Host, strconv.Itoa(p.Server.Port))
}

// Load reads a plan file.
func Load(path string) (Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Plan{}, err
	}
	p := Default()
	if err := json.Unmarshal(data, &p); err != nil {
		return Plan{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return Plan{}, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Save writes the plan as JSON without secrets.
func (p Plan) Save(path string) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// LocalSavePath is where `secure-setup here` stores its plan.
const LocalSavePath = "/etc/secure-setup/plan.json"

// DefaultSavePath is where the wizard stores the plan for replay.
func DefaultSavePath(host string) string {
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '_'
	}, host)
	return filepath.Join(ConfigDir(), safe+".json")
}

// ConfigDir is ~/.config/secure-setup.
func ConfigDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "secure-setup")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "secure-setup"
	}
	return filepath.Join(home, ".config", "secure-setup")
}

// ParsePorts turns "22, 8080" into a sorted, deduplicated list.
func ParsePorts(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%q is not a port number", f)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}

// FormatPorts is the inverse of ParsePorts.
func FormatPorts(ports []int) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}
