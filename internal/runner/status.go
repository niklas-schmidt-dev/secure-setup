package runner

import (
	"context"
	"fmt"
	"strings"

	"github.com/niklas-schmidt-dev/secure-setup/internal/remote"
)

// Status is what `secure-setup status` reports: what the server shows of the
// lockdown, and what is wrong with it. It is read from the server itself, so
// it needs no plan and works for a server set up by an earlier version.
type Status struct {
	Hostname        string   `json:"hostname"`
	System          string   `json:"system"`
	OK              bool     `json:"ok"`
	Problems        []string `json:"problems"`
	FirewallLoaded  bool     `json:"firewall_loaded"`
	EnabledAtBoot   bool     `json:"enabled_at_boot"`
	RollbackPending bool     `json:"rollback_pending"`
	RolledBack      string   `json:"rolled_back,omitempty"`
	AdminInterface  string   `json:"admin_interface,omitempty"`
	AdminAddress    string   `json:"admin_address,omitempty"`
	AdminPorts      string   `json:"admin_ports,omitempty"`
	WebPorts        string   `json:"web_ports,omitempty"`
	CloudflareV4    int      `json:"cloudflare_v4_ranges"`
	CloudflareV6    int      `json:"cloudflare_v6_ranges"`
	CloudflareSync  bool     `json:"cloudflare_refresh"`
	Tunnel          string   `json:"tunnel,omitempty"` // "connected" or "not connected"
	Tailscale       string   `json:"tailscale,omitempty"`
	TailscaleIP     string   `json:"tailscale_ip,omitempty"`
	TailscaleName   string   `json:"tailscale_name,omitempty"`
	TailscaleSSH    bool     `json:"tailscale_ssh"`
	KeysOnly        bool     `json:"sshd_keys_only"`
	SSHPort         int      `json:"sshd_port"`
	RebootRequired  bool     `json:"reboot_required"`
}

// ReadStatus looks at host and lists what is wrong with its lockdown.
func ReadStatus(ctx context.Context, host remote.Host) (*Status, error) {
	s, err := remote.ReadState(ctx, host)
	if err != nil {
		return nil, err
	}
	st := &Status{
		Hostname:        s.Hostname,
		System:          s.PrettyName,
		FirewallLoaded:  s.TableLoaded,
		EnabledAtBoot:   s.NFTAtBoot,
		RollbackPending: s.RollbackPending,
		RolledBack:      s.RolledBack,
		AdminInterface:  s.AdminInterface,
		AdminAddress:    s.AdminAddress,
		AdminPorts:      s.AdminPorts,
		WebPorts:        s.WebPorts,
		CloudflareV4:    s.CloudflareV4,
		CloudflareV6:    s.CloudflareV6,
		CloudflareSync:  s.SyncTimer,
		KeysOnly:        s.Hardened,
		SSHPort:         s.SSHPort,
		RebootRequired:  s.Reboot,
		Problems:        []string{},
	}
	// An admin rule without an address is Tailscale's: its interface carries
	// nothing but the tailnet.
	onTailscale := s.Tailscale && s.AdminAddress == "" && (s.AdminInterface != "" || !s.TableLoaded)
	admin := s.AdminAddress
	if s.Tailscale {
		if ts, err := remote.TailscaleStatus(ctx, host); err == nil {
			st.Tailscale = remote.Printable(ts.BackendState)
			st.TailscaleName = remote.Printable(strings.TrimSuffix(ts.Self.DNSName, "."))
			for _, ip := range ts.Self.TailscaleIPs {
				if !strings.Contains(ip, ":") {
					st.TailscaleIP = remote.Printable(ip)
				}
			}
		}
		st.TailscaleSSH = remote.TailscaleSSHOn(ctx, host)
		if onTailscale {
			admin = st.TailscaleIP
		}
	}
	if !s.TableLoaded && !s.Persisted && !s.Hardened && !s.TunnelUnit {
		st.Problems = append(st.Problems, "nothing of secure-setup is in place on this server")
		return st, nil
	}
	if admin == "" {
		// Tailscale is down: sshd's policy is still checked, for a login
		// that arrives on any address.
		admin = "127.0.0.1"
	}
	// The checks a reboot is followed by, against what the server itself
	// shows as set up.
	st.Problems = append(st.Problems, CheckLockdown(ctx, host, BootExpect{
		Tailscale:    onTailscale,
		TailscaleSSH: st.TailscaleSSH,
		Hardened:     s.Hardened,
		Tunnel:       s.TunnelUnit,
		User:         "root",
		AdminAddress: admin,
		SSHPort:      s.SSHPort,
	})...)
	if s.TunnelUnit {
		st.Tunnel = "connected"
		if !remote.TunnelReady(ctx, host) {
			st.Tunnel = "not connected"
		}
	}
	if s.TableLoaded {
		if s.InputPolicy != "drop" {
			st.Problems = append(st.Problems, "the input chain does not drop by default (policy "+orUnknown(s.InputPolicy)+")")
		}
		if s.AdminInterface == "" {
			st.Problems = append(st.Problems, "the loaded rules have no rule for the private network")
		}
		if !s.Persisted && !s.RollbackPending {
			st.Problems = append(st.Problems, "/etc/nftables.conf is not the secure-setup ruleset, so the rules would not survive a reboot")
		}
		if s.WebPorts != "" && s.CloudflareV4 == 0 && s.CloudflareV6 == 0 {
			st.Problems = append(st.Problems, "the Cloudflare ranges are empty, so the web ports are closed to everyone; run secure-setup-cloudflare-sync on the server")
		}
	}
	if s.RollbackPending {
		st.Problems = append(st.Problems, "the loaded rules still wait for their confirmation; the rollback timer restores the previous firewall")
	}
	if s.SyncTimer && s.SyncResult != "" && s.SyncResult != "success" {
		st.Problems = append(st.Problems, "the last daily refresh of the Cloudflare ranges failed ("+s.SyncResult+"); see journalctl -u "+remote.SyncUnit)
	}
	st.OK = len(st.Problems) == 0
	return st, nil
}

// Text is the report for a terminal.
func (st *Status) Text() string {
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "  %-16s %s\n", k, Printable(v)) }
	fmt.Fprintf(&b, "%s (%s)\n\n", Printable(orUnknown(st.Hostname)), Printable(orUnknown(st.System)))
	switch {
	case !st.FirewallLoaded:
		line("Firewall", "not loaded")
	case st.RollbackPending:
		line("Firewall", "loaded, not confirmed yet")
	case st.EnabledAtBoot:
		line("Firewall", "loaded, comes back at boot")
	default:
		line("Firewall", "loaded")
	}
	if st.AdminInterface != "" {
		what := "TCP " + st.AdminPorts
		if st.AdminPorts == "all" {
			what = "everything"
		}
		to := ""
		if st.AdminAddress != "" {
			to = " to " + st.AdminAddress
		}
		line("Administration", what+" on "+st.AdminInterface+to+" only")
	}
	switch {
	case st.Tunnel != "":
		line("Web", "through a Cloudflare Tunnel ("+st.Tunnel+"); no web port open")
	case st.WebPorts != "":
		refresh := "no daily refresh"
		if st.CloudflareSync {
			refresh = "refreshed daily"
		}
		line("Web", fmt.Sprintf("TCP %s from Cloudflare only (%d IPv4 and %d IPv6 ranges, %s)", st.WebPorts, st.CloudflareV4, st.CloudflareV6, refresh))
	case st.FirewallLoaded:
		line("Web", "no web port open")
	}
	if st.Tailscale != "" {
		v := st.Tailscale
		if st.TailscaleIP != "" {
			v += " as " + st.TailscaleIP
		}
		if st.TailscaleName != "" {
			v += " (" + st.TailscaleName + ")"
		}
		line("Tailscale", v+"; Tailscale SSH "+onOff(st.TailscaleSSH))
	}
	line("sshd", fmt.Sprintf("port %d, %s", st.SSHPort, map[bool]string{true: "keys only", false: "password login unchanged"}[st.KeysOnly]))
	if st.RolledBack != "" {
		line("Last rollback", st.RolledBack+" UTC")
	}
	if st.RebootRequired {
		line("Reboot", "needed to finish a system update")
	}
	b.WriteString("\n")
	if st.OK {
		b.WriteString("No problems found.\n")
		return b.String()
	}
	b.WriteString("Problems:\n")
	for _, p := range st.Problems {
		fmt.Fprintf(&b, "  - %s\n", Printable(p))
	}
	return b.String()
}
