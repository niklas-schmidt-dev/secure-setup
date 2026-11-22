package remote

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/niklas-schmidt-dev/secure-setup/internal/nftgen"
)

// State is what a server shows of an earlier secure-setup run. It is read
// from the server itself, so `secure-setup status` needs no plan.
type State struct {
	Hostname   string
	PrettyName string

	TableLoaded     bool
	InputPolicy     string // "drop" when the ruleset is ours
	AdminInterface  string // interface of the admin rule
	AdminAddress    string // address the admin rule is bound to, "" for Tailscale
	AdminPorts      string // "22, 8080", or "all"
	WebPorts        string // "443", "" without a web rule
	PublicPorts     string // "TCP 25, 587 and UDP 51820", "" when nothing is open to everyone
	CloudflareV4    int    // prefixes in the loaded sets
	CloudflareV6    int
	NFTAtBoot       bool   // nftables.service is enabled
	Persisted       bool   // /etc/nftables.conf is the secure-setup ruleset
	RollbackPending bool   // the loaded rules still await their confirmation
	RolledBack      string // time of the last rollback, "" when the last apply was kept

	SyncTimer  bool   // the daily Cloudflare refresh is scheduled
	SyncResult string // result of its last run: "success", "exit-code", ...

	TunnelUnit bool // a Cloudflare Tunnel service was set up
	Hardened   bool // the keys-only sshd drop-in is in place
	SSHPort    int
	Tailscale  bool // CLI installed
	Reboot     bool // the system asks for a reboot
	// AutoUpdates: the unattended updates secure-setup sets up are on.
	AutoUpdates bool
}

var stateScript = `
printf 'HOSTNAME=%s\n' "$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || true)"
if [ -r /etc/os-release ]; then . /etc/os-release; fi
printf 'PRETTY=%s\n' "${PRETTY_NAME:-}"
if command -v nft >/dev/null 2>&1 && nft list table inet ` + nftgen.TableName + ` >/dev/null 2>&1; then
	echo TABLE=1
	nft list chain inet ` + nftgen.TableName + ` input 2>/dev/null | sed -e 's/^[[:space:]]*//' -e 's/^/RULE=/'
	printf 'CF4=%s\n' "$(nft list set inet ` + nftgen.TableName + ` cloudflare_v4 2>/dev/null | grep -o '[0-9.]*/[0-9][0-9]*' | wc -l)"
	printf 'CF6=%s\n' "$(nft list set inet ` + nftgen.TableName + ` cloudflare_v6 2>/dev/null | grep -o '[0-9a-f:]*/[0-9][0-9]*' | wc -l)"
fi
printf 'NFT_BOOT=%s\n' "$(systemctl is-enabled nftables 2>/dev/null || true)"
if grep -q '` + nftgen.Marker + `' ` + nftgen.ConfigPath + ` 2>/dev/null; then echo PERSISTED=1; fi
if ` + rollbackPendingTest + `; then echo ROLLBACK_PENDING=1; fi
if [ -f ` + RolledBackMarker + ` ]; then printf 'ROLLED_BACK=%s\n' "$(cat ` + RolledBackMarker + `)"; fi
printf 'SYNC_TIMER=%s\n' "$(systemctl is-active ` + SyncUnit + `.timer 2>/dev/null || true)"
printf 'SYNC_RESULT=%s\n' "$(systemctl show -p Result --value ` + SyncUnit + `.service 2>/dev/null || true)"
if [ -f ` + unitDir + TunnelUnit + `.service ]; then echo TUNNEL=1; fi
if [ -f ` + dropInPath + ` ]; then echo HARDENED=1; fi
sshd_bin=$(command -v sshd || echo /usr/sbin/sshd)
printf 'SSHPORT=%s\n' "$("$sshd_bin" -T 2>/dev/null | awk '$1=="port"{print $2; exit}')"
if command -v tailscale >/dev/null 2>&1; then echo TAILSCALE=1; fi
if [ -f /var/run/reboot-required ] || { command -v needs-restarting >/dev/null 2>&1 && ! needs-restarting -r >/dev/null 2>&1; }; then echo REBOOT=1; fi
if ` + AutoUpdatesOnTest + `; then echo AUTO_UPDATES=1; fi
`

var stateKeys = []string{"HOSTNAME", "PRETTY", "TABLE", "RULE", "CF4", "CF6", "NFT_BOOT", "PERSISTED", "ROLLBACK_PENDING", "ROLLED_BACK", "SYNC_TIMER", "SYNC_RESULT", "TUNNEL", "HARDENED", "SSHPORT", "TAILSCALE", "REBOOT", "AUTO_UPDATES"}

// ReadState reads the State of the server in one round trip.
func ReadState(ctx context.Context, c Host) (*State, error) {
	kv := map[string]string{}
	var rules []string
	err := c.Script(ctx, stateScript, func(line string) {
		k, v, ok := strings.Cut(line, "=")
		if !ok || !slices.Contains(stateKeys, k) {
			return
		}
		if k == "RULE" {
			rules = append(rules, Printable(v))
			return
		}
		kv[k] = Printable(v)
	})
	if err != nil {
		return nil, fmt.Errorf("read the server's state: %w", err)
	}
	s := &State{
		Hostname:        kv["HOSTNAME"],
		PrettyName:      kv["PRETTY"],
		TableLoaded:     kv["TABLE"] == "1",
		NFTAtBoot:       kv["NFT_BOOT"] == "enabled",
		Persisted:       kv["PERSISTED"] == "1",
		RollbackPending: kv["ROLLBACK_PENDING"] == "1",
		RolledBack:      kv["ROLLED_BACK"],
		SyncTimer:       kv["SYNC_TIMER"] == "active",
		SyncResult:      kv["SYNC_RESULT"],
		TunnelUnit:      kv["TUNNEL"] == "1",
		Hardened:        kv["HARDENED"] == "1",
		Tailscale:       kv["TAILSCALE"] == "1",
		Reboot:          kv["REBOOT"] == "1",
		AutoUpdates:     kv["AUTO_UPDATES"] == "1",
	}
	s.CloudflareV4, _ = strconv.Atoi(kv["CF4"])
	s.CloudflareV6, _ = strconv.Atoi(kv["CF6"])
	if s.SSHPort, _ = strconv.Atoi(kv["SSHPORT"]); s.SSHPort == 0 {
		s.SSHPort = 22
	}
	s.readRules(rules)
	return s, nil
}

// The rules of the input chain as `nft list chain` prints them. A set with
// one element is printed with or without braces, depending on the version.
var (
	policyRe    = regexp.MustCompile(`policy (\w+);`)
	adminRuleRe = regexp.MustCompile(`^iifname "([^"]+)"(?: ip6? daddr (\S+))?(?: tcp dport (\{[^}]*\}|\d+))? counter .*accept$`)
	webRuleRe   = regexp.MustCompile(`^ip saddr @cloudflare_v4 tcp dport (\{[^}]*\}|\d+) accept$`)
	publicRe    = regexp.MustCompile(`^(tcp|udp) dport (\{[^}]*\}|\d+) accept comment "public"$`)
)

func (s *State) readRules(rules []string) {
	for _, r := range rules {
		if m := policyRe.FindStringSubmatch(r); m != nil && strings.Contains(r, "hook input") {
			s.InputPolicy = m[1]
		}
		if m := adminRuleRe.FindStringSubmatch(r); m != nil {
			s.AdminInterface, s.AdminAddress, s.AdminPorts = m[1], m[2], portList(m[3])
			if m[3] == "" {
				s.AdminPorts = "all"
			}
		}
		if m := webRuleRe.FindStringSubmatch(r); m != nil {
			s.WebPorts = portList(m[1])
		}
		if m := publicRe.FindStringSubmatch(r); m != nil {
			if s.PublicPorts != "" {
				s.PublicPorts += " and "
			}
			s.PublicPorts += strings.ToUpper(m[1]) + " " + portList(m[2])
		}
	}
}

// portList turns "{ 22, 8080 }" or "22" into "22, 8080" or "22".
func portList(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r < '0' || r > '9' }), ", ")
}
