// Package nftgen renders the nftables ruleset secure-setup installs on a server.
package nftgen

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"
)

//go:embed nftables.conf.tmpl
var rulesetTemplate string

const (
	TableName               = "secure_setup"
	ConfigPath              = "/etc/nftables.conf"
	ElementsPath            = "/etc/secure-setup/cloudflare.nft"
	DefaultAdminInterface   = "tailscale0"
	DefaultTailscaleUDPPort = 41641
	// Marker appears in the first comment line of every file we manage.
	Marker = "Managed by secure-setup"
)

// Params describes the inbound policy for one server.
type Params struct {
	AdminInterface string // interface the tailnet arrives on (tailscale0)
	// AdminAddress, when set, is the only address on AdminInterface the
	// admin rule accepts: an existing private network, whose interface may
	// also carry public addresses (and may then be an uplink too). Unset for
	// Tailscale, whose interface carries nothing but tailnet addresses.
	AdminAddress     netip.Addr
	WANInterface     string   // interface that carries the default route (eth0, ens3, ...)
	ExtraWAN         []string // further internet-facing interfaces (an IPv6 uplink, a second default route)
	TailnetTCPPorts  []int    // TCP ports reachable from the tailnet; must contain the SSH port
	TailnetAll       bool     // allow everything from the tailnet instead of only TailnetTCPPorts
	WebPorts         []int    // TCP ports Cloudflare may reach (443, optionally 80); empty = no web traffic
	AllowPing        bool     // rate-limited ICMP echo from anywhere
	TailscaleUDPPort int      // WireGuard port for direct Tailscale connections
	ElementsPath     string   // include file holding the Cloudflare set elements
}

type view struct {
	Params
	TableName       string
	Marker          string
	AdminMatch      string // `iifname "tailscale0"`, or with `ip daddr ...` for AdminAddress
	TailnetPortList string
	WebPortList     string
	WANSet          string // "eth0", or { "eth0", "he-ipv6" } with extra uplinks
}

var ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// Render returns the full /etc/nftables.conf content for p.
func Render(p Params) (string, error) {
	p, err := p.normalized()
	if err != nil {
		return "", err
	}
	t, err := template.New("nftables.conf").Parse(rulesetTemplate)
	if err != nil {
		return "", fmt.Errorf("nftgen: parse template: %w", err)
	}
	v := view{
		Params:          p,
		TableName:       TableName,
		Marker:          Marker,
		AdminMatch:      adminMatch(p.AdminInterface, p.AdminAddress),
		TailnetPortList: joinPorts(p.TailnetTCPPorts),
		WebPortList:     joinPorts(p.WebPorts),
		WANSet:          ifaceSet(append([]string{p.WANInterface}, p.ExtraWAN...)),
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, v); err != nil {
		return "", fmt.Errorf("nftgen: render: %w", err)
	}
	return buf.String(), nil
}

// RenderElements returns the include file that carries the Cloudflare set
// elements. An empty list leaves its set empty, which blocks that family.
func RenderElements(v4, v6 []netip.Prefix) string {
	var b strings.Builder
	b.WriteString("# Cloudflare IP ranges - managed by secure-setup-cloudflare-sync, refreshed daily. Do not edit.\n")
	if len(v4) > 0 {
		fmt.Fprintf(&b, "add element inet %s cloudflare_v4 { %s }\n", TableName, joinPrefixes(v4))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "add element inet %s cloudflare_v6 { %s }\n", TableName, joinPrefixes(v6))
	}
	return b.String()
}

func (p Params) normalized() (Params, error) {
	if p.AdminInterface == "" {
		p.AdminInterface = DefaultAdminInterface
	}
	if p.WANInterface == "" {
		return p, errors.New("nftgen: the internet-facing interface is required")
	}
	var extra []string
	for _, n := range p.ExtraWAN {
		if n != p.WANInterface && !slices.Contains(extra, n) {
			extra = append(extra, n)
		}
	}
	p.ExtraWAN = extra
	for _, n := range append([]string{p.AdminInterface, p.WANInterface}, p.ExtraWAN...) {
		if !ifaceRe.MatchString(n) {
			return p, fmt.Errorf("nftgen: invalid interface name %q", n)
		}
	}
	if p.AdminAddress.IsValid() {
		if p.AdminAddress.Zone() != "" || !p.AdminAddress.Unmap().IsGlobalUnicast() {
			return p, fmt.Errorf("nftgen: admin address %s is not a unicast address", p.AdminAddress)
		}
		p.AdminAddress = p.AdminAddress.Unmap()
	} else {
		// Without an address the admin rule trusts the whole interface, so it
		// must never face the internet.
		for _, n := range append([]string{p.WANInterface}, p.ExtraWAN...) {
			if p.AdminInterface == n {
				return p, fmt.Errorf("nftgen: admin interface and internet interface are both %q", n)
			}
		}
	}
	if p.TailscaleUDPPort == 0 {
		p.TailscaleUDPPort = DefaultTailscaleUDPPort
	}
	if p.ElementsPath == "" {
		p.ElementsPath = ElementsPath
	}
	var err error
	if p.TailnetTCPPorts, err = cleanPorts(p.TailnetTCPPorts); err != nil {
		return p, fmt.Errorf("nftgen: tailnet ports: %w", err)
	}
	if p.WebPorts, err = cleanPorts(p.WebPorts); err != nil {
		return p, fmt.Errorf("nftgen: web ports: %w", err)
	}
	if !p.TailnetAll && len(p.TailnetTCPPorts) == 0 {
		return p, errors.New("nftgen: no tailnet ports allowed: that would lock you out")
	}
	return p, nil
}

func cleanPorts(ports []int) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port %d out of range", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out, nil
}

func joinPorts(ports []int) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}

func joinPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}

// adminMatch is what the admin rule matches: the interface, and the admin
// address on it when there is one.
func adminMatch(iface string, addr netip.Addr) string {
	m := `iifname "` + iface + `"`
	switch {
	case !addr.IsValid():
	case addr.Is4():
		m += " ip daddr " + addr.String()
	default:
		m += " ip6 daddr " + addr.String()
	}
	return m
}

// ifaceSet renders one interface name as "eth0" and several as an
// anonymous set, so a single uplink keeps the plain form.
func ifaceSet(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = `"` + n + `"`
	}
	if len(quoted) == 1 {
		return quoted[0]
	}
	return "{ " + strings.Join(quoted, ", ") + " }"
}
