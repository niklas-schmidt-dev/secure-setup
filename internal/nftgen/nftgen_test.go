package nftgen

import (
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestRenderGolden(t *testing.T) {
	cases := map[string]Params{
		"default":           {WANInterface: "eth0", TailnetTCPPorts: []int{22}, WebPorts: []int{443}, AllowPing: true},
		"web-both":          {WANInterface: "ens3", TailnetTCPPorts: []int{22, 8080}, WebPorts: []int{80, 443}},
		"tailnet-all-noweb": {WANInterface: "eth0", TailnetAll: true, TailnetTCPPorts: []int{22}, AllowPing: true},
		"two-uplinks":       {WANInterface: "eth0", ExtraWAN: []string{"he-ipv6", "eth0", "he-ipv6"}, TailnetTCPPorts: []int{22}, WebPorts: []int{443}},
		// An existing private network on a card that also carries a public
		// address: administration only to the private address, forwarding
		// from the card filtered like the internet.
		"existing-network": {AdminInterface: "eth1", AdminAddress: netip.MustParseAddr("10.0.0.5"), WANInterface: "eth0", ExtraWAN: []string{"eth1"}, TailnetTCPPorts: []int{22}, WebPorts: []int{443}},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Render(p)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", name+".nft")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden: %v (run with -update)", err)
			}
			if string(want) != got {
				t.Errorf("rendered ruleset differs from %s:\n%s", path, got)
			}
		})
	}
}

func TestRenderRejectsBadInput(t *testing.T) {
	bad := []Params{
		{WANInterface: "eth0"},                                     // no tailnet ports: lockout
		{WANInterface: "eth0", TailnetTCPPorts: []int{70000}},      // port range
		{WANInterface: "tailscale0", TailnetTCPPorts: []int{22}},   // admin == wan
		{WANInterface: "eth0; reboot", TailnetTCPPorts: []int{22}}, // injection
		{TailnetTCPPorts: []int{22}},                               // no wan
		{WANInterface: "eth0", TailnetTCPPorts: []int{22}, WebPorts: []int{0}},
		{WANInterface: "eth0", ExtraWAN: []string{"tailscale0"}, TailnetTCPPorts: []int{22}}, // admin as an uplink
		{WANInterface: "eth0", ExtraWAN: []string{"x\"y"}, TailnetTCPPorts: []int{22}},       // injection
		{AdminInterface: "eth1", AdminAddress: netip.MustParseAddr("fe80::1%eth1"), WANInterface: "eth0", TailnetTCPPorts: []int{22}},
		{AdminInterface: "eth1", AdminAddress: netip.MustParseAddr("127.0.0.1"), WANInterface: "eth0", TailnetTCPPorts: []int{22}},
	}
	for i, p := range bad {
		if _, err := Render(p); err == nil {
			t.Errorf("case %d: expected an error for %+v", i, p)
		}
	}
}

func TestRenderContents(t *testing.T) {
	out, err := Render(Params{WANInterface: "eth0", TailnetTCPPorts: []int{8080, 22, 22}, WebPorts: []int{443}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"policy drop",
		`iifname "tailscale0" tcp dport { 22, 8080 } counter accept`,
		"ip saddr @cloudflare_v4 tcp dport { 443 } accept",
		"ip6 saddr @cloudflare_v6 tcp dport { 443 } accept",
		`iifname != "eth0" accept`,
		"meta l4proto tcp ip saddr @cloudflare_v4 ct original proto-dst { 443 }",
		"udp dport 41641 accept",
		`include "/etc/secure-setup/cloudflare.nft"`,
		Marker,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "echo-request") {
		t.Error("ping rule present although AllowPing is false")
	}
	noweb, err := Render(Params{WANInterface: "eth0", TailnetTCPPorts: []int{22}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(noweb, "@cloudflare_v4 tcp") {
		t.Error("web rule present although no web ports were given")
	}
}

// With an admin address the admin rule matches it, IPv4 or IPv6, and the
// admin interface may also be an uplink; without one it may not.
func TestRenderAdminAddress(t *testing.T) {
	for addr, want := range map[string]string{
		"10.0.0.5":           `iifname "eth0" ip daddr 10.0.0.5 counter accept`,
		"::ffff:10.0.0.5":    `iifname "eth0" ip daddr 10.0.0.5 counter accept`,
		"fd00:5::7":          `iifname "eth0" ip6 daddr fd00:5::7 counter accept`,
		"2001:db8:0:1::4002": `iifname "eth0" ip6 daddr 2001:db8:0:1::4002 counter accept`,
	} {
		out, err := Render(Params{AdminInterface: "eth0", AdminAddress: netip.MustParseAddr(addr), WANInterface: "eth0", TailnetAll: true})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, want) || !strings.Contains(out, `iifname != "eth0" accept`) {
			t.Errorf("%s: missing %q in:\n%s", addr, want, out)
		}
	}
	if _, err := Render(Params{AdminInterface: "eth0", WANInterface: "eth0", TailnetAll: true}); err == nil {
		t.Error("an uplink was trusted as the admin interface without an admin address")
	}
}

func TestRenderElements(t *testing.T) {
	v4 := []netip.Prefix{netip.MustParsePrefix("173.245.48.0/20"), netip.MustParsePrefix("103.21.244.0/22")}
	v6 := []netip.Prefix{netip.MustParsePrefix("2400:cb00::/32")}
	got := RenderElements(v4, v6)
	for _, want := range []string{
		"add element inet secure_setup cloudflare_v4 { 173.245.48.0/20, 103.21.244.0/22 }\n",
		"add element inet secure_setup cloudflare_v6 { 2400:cb00::/32 }\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if empty := RenderElements(nil, nil); strings.Contains(empty, "add element") {
		t.Errorf("empty lists must not render elements: %q", empty)
	}
}
