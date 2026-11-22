package runner

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// statusHost prints the state lines of a server and answers the checks like
// lockdownHost.
type statusHost struct {
	*lockdownHost
	state []string
}

func (h statusHost) Script(_ context.Context, _ string, onLine func(string)) error {
	for _, l := range h.state {
		onLine(l)
	}
	return nil
}

// lockedDown is what a server shows after a run with the default plan, with
// the input chain as nft 1.0.6 lists it.
func lockedDown() []string {
	return []string{
		"HOSTNAME=vps", "PRETTY=Debian GNU/Linux 12 (bookworm)", "TABLE=1",
		"RULE=chain input {",
		"RULE=type filter hook input priority filter; policy drop;",
		`RULE=iif "lo" accept`,
		"RULE=ct state established,related accept",
		"RULE=udp dport 41641 accept",
		`RULE=iifname "tailscale0" tcp dport { 22, 8080 } counter packets 3 bytes 180 accept`,
		"RULE=ip saddr @cloudflare_v4 tcp dport { 443 } accept",
		"RULE=ip6 saddr @cloudflare_v6 tcp dport { 443 } accept",
		"CF4=15", "CF6=7", "NFT_BOOT=enabled", "PERSISTED=1", "SYNC_TIMER=active", "SYNC_RESULT=success",
		"HARDENED=1", "SSHPORT=22", "TAILSCALE=1",
	}
}

func without(lines []string, prefix string) []string {
	var out []string
	for _, l := range lines {
		if !strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}

func TestReadStatus(t *testing.T) {
	st, err := ReadStatus(context.Background(), statusHost{goodHost(), lockedDown()})
	if err != nil || !st.OK || len(st.Problems) != 0 {
		t.Fatalf("a locked-down server reported %v, %q", err, st.Problems)
	}
	if st.AdminInterface != "tailscale0" || st.AdminPorts != "22, 8080" || st.WebPorts != "443" || st.CloudflareV4 != 15 || !st.KeysOnly || st.Tailscale != "Running" {
		t.Fatalf("status %+v", st)
	}
	text := st.Text()
	for _, want := range []string{"vps (Debian GNU/Linux 12 (bookworm))", "TCP 22, 8080 on tailscale0 only", "TCP 443 from Cloudflare only (15 IPv4 and 7 IPv6 ranges, refreshed daily)", "No problems found."} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	// --json prints the same, with an empty list when nothing is wrong.
	data, _ := json.Marshal(st)
	if !strings.Contains(string(data), `"ok":true`) || !strings.Contains(string(data), `"problems":[]`) {
		t.Fatalf("json %s", data)
	}

	// An existing private network: the admin rule carries its address, and
	// newer nft versions print a single port without braces.
	lines := append(without(lockedDown(), `RULE=iifname`), `RULE=iifname "eth1" ip daddr 10.0.0.5 tcp dport 22 counter packets 0 bytes 0 accept`)
	st, _ = ReadStatus(context.Background(), statusHost{goodHost(), lines})
	if !st.OK || st.AdminInterface != "eth1" || st.AdminAddress != "10.0.0.5" || st.AdminPorts != "22" {
		t.Fatalf("existing network: %+v", st)
	}

	for name, c := range map[string]struct {
		lines []string
		host  func(*lockdownHost)
		want  string
	}{
		"rules gone":         {lines: without(without(lockedDown(), "TABLE"), "RULE"), host: func(h *lockdownHost) { h.table = "" }, want: "the firewall rules are not loaded"},
		"policy accept":      {lines: append(without(lockedDown(), "RULE=type"), "RULE=type filter hook input priority filter; policy accept;"), want: "does not drop by default"},
		"no admin rule":      {lines: without(lockedDown(), "RULE=iifname"), want: "no rule for the private network"},
		"not persisted":      {lines: without(lockedDown(), "PERSISTED"), want: "would not survive a reboot"},
		"not confirmed":      {lines: append(lockedDown(), "ROLLBACK_PENDING=1"), want: "still wait for their confirmation"},
		"empty ranges":       {lines: append(without(without(lockedDown(), "CF4"), "CF6"), "CF4=0", "CF6=0"), want: "the Cloudflare ranges are empty"},
		"refresh failed":     {lines: append(without(lockedDown(), "SYNC_RESULT"), "SYNC_RESULT=exit-code"), want: "refresh of the Cloudflare ranges failed (exit-code)"},
		"tailscale stopped":  {lines: lockedDown(), host: func(h *lockdownHost) { h.tsState = "Stopped" }, want: "tailscale is in state Stopped"},
		"passwords back on":  {lines: lockedDown(), host: func(h *lockdownHost) { h.passwords = "yes" }, want: "sshd still allows passwordauthentication"},
		"nothing set up yet": {lines: []string{"HOSTNAME=vps", "SSHPORT=22", "NFT_BOOT=disabled"}, want: "nothing of secure-setup is in place"},
	} {
		h := goodHost()
		if c.host != nil {
			c.host(h)
		}
		st, err := ReadStatus(context.Background(), statusHost{h, c.lines})
		if err != nil || st.OK || len(st.Problems) != 1 || !strings.Contains(st.Problems[0], c.want) {
			t.Errorf("%s: err %v, problems %q", name, err, st.Problems)
		}
		if !strings.Contains(st.Text(), "Problems:\n  - ") {
			t.Errorf("%s: report does not list the problem:\n%s", name, st.Text())
		}
	}
}
