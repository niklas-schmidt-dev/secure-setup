package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/niklas-schmidt-dev/secure-setup/internal/localhost"
	"github.com/niklas-schmidt-dev/secure-setup/internal/plan"
	"github.com/niklas-schmidt-dev/secure-setup/internal/remote"
)

func TestPrintable(t *testing.T) {
	got := Printable("login by x\x1b]0;TITLE\a from 100.64.0.9\x1b[2K\x1b[1A\nnext\tline")
	if strings.ContainsAny(got, "\x1b\a") {
		t.Fatalf("control characters left: %q", got)
	}
	if !strings.Contains(got, "\nnext\tline") {
		t.Fatalf("newline or tab removed: %q", got)
	}
}

// Events reaching the reporter carry no terminal control sequences.
func TestReportSanitizesEvents(t *testing.T) {
	var got []Event
	p := plan.Default()
	r := New(Options{Plan: &p, Report: func(e Event) { got = append(got, e) }})
	r.o.Report(Event{Kind: Log, Text: "x\x1b]52;c;ZXZpbA==\a"})
	if len(got) != 1 || strings.ContainsAny(got[0].Text, "\x1b\a") {
		t.Fatalf("event not sanitized: %+v", got)
	}
}

func TestUsableKeys(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHHT9zwfT6widjbTcsKOGGlmx58L4skpUKesGUJ0u4kk operator@laptop"
	for in, want := range map[string]int{
		key:                                  1,
		"# a comment\n\n" + key + "\n" + key: 2,
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHHT9z\nwfT6widjbTcsKOGGlmx58L4skpUKesGUJ0u4kk operator@laptop": 0,
		`from="198.51.100.1" ` + key:  0,
		`command="/bin/false" ` + key: 0,
		"junk line":                   0,
		"":                            0,
	} {
		if got := usableKeys(in); got != want {
			t.Errorf("usableKeys(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestParseAcceptedLogins(t *testing.T) {
	out := "Accepted publickey for root from 100.64.0.9 port 51000 ssh2: ED25519 SHA256:x\n" +
		"Accepted publickey for x\x1b]0;T\a from 100.64.0.9 port 1 ssh2\n" +
		"Accepted publickey for root from fe80::1%eth0 port 1 ssh2\n" +
		"Accepted password for deploy from ::ffff:10.0.0.4 port 2 ssh2"
	got := parseAcceptedLogins(out)
	if len(got) != 2 || got[0].From != "100.64.0.9" || got[1].User != "deploy" || got[1].From != "10.0.0.4" {
		t.Fatalf("got %+v", got)
	}
}

// fakeHost answers `ip -o link show <iface>` for the listed interfaces.
type fakeHost struct{ ifaces []string }

func (h fakeHost) Output(_ context.Context, cmd string) (string, error) {
	for _, i := range h.ifaces {
		if strings.Contains(cmd, "ip -o link show '"+i+"'") {
			return "2: " + i + ": <UP>", nil
		}
	}
	return "", context.Canceled // any error means "does not exist"
}
func (fakeHost) Script(context.Context, string, func(string)) error      { return nil }
func (fakeHost) WriteFile(context.Context, string, []byte, string) error { return nil }

// A wan_interface carried over from another server must not silently win
// over this server's default-route interface.
func TestResolveWAN(t *testing.T) {
	ctx, log := context.Background(), func(string) {}
	f := &remote.Facts{WANIface: "ens3"}

	p := plan.Default()
	if err := resolveWAN(ctx, fakeHost{}, &p, f, log); err != nil || p.Firewall.WANInterface != "ens3" {
		t.Fatalf("empty plan value: %v %q", err, p.Firewall.WANInterface)
	}
	p.Firewall.WANInterface = "eth0"
	if err := resolveWAN(ctx, fakeHost{}, &p, f, log); err == nil {
		t.Fatal("a stale, absent wan_interface was accepted")
	}
	if err := resolveWAN(ctx, fakeHost{ifaces: []string{"eth0"}}, &p, f, log); err == nil || !strings.Contains(err.Error(), "wan_interface_override") {
		t.Fatalf("an existing but different interface was accepted without the override: %v", err)
	}
	p.Firewall.WANOverride = true
	if err := resolveWAN(ctx, fakeHost{ifaces: []string{"eth0"}}, &p, f, log); err != nil || p.Firewall.WANInterface != "eth0" {
		t.Fatalf("explicit override refused: %v", err)
	}
}

// Other default-route devices join the internet set; the primary uplink and
// the admin interface do not.
func TestExtraWAN(t *testing.T) {
	p := plan.Default()
	p.Firewall.WANInterface = "eth0"
	p.Tailscale.AdminInterface = "eth1"
	r := &Runner{o: Options{Plan: &p}, facts: &remote.Facts{WANIfaces: []string{"eth0", "he-ipv6", "eth1", "ens4"}}}
	var logs []string
	got := r.extraWAN(func(l string) { logs = append(logs, l) })
	if !slices.Equal(got, []string{"he-ipv6", "ens4"}) {
		t.Fatalf("extraWAN = %q", got)
	}
	if len(logs) != 2 || !strings.Contains(logs[0], "eth1") {
		t.Fatalf("logs = %q", logs)
	}
}

// scriptHost records scripts and fails them when fail is set.
type scriptHost struct {
	fakeHost
	scripts *[]string
	fail    bool
}

func (h scriptHost) Script(ctx context.Context, s string, _ func(string)) error {
	*h.scripts = append(*h.scripts, s)
	if h.fail {
		return errors.New("exit status 1")
	}
	return ctx.Err()
}

// A failure while a login-link join is unverified logs the node out, even
// when the run itself was cancelled, and says so; a failed logout is reported.
func TestLeaveUnverifiedTailnet(t *testing.T) {
	var scripts []string
	r := &Runner{joinedByLink: true}
	err := r.leaveUnverifiedTailnet(scriptHost{scripts: &scripts}, context.Canceled, func(string) {})
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "logged out") || len(scripts) != 1 || !strings.Contains(scripts[0], "tailscale logout") || r.joinedByLink {
		t.Fatalf("err %v, scripts %q", err, scripts)
	}
	r.joinedByLink = true
	err = r.leaveUnverifiedTailnet(scriptHost{scripts: &scripts, fail: true}, errors.New("unreachable"), func(string) {})
	if !strings.Contains(err.Error(), "failed too") {
		t.Fatalf("failed logout not reported: %v", err)
	}
	scripts = nil
	if err := r.leaveUnverifiedTailnet(scriptHost{scripts: &scripts}, errors.New("x"), func(string) {}); len(scripts) != 0 || err.Error() != "x" {
		t.Fatal("a verified tailnet was logged out")
	}
}

// The system update comes before anything is installed, and Tailscale SSH is
// the last remote step: it takes over port 22 on the tailnet address, which
// every earlier step uses to reach sshd.
func TestStepOrder(t *testing.T) {
	p := plan.Default()
	remoteSteps := New(Options{Plan: &p}).Steps()
	n := len(remoteSteps)
	if remoteSteps[1] != "Update the system" || remoteSteps[n-2] != "Turn on Tailscale SSH" || remoteSteps[n-1] != "Reboot and check" {
		t.Fatalf("remote steps: %q", remoteSteps)
	}
	lp := plan.Default()
	lp.Local = true
	localSteps := New(Options{Plan: &lp, Local: &localhost.Host{}}).Steps()
	if localSteps[1] != "Update the system" || localSteps[len(localSteps)-1] != "Reboot and check after the boot" {
		t.Fatalf("local steps: %q", localSteps)
	}
	if !plan.Default().UpdateSystem || !plan.Default().Reboot {
		t.Fatal("the system update and the reboot check are not on by default")
	}
}

func TestTailnetAddr(t *testing.T) {
	for ip, want := range map[string]bool{"100.65.75.118": true, "100.64.0.1": true, "100.128.0.1": false, "159.69.46.241": false, "fd7a:115c:a1e0::2": true, "2001:db8::1": false} {
		if got := tailnetAddr(netip.MustParseAddr(ip)); got != want {
			t.Fatalf("%s: %v", ip, got)
		}
	}
}

// lockdownHost answers the commands CheckLockdown runs.
type lockdownHost struct {
	fakeHost
	table, enabled, tsState, tsSSH, passwords string
	written                                   map[string]string
}

func (h *lockdownHost) Output(_ context.Context, cmd string) (string, error) {
	switch {
	case strings.HasPrefix(cmd, "nft list table"):
		if h.table == "" {
			return "", errors.New("exit status 1")
		}
		return h.table, nil
	case strings.HasPrefix(cmd, "systemctl is-enabled nftables"):
		return h.enabled, nil
	case cmd == "tailscale status --json":
		return `{"BackendState":"` + h.tsState + `"}`, nil
	case cmd == "tailscale debug prefs":
		return `{"RunSSH": ` + h.tsSSH + `}`, nil
	case strings.Contains(cmd, "-T -C"):
		return "passwordauthentication " + h.passwords + "\nkbdinteractiveauthentication no", nil
	case strings.Contains(cmd, "awk"):
		return "", nil // no Match block enables passwords
	}
	return "", nil
}

func (h *lockdownHost) WriteFile(_ context.Context, path string, data []byte, _ string) error {
	if h.written == nil {
		h.written = map[string]string{}
	}
	h.written[path] = string(data)
	return nil
}

func goodHost() *lockdownHost {
	return &lockdownHost{table: "table inet secure_setup {}", enabled: "enabled", tsState: "Running", tsSSH: "true", passwords: "no"}
}

func TestCheckLockdown(t *testing.T) {
	e := BootExpect{Tailscale: true, TailscaleSSH: true, Hardened: true, User: "root", AdminAddress: "100.64.0.2", SSHPort: 22}
	if p := CheckLockdown(context.Background(), goodHost(), e); len(p) != 0 {
		t.Fatalf("healthy server reported %q", p)
	}
	for name, broken := range map[string]func(*lockdownHost){
		"rules not loaded":      func(h *lockdownHost) { h.table = "" },
		"nftables not enabled":  func(h *lockdownHost) { h.enabled = "disabled" },
		"tailscale not running": func(h *lockdownHost) { h.tsState = "NeedsLogin" },
		"tailscale ssh off":     func(h *lockdownHost) { h.tsSSH = "false" },
		"passwords back on":     func(h *lockdownHost) { h.passwords = "yes" },
	} {
		h := goodHost()
		broken(h)
		if p := CheckLockdown(context.Background(), h, e); len(p) != 1 {
			t.Fatalf("%s: problems %q", name, p)
		}
	}
}

// The boot check reads what the run expected, writes the result to the log
// and the login message, and fails when something did not come back.
func TestBootCheck(t *testing.T) {
	bootCheckWait = 0
	bootCheckExpectPath = filepath.Join(t.TempDir(), "bootcheck.json")
	data, _ := json.Marshal(BootExpect{Tailscale: true, TailscaleSSH: true, Hardened: true, User: "root", AdminAddress: "100.64.0.2", SSHPort: 22})
	if err := os.WriteFile(bootCheckExpectPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	h := goodHost()
	msg, err := BootCheck(context.Background(), h)
	if err != nil || !strings.Contains(msg, "all checks passed") || h.written[remote.BootCheckLog] != msg || h.written[remote.BootCheckMotd] != msg {
		t.Fatalf("healthy: %v %q %v", err, msg, h.written)
	}
	h = goodHost()
	h.table = ""
	if msg, err := BootCheck(context.Background(), h); err == nil || !strings.Contains(msg, "PROBLEMS: the firewall rules are not loaded") {
		t.Fatalf("broken: %v %q", err, msg)
	}
}
