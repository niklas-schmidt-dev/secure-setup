package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

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
	if len(got) != 2 || got[0].From != "100.64.0.9" || got[0].Port != 51000 || got[1].User != "deploy" || got[1].From != "10.0.0.4" || got[1].Port != 2 {
		t.Fatalf("got %+v", got)
	}
}

// Only an accepted login from another machine over a connection that opened
// after the rules went live confirms them; a bare TCP connection, which never
// reaches the journal, confirms nothing.
func TestConfirmingLogin(t *testing.T) {
	admin, self := netip.MustParseAddr("100.64.0.5"), netip.MustParseAddr("203.0.113.7")
	before := remote.ParseSessions("0 0 203.0.113.7:22 198.51.100.4:50000\n0 0 100.64.0.5:22 100.64.0.9:41000\n")
	logins := parseAcceptedLogins("Accepted publickey for root from 127.0.0.1 port 40000 ssh2\n" +
		"Accepted publickey for root from 100.64.0.5 port 40001 ssh2\n" +
		"Accepted publickey for root from 203.0.113.7 port 40002 ssh2\n" +
		"Accepted publickey for root from 198.51.100.4 port 50000 ssh2\n" +
		"Accepted publickey for root from 100.64.0.9 port 41000 ssh2\n")
	if l, ok := confirmingLogin(logins, before, self, admin); ok {
		t.Fatalf("a local or pre-existing connection confirmed: %+v", l)
	}
	if _, ok := confirmingLogin(nil, before, self, admin); ok {
		t.Fatal("confirmed without any accepted login")
	}
	logins = append(logins, parseAcceptedLogins("Accepted publickey for root from 100.64.0.9 port 41001 ssh2")...)
	if l, ok := confirmingLogin(logins, before, self, admin); !ok || l.From != "100.64.0.9" || l.Port != 41001 {
		t.Fatalf("a new login from a tailnet peer did not confirm: %+v %v", l, ok)
	}
}

// The journal query starts once the rules are live and also reads
// sshd-session, which logs logins since OpenSSH 9.8.
func TestAcceptedLoginsQuery(t *testing.T) {
	var cmds []string
	acceptedLoginsSince(context.Background(), outputHost{cmds: &cmds}, 1700000000)
	if len(cmds) != 1 {
		t.Fatalf("commands %q", cmds)
	}
	for _, want := range []string{"--since=@1700000000 ", "_UID=0 _COMM=sshd-session", "_UID=0 SYSLOG_IDENTIFIER=sshd "} {
		if !strings.Contains(cmds[0], want) {
			t.Fatalf("query %q lacks %q", cmds[0], want)
		}
	}
}

// outputHost records the commands Output runs and prints nothing.
type outputHost struct {
	fakeHost
	cmds *[]string
}

func (h outputHost) Output(_ context.Context, cmd string) (string, error) {
	*h.cmds = append(*h.cmds, cmd)
	return "", nil
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
	p.Firewall.ExtraWANInterfaces = []string{"ens10"}
	if err := resolveWAN(ctx, fakeHost{ifaces: []string{"eth0"}}, &p, f, log); err == nil || !strings.Contains(err.Error(), "extra_wan_interfaces") {
		t.Fatalf("an absent extra_wan_interfaces entry was accepted: %v", err)
	}
	if err := resolveWAN(ctx, fakeHost{ifaces: []string{"eth0", "ens10"}}, &p, f, log); err != nil {
		t.Fatal(err)
	}
}

// Other default-route devices and public network cards join the internet
// set, each once; the primary uplink and the admin interface do not.
func TestExtraWAN(t *testing.T) {
	p := plan.Default()
	p.Firewall.WANInterface = "eth0"
	p.Tailscale.AdminInterface = "eth1"
	r := &Runner{o: Options{Plan: &p}, facts: &remote.Facts{
		WANIfaces:  []string{"eth0", "he-ipv6", "eth1", "ens4"},
		PublicNICs: []string{"eth0", "ens5", "ens4", "eth1"},
	}}
	var logs []string
	got := r.extraWAN(func(l string) { logs = append(logs, l) })
	if !slices.Equal(got, []string{"he-ipv6", "ens4", "ens5"}) {
		t.Fatalf("extraWAN = %q", got)
	}
	if len(logs) != 2 || !strings.Contains(logs[0], "eth1") {
		t.Fatalf("logs = %q", logs)
	}
	// An uplink detection cannot see (a private address behind the
	// provider's NAT) joins when the plan names it.
	p.Firewall.ExtraWANInterfaces = []string{"ens10", "ens4"}
	if got := r.extraWAN(func(string) {}); !slices.Equal(got, []string{"he-ipv6", "ens4", "ens5", "ens10"}) {
		t.Fatalf("extraWAN with extra_wan_interfaces = %q", got)
	}
	p.Firewall.ExtraWANInterfaces = nil
	// An existing private network binds its rule to the admin address, so
	// its internet-facing interface is filtered like the internet.
	p.Tailscale.UseExisting, p.Tailscale.AdminAddress = true, "10.0.0.5"
	logs = nil
	got = r.extraWAN(func(l string) { logs = append(logs, l) })
	if !slices.Equal(got, []string{"he-ipv6", "eth1", "ens4", "ens5"}) || !strings.Contains(logs[0], "only accepted on 10.0.0.5") {
		t.Fatalf("existing network: extraWAN = %q, logs %q", got, logs)
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
	if !before(remoteSteps, "Cloudflare Tunnel", "Stage the firewall") {
		t.Fatalf("remote steps: %q", remoteSteps)
	}
	if remoteSteps[1] != "Update the system" || remoteSteps[n-2] != "Turn on Tailscale SSH" || remoteSteps[n-1] != "Reboot and check" {
		t.Fatalf("remote steps: %q", remoteSteps)
	}
	lp := plan.Default()
	lp.Local = true
	localSteps := New(Options{Plan: &lp, Local: &localhost.Host{}}).Steps()
	if localSteps[1] != "Update the system" || localSteps[len(localSteps)-1] != "Reboot and check after the boot" {
		t.Fatalf("local steps: %q", localSteps)
	}
	if !plan.Default().UpdateSystem || !plan.Default().Reboot || !plan.Default().AutoUpdates {
		t.Fatal("the system update, automatic updates and the reboot check are not on by default")
	}
	// Automatic updates are set up right after the update, before the
	// firewall can close anything.
	if remoteSteps[2] != autoUpdatesStep || localSteps[2] != autoUpdatesStep {
		t.Fatalf("automatic updates: remote %q, local %q", remoteSteps[2], localSteps[2])
	}
}

// The public SSH probe tells blocked (refused, timed out) from open and from
// what proves nothing about the server (a failed lookup on this side).
func TestProbePublicSSH(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	open := ln.Addr().(*net.TCPAddr).Port
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	defer ln.Close()
	for _, c := range []struct {
		host string
		port int
		want probeResult
	}{
		{"127.0.0.1", open, probeOpen},
		{"127.0.0.1", refused, probeBlocked},
		{"no-such-host.invalid", 22, probeUntested},
	} {
		p := plan.Default()
		p.Server.Host, p.Server.Port = c.host, c.port
		r := &Runner{o: Options{Plan: &p}}
		if got, detail := r.probePublicSSH(context.Background()); got != c.want {
			t.Errorf("%s:%d: %v (%s), want %v", c.host, c.port, got, detail, c.want)
		}
	}
	timeout := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	unreachable := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}
	if dialResult(timeout) != probeBlocked || dialResult(unreachable) != probeUntested {
		t.Fatal("a timeout must count as blocked, a missing route as untested")
	}
}

// A run that reached the server over the tailnet, or at the existing
// network's address, does not test public SSH there.
func TestReachedPrivately(t *testing.T) {
	r := &Runner{result: Result{AdminAddress: "10.0.0.5"}}
	if !r.reachedPrivately(netip.MustParseAddr("10.0.0.5")) || r.reachedPrivately(netip.MustParseAddr("203.0.113.7")) || r.reachedPrivately(netip.Addr{}) {
		t.Fatal("existing network address not told apart")
	}
	r.viaTailnet = true
	if !r.reachedPrivately(netip.MustParseAddr("100.64.0.5")) {
		t.Fatal("a run over the tailnet tested public SSH")
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
	tunnelDown                                bool
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
	case strings.Contains(cmd, "/ready"):
		if h.tunnelDown {
			return "", errors.New("exit status 7")
		}
		return "", nil
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
	e := BootExpect{Tailscale: true, TailscaleSSH: true, Hardened: true, Tunnel: true, User: "root", AdminAddress: "100.64.0.2", SSHPort: 22}
	if p := CheckLockdown(context.Background(), goodHost(), e); len(p) != 0 {
		t.Fatalf("healthy server reported %q", p)
	}
	for name, broken := range map[string]func(*lockdownHost){
		"rules not loaded":      func(h *lockdownHost) { h.table = "" },
		"nftables not enabled":  func(h *lockdownHost) { h.enabled = "disabled" },
		"tailscale not running": func(h *lockdownHost) { h.tsState = "NeedsLogin" },
		"tailscale ssh off":     func(h *lockdownHost) { h.tsSSH = "false" },
		"passwords back on":     func(h *lockdownHost) { h.passwords = "yes" },
		"tunnel not connected":  func(h *lockdownHost) { h.tunnelDown = true },
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

// yesPrompter answers every question with yes, like `--yes`, and counts them.
type yesPrompter struct{ asked *int }

func (p yesPrompter) ConfirmHostKey(context.Context, string, string, string) (bool, error) {
	return true, nil
}
func (p yesPrompter) Confirm(context.Context, string, string) (bool, error) {
	*p.asked++
	return true, nil
}
func (p yesPrompter) Secret(context.Context, string, string) (string, error) { return "", nil }

// With --yes the question "try again?" answers itself, so a run nobody
// answers must stop when this computer is not on the tailnet, and it must do
// so in the first step, before the server is touched.
func TestUnattendedRunStopsWithoutLocalTailscale(t *testing.T) {
	asked, ready := 0, false
	p := plan.Default()
	o := Options{Plan: &p, Prompt: yesPrompter{&asked}, Unattended: true,
		LocalTailscaleReady: func(context.Context) (bool, string) { return ready, "Tailscale is stopped." }}
	r := New(o)
	err := r.connect(context.Background(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "not on the tailnet") || asked != 0 || r.pub != nil {
		t.Fatalf("err %v, asked %d times, connected %v", err, asked, r.pub != nil)
	}
	// Someone at the keyboard is asked, and the run goes on once it is up.
	o.Unattended = false
	o.LocalTailscaleReady = func(context.Context) (bool, string) { ready = asked >= 2; return ready, "Tailscale is stopped." }
	if err := New(o).requireLocalTailscale(context.Background(), "x"); err != nil || asked != 2 {
		t.Fatalf("err %v, asked %d times", err, asked)
	}
}

// markerHost shows the rollback marker from the nth read on.
type markerHost struct {
	fakeHost
	reads *int
	from  int
}

func (h markerHost) Output(context.Context, string) (string, error) {
	*h.reads++
	if h.from > 0 && *h.reads >= h.from {
		return "2026-01-01T00:00:00Z", nil
	}
	return "", nil
}

// A failed confirmation ends as soon as the server has rolled back, not after
// a second full rollback window.
func TestWaitForRollbackPolls(t *testing.T) {
	defer func(d time.Duration) { rollbackPoll = d }(rollbackPoll)
	rollbackPoll = time.Millisecond
	p := plan.Default() // 120 s window
	r := New(Options{Plan: &p})
	r.appliedAt = time.Now()
	reads := 0
	start := time.Now()
	err := r.waitForRollback(context.Background(), markerHost{reads: &reads, from: 3}, func(string) {}, errors.New("blocked"))
	if err == nil || !strings.Contains(err.Error(), "rolled back to its previous rules at 2026-01-01T00:00:00Z") || reads != 3 || time.Since(start) > 5*time.Second {
		t.Fatalf("err %v after %d reads and %s", err, reads, time.Since(start))
	}
	// No marker by the time the timer was long due: say so instead of waiting on.
	r.appliedAt = time.Now().Add(-10 * time.Minute)
	err = r.waitForRollback(context.Background(), markerHost{reads: &reads}, func(string) {}, errors.New("blocked"))
	if err == nil || !strings.Contains(err.Error(), "left no marker") {
		t.Fatalf("err %v", err)
	}
}

// settleHost reports a pending rollback for the first reads and prints the
// facts of a server whose earlier run has rolled back.
type settleHost struct {
	fakeHost
	reads, detects *int
	pending        int
}

func (h settleHost) Output(_ context.Context, cmd string) (string, error) {
	if strings.Contains(cmd, "echo pending") {
		*h.reads++
		if *h.reads <= h.pending {
			return "pending", nil
		}
	}
	return "", nil
}

func (h settleHost) Script(_ context.Context, _ string, onLine func(string)) error {
	*h.detects++
	onLine("SS_TABLE=0")
	onLine("ROLLED_BACK=2026-01-01T00:00:00Z")
	return nil
}

// A run that finds the firewall of an earlier run still unconfirmed waits for
// its rollback and reads the facts again, instead of staging over rules that
// were never confirmed.
func TestSettleEarlierRun(t *testing.T) {
	defer func(d time.Duration) { settlePoll = d }(settlePoll)
	settlePoll = time.Millisecond
	p := plan.Default()
	var events []Event
	r := New(Options{Plan: &p, Report: func(e Event) { events = append(events, e) }})
	reads, detects := 0, 0
	h := settleHost{reads: &reads, detects: &detects, pending: 2}

	settled := &remote.Facts{SecureSetupTable: true}
	if f, err := r.settleEarlierRun(context.Background(), h, settled, func(string) {}); err != nil || f != settled || reads != 0 {
		t.Fatalf("a settled server was waited for: %v, %d reads", err, reads)
	}
	f, err := r.settleEarlierRun(context.Background(), h, &remote.Facts{SecureSetupTable: true, RollbackArmed: true}, func(string) {})
	if err != nil || reads != 3 || detects != 1 {
		t.Fatalf("err %v, %d reads, %d detects", err, reads, detects)
	}
	if f.RollbackArmed || f.SecureSetupTable || f.RolledBack == "" {
		t.Fatalf("the facts are not those after the rollback: %+v", f)
	}
	if len(events) != 1 || events[0].Kind != Attention {
		t.Fatalf("the operator was not told about the wait: %+v", events)
	}
}

// `secure-setup confirm` counts only in a session that arrived on the private
// address over a connection opened after the rules went live. One that was
// open before stays open under any rules (also when ssh shares it for a new
// session, as ControlMaster does) and proves nothing.
func TestCheckConfirm(t *testing.T) {
	ap := netip.MustParseAddrPort
	open := remote.ParseSessions("0 0 100.64.0.5:22 100.64.0.9:41000\n0 0 203.0.113.7:22 198.51.100.4:50000\n")
	expect := formatConfirmExpect("100.64.0.5", open)
	server := ap("100.64.0.5:22")
	if err := CheckConfirm(expect, ap("100.64.0.9:41001"), server); err != nil {
		t.Fatalf("a new connection was refused: %v", err)
	}
	if err := CheckConfirm(expect, ap("100.64.0.9:41000"), server); err == nil || !strings.Contains(err.Error(), "already open") {
		t.Fatalf("a connection from before the apply confirmed: %v", err)
	}
	if err := CheckConfirm(expect, ap("198.51.100.4:50001"), ap("203.0.113.7:22")); err == nil || !strings.Contains(err.Error(), "came in over 203.0.113.7, not 100.64.0.5") {
		t.Fatalf("a session over the public address confirmed: %v", err)
	}
	if err := CheckConfirm("", ap("100.64.0.9:41001"), server); err == nil || !strings.Contains(err.Error(), "nothing to confirm") {
		t.Fatalf("confirmed without a waiting run: %v", err)
	}
	if !openBefore(open, ap("100.64.0.9:41000")) || openBefore(open, ap("100.64.0.9:41001")) {
		t.Fatal("openBefore does not match by peer address and port")
	}
}

// The plan cannot know which port sshd listens on; staging refuses a public
// port that is sshd's, before anything is written.
func TestPublicPortsNeverOpenSSH(t *testing.T) {
	p := plan.Default()
	p.Server.Host, p.Firewall.WebPorts, p.Firewall.WANInterface = "203.0.113.10", nil, "eth0"
	p.Firewall.PublicTCPPorts = []int{2222}
	r := New(Options{Plan: &p})
	r.facts = &remote.Facts{SSHPort: 2222, NFT: true, PkgMgr: "apt-get"}
	var scripts []string
	err := r.stageFirewallOn(context.Background(), scriptHost{scripts: &scripts}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "open SSH to the internet again") || len(scripts) != 0 {
		t.Fatalf("err %v, scripts %q", err, scripts)
	}
	r.facts.SSHPort = 22
	p.Firewall.TailnetPorts = []int{22}
	if err := r.stageFirewallOn(context.Background(), scriptHost{scripts: &scripts}, func(string) {}); err != nil || len(scripts) == 0 {
		t.Fatalf("a public port that is not sshd's: %v", err)
	}
}

func before(steps []string, a, b string) bool {
	return slices.Index(steps, a) >= 0 && slices.Index(steps, a) < slices.Index(steps, b)
}
