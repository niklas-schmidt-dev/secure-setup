package remote

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// recordHost captures what would run on the server.
type recordHost struct {
	scripts []string
	files   map[string]string
	output  func(cmd string) string
	stdout  func(script string) string // lines a script prints, when set
}

func (h *recordHost) Output(_ context.Context, cmd string) (string, error) {
	if h.output != nil {
		return h.output(cmd), nil
	}
	return "", nil
}

func (h *recordHost) Script(_ context.Context, s string, onLine func(string)) error {
	h.scripts = append(h.scripts, s)
	if h.stdout != nil && onLine != nil {
		for _, l := range strings.Split(h.stdout(s), "\n") {
			onLine(l)
		}
	}
	return nil
}

func (h *recordHost) WriteFile(_ context.Context, path string, data []byte, _ string) error {
	if h.files == nil {
		h.files = map[string]string{}
	}
	h.files[path] = string(data)
	return nil
}

func (h *recordHost) all() string { return strings.Join(h.scripts, "\n") }

// Staging must not stop the running host firewall: before the rollback timer
// exists nothing could bring it back.
func TestPrepareDoesNotRetireHostFirewall(t *testing.T) {
	h := &recordHost{}
	f := &Facts{PkgMgr: "apt-get", NFT: true, UFWActive: true, FirewalldActive: true}
	if err := PrepareFirewall(context.Background(), h, f, FirewallFiles{Ruleset: "x", Elements: "y"}, func(string) {}); err != nil {
		t.Fatal(err)
	}
	all := h.all()
	for _, bad := range []string{"ufw --force disable", "disable --now ufw", "disable --now firewalld", "systemctl stop firewalld"} {
		if strings.Contains(all, bad) {
			t.Fatalf("staging runs %q", bad)
		}
	}
	for _, want := range []string{"touch " + UFWWasActive, "touch " + FirewalldWasActive} {
		if !strings.Contains(all, want) {
			t.Fatalf("staging does not record %q", want)
		}
	}
}

// Apply stops the host firewall only after the timer is armed, and brings it
// back when the new rules fail to load; the rollback brings it back too.
func TestApplyAndRollbackRestoreHostFirewall(t *testing.T) {
	h := &recordHost{}
	if err := ApplyFirewall(context.Background(), h, 60, func(string) {}); err != nil {
		t.Fatal(err)
	}
	s := h.all()
	armed, stop, load := strings.Index(s, "systemd-run"), strings.Index(s, `"$ufw_init" stop`), strings.Index(s, "nft -f ")
	if armed < 0 || stop < armed || load < stop {
		t.Fatalf("order must be: arm timer, stop host firewall, load rules:\n%s", s)
	}
	// ufw stays enabled at boot until the rules are confirmed, so a reboot
	// inside the rollback window brings it back.
	if strings.Index(s, "ufw --force disable") < strings.Index(s, "else ufw --force disable") {
		t.Fatal("apply disables ufw at boot when ufw-init exists")
	}
	if !strings.Contains(s, `"$ufw_init" start`) || !strings.Contains(s, "systemctl start firewalld") {
		t.Fatal("failed apply does not restart the host firewall")
	}
	rb := asset("rollback.sh")
	if !strings.Contains(rb, `"$ufw_init" start`) || !strings.Contains(rb, "systemctl start firewalld") {
		t.Fatal("rollback.sh does not restart the host firewall")
	}
}

// Confirmation retires the host firewall for good, and masks a firewalld
// that is enabled at boot even when it was not running.
func TestConfirmRetiresAndMasks(t *testing.T) {
	h := &recordHost{}
	if err := ConfirmFirewall(context.Background(), h, &Facts{ID: "rocky"}, false, func(string) {}); err != nil {
		t.Fatal(err)
	}
	s := h.all()
	timer, mask := strings.Index(s, "systemctl stop "+RollbackUnit+".timer"), strings.Index(s, "systemctl mask firewalld")
	if timer < 0 || mask < timer {
		t.Fatalf("firewalld must be masked after the rollback timer is cancelled:\n%s", s)
	}
	if !strings.Contains(s, FirewalldWasEnabled) {
		t.Fatal("an enabled-but-stopped firewalld is not handled")
	}
	if d := strings.Index(s, "ufw --force disable"); d < timer {
		t.Fatal("ufw is not disabled at boot after confirmation")
	}
}

func TestDetectReadsFirewalldEnablement(t *testing.T) {
	if !strings.Contains(detectScript, "is-enabled --quiet firewalld") {
		t.Fatal("detect does not ask whether firewalld is enabled at boot")
	}
}

// Every device with a default route is internet-facing, the IPv4 one first.
func TestDetectListsEveryDefaultRouteDevice(t *testing.T) {
	for _, c := range []struct {
		out     string
		primary string
		all     []string
	}{
		{"SYSTEMD=1\nWAN=eth0\nWAN6=he-ipv6\nWANS=eth0 eth0 he-ipv6 \n", "eth0", []string{"eth0", "he-ipv6"}},
		{"SYSTEMD=1\nWAN=\nWAN6=ens3\nWANS=ens3 \n", "ens3", []string{"ens3"}},
		{"SYSTEMD=1\nWAN=\nWAN6=\nWANS=\n", "", nil},
	} {
		f, err := Detect(context.Background(), &recordHost{stdout: func(string) string { return c.out }})
		if err != nil {
			t.Fatal(err)
		}
		if f.WANIface != c.primary || !slices.Equal(f.WANIfaces, c.all) {
			t.Fatalf("%q: WANIface %q WANIfaces %q, want %q %q", c.out, f.WANIface, f.WANIfaces, c.primary, c.all)
		}
	}
}

// HardenSSHD keeps a stricter root-login policy.
func TestHardenKeepsStricterPermitRootLogin(t *testing.T) {
	for cur, want := range map[string]string{"no": "PermitRootLogin no", "forced-commands-only": "PermitRootLogin forced-commands-only", "yes": "PermitRootLogin prohibit-password", "without-password": "PermitRootLogin prohibit-password"} {
		h := &recordHost{output: func(string) string { return cur }}
		if _, err := HardenSSHD(context.Background(), h, func(string) {}); err != nil {
			t.Fatal(err)
		}
		if got := h.files[dropInPath]; !strings.Contains(got, want) {
			t.Fatalf("current %q: drop-in has %q, want %q", cur, got, want)
		}
	}
	if !strings.Contains(applySSHDScript, "rm -f "+dropInPath) {
		t.Fatal("a rejected configuration does not remove the drop-in")
	}
}

func TestVerifySSHDFindsRemainingPasswordAuth(t *testing.T) {
	yes := &recordHost{output: func(cmd string) string {
		if strings.Contains(cmd, "addr=100.64.0.1") {
			return "passwordauthentication yes\nkbdinteractiveauthentication no"
		}
		return "passwordauthentication no\nkbdinteractiveauthentication no"
	}}
	if err := VerifySSHD(context.Background(), yes, "root", "100.64.0.10", 22, "203.0.113.1", "100.64.0.1"); err == nil {
		t.Fatal("a Match block that keeps passwords on was not detected")
	}
	no := &recordHost{output: func(cmd string) string {
		if strings.Contains(cmd, "awk") {
			return "" // no Match block enables passwords
		}
		return "passwordauthentication no\nkbdinteractiveauthentication no"
	}}
	if err := VerifySSHD(context.Background(), no, "root", "100.64.0.10", 22, "203.0.113.1"); err != nil {
		t.Fatal(err)
	}
	match := &recordHost{output: func(cmd string) string {
		if strings.Contains(cmd, "awk") {
			return "/etc/ssh/sshd_config:120: PasswordAuthentication yes"
		}
		return "passwordauthentication no\nkbdinteractiveauthentication no"
	}}
	if err := VerifySSHD(context.Background(), match, "root", "100.64.0.10", 22, "203.0.113.1"); err == nil {
		t.Fatal("a Match block outside the probed connections was not reported")
	}
}

// The Match scan runs with the system's sh and awk on real files: a Match
// for another user or range that enables passwords is found, also in a file
// pulled in by a top-level Include; everything outside Match blocks and
// every "no" is ignored, and Includes it cannot follow are reported.
func TestMatchPasswordScript(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("sshd_config", "Include "+filepath.Join(dir, "extra.conf")+"\nPasswordAuthentication yes\n#Match User anoncvs\n#\tPasswordAuthentication yes\nMatch User alice\n\tX11Forwarding no\n\tPasswordAuthentication no\nMatch Address 100.100.0.0/16\n    passwordauthentication=YES\n")
	write("d/50-cloud.conf", "PasswordAuthentication yes\n")
	write("d/60-match.conf", "Match Group admins\n  KbdInteractiveAuthentication yes\n")
	write("extra.conf", "Include /nowhere/*.conf\nMatch User bob\n  PasswordAuthentication yes\n")
	write("d/65-include.conf", "Match User alice\n  Include /etc/ssh/passwords.conf\n")
	write("d/66-quoted.conf", "Include \"/etc/ssh/extra.conf\"\n")
	write("d/70-ok.conf", "Match all\n  PasswordAuthentication no\n")
	out, err := exec.Command("sh", "-c", matchPasswordScript(filepath.Join(dir, "sshd_config")+" "+filepath.Join(dir, "d", "*.conf"))).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	got := strings.Split(strings.TrimSpace(string(out)), "\n")
	want := []string{
		"sshd_config:9: passwordauthentication YES",
		"60-match.conf:2: KbdInteractiveAuthentication yes",
		"65-include.conf:2: Include /etc/ssh/passwords.conf (an Include inside a Match block)",
		`66-quoted.conf:1: Include "/etc/ssh/extra.conf" (a quoted Include)`,
		"extra.conf:1: Include /nowhere/*.conf (a nested Include)",
		"extra.conf:3: PasswordAuthentication yes",
	}
	if len(got) != len(want) {
		t.Fatalf("scan found %q", got)
	}
	for i := range want {
		if !strings.HasSuffix(got[i], want[i]) {
			t.Fatalf("scan found %q, want %q at %d", got, want[i], i)
		}
	}
}

// A run that fails puts back the drop-in an earlier run left, and only
// removes the hardening when there was none before.
func TestRestoreSSHDKeepsEarlierRun(t *testing.T) {
	earlier := "PasswordAuthentication no\nPermitRootLogin no\n"
	h := &recordHost{output: func(cmd string) string {
		if strings.Contains(cmd, "echo present") {
			return "present\n" + earlier
		}
		return "no"
	}}
	prev, err := HardenSSHD(context.Background(), h, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if prev != earlier {
		t.Fatalf("prev = %q, want %q", prev, earlier)
	}
	if err := RestoreSSHD(context.Background(), h, prev, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if h.files[dropInPath] != earlier || strings.Contains(h.all(), "rm -f "+dropInPath+"\nsed") {
		t.Fatalf("earlier drop-in not restored: %q", h.files[dropInPath])
	}
	fresh := &recordHost{output: func(string) string { return "" }}
	if err := RestoreSSHD(context.Background(), fresh, "", func(string) {}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fresh.all(), RevertSSHDScript) {
		t.Fatal("without an earlier drop-in the hardening is not removed")
	}
}

// The boot file comes from nftables.service itself, parsed with the
// system's sh and sed from what `systemctl show` prints.
func TestNFTBootFileScript(t *testing.T) {
	for show, want := range map[string]string{
		"{ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f /etc/nftables.conf ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }":   "/etc/nftables.conf",
		"{ path=/sbin/nft ; argv[]=/sbin/nft -f /etc/sysconfig/nftables.conf ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }": "/etc/sysconfig/nftables.conf",
		"{ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -I /etc/nftables --file /etc/nftables/main.nft ; ignore_errors=no }":                                                  "/etc/nftables/main.nft",
		"": "",
	} {
		dir := t.TempDir()
		stub := "#!/bin/sh\nprintf '%s\\n' '" + show + "'\n"
		if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", "-c", NFTBootFileScript+`printf '%s' "$boot"`)
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if string(out) != want {
			t.Fatalf("show %q: boot %q, want %q", show, out, want)
		}
	}
}

// Staging refuses a system whose nftables.service loads no file, and
// confirmation wires the ruleset into whatever file it loads.
func TestBootFileWiring(t *testing.T) {
	h := &recordHost{}
	if err := PrepareFirewall(context.Background(), h, &Facts{NFT: true}, FirewallFiles{Ruleset: "x"}, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h.scripts[0], NFTBootFileScript) || !strings.Contains(h.scripts[0], `if [ -z "$boot" ]`) {
		t.Fatal("staging does not check the boot file first")
	}
	h = &recordHost{}
	if err := ConfirmFirewall(context.Background(), h, &Facts{}, false, func(string) {}); err != nil {
		t.Fatal(err)
	}
	s := h.all()
	check, dry, stop := strings.Index(s, `if [ -z "$boot" ]`), strings.Index(s, `nft -c -f "$check"`), strings.Index(s, "systemctl stop "+RollbackUnit+".timer")
	if check < 0 || dry < check || stop < dry {
		t.Fatal("the boot file is not dry-run with the new rules before the rollback timer is cancelled")
	}
	// The host firewall is retired only after the rules are persisted and
	// loaded by nftables.service, so a failure leaves it enabled at boot.
	start, retire := strings.Index(s, "systemctl start nftables"), strings.Index(s, "ufw --force disable")
	if start < stop || retire < start {
		t.Fatal("ufw/firewalld are retired before persistence succeeded")
	}
	for _, want := range []string{bootIncludeMarker, `nft -c -f "$boot"`, "systemctl enable nftables"} {
		if !strings.Contains(s, want) {
			t.Fatalf("confirm script lacks %q", want)
		}
	}
	if strings.Contains(s, "sysconfig") {
		t.Fatal("confirm still hard-codes a distribution path")
	}
}

// The join never turns Tailscale SSH on; that waits until the tailnet is
// known to be the operator's.
func TestTailscaleUpLeavesSSHOff(t *testing.T) {
	h := &recordHost{}
	if err := TailscaleUp(context.Background(), h, UpOptions{Hostname: "srv"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h.all(), "--ssh") || !strings.Contains(h.all(), "tailscale up") {
		t.Fatalf("join script: %s", h.all())
	}
	h = &recordHost{}
	if err := TailscaleSetSSH(context.Background(), h, true, nil); err != nil || !strings.Contains(h.all(), "tailscale set --ssh=true") {
		t.Fatalf("set ssh: %v %s", err, h.all())
	}
}

func TestTailnetName(t *testing.T) {
	for _, c := range []struct {
		json, want string
	}{
		{`{"MagicDNSSuffix":"tail1234.ts.net","CurrentTailnet":{"Name":"alice@example.com"}}`, "alice@example.com (tail1234.ts.net)"},
		{`{"MagicDNSSuffix":"","Self":{"DNSName":"srv.other-tailnet.ts.net."}}`, "other-tailnet.ts.net"},
		{`{}`, "unknown"},
	} {
		var st TSStatus
		if err := json.Unmarshal([]byte(c.json), &st); err != nil {
			t.Fatal(err)
		}
		if got := st.Tailnet(); got != c.want {
			t.Fatalf("%s: %q, want %q", c.json, got, c.want)
		}
	}
}

func TestTailscaleSSHOn(t *testing.T) {
	for out, want := range map[string]bool{`{"RunSSH": true, "WantRunning": true}`: true, `{"RunSSH": false}`: false, "": false} {
		if got := TailscaleSSHOn(context.Background(), &recordHost{output: func(string) string { return out }}); got != want {
			t.Fatalf("%q: %v, want %v", out, got, want)
		}
	}
}

// The update uses each package manager non-interactively and reports a
// pending reboot instead of printing the marker.
func TestUpdateSystem(t *testing.T) {
	for mgr, want := range map[string]string{
		"apt-get": "apt-get upgrade -y -q -o DPkg::Lock::Timeout=300",
		"dnf":     "dnf upgrade -y",
		"pacman":  "pacman -Syu --noconfirm",
		"zypper":  "zypper --non-interactive update",
	} {
		var lines []string
		h := &recordHost{stdout: func(string) string { return "Setting up openssl\nREBOOT_REQUIRED" }}
		reboot, err := UpdateSystem(context.Background(), h, &Facts{PkgMgr: mgr}, func(l string) { lines = append(lines, l) })
		if err != nil || !reboot || !strings.Contains(h.all(), want) || slices.Contains(lines, "REBOOT_REQUIRED") {
			t.Fatalf("%s: reboot %v err %v lines %q script %s", mgr, reboot, err, lines, h.all())
		}
	}
	if _, err := UpdateSystem(context.Background(), &recordHost{}, &Facts{}, nil); err == nil {
		t.Fatal("no package manager accepted")
	}
}
