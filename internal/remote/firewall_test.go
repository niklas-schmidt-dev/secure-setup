package remote

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// recordHost captures what would run on the server.
type recordHost struct {
	scripts []string
	files   map[string]string
	output  func(cmd string) string
}

func (h *recordHost) Output(_ context.Context, cmd string) (string, error) {
	if h.output != nil {
		return h.output(cmd), nil
	}
	return "", nil
}

func (h *recordHost) Script(_ context.Context, s string, _ func(string)) error {
	h.scripts = append(h.scripts, s)
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
	armed, stop, load := strings.Index(s, "systemd-run"), strings.Index(s, "ufw --force disable"), strings.Index(s, "nft -f ")
	if armed < 0 || stop < armed || load < stop {
		t.Fatalf("order must be: arm timer, stop host firewall, load rules:\n%s", s)
	}
	if !strings.Contains(s, "ufw --force enable") || !strings.Contains(s, "systemctl start firewalld") {
		t.Fatal("failed apply does not restart the host firewall")
	}
	rb := asset("rollback.sh")
	if !strings.Contains(rb, "ufw --force enable") || !strings.Contains(rb, "systemctl start firewalld") {
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
}

func TestDetectReadsFirewalldEnablement(t *testing.T) {
	if !strings.Contains(detectScript, "is-enabled --quiet firewalld") {
		t.Fatal("detect does not ask whether firewalld is enabled at boot")
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
