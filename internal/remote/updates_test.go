package remote

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// bareHost is a server on which no command is installed yet.
type bareHost struct{ recordHost }

func (h *bareHost) Output(context.Context, string) (string, error) {
	return "", errors.New("exit status 127")
}

// On Debian and Ubuntu the package is installed, the setting goes into its
// own apt file, and the run fails when apt would not act on it.
func TestEnableAutoUpdatesAPT(t *testing.T) {
	h := &bareHost{}
	note, err := EnableAutoUpdates(context.Background(), h, &Facts{PkgMgr: "apt-get"}, func(string) {})
	if err != nil || note != "" {
		t.Fatalf("note %q, err %v", note, err)
	}
	conf := h.files[AutoUpdatesAPT]
	for _, want := range []string{`APT::Periodic::Update-Package-Lists "1";`, `APT::Periodic::Unattended-Upgrade "1";`, "Managed by secure-setup"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("%s lacks %q:\n%s", AutoUpdatesAPT, want, conf)
		}
	}
	all := h.all()
	if !strings.Contains(all, "apt-get install -y -q --no-install-recommends unattended-upgrades") || !strings.Contains(all, "apt-daily-upgrade.timer") {
		t.Fatalf("scripts:\n%s", all)
	}
	// Already installed (a rerun): no package manager call.
	again := &recordHost{}
	if _, err := EnableAutoUpdates(context.Background(), again, &Facts{PkgMgr: "apt-get"}, func(string) {}); err != nil || strings.Contains(again.all(), "apt-get install") {
		t.Fatalf("err %v, scripts:\n%s", err, again.all())
	}
	// No recipe for this package manager: nothing changes, and the note says why.
	none := &recordHost{}
	note, err = EnableAutoUpdates(context.Background(), none, &Facts{PkgMgr: "pacman"}, func(string) {})
	if err != nil || !strings.Contains(note, "pacman") || len(none.scripts) != 0 || len(none.files) != 0 {
		t.Fatalf("note %q, err %v, scripts %q", note, err, none.scripts)
	}
}

// The dnf script picks what installs: dnf 4's own install timer, or dnf 5's
// single timer with --installupdates added to its service through a drop-in,
// which undo removes again whoever enabled the timer. Run with systemctl
// stubbed.
func TestAutoUpdatesDNFScript(t *testing.T) {
	type result struct {
		out, enabled, dropIn string
		err                  error
	}
	run := func(units, script string, dir string) result {
		t.Helper()
		bin, dropIn := filepath.Join(dir, "bin"), filepath.Join(dir, "dropin", "secure-setup.conf")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		// systemctl cat succeeds for the listed units and prints the service's
		// command, with the drop-in's once it exists. is-enabled reads "on".
		stub := "#!/bin/sh\ncase \"$1\" in\ncat) case \" " + units + " \" in *\" $2 \"*) ;; *) exit 1 ;; esac\n" +
			"  if [ \"$2\" = dnf5-automatic.service ]; then echo 'ExecStart=/usr/bin/dnf5 automatic --timer'; cat " + dropIn + " 2>/dev/null; fi ;;\n" +
			"is-enabled) [ -e " + filepath.Join(dir, "on") + " ] || exit 1 ;;\nenable) : > " + filepath.Join(dir, "on") + " ;;\ndisable) rm -f " + filepath.Join(dir, "on") + " ;;\nesac\nexit 0\n"
		if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
		script = strings.ReplaceAll(script, AutoUpdatesDNF5, dropIn)
		script = strings.ReplaceAll(script, StateDir, filepath.Join(dir, "state"))
		cmd := exec.Command("sh", "-c", "set -eu\n"+script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		b, err := cmd.CombinedOutput()
		st, _ := os.ReadFile(filepath.Join(dir, "state", "auto-updates-timer"))
		w, _ := os.ReadFile(dropIn)
		return result{string(b), strings.TrimSpace(string(st)), string(w), err}
	}
	if r := run("dnf-automatic.timer dnf-automatic-install.timer", autoUpdatesDNFScript, t.TempDir()); r.err != nil || r.enabled != "dnf-automatic-install.timer" || r.dropIn != "" {
		t.Fatalf("dnf 4: %v %q, enabled %q, drop-in %q", r.err, r.out, r.enabled, r.dropIn)
	}
	dnf5 := "dnf5-automatic.timer dnf5-automatic.service"
	dir := t.TempDir()
	r := run(dnf5, autoUpdatesDNFScript, dir)
	if r.err != nil || r.enabled != "dnf5-automatic.timer" || !strings.Contains(r.dropIn, "ExecStart=\nExecStart=/usr/bin/dnf5 automatic --timer --installupdates\n") {
		t.Fatalf("dnf 5: %v %q, enabled %q, drop-in %q", r.err, r.out, r.enabled, r.dropIn)
	}
	// A second run changes nothing, and undo takes the drop-in away.
	if again := run(dnf5, autoUpdatesDNFScript, dir); again.err != nil || again.dropIn != r.dropIn {
		t.Fatalf("dnf 5 again: %v %q, drop-in %q", again.err, again.out, again.dropIn)
	}
	if undone := run(dnf5, UndoAutoUpdatesScript, dir); undone.err != nil || undone.dropIn != "" {
		t.Fatalf("undo: %v %q, drop-in %q", undone.err, undone.out, undone.dropIn)
	}
	// The timer was on before: undo leaves it on, but still removes the drop-in.
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "on"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if r := run(dnf5, autoUpdatesDNFScript, dir); r.err != nil || r.enabled != "" || r.dropIn == "" {
		t.Fatalf("dnf 5 with its timer already on: %v %q, enabled %q", r.err, r.out, r.enabled)
	}
	if undone := run(dnf5, UndoAutoUpdatesScript, dir); undone.err != nil || undone.dropIn != "" {
		t.Fatalf("undo with the timer already on: %v %q, drop-in %q", undone.err, undone.out, undone.dropIn)
	}
	if _, err := os.Stat(filepath.Join(dir, "on")); err != nil {
		t.Fatal("undo switched off a timer that was on before")
	}
	if r := run("", autoUpdatesDNFScript, t.TempDir()); r.err == nil || !strings.Contains(r.out, "no timer") {
		t.Fatalf("no timer at all: %v %q", r.err, r.out)
	}
}
