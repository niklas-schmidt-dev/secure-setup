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

// The dnf script picks the timer that installs: dnf 4's own install timer, or
// dnf 5's single timer with apply_updates = yes, which it writes unless a
// configuration is already there. Run with systemctl stubbed.
func TestAutoUpdatesDNFScript(t *testing.T) {
	run := func(units string, conf string) (out string, err error, state, written string) {
		t.Helper()
		dir := t.TempDir()
		bin := filepath.Join(dir, "bin")
		if err := os.Mkdir(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		// systemctl cat succeeds for the listed units; nothing is enabled yet.
		stub := "#!/bin/sh\ncase \"$1\" in\ncat) case \" " + units + " \" in *\" $2 \"*) exit 0 ;; esac; exit 1 ;;\nis-enabled) exit 1 ;;\nenable) echo \"$*\" >> " + filepath.Join(dir, "calls") + " ;;\nesac\nexit 0\n"
		if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
		confPath := filepath.Join(dir, "etc", "automatic.conf")
		if conf != "" {
			if err := os.MkdirAll(filepath.Dir(confPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		script := strings.ReplaceAll(autoUpdatesDNFScript, StateDir, filepath.Join(dir, "state"))
		script = strings.ReplaceAll(script, AutoUpdatesDNF5, confPath)
		cmd := exec.Command("sh", "-c", "set -eu\n"+script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		b, err := cmd.CombinedOutput()
		st, _ := os.ReadFile(filepath.Join(dir, "state", "auto-updates-timer"))
		w, _ := os.ReadFile(confPath)
		return string(b), err, strings.TrimSpace(string(st)), string(w)
	}
	if out, err, state, written := run("dnf-automatic.timer dnf-automatic-install.timer", ""); err != nil || state != "dnf-automatic-install.timer" || written != "" {
		t.Fatalf("dnf 4: %v %q, enabled %q, wrote %q", err, out, state, written)
	}
	if out, err, state, written := run("dnf-automatic.timer dnf5-automatic.timer", ""); err != nil || state != "dnf5-automatic.timer" || !strings.Contains(written, "apply_updates = yes") {
		t.Fatalf("dnf 5: %v %q, enabled %q, wrote %q", err, out, state, written)
	}
	mine := "[commands]\napply_updates = no\n"
	if out, err, _, written := run("dnf5-automatic.timer", mine); err == nil || written != mine || !strings.Contains(out, "does not set apply_updates = yes") {
		t.Fatalf("dnf 5 with the admin's own configuration: %v %q, file %q", err, out, written)
	}
	if out, err, _, _ := run("", ""); err == nil || !strings.Contains(out, "no timer") {
		t.Fatalf("no timer at all: %v %q", err, out)
	}
}

// TestDumpDNFScript writes the script to the file named in DUMP_DNF_SCRIPT,
// to try it by hand on a real Fedora or Rocky system.
func TestDumpDNFScript(t *testing.T) {
	if p := os.Getenv("DUMP_DNF_SCRIPT"); p != "" {
		if err := os.WriteFile(p, []byte("set -eu\n"+autoUpdatesDNFScript+"\n"+UndoAutoUpdatesScript), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
