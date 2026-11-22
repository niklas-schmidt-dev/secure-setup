package textui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/niklas-schmidt-dev/secure-setup/internal/runner"
)

// A run leaves a log only its owner can read, with every event and the
// summary; old logs are removed.
func TestTranscript(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir := TranscriptDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < keepTranscripts+5; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("old-%02d.log", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tr := OpenTranscript("2001:db8::10", []string{"Connect to the server", "Update the system"})
	tr.Event(runner.Event{Kind: runner.StepStart, Step: 0})
	tr.Event(runner.Event{Kind: runner.Log, Step: 0, Text: "connecting to [2001:db8::10]:22 as root"})
	tr.Event(runner.Event{Kind: runner.StepDone, Step: 0})
	tr.Event(runner.Event{Kind: runner.StepSkipped, Step: 1, Text: "not requested"})
	tr.Event(runner.Event{Kind: runner.Attention, Step: 1, Text: "look\nhere"})
	tr.Event(runner.Event{Kind: runner.StepFailed, Step: 1, Text: "it broke"})
	tr.Note("Public SSH  \x1b[33mnot tested\x1b[0m\n")
	tr.Close()
	tr.Event(runner.Event{Kind: runner.Log, Text: "after the end"}) // must not panic

	if filepath.Dir(tr.Path) != dir || !strings.HasPrefix(filepath.Base(tr.Path), "2001_db8__10-") {
		t.Fatalf("log path %q", tr.Path)
	}
	st, err := os.Stat(tr.Path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("log file: %v, mode %v", err, st.Mode())
	}
	data, _ := os.ReadFile(tr.Path)
	for _, want := range []string{" ==> Connect to the server\n", "     connecting to [2001:db8::10]:22 as root\n", "     done\n", " ==> Update the system: skipped (not requested)\n", " *** look\n         here\n", "     FAILED: it broke\n", " Public SSH  not tested\n"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("log lacks %q:\n%s", want, data)
		}
	}
	if strings.Contains(string(data), "after the end") || strings.Contains(string(data), "[33m") {
		t.Errorf("log:\n%s", data)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != keepTranscripts {
		t.Errorf("%d logs kept, want %d", len(entries), keepTranscripts)
	}
	// No place for a log: the run goes on without one.
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", blocked)
	none := OpenTranscript("x", nil)
	none.Event(runner.Event{Kind: runner.Log, Text: "x"})
	none.Note("x")
	none.Close()
	if none.Path != "" {
		t.Fatalf("log at %q", none.Path)
	}
}
