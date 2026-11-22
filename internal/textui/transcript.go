package textui

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/niklas-schmidt-dev/secure-setup/internal/plan"
	"github.com/niklas-schmidt-dev/secure-setup/internal/runner"
)

// keepTranscripts is how many run logs stay in the log directory.
const keepTranscripts = 20

// Transcript is the log file of one run: every step, output line and notice
// with its time, to read after the wizard's screen or the terminal is gone.
type Transcript struct {
	Path  string // "" when the file could not be created
	f     *os.File
	steps []string
}

// TranscriptDir is ~/.config/secure-setup/logs.
func TranscriptDir() string { return filepath.Join(plan.ConfigDir(), "logs") }

// OpenTranscript starts the log of a run on name (a server address, or
// "this-machine"). A run goes on without a log when the file cannot be
// created: Path is empty then and nothing is written.
func OpenTranscript(name string, steps []string) *Transcript {
	t := &Transcript{steps: steps}
	dir := TranscriptDir()
	// Without a home directory (some first-boot environments) there is no
	// place of the user's own, and the current directory is not one.
	if !filepath.IsAbs(dir) {
		return t
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return t
	}
	prune(dir)
	path := filepath.Join(dir, plan.SafeName(name)+"-"+time.Now().Format("20060102-150405")+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return t
	}
	t.Path, t.f = path, f
	return t
}

// prune removes all but the newest logs; their names sort by time per server,
// so the modification time decides.
func prune(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type logFile struct {
		name string
		mod  time.Time
	}
	var logs []logFile
	for _, e := range entries {
		if info, err := e.Info(); err == nil && !e.IsDir() && strings.HasSuffix(e.Name(), ".log") {
			logs = append(logs, logFile{e.Name(), info.ModTime()})
		}
	}
	sort.Slice(logs, func(i, j int) bool { return logs[i].mod.After(logs[j].mod) })
	for i := keepTranscripts - 1; i < len(logs); i++ {
		_ = os.Remove(filepath.Join(dir, logs[i].name))
	}
}

func (t *Transcript) line(format string, args ...any) {
	if t.f == nil {
		return
	}
	text := strings.ReplaceAll(fmt.Sprintf(format, args...), "\n", "\n         ")
	fmt.Fprintf(t.f, "%s %s\n", time.Now().Format("15:04:05"), text)
}

// Event writes one runner event.
func (t *Transcript) Event(e runner.Event) {
	name := "?"
	if e.Step >= 0 && e.Step < len(t.steps) {
		name = t.steps[e.Step]
	}
	switch e.Kind {
	case runner.StepStart:
		t.line("==> %s", name)
	case runner.StepDone:
		t.line("    done")
	case runner.StepSkipped:
		t.line("==> %s: skipped (%s)", name, e.Text)
	case runner.StepFailed:
		t.line("    FAILED: %s", e.Text)
	case runner.Log:
		t.line("    %s", e.Text)
	case runner.Attention:
		t.line("*** %s", e.Text)
	}
}

// colorRe matches the colour codes of text styled for a terminal.
var colorRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

// Note writes text that is no event, such as the summary of a finished run.
func (t *Transcript) Note(text string) {
	t.line("%s", runner.Printable(colorRe.ReplaceAllString(strings.TrimRight(text, "\n"), "")))
}

// Close ends the log.
func (t *Transcript) Close() {
	if t.f != nil {
		_ = t.f.Close()
		t.f = nil
	}
}
