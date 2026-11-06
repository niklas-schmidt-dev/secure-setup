package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/niklas-schmidt-dev/secure-setup/internal/plan"
)

var ctrlC = tea.KeyMsg{Type: tea.KeyCtrlC}

func isQuit(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	_, ok := cmd().(tea.QuitMsg)
	return ok
}

func runningModel(t *testing.T) (*model, context.Context) {
	t.Helper()
	p := plan.Default()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m := newModel(ctx, cancel, &p, "test")
	m.phase, m.form, m.running = phaseRun, nil, true
	return m, ctx
}

// ctrl+c during a run cancels it, but the wizard stays until the runner has
// cleaned up and returned; only then does q leave.
func TestCtrlCWaitsForTheRunToCleanUp(t *testing.T) {
	m, ctx := runningModel(t)
	m.attention = []string{"Now prove the new rules let you in"}
	if _, cmd := m.Update(ctrlC); isQuit(cmd) {
		t.Fatal("the wizard quit while the run was still cleaning up")
	}
	if ctx.Err() == nil {
		t.Fatal("ctrl+c did not cancel the run")
	}
	v := m.View()
	if !strings.Contains(v, "Stopping") || strings.Contains(v, "prove the new rules") {
		t.Fatalf("run screen after ctrl+c:\n%s", v)
	}
	m.Update(runDoneMsg{err: fmt.Errorf("Wait for the login: %w", context.Canceled)})
	if m.phase != phaseDone || m.running {
		t.Fatalf("phase %v, running %v after the runner returned", m.phase, m.running)
	}
	if v := m.View(); !strings.Contains(v, "Setup stopped") {
		t.Fatalf("done screen after an abort:\n%s", v)
	}
	if _, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")}); !isQuit(cmd) {
		t.Fatal("q did not leave the done screen")
	}
}

// A cancelled step may fail with an error that is not context.Canceled (a
// killed command); the wizard still exits as aborted.
func TestAbortedRunExitsAsAborted(t *testing.T) {
	m, _ := runningModel(t)
	m.Update(ctrlC)
	m.Update(runDoneMsg{err: errors.New("Update the system: signal: killed")})
	if err := m.exitErr(); !errors.Is(err, context.Canceled) {
		t.Fatalf("exit error %v, want context.Canceled", err)
	}
	m, _ = runningModel(t)
	failed := errors.New("Connect: no route to host")
	m.Update(runDoneMsg{err: failed})
	if err := m.exitErr(); err != failed {
		t.Fatalf("a failed run without an abort returned %v", err)
	}
}

// A second ctrl+c leaves without waiting.
func TestSecondCtrlCLeavesAtOnce(t *testing.T) {
	m, _ := runningModel(t)
	m.Update(ctrlC)
	if _, cmd := m.Update(ctrlC); !isQuit(cmd) {
		t.Fatal("the second ctrl+c did not leave")
	}
}

// SIGINT and SIGTERM reach the model as abortMsg and wait the same way, but
// nobody is there to press q: the wizard leaves once the run has returned.
func TestSignalWaitsThenLeaves(t *testing.T) {
	m, ctx := runningModel(t)
	if _, cmd := m.Update(abortMsg{}); isQuit(cmd) || ctx.Err() == nil {
		t.Fatal("a signal during the run did not cancel it and wait")
	}
	if _, cmd := m.Update(runDoneMsg{err: context.Canceled}); !isQuit(cmd) {
		t.Fatal("the wizard did not leave after the signalled run returned")
	}
}

// Before the run starts there is nothing to undo: ctrl+c leaves at once.
func TestCtrlCBeforeTheRunQuits(t *testing.T) {
	p := plan.Default()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newModel(ctx, cancel, &p, "test")
	if _, cmd := m.Update(ctrlC); !isQuit(cmd) || !m.aborted {
		t.Fatal("ctrl+c on the first form did not leave")
	}
}

// A question the runner sent just before the cancel is answered with an
// abort instead of showing a form nobody waits for.
func TestQuestionAfterAbortIsNotShown(t *testing.T) {
	m, _ := runningModel(t)
	m.Update(ctrlC)
	reply := make(chan promptReply, 1)
	m.Update(promptMsg{kind: promptConfirm, title: "Is this your tailnet?", reply: reply})
	if m.promptForm != nil {
		t.Fatal("a question was shown after the abort")
	}
	if r := <-reply; !r.abort {
		t.Fatalf("reply %+v, want abort", r)
	}
}
