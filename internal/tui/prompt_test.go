package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// A question that carries server text (the tailnet a login link joined)
// reaches the form without terminal control sequences.
func TestPromptCleansServerText(t *testing.T) {
	var got promptMsg
	p := prompter{send: func(m tea.Msg) {
		got = m.(promptMsg)
		got.reply <- promptReply{ok: true}
	}}
	if _, err := p.Confirm(context.Background(), "Is evil\x1b]52;c;ZXZpbA==\a your tailnet?", "joined\x1b[2J it"); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(got.title+got.detail, "\x1b\a") || !strings.Contains(got.title, "your tailnet?") {
		t.Fatalf("prompt not cleaned: %q %q", got.title, got.detail)
	}
}
