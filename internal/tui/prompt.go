package tui

import (
	"context"
	"errors"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/niklas-schmidt-dev/secure-setup/internal/runner"
)

// promptKind selects the form a prompt renders as.
type promptKind int

const (
	promptConfirm promptKind = iota
	promptSecret
)

// promptMsg asks the model to show a question; the answer goes to reply.
type promptMsg struct {
	kind   promptKind
	title  string
	detail string
	reply  chan promptReply
}

type promptReply struct {
	ok    bool
	text  string
	abort bool
}

// prompter bridges runner questions (from a goroutine) into the program.
type prompter struct {
	send func(tea.Msg)
}

var errAborted = errors.New("cancelled by the user")

func (p prompter) ask(ctx context.Context, m promptMsg) (promptReply, error) {
	// Questions can carry server text, such as the name of the tailnet a
	// login link joined.
	m.title, m.detail = runner.Printable(m.title), runner.Printable(m.detail)
	m.reply = make(chan promptReply, 1)
	p.send(m)
	select {
	case <-ctx.Done():
		return promptReply{}, ctx.Err()
	case r := <-m.reply:
		if r.abort {
			return r, errAborted
		}
		return r, nil
	}
}

func (p prompter) ConfirmHostKey(ctx context.Context, addr, keyType, fingerprint string) (bool, error) {
	r, err := p.ask(ctx, promptMsg{
		kind:   promptConfirm,
		title:  "First connection to " + addr,
		detail: "The server presents this " + keyType + " key:\n" + fingerprint + "\n\nIf the provider's console shows the same fingerprint, accept it. It is then remembered in ~/.ssh/known_hosts.",
	})
	return r.ok, err
}

func (p prompter) Confirm(ctx context.Context, title, detail string) (bool, error) {
	r, err := p.ask(ctx, promptMsg{kind: promptConfirm, title: title, detail: detail})
	return r.ok, err
}

func (p prompter) Secret(ctx context.Context, title, detail string) (string, error) {
	r, err := p.ask(ctx, promptMsg{kind: promptSecret, title: title, detail: detail})
	return r.text, err
}
