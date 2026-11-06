// Package textui drives a run without a TUI: plain lines on stdout, questions
// on the terminal. Used by `secure-setup apply`.
package textui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/niklas-schmidt-dev/secure-setup/internal/runner"
)

// Prompter answers on the terminal, or automatically with Yes.
type Prompter struct {
	AssumeYes bool
	In        io.Reader
	Out       io.Writer
}

func (p Prompter) out() io.Writer {
	if p.Out == nil {
		return os.Stdout
	}
	return p.Out
}

func (p Prompter) ConfirmHostKey(ctx context.Context, addr, keyType, fingerprint string) (bool, error) {
	fmt.Fprintf(p.out(), "\nFirst connection to %s. Server key: %s %s\n", addr, keyType, fingerprint)
	if p.AssumeYes {
		fmt.Fprintln(p.out(), "accepted (--yes) and remembered in ~/.ssh/known_hosts")
		return true, nil
	}
	return p.Confirm(ctx, "Accept this host key?", "")
}

func (p Prompter) Confirm(ctx context.Context, title, detail string) (bool, error) {
	if detail != "" {
		fmt.Fprintln(p.out(), detail)
	}
	if p.AssumeYes {
		fmt.Fprintf(p.out(), "%s yes (--yes)\n", title)
		return true, nil
	}
	in := p.In
	if in == nil {
		in = os.Stdin
	}
	r := bufio.NewReader(in)
	for {
		fmt.Fprintf(p.out(), "%s [y/N] ", title)
		line, err := r.ReadString('\n')
		if err != nil {
			return false, errors.New("no terminal to answer on; use --yes")
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true, nil
		case "n", "no", "":
			return false, nil
		}
	}
}

func (p Prompter) Secret(ctx context.Context, title, detail string) (string, error) {
	if detail != "" {
		fmt.Fprintln(p.out(), detail)
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("%s: no terminal to read it from (set SECURE_SETUP_PASSPHRASE)", title)
	}
	fmt.Fprintf(p.out(), "%s: ", title)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(p.out())
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Reporter prints runner events as lines.
func Reporter(out io.Writer, steps []string) func(runner.Event) {
	name := func(i int) string {
		if i >= 0 && i < len(steps) {
			return steps[i]
		}
		return "?"
	}
	return func(e runner.Event) {
		switch e.Kind {
		case runner.StepStart:
			fmt.Fprintf(out, "\n==> %s\n", name(e.Step))
		case runner.StepDone:
			fmt.Fprintf(out, "    done\n")
		case runner.StepSkipped:
			fmt.Fprintf(out, "\n==> %s: skipped (%s)\n", name(e.Step), e.Text)
		case runner.StepFailed:
			fmt.Fprintf(out, "    FAILED: %s\n", e.Text)
		case runner.Log:
			fmt.Fprintf(out, "    %s\n", e.Text)
		case runner.Attention:
			fmt.Fprintf(out, "\n    *** %s\n\n", strings.ReplaceAll(e.Text, "\n", "\n    "))
		}
	}
}
