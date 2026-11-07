package textui

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// A question that carries server text is printed without terminal control
// sequences.
func TestConfirmCleansServerText(t *testing.T) {
	var out bytes.Buffer
	p := Prompter{AssumeYes: true, Out: &out}
	if ok, err := p.Confirm(context.Background(), "Is evil\x1b]52;c;ZXZpbA==\a your tailnet?", "joined\x1b[2J it"); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if strings.ContainsAny(out.String(), "\x1b\a") || !strings.Contains(out.String(), "your tailnet? yes") {
		t.Fatalf("output not cleaned: %q", out.String())
	}
}
