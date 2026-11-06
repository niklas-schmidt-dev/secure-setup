package sshx

import (
	"bufio"
	"strings"
	"testing"
)

func TestQuote(t *testing.T) {
	cases := map[string]string{
		"plain":      "'plain'",
		"it's":       `'it'\''s'`,
		"a b; rm -r": "'a b; rm -r'",
	}
	for in, want := range cases {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScanLines(t *testing.T) {
	sc := bufio.NewScanner(strings.NewReader("one\ntwo\r\nprogress 10%\rprogress 100%\nlast"))
	sc.Split(scanLines)
	var got []string
	for sc.Scan() {
		got = append(got, sc.Text())
	}
	want := []string{"one", "two", "progress 10%", "progress 100%", "last"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestPublicKeyBlob(t *testing.T) {
	if got := PublicKeyBlob("ssh-ed25519 AAAAC3Nza comment"); got != "AAAAC3Nza" {
		t.Errorf("got %q", got)
	}
	if got := PublicKeyBlob("broken"); got != "" {
		t.Errorf("got %q", got)
	}
}
