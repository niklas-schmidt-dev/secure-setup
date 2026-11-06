package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/niklas-schmidt-dev/secure-setup/internal/plan"
	"github.com/niklas-schmidt-dev/secure-setup/internal/remote"
)

func TestPrintable(t *testing.T) {
	got := Printable("login by x\x1b]0;TITLE\a from 100.64.0.9\x1b[2K\x1b[1A\nnext\tline")
	if strings.ContainsAny(got, "\x1b\a") {
		t.Fatalf("control characters left: %q", got)
	}
	if !strings.Contains(got, "\nnext\tline") {
		t.Fatalf("newline or tab removed: %q", got)
	}
}

// Events reaching the reporter carry no terminal control sequences.
func TestReportSanitizesEvents(t *testing.T) {
	var got []Event
	p := plan.Default()
	r := New(Options{Plan: &p, Report: func(e Event) { got = append(got, e) }})
	r.o.Report(Event{Kind: Log, Text: "x\x1b]52;c;ZXZpbA==\a"})
	if len(got) != 1 || strings.ContainsAny(got[0].Text, "\x1b\a") {
		t.Fatalf("event not sanitized: %+v", got)
	}
}

func TestUsableKeys(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHHT9zwfT6widjbTcsKOGGlmx58L4skpUKesGUJ0u4kk operator@laptop"
	for in, want := range map[string]int{
		key:                                  1,
		"# a comment\n\n" + key + "\n" + key: 2,
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHHT9z\nwfT6widjbTcsKOGGlmx58L4skpUKesGUJ0u4kk operator@laptop": 0,
		`from="198.51.100.1" ` + key:  0,
		`command="/bin/false" ` + key: 0,
		"junk line":                   0,
		"":                            0,
	} {
		if got := usableKeys(in); got != want {
			t.Errorf("usableKeys(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestParseAcceptedLogins(t *testing.T) {
	out := "Accepted publickey for root from 100.64.0.9 port 51000 ssh2: ED25519 SHA256:x\n" +
		"Accepted publickey for x\x1b]0;T\a from 100.64.0.9 port 1 ssh2\n" +
		"Accepted publickey for root from fe80::1%eth0 port 1 ssh2\n" +
		"Accepted password for deploy from ::ffff:10.0.0.4 port 2 ssh2"
	got := parseAcceptedLogins(out)
	if len(got) != 2 || got[0].From != "100.64.0.9" || got[1].User != "deploy" || got[1].From != "10.0.0.4" {
		t.Fatalf("got %+v", got)
	}
}

// fakeHost answers `ip -o link show <iface>` for the listed interfaces.
type fakeHost struct{ ifaces []string }

func (h fakeHost) Output(_ context.Context, cmd string) (string, error) {
	for _, i := range h.ifaces {
		if strings.Contains(cmd, "ip -o link show '"+i+"'") {
			return "2: " + i + ": <UP>", nil
		}
	}
	return "", context.Canceled // any error means "does not exist"
}
func (fakeHost) Script(context.Context, string, func(string)) error      { return nil }
func (fakeHost) WriteFile(context.Context, string, []byte, string) error { return nil }

// A wan_interface carried over from another server must not silently win
// over this server's default-route interface.
func TestResolveWAN(t *testing.T) {
	ctx, log := context.Background(), func(string) {}
	f := &remote.Facts{WANIface: "ens3"}

	p := plan.Default()
	if err := resolveWAN(ctx, fakeHost{}, &p, f, log); err != nil || p.Firewall.WANInterface != "ens3" {
		t.Fatalf("empty plan value: %v %q", err, p.Firewall.WANInterface)
	}
	p.Firewall.WANInterface = "eth0"
	if err := resolveWAN(ctx, fakeHost{}, &p, f, log); err == nil {
		t.Fatal("a stale, absent wan_interface was accepted")
	}
	if err := resolveWAN(ctx, fakeHost{ifaces: []string{"eth0"}}, &p, f, log); err == nil || !strings.Contains(err.Error(), "wan_interface_override") {
		t.Fatalf("an existing but different interface was accepted without the override: %v", err)
	}
	p.Firewall.WANOverride = true
	if err := resolveWAN(ctx, fakeHost{ifaces: []string{"eth0"}}, &p, f, log); err != nil || p.Firewall.WANInterface != "eth0" {
		t.Fatalf("explicit override refused: %v", err)
	}
}
