package tui

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/niklas-schmidt-dev/secure-setup/internal/plan"
	"github.com/niklas-schmidt-dev/secure-setup/internal/remote"
)

// wizardModel is a wizard past its pre-flight, with plans saved under a
// temporary directory.
func wizardModel(t *testing.T, p *plan.Plan) *model {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m := newModel(ctx, cancel, p, "test")
	m.facts = &remote.Facts{Hostname: "vps", PrettyName: "Debian", SSHPort: 22, WANIface: "eth0", TailscaleState: "Running", TailscaleIPv4: "100.64.0.5"}
	return m
}

// Web ports the wizard has no choice for come from a plan file; walking
// through the wizard must not turn them into 443.
func TestWizardKeepsCustomWebPorts(t *testing.T) {
	p := plan.Default()
	p.Server.Host = "203.0.113.10"
	p.Firewall.WebPorts = []int{8443}
	m := wizardModel(t, &p)
	if m.webChoice != "custom" {
		t.Fatalf("web choice %q for ports %v", m.webChoice, p.Firewall.WebPorts)
	}
	m.phase = phaseFirewall
	m.advance()
	if !slices.Equal(p.Firewall.WebPorts, []int{8443}) || m.phase != phaseReview {
		t.Fatalf("web ports %v, phase %v", p.Firewall.WebPorts, m.phase)
	}
	if !strings.Contains(m.summary(), "TCP 8443") {
		t.Fatalf("review:\n%s", m.summary())
	}
	// The usual choices are still what they were.
	for ports, want := range map[string]string{"443": "https", "80, 443": "both", "": "none"} {
		f := plan.Firewall{}
		f.WebPorts, _ = plan.ParsePorts(ports)
		if got := webChoiceFor(f); got != want {
			t.Errorf("ports %q: choice %q, want %q", ports, got, want)
		}
	}
}

// The review can go back to the questions with every answer still filled in,
// and quitting there leaves without a run.
func TestReviewCanGoBack(t *testing.T) {
	p := plan.Default()
	p.Server.Host = "203.0.113.10"
	m := wizardModel(t, &p)
	m.phase, m.extraPorts, m.allowPing = phaseFirewall, "8080", false
	m.advance()
	if m.phase != phaseReview || m.review != "apply" {
		t.Fatalf("phase %v, review %q", m.phase, m.review)
	}
	m.review = "change"
	if _, cmd := m.advance(); isQuit(cmd) || m.phase != phaseFirewall || m.form == nil {
		t.Fatalf("Change did not go back to the questions: phase %v", m.phase)
	}
	if m.extraPorts != "8080" || m.allowPing || m.running {
		t.Fatalf("answers lost on the way back: ports %q, ping %v", m.extraPorts, m.allowPing)
	}
	// A server that still has to join the tailnet goes back to that page.
	m.facts.TailscaleState = ""
	m.advance()
	m.review = "change"
	if m.advance(); m.phase != phaseTailscale {
		t.Fatalf("phase %v, want the Tailscale page", m.phase)
	}
	m.phase, m.form = phaseReview, m.reviewForm()
	m.review = "quit"
	if _, cmd := m.advance(); !isQuit(cmd) || !m.aborted || m.running {
		t.Fatal("Quit on the review did not leave")
	}
}

// A second pass through the wizard for a server starts from the answers of
// the last one, not from the defaults; the connection just typed stays.
func TestWizardLoadsSavedAnswers(t *testing.T) {
	p := plan.Default()
	m := wizardModel(t, &p)
	saved := plan.Default()
	saved.Server.Host, saved.Server.User = "203.0.113.10", "root"
	saved.Firewall.WebPorts, saved.Firewall.AllowPing, saved.Firewall.RollbackSeconds = nil, false, 300
	saved.Firewall.TailnetPorts = []int{22, 9090}
	saved.Tailscale.Hostname, saved.Reboot = "web-1", false
	if err := saved.Save(plan.DefaultSavePath("203.0.113.10")); err != nil {
		t.Fatal(err)
	}
	p.Server.Host, p.Server.User, m.port = "203.0.113.10", "deploy", "2222"
	m.phase = phaseConnect
	m.advance()
	if m.webChoice != "none" || m.allowPing || m.rollback != 300 || m.extraPorts != "9090" || m.tsHostname != "web-1" || p.Reboot {
		t.Fatalf("saved answers not filled in: web %q ping %v rollback %d ports %q name %q reboot %v", m.webChoice, m.allowPing, m.rollback, m.extraPorts, m.tsHostname, p.Reboot)
	}
	if p.Server.User != "deploy" || p.Server.Port != 2222 || m.loadedFrom == "" {
		t.Fatalf("the connection just typed was replaced: %+v", p.Server)
	}
	// Another server has no saved plan: the defaults stay.
	q := plan.Default()
	n := newModel(m.ctx, m.cancel, &q, "test")
	q.Server.Host = "198.51.100.7"
	n.phase = phaseConnect
	n.advance()
	if n.webChoice != "https" || n.loadedFrom != "" {
		t.Fatalf("answers of another server were loaded: %q from %q", n.webChoice, n.loadedFrom)
	}
}
