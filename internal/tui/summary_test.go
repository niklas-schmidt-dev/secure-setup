package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/niklas-schmidt-dev/secure-setup/internal/plan"
	"github.com/niklas-schmidt-dev/secure-setup/internal/runner"
)

// Highlighted summary lines keep their colour codes, while text from the
// server still loses its own control characters.
func TestSummaryHighlightSurvivesCleaning(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(termenv.Ascii)
	p := plan.Default()
	out := Summary(&p, &runner.Result{RebootNeeded: true, TailscaleSSH: "off: refused\x1b]0;evil\a"})
	if strings.Contains(out, "?[") || !strings.Contains(out, "\x1b[") {
		t.Fatalf("highlight mangled or missing: %q", out)
	}
	if strings.Contains(out, "\x1b]0;") || strings.Contains(out, "\a") {
		t.Fatalf("server control characters reached the summary: %q", out)
	}
}
