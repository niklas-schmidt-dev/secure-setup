package tui

import "github.com/charmbracelet/lipgloss"

var (
	colorAccent = lipgloss.AdaptiveColor{Light: "#1d4ed8", Dark: "#7dd3fc"}
	colorMuted  = lipgloss.AdaptiveColor{Light: "#6b7280", Dark: "#9ca3af"}
	colorOK     = lipgloss.AdaptiveColor{Light: "#15803d", Dark: "#86efac"}
	colorWarn   = lipgloss.AdaptiveColor{Light: "#b45309", Dark: "#fcd34d"}
	colorErr    = lipgloss.AdaptiveColor{Light: "#b91c1c", Dark: "#fca5a5"}

	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	mutedStyle   = lipgloss.NewStyle().Foreground(colorMuted)
	okStyle      = lipgloss.NewStyle().Foreground(colorOK)
	warnStyle    = lipgloss.NewStyle().Foreground(colorWarn)
	errStyle     = lipgloss.NewStyle().Foreground(colorErr)
	boldStyle    = lipgloss.NewStyle().Bold(true)
	headerStyle  = lipgloss.NewStyle().Bold(true).MarginBottom(1)
	boxStyle     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colorMuted).Padding(0, 1)
	attentionBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colorWarn).Foreground(colorWarn).Padding(0, 1)
	errorBox     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colorErr).Padding(0, 1)
	logStyle     = lipgloss.NewStyle().Foreground(colorMuted)
)
