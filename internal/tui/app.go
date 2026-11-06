// Package tui is the guided wizard: a few forms, a pre-flight connection,
// then the run screen that follows the runner step by step.
package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

	"github.com/niklas-schmidt-dev/secure-setup/internal/plan"
	"github.com/niklas-schmidt-dev/secure-setup/internal/remote"
	"github.com/niklas-schmidt-dev/secure-setup/internal/runner"
	"github.com/niklas-schmidt-dev/secure-setup/internal/sshx"
)

type phase int

const (
	phaseConnect phase = iota
	phasePreflight
	phaseTailscale
	phaseFirewall
	phaseReview
	phaseRun
	phaseDone
)

type stepState int

const (
	stepPending stepState = iota
	stepRunning
	stepDone
	stepSkipped
	stepFailed
)

// Run starts the wizard and blocks until it ends.
func Run(ctx context.Context, p *plan.Plan, version string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	m := newModel(ctx, cancel, p, version)
	prog := tea.NewProgram(m, tea.WithContext(ctx), tea.WithAltScreen())
	m.send = prog.Send
	final, err := prog.Run()
	if err != nil {
		return err
	}
	if fm, ok := final.(*model); ok && fm.runErr != nil {
		return fm.runErr
	}
	return nil
}

type model struct {
	ctx     context.Context
	cancel  context.CancelFunc
	send    func(tea.Msg)
	version string
	plan    *plan.Plan

	phase  phase
	width  int
	height int
	form   *huh.Form
	err    error // form-level or pre-flight error shown above the form

	// form bindings
	port        string
	authMethod  string
	keyPath     string
	password    string
	tsHostname  string
	tsAuthKey   string
	tsSSH       bool
	webChoice   string
	extraPorts  string
	allowPing   bool
	harden      bool
	rollback    int
	confirmed   bool
	preflightOK bool

	spin  spinner.Model
	facts *remote.Facts

	// pending question from the runner / pre-flight
	prompt     *promptMsg
	promptForm *huh.Form
	promptOK   bool
	promptText string

	// run screen
	steps      []string
	states     []stepState
	skipReason []string
	logs       []string
	attention  []string
	vp         viewport.Model
	result     *runner.Result
	runErr     error
	savedPath  string
}

func newModel(ctx context.Context, cancel context.CancelFunc, p *plan.Plan, version string) *model {
	m := &model{
		ctx:        ctx,
		cancel:     cancel,
		version:    version,
		plan:       p,
		port:       strconv.Itoa(p.Server.Port),
		authMethod: "key",
		keyPath:    p.Server.KeyPath,
		tsHostname: p.Tailscale.Hostname,
		tsSSH:      p.Tailscale.SSH,
		webChoice:  webChoiceFor(p.Firewall.WebPorts),
		allowPing:  p.Firewall.AllowPing,
		harden:     p.SSH.Harden,
		rollback:   p.Firewall.RollbackSeconds,
		width:      80,
		height:     24,
	}
	m.spin = spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(lipgloss.NewStyle().Foreground(colorAccent)))
	m.vp = viewport.New(78, 10)
	m.form = m.connectForm()
	return m
}

func webChoiceFor(ports []int) string {
	s := plan.FormatPorts(ports)
	switch s {
	case "80, 443":
		return "both"
	case "":
		return "none"
	}
	return "https"
}

// ---- forms ----

func (m *model) connectForm() *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title("secure-setup "+m.version).
				Description("Locks a fresh server down so only you can reach it: SSH over Tailscale, HTTPS only from Cloudflare, nothing else.\nFirst, how do we reach the server today?"),
			huh.NewInput().Title("Server address").Description("Public IP or hostname from your provider").
				Placeholder("203.0.113.10").Value(&m.plan.Server.Host).Validate(validateHost),
			huh.NewInput().Title("SSH port").Value(&m.port).Validate(validatePort),
			huh.NewInput().Title("SSH user").Description("root, or a user with passwordless sudo").Value(&m.plan.Server.User).Validate(huh.ValidateNotEmpty()),
			huh.NewSelect[string]().Title("Authentication").
				Options(
					huh.NewOption("SSH key or ssh-agent (recommended)", "key"),
					huh.NewOption("Password", "password"),
				).Value(&m.authMethod),
		),
		huh.NewGroup(
			huh.NewInput().Title("Private key file").Description("Leave empty to use ssh-agent and ~/.ssh/id_ed25519, id_ecdsa, id_rsa").
				Placeholder("~/.ssh/id_ed25519").Value(&m.keyPath).Validate(validateKeyPath),
		).WithHideFunc(func() bool { return m.authMethod != "key" }),
		huh.NewGroup(
			huh.NewInput().Title("Password").Description("Used once to log in; your public key is installed and password login is turned off afterwards").
				EchoMode(huh.EchoModePassword).Value(&m.password).Validate(huh.ValidateNotEmpty()),
		).WithHideFunc(func() bool { return m.authMethod != "password" }),
	).WithShowHelp(true)
}

func (m *model) tailscaleForm() *huh.Form {
	f := m.facts
	desc := "Not installed yet; the official installer will be used."
	if f.Tailscale {
		desc = "Installed, state: " + orDash(f.TailscaleState) + "."
	}
	if m.tsHostname == "" {
		m.tsHostname = f.Hostname
	}
	fields := []huh.Field{
		huh.NewNote().Title("Tailscale").Description(desc + "\nThe tailnet becomes the only way to administer this server."),
		huh.NewInput().Title("Name in the tailnet").Value(&m.tsHostname).Validate(validateHost),
		huh.NewInput().Title("Auth key (optional)").
			Description("From https://login.tailscale.com/admin/settings/keys. Leave empty to approve the server with a login link instead.").
			EchoMode(huh.EchoModePassword).Value(&m.tsAuthKey),
		huh.NewConfirm().Title("Enable Tailscale SSH?").
			Description("Lets tailnet identities log in without keys; your normal SSH keys keep working too.").
			Affirmative("Yes").Negative("No").Value(&m.tsSSH),
	}
	return huh.NewForm(huh.NewGroup(fields...)).WithShowHelp(true)
}

func (m *model) firewallForm() *huh.Form {
	f := m.facts
	note := fmt.Sprintf("Internet interface: %s. SSH port: %d. Everything inbound is dropped except what you allow here.", f.WANIface, f.SSHPort)
	if f.Docker {
		note += "\nDocker found: published container ports stay reachable from the tailnet, and from the internet only via Cloudflare on the web ports."
	}
	fields := []huh.Field{
		huh.NewNote().Title("Firewall").Description(note),
		huh.NewSelect[string]().Title("Web traffic").
			Options(
				huh.NewOption("HTTPS (443) from Cloudflare only (recommended)", "https"),
				huh.NewOption("HTTP (80) and HTTPS (443) from Cloudflare only", "both"),
				huh.NewOption("No web traffic at all", "none"),
			).Value(&m.webChoice),
		huh.NewInput().Title("Extra ports reachable from the tailnet (optional)").
			Description(fmt.Sprintf("SSH (%d) is always included. Example: 8080, 9090", f.SSHPort)).
			Placeholder("none").Value(&m.extraPorts).Validate(validatePorts),
		huh.NewConfirm().Title("Answer ping from the internet?").Description("Rate limited. Handy for uptime checks; off hides the host a little more.").
			Affirmative("Yes").Negative("No").Value(&m.allowPing),
		huh.NewConfirm().Title("Turn off password login for SSH?").Description("Keys only. Your public key is installed first and verified before passwords are disabled.").
			Affirmative("Yes").Negative("No").Value(&m.harden),
		huh.NewSelect[int]().Title("Rollback window").
			Description("If the new rules cannot be confirmed over the tailnet in time, the server restores its previous firewall by itself.").
			Options(
				huh.NewOption("60 seconds", 60),
				huh.NewOption("2 minutes (recommended)", 120),
				huh.NewOption("5 minutes", 300),
			).Value(&m.rollback),
	}
	return huh.NewForm(huh.NewGroup(fields...)).WithShowHelp(true)
}

func (m *model) reviewForm() *huh.Form {
	return huh.NewForm(huh.NewGroup(
		huh.NewNote().Title("Review").Description(m.summary()),
		huh.NewConfirm().Title("Apply this setup now?").Affirmative("Apply").Negative("Quit").Value(&m.confirmed),
	)).WithShowHelp(true)
}

func (m *model) summary() string {
	p := m.plan
	f := m.facts
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "%-17s %s\n", k, v) }
	line("Server", p.Address())
	line("", f.PrettyName+", host "+f.Hostname)
	switch {
	case f.TailscaleState == "Running":
		line("Tailscale", "already connected as "+f.TailscaleIPv4)
	case p.Tailscale.AuthKey != "":
		line("Tailscale", "join as "+p.Tailscale.Hostname+" with the auth key")
	default:
		line("Tailscale", "join as "+p.Tailscale.Hostname+" via login link")
	}
	if p.Tailscale.SSH {
		line("", "Tailscale SSH enabled")
	}
	line("SSH", "TCP "+plan.FormatPorts(p.Firewall.TailnetPorts)+" on "+p.Tailscale.AdminInterface+" only")
	if len(p.Firewall.WebPorts) > 0 {
		line("Web", "TCP "+plan.FormatPorts(p.Firewall.WebPorts)+" on "+p.Firewall.WANInterface+", Cloudflare only")
		line("", "ranges refreshed daily")
	} else {
		line("Web", "none")
	}
	line("Ping", yesNo(p.Firewall.AllowPing))
	line("Password login", map[bool]string{true: "disabled (keys only)", false: "unchanged"}[p.SSH.Harden])
	line("Everything else", "dropped")
	line("Rollback window", fmt.Sprintf("%d seconds", p.Firewall.RollbackSeconds))
	if m.savedPath != "" {
		line("Plan saved to", shortenHome(m.savedPath))
	}
	return b.String()
}

func shortenHome(path string) string {
	home, err := os.UserHomeDir()
	if err == nil && home != "" && strings.HasPrefix(path, home+string(os.PathSeparator)) {
		return "~" + path[len(home):]
	}
	return path
}

// ---- validators ----

func validateHost(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("required")
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == ':') {
			return errors.New("only letters, digits, dots and dashes")
		}
	}
	return nil
}

func validatePort(s string) error {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return errors.New("1-65535")
	}
	return nil
}

func validatePorts(s string) error {
	_, err := plan.ParsePorts(s)
	return err
}

func validateKeyPath(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if _, err := os.Stat(sshx.ExpandHome(s)); err != nil {
		return errors.New("file not found")
	}
	return nil
}

// ---- messages ----

type preflightMsg struct {
	facts *remote.Facts
	err   error
}

type runEventMsg runner.Event

type runDoneMsg struct {
	result *runner.Result
	err    error
}

// ---- tea.Model ----

func (m *model) Init() tea.Cmd {
	return tea.Batch(m.form.Init(), m.spin.Tick)
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.vp.Width = clamp(m.width-4, 20, 160)
		m.vp.Height = clamp(m.height-len(m.steps)-12, 4, 30)
		m.vp.SetContent(strings.Join(m.logs, "\n"))
		m.vp.GotoBottom()
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.cancel()
			return m, tea.Quit
		case "q", "enter", "esc":
			if m.phase == phaseDone {
				return m, tea.Quit
			}
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case promptMsg:
		pm := msg
		m.prompt = &pm
		m.promptOK, m.promptText = false, ""
		switch msg.kind {
		case promptConfirm:
			m.promptForm = huh.NewForm(huh.NewGroup(
				huh.NewConfirm().Title(msg.title).Description(msg.detail).Affirmative("Yes").Negative("No").Value(&m.promptOK),
			))
		case promptSecret:
			m.promptForm = huh.NewForm(huh.NewGroup(
				huh.NewInput().Title(msg.title).Description(msg.detail).EchoMode(huh.EchoModePassword).Value(&m.promptText),
			))
		}
		return m, m.promptForm.Init()

	case preflightMsg:
		if msg.err != nil {
			m.err = msg.err
			m.phase = phaseConnect
			m.form = m.connectForm()
			return m, m.form.Init()
		}
		m.facts = msg.facts
		m.err = nil
		if m.facts.TailscaleState == "Running" {
			m.phase = phaseFirewall
			m.form = m.firewallForm()
		} else {
			m.phase = phaseTailscale
			m.form = m.tailscaleForm()
		}
		return m, m.form.Init()

	case runEventMsg:
		m.applyEvent(runner.Event(msg))
		return m, nil

	case runDoneMsg:
		m.result, m.runErr = msg.result, msg.err
		m.phase = phaseDone
		return m, nil
	}

	// A pending question takes all input until answered.
	if m.promptForm != nil {
		f, cmd := m.promptForm.Update(msg)
		if ff, ok := f.(*huh.Form); ok {
			m.promptForm = ff
		}
		switch m.promptForm.State {
		case huh.StateCompleted:
			m.prompt.reply <- promptReply{ok: m.promptOK, text: m.promptText}
			m.prompt, m.promptForm = nil, nil
		case huh.StateAborted:
			m.prompt.reply <- promptReply{abort: true}
			m.prompt, m.promptForm = nil, nil
		}
		return m, cmd
	}

	if m.form == nil {
		return m, nil
	}
	f, cmd := m.form.Update(msg)
	if ff, ok := f.(*huh.Form); ok {
		m.form = ff
	}
	switch m.form.State {
	case huh.StateAborted:
		m.cancel()
		return m, tea.Quit
	case huh.StateCompleted:
		return m.advance()
	}
	return m, cmd
}

// advance moves from a completed form to the next phase.
func (m *model) advance() (tea.Model, tea.Cmd) {
	p := m.plan
	switch m.phase {
	case phaseConnect:
		p.Server.Host = strings.TrimSpace(p.Server.Host)
		p.Server.Port, _ = strconv.Atoi(strings.TrimSpace(m.port))
		p.Server.User = strings.TrimSpace(p.Server.User)
		if m.authMethod == "key" {
			p.Server.KeyPath = strings.TrimSpace(m.keyPath)
			p.Server.Password = ""
		} else {
			p.Server.KeyPath = ""
			p.Server.Password = m.password
		}
		m.phase = phasePreflight
		m.form = nil
		m.err = nil
		return m, tea.Batch(m.spin.Tick, m.preflight())

	case phaseTailscale:
		p.Tailscale.Hostname = strings.TrimSpace(m.tsHostname)
		p.Tailscale.AuthKey = strings.TrimSpace(m.tsAuthKey)
		p.Tailscale.SSH = m.tsSSH
		m.phase = phaseFirewall
		m.form = m.firewallForm()
		return m, m.form.Init()

	case phaseFirewall:
		switch m.webChoice {
		case "https":
			p.Firewall.WebPorts = []int{443}
		case "both":
			p.Firewall.WebPorts = []int{80, 443}
		default:
			p.Firewall.WebPorts = nil
		}
		p.Firewall.CloudflareSync = len(p.Firewall.WebPorts) > 0
		extra, _ := plan.ParsePorts(m.extraPorts)
		p.Firewall.TailnetPorts = append([]int{m.facts.SSHPort}, extra...)
		p.Firewall.AllowPing = m.allowPing
		p.Firewall.RollbackSeconds = m.rollback
		p.Firewall.WANInterface = m.facts.WANIface
		p.SSH.Harden = m.harden
		p.SSH.AddLocalKey = m.harden
		if err := p.Validate(); err != nil {
			m.err = err
			m.form = m.firewallForm()
			return m, m.form.Init()
		}
		m.savedPath = plan.DefaultSavePath(p.Server.Host)
		if err := p.Save(m.savedPath); err != nil {
			m.savedPath = ""
		}
		m.phase = phaseReview
		m.form = m.reviewForm()
		return m, m.form.Init()

	case phaseReview:
		if !m.confirmed {
			m.cancel()
			return m, tea.Quit
		}
		m.phase = phaseRun
		m.form = nil
		return m, tea.Batch(m.spin.Tick, m.startRun())
	}
	return m, nil
}

// preflight connects once: host key prompt, root check, facts.
func (m *model) preflight() tea.Cmd {
	p := *m.plan
	pr := prompter{send: m.send}
	ctx := m.ctx
	return func() tea.Msg {
		auth := sshx.Auth{User: p.Server.User, KeyPath: p.Server.KeyPath, Password: p.Server.Password}
		if auth.KeyPath != "" && sshx.KeyNeedsPassphrase(auth.KeyPath) {
			pp, err := pr.Secret(ctx, "Passphrase for "+auth.KeyPath, "The private key is encrypted.")
			if err != nil {
				return preflightMsg{err: err}
			}
			auth.Passphrase = pp
			m.plan.Server.Passphrase = pp
		}
		if auth.Password != "" && p.SSH.Harden && len(sshx.LocalPublicKeys(auth, "")) == 0 {
			return preflightMsg{err: errors.New("no public key on this computer to install on the server; run `ssh-keygen -t ed25519` first (or choose key authentication)")}
		}
		c, err := sshx.Dial(ctx, p.Address(), auth, sshx.HostKeyPolicy{Prompter: pr})
		if err != nil {
			return preflightMsg{err: err}
		}
		defer c.Close()
		if err := c.EnsureRoot(ctx); err != nil {
			return preflightMsg{err: err}
		}
		f, err := remote.Detect(ctx, c)
		if err != nil {
			return preflightMsg{err: err}
		}
		if !f.Systemd {
			return preflightMsg{err: errors.New("the server does not run systemd, which secure-setup needs for the rollback timer")}
		}
		if f.PkgMgr == "" {
			return preflightMsg{err: errors.New("no supported package manager on the server (apt-get, dnf, yum, pacman, zypper)")}
		}
		if f.WANIface == "" {
			return preflightMsg{err: errors.New("could not find the server's internet interface (no default route)")}
		}
		return preflightMsg{facts: f}
	}
}

func (m *model) startRun() tea.Cmd {
	r := runner.New(runner.Options{
		Plan:   m.plan,
		Report: func(e runner.Event) { m.send(runEventMsg(e)) },
		Prompt: prompter{send: m.send},
	})
	m.steps = r.Steps()
	m.states = make([]stepState, len(m.steps))
	m.skipReason = make([]string, len(m.steps))
	m.vp.Height = clamp(m.height-len(m.steps)-12, 4, 30)
	ctx := m.ctx
	return func() tea.Msg {
		res, err := r.Run(ctx)
		return runDoneMsg{result: res, err: err}
	}
}

func (m *model) applyEvent(e runner.Event) {
	if e.Step >= 0 && e.Step < len(m.states) {
		switch e.Kind {
		case runner.StepStart:
			m.states[e.Step] = stepRunning
		case runner.StepDone:
			m.states[e.Step] = stepDone
		case runner.StepSkipped:
			m.states[e.Step] = stepSkipped
			m.skipReason[e.Step] = e.Text
		case runner.StepFailed:
			m.states[e.Step] = stepFailed
		}
	}
	switch e.Kind {
	case runner.Log:
		m.addLog(e.Text)
	case runner.Attention:
		m.attention = append(m.attention, e.Text)
		m.addLog("! " + strings.ReplaceAll(e.Text, "\n", " "))
	case runner.StepFailed:
		m.addLog(errStyle.Render("error: ") + e.Text)
	}
}

func (m *model) addLog(line string) {
	m.logs = append(m.logs, line)
	if len(m.logs) > 400 {
		m.logs = m.logs[len(m.logs)-400:]
	}
	m.vp.SetContent(strings.Join(m.logs, "\n"))
	m.vp.GotoBottom()
}

// ---- view ----

func (m *model) View() string {
	var b strings.Builder
	if m.promptForm != nil {
		b.WriteString(headerStyle.Render(titleStyle.Render("secure-setup") + mutedStyle.Render("  needs your answer")))
		b.WriteString("\n")
		b.WriteString(m.promptForm.View())
		return b.String()
	}
	switch m.phase {
	case phasePreflight:
		b.WriteString(headerStyle.Render(titleStyle.Render("secure-setup")))
		b.WriteString("\n")
		b.WriteString(m.spin.View() + " Connecting to " + m.plan.Address() + " and looking around...\n")
		b.WriteString(mutedStyle.Render("\nctrl+c to abort"))
	case phaseRun:
		b.WriteString(m.runView())
	case phaseDone:
		b.WriteString(m.doneView())
	default:
		if m.err != nil {
			b.WriteString(errorBox.Width(clamp(m.width-2, 20, 100)).Render(errStyle.Render("Could not continue: ") + m.err.Error()))
			b.WriteString("\n\n")
		}
		if m.form != nil {
			b.WriteString(m.form.View())
		}
	}
	return b.String()
}

func (m *model) runView() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render(titleStyle.Render("secure-setup") + mutedStyle.Render("  "+m.plan.Server.Host)))
	b.WriteString("\n")
	for i, name := range m.steps {
		var mark, text string
		switch m.states[i] {
		case stepRunning:
			mark, text = m.spin.View(), boldStyle.Render(name)
		case stepDone:
			mark, text = okStyle.Render("✓"), name
		case stepSkipped:
			mark, text = mutedStyle.Render("–"), mutedStyle.Render(name+"  ("+m.skipReason[i]+")")
		case stepFailed:
			mark, text = errStyle.Render("✗"), errStyle.Render(name)
		default:
			mark, text = mutedStyle.Render("○"), mutedStyle.Render(name)
		}
		fmt.Fprintf(&b, " %s %s\n", mark, text)
	}
	if n := len(m.attention); n > 0 {
		b.WriteString("\n")
		b.WriteString(attentionBox.Width(clamp(m.width-2, 20, 100)).Render(m.attention[n-1]))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(boxStyle.Width(m.vp.Width).Render(logStyle.Render(m.vp.View())))
	b.WriteString("\n")
	b.WriteString(mutedStyle.Render("ctrl+c aborts; a rollback timer protects the server during the firewall steps"))
	return b.String()
}

func (m *model) doneView() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render(titleStyle.Render("secure-setup") + mutedStyle.Render("  "+m.plan.Server.Host)))
	b.WriteString("\n")
	if m.runErr != nil {
		b.WriteString(errorBox.Width(clamp(m.width-2, 20, 100)).Render(errStyle.Render("Setup did not finish\n\n") + m.runErr.Error()))
		b.WriteString("\n\n")
		b.WriteString("Last output:\n")
		tail := m.logs
		if len(tail) > 12 {
			tail = tail[len(tail)-12:]
		}
		b.WriteString(logStyle.Render(strings.Join(tail, "\n")))
		b.WriteString("\n\n")
		if m.savedPath != "" {
			b.WriteString("Fix the cause and run again with:  secure-setup apply -f " + m.savedPath + "\n")
		}
	} else {
		b.WriteString(okStyle.Render("✓ The server is locked down.") + "\n\n")
		b.WriteString(Summary(m.plan, m.result))
	}
	b.WriteString("\n" + mutedStyle.Render("press q to exit"))
	return b.String()
}

// Summary describes the final state in plain words (shared with the text UI).
func Summary(p *plan.Plan, r *runner.Result) string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "%-24s %s\n", k, v) }
	target := r.AdminAddress
	if r.DNSName != "" {
		target = r.DNSName
	}
	port := ""
	if r.SSHPort != 22 {
		port = fmt.Sprintf(" -p %d", r.SSHPort)
	}
	line("SSH from now on", fmt.Sprintf("ssh%s %s@%s", port, p.Server.User, target))
	if r.DNSName != "" {
		line("", "(tailnet IP "+r.AdminAddress+")")
	}
	if len(r.WebPorts) > 0 {
		line("Web", "TCP "+plan.FormatPorts(r.WebPorts)+" from Cloudflare only; point a proxied DNS record at "+p.Server.Host)
	}
	if r.PublicSSHClosed {
		line("Public SSH", "blocked (verified with a fresh connection from here)")
	} else {
		line("Public SSH", warnStyle.Render("still reachable: "+r.PublicSSHNote))
	}
	if r.Hardened {
		line("Password login", "disabled; keys only")
	}
	line("Rules", "/etc/nftables.conf (nft list ruleset)")
	if len(r.WebPorts) > 0 {
		line("Cloudflare ranges", "/etc/secure-setup/cloudflare.nft, refreshed daily")
	}
	line("Undo everything", fmt.Sprintf("secure-setup undo --host %s --user %s", r.AdminAddress, p.Server.User))
	return b.String()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orDash(s string) string {
	if s == "" {
		return "not running"
	}
	return s
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
