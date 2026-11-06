// Package runner executes a plan step by step and reports progress through
// events, so the same logic drives the TUI and the non-interactive command.
package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/niklas-schmidt-dev/secure-setup/internal/cloudflare"
	"github.com/niklas-schmidt-dev/secure-setup/internal/localhost"
	"github.com/niklas-schmidt-dev/secure-setup/internal/nftgen"
	"github.com/niklas-schmidt-dev/secure-setup/internal/plan"
	"github.com/niklas-schmidt-dev/secure-setup/internal/remote"
	"github.com/niklas-schmidt-dev/secure-setup/internal/sshx"
)

// EventKind classifies an Event.
type EventKind int

const (
	StepStart EventKind = iota
	StepDone
	StepSkipped
	StepFailed
	Log       // ordinary output line
	Attention // something the user must look at (login URL, warning)
)

// Event is one progress update.
type Event struct {
	Kind EventKind
	Step int    // index into Steps()
	Text string // log line, skip reason, error or attention text
}

// Prompter answers the questions a run can raise.
type Prompter interface {
	sshx.HostKeyPrompter
	// Confirm asks a yes/no question.
	Confirm(ctx context.Context, title, detail string) (bool, error)
	// Secret asks for a hidden value (passphrase, password).
	Secret(ctx context.Context, title, detail string) (string, error)
}

// Options configure a Runner.
type Options struct {
	Plan   *plan.Plan
	Report func(Event)
	Prompt Prompter
	// LocalTailscaleReady reports whether this machine is on the tailnet.
	// Nil uses the local tailscale CLI.
	LocalTailscaleReady func(ctx context.Context) (bool, string)
	// Local runs the plan on this machine (`secure-setup here`) instead of
	// over SSH. Plan.Local must be set too.
	Local *localhost.Host
}

// Result is what a successful run learned.
type Result struct {
	Local           bool
	Facts           *remote.Facts
	AdminAddress    string // tailnet IP (or the existing private address)
	DNSName         string // MagicDNS name, when known
	SSHPort         int
	PublicAddress   string // the server's internet address, when known
	PublicSSHClosed bool
	PublicSSHNote   string
	ConfirmedBy     string // local runs: "login from <peer>" or the self-check summary
	Hardened        bool
	HardenNote      string // why hardening was skipped, if it was
	WebPorts        []int
}

// Runner executes one plan.
type Runner struct {
	o     Options
	steps []step

	facts   *remote.Facts
	pub     *sshx.Client
	admin   *sshx.Client
	hostKey ssh.PublicKey
	result  Result

	// local mode
	local      *localhost.Host
	before     []remote.Session // sshd sessions before the firewall was applied
	applyEpoch int64            // server clock when the rules went live
	tsState    *remote.TSStatus
}

type step struct {
	name string
	skip func() string // non-empty = skip with this reason
	run  func(ctx context.Context, log func(string)) error
}

// New builds a runner for p.
func New(o Options) *Runner {
	if o.Report == nil {
		o.Report = func(Event) {}
	}
	if o.LocalTailscaleReady == nil {
		o.LocalTailscaleReady = LocalTailscaleReady
	}
	r := &Runner{o: o}
	if o.Local != nil {
		r.local = o.Local
		r.result.Local = true
		r.steps = r.localSteps()
		return r
	}
	p := o.Plan
	ts := &p.Tailscale
	r.steps = []step{
		{name: "Connect to the server", run: r.connect},
		{name: "Install Tailscale", skip: func() string {
			if ts.UseExisting {
				return "using the existing private network " + ts.AdminAddress
			}
			if r.facts != nil && r.facts.Tailscale {
				return "already installed"
			}
			return ""
		}, run: r.installTailscale},
		{name: "Join the tailnet", skip: func() string {
			if ts.UseExisting {
				return "using the existing private network"
			}
			if r.facts != nil && r.facts.TailscaleState == "Running" {
				return "already connected as " + r.facts.TailscaleIPv4
			}
			return ""
		}, run: r.joinTailnet},
		{name: "Reach the server over the private network", run: r.reachAdmin},
		{name: "Harden SSH (keys only)", skip: func() string {
			if !p.SSH.Harden {
				return "not requested"
			}
			return ""
		}, run: r.hardenSSH},
		{name: "Stage the firewall", run: r.stageFirewall},
		{name: "Apply the firewall with a rollback timer", run: r.applyFirewall},
		{name: "Confirm over the private network", run: r.confirmFirewall},
		{name: "Verify from the outside", run: r.verify},
	}
	return r
}

// Steps lists the step names in order.
func (r *Runner) Steps() []string {
	out := make([]string, len(r.steps))
	for i, s := range r.steps {
		out[i] = s.name
	}
	return out
}

// Run executes every step. The returned error belongs to the step that failed.
func (r *Runner) Run(ctx context.Context) (*Result, error) {
	defer func() { r.pub.Close() }()
	defer func() { r.admin.Close() }()
	for i, s := range r.steps {
		if s.skip != nil {
			if reason := s.skip(); reason != "" {
				r.o.Report(Event{Kind: StepSkipped, Step: i, Text: reason})
				continue
			}
		}
		r.o.Report(Event{Kind: StepStart, Step: i})
		log := func(line string) { r.o.Report(Event{Kind: Log, Step: i, Text: line}) }
		if err := s.run(ctx, log); err != nil {
			r.o.Report(Event{Kind: StepFailed, Step: i, Text: err.Error()})
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
		r.o.Report(Event{Kind: StepDone, Step: i})
	}
	return &r.result, nil
}

func (r *Runner) attention(step int, text string) {
	r.o.Report(Event{Kind: Attention, Step: step, Text: text})
}

func (r *Runner) auth() sshx.Auth {
	s := r.o.Plan.Server
	return sshx.Auth{User: s.User, KeyPath: s.KeyPath, Passphrase: s.Passphrase, Password: s.Password}
}

// dial opens a connection, asking for a key passphrase when needed.
func (r *Runner) dial(ctx context.Context, addr string, policy sshx.HostKeyPolicy) (*sshx.Client, error) {
	auth := r.auth()
	if auth.KeyPath != "" && auth.Passphrase == "" && sshx.KeyNeedsPassphrase(auth.KeyPath) {
		pp, err := r.o.Prompt.Secret(ctx, "Passphrase for "+auth.KeyPath, "The private key is encrypted.")
		if err != nil {
			return nil, err
		}
		r.o.Plan.Server.Passphrase = pp
		auth.Passphrase = pp
	}
	c, err := sshx.Dial(ctx, addr, auth, policy)
	if err != nil {
		return nil, err
	}
	if err := c.EnsureRoot(ctx); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// ---- steps ----

func (r *Runner) connect(ctx context.Context, log func(string)) error {
	p := r.o.Plan
	log("connecting to " + p.Address() + " as " + p.Server.User)
	c, err := r.dial(ctx, p.Address(), sshx.HostKeyPolicy{Prompter: r.o.Prompt, Warn: log})
	if err != nil {
		return err
	}
	r.pub = c
	r.hostKey = c.HostKey
	if c.Sudo {
		log("not root; using passwordless sudo")
	}
	f, err := remote.Detect(ctx, c)
	if err != nil {
		return err
	}
	r.facts = f
	r.result.Facts = f
	log(fmt.Sprintf("%s, host %s, sshd on port %d, internet interface %s", f.PrettyName, f.Hostname, f.SSHPort, orUnknown(f.WANIface)))
	if !f.Systemd {
		return errors.New("this server does not run systemd; secure-setup relies on it for the rollback timer and services")
	}
	if f.PkgMgr == "" {
		return errors.New("no supported package manager found (apt-get, dnf, yum, pacman, zypper)")
	}
	if f.WANIface == "" && p.Firewall.WANInterface == "" {
		return errors.New("could not find the interface with the default route; set wan_interface in the plan")
	}
	if p.Firewall.WANInterface == "" {
		p.Firewall.WANInterface = f.WANIface
	}
	if f.Docker {
		log("docker found: published container ports will only be reachable from Cloudflare on the web ports")
	}
	if f.UFWActive {
		log("ufw is active and will be replaced by nftables")
	}
	if f.FirewalldActive {
		log("firewalld is active and will be replaced by nftables")
	}
	if f.SecureSetupTable {
		log("a secure-setup firewall is already loaded; it will be replaced")
	}
	if f.RolledBack != "" {
		r.attention(0, "an earlier secure-setup run rolled its firewall back at "+f.RolledBack+" UTC; this run starts fresh")
	}
	if f.Tailscale {
		log("tailscale installed, state: " + orUnknown(f.TailscaleState))
	}
	r.result.SSHPort = f.SSHPort
	r.result.PublicAddress = p.Server.Host
	if !containsInt(p.Firewall.TailnetPorts, f.SSHPort) {
		p.Firewall.TailnetPorts = append(p.Firewall.TailnetPorts, f.SSHPort)
		log(fmt.Sprintf("added sshd port %d to the tailnet ports", f.SSHPort))
	}

	// Key-only sshd needs our key on the server before passwords stop working.
	if p.SSH.Harden && p.SSH.AddLocalKey {
		if err := r.ensureAuthorizedKey(ctx, log); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) ensureAuthorizedKey(ctx context.Context, log func(string)) error {
	p := r.o.Plan
	keys := sshx.LocalPublicKeys(r.auth(), p.SSH.PublicKeyPath)
	if len(keys) == 0 {
		if p.Server.Password == "" {
			return nil // logged in with a key we cannot read; it is already authorized
		}
		return errors.New("no public key found on this machine to install on the server; create one with `ssh-keygen -t ed25519` or turn off SSH hardening")
	}
	existing, err := remote.AuthorizedKeys(ctx, r.pub, p.Server.User)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if blob := sshx.PublicKeyBlob(k); blob != "" && strings.Contains(existing, blob) {
			log("this machine's public key is already authorized on the server")
			return nil
		}
	}
	if err := remote.AddAuthorizedKey(ctx, r.pub, p.Server.User, keys[0], log); err != nil {
		return err
	}
	// Prove the key works before anything else relies on it.
	auth := r.auth()
	auth.Password = ""
	test, err := sshx.Dial(ctx, p.Address(), auth, sshx.HostKeyPolicy{Expect: r.hostKey})
	if err != nil {
		return fmt.Errorf("the key was added but key login failed: %w", err)
	}
	test.Close()
	log("key login verified")
	return nil
}

func (r *Runner) installTailscale(ctx context.Context, log func(string)) error {
	return remote.InstallTailscale(ctx, r.server(), r.facts, log)
}

// server is the host the server-side steps before the firewall run on.
func (r *Runner) server() remote.Host {
	if r.local != nil {
		return r.local
	}
	return r.pub
}

func (r *Runner) joinTailnet(ctx context.Context, log func(string)) error {
	p := r.o.Plan
	host := r.server()
	key := p.Tailscale.AuthKey
	if key == "" {
		log("no auth key given: tailscale will print a login link")
	}
	err := remote.TailscaleUp(ctx, host, remote.UpOptions{AuthKey: key, Hostname: p.Tailscale.Hostname, SSH: p.Tailscale.SSH}, log,
		func(url string) {
			r.attention(2, "Open this link in your browser to add the server to your tailnet:\n"+url)
		})
	if err != nil {
		return err
	}
	st, err := remote.TailscaleStatus(ctx, host)
	if err != nil {
		return err
	}
	if st.BackendState != "Running" {
		return fmt.Errorf("tailscale is in state %s after `tailscale up`", st.BackendState)
	}
	r.facts.TailscaleState = st.BackendState
	for _, ip := range st.Self.TailscaleIPs {
		if !strings.Contains(ip, ":") {
			r.facts.TailscaleIPv4 = ip
		}
	}
	r.result.DNSName = strings.TrimSuffix(st.Self.DNSName, ".")
	log("joined as " + r.facts.TailscaleIPv4 + " (" + r.result.DNSName + ")")
	return nil
}

func (r *Runner) reachAdmin(ctx context.Context, log func(string)) error {
	p := r.o.Plan
	addr := p.Tailscale.AdminAddress
	if !p.Tailscale.UseExisting {
		addr = r.facts.TailscaleIPv4
		if addr == "" {
			ip, err := remote.TailscaleIPv4(ctx, r.pub)
			if err != nil {
				return err
			}
			addr = ip
		}
		if r.result.DNSName == "" {
			if st, err := remote.TailscaleStatus(ctx, r.pub); err == nil {
				r.result.DNSName = strings.TrimSuffix(st.Self.DNSName, ".")
			}
		}
		for {
			ok, detail := r.o.LocalTailscaleReady(ctx)
			if ok {
				break
			}
			again, err := r.o.Prompt.Confirm(ctx, "Tailscale on this computer is not connected",
				detail+"\n\nConnect this computer to the tailnet, then choose Yes to try again. No aborts; the server stays reachable over its public address.")
			if err != nil {
				return err
			}
			if !again {
				return errors.New("this computer is not on the tailnet, so the new firewall could not be confirmed")
			}
		}
	}
	if !remote.InterfaceExists(ctx, r.pub, p.Tailscale.AdminInterface) {
		return fmt.Errorf("interface %s does not exist on the server", p.Tailscale.AdminInterface)
	}
	r.result.AdminAddress = addr
	target := net.JoinHostPort(addr, fmt.Sprint(r.facts.SSHPort))
	log("connecting to " + target + " over " + p.Tailscale.AdminInterface)
	c, err := r.dialAdminRetry(ctx, target, 90*time.Second, log)
	if err != nil {
		return err
	}
	r.admin = c
	log("private connection works; the rest of the setup uses it")
	return nil
}

// dialAdminRetry keeps trying for up to wait; new tailnet nodes take a moment.
func (r *Runner) dialAdminRetry(ctx context.Context, target string, wait time.Duration, log func(string)) (*sshx.Client, error) {
	deadline := time.Now().Add(wait)
	var last error
	for attempt := 1; ; attempt++ {
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		c, err := r.dial(dctx, target, sshx.HostKeyPolicy{Expect: r.hostKey, Warn: log})
		cancel()
		if err == nil {
			return c, nil
		}
		last = err
		if errors.Is(err, sshx.ErrHostKeyMismatch) || ctx.Err() != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no SSH connection to %s after %s: %w", target, wait, last)
		}
		if attempt == 1 || attempt%4 == 0 {
			log("not reachable yet, retrying: " + shortErr(err))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func (r *Runner) hardenSSH(ctx context.Context, log func(string)) error {
	if err := remote.HardenSSHD(ctx, r.admin, log); err != nil {
		return err
	}
	auth := r.auth()
	auth.Password = ""
	target := net.JoinHostPort(r.result.AdminAddress, fmt.Sprint(r.facts.SSHPort))
	// sshd may be restarting for a moment; give key login up to 30s to work.
	deadline := time.Now().Add(30 * time.Second)
	for {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		test, err := sshx.Dial(dctx, target, auth, sshx.HostKeyPolicy{Expect: r.hostKey})
		cancel()
		if err == nil {
			test.Close()
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			log("key login no longer works, reverting the sshd change: " + shortErr(err))
			if rerr := remote.RevertSSHD(ctx, r.admin, log); rerr != nil {
				return fmt.Errorf("key login failed (%v) and the revert failed too: %w", err, rerr)
			}
			return fmt.Errorf("key-only login did not work, sshd hardening was reverted: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	log("key-only login verified over the private network")
	r.result.Hardened = true
	return nil
}

func (r *Runner) stageFirewall(ctx context.Context, log func(string)) error {
	return r.stageFirewallOn(ctx, r.admin, log)
}

func (r *Runner) stageFirewallOn(ctx context.Context, host remote.Host, log func(string)) error {
	p := r.o.Plan
	elements := nftgen.RenderElements(nil, nil)
	if len(p.Firewall.WebPorts) > 0 {
		log("fetching Cloudflare IP ranges")
		v4, v6, err := cloudflare.Fetch(ctx)
		if err != nil {
			return err
		}
		log(fmt.Sprintf("%d IPv4 and %d IPv6 Cloudflare prefixes", len(v4), len(v6)))
		elements = nftgen.RenderElements(v4, v6)
	}
	ruleset, err := nftgen.Render(nftgen.Params{
		AdminInterface:   p.Tailscale.AdminInterface,
		WANInterface:     p.Firewall.WANInterface,
		TailnetTCPPorts:  p.Firewall.TailnetPorts,
		TailnetAll:       p.Firewall.TailnetAll,
		WebPorts:         p.Firewall.WebPorts,
		AllowPing:        p.Firewall.AllowPing,
		TailscaleUDPPort: p.Tailscale.UDPPort,
	})
	if err != nil {
		return err
	}
	r.result.WebPorts = p.Firewall.WebPorts
	return remote.PrepareFirewall(ctx, host, r.facts, remote.FirewallFiles{
		Ruleset:        ruleset,
		Elements:       elements,
		CloudflareSync: p.Firewall.CloudflareSync && len(p.Firewall.WebPorts) > 0,
	}, log)
}

func (r *Runner) applyFirewall(ctx context.Context, log func(string)) error {
	return r.applyFirewallOn(ctx, r.admin, log)
}

func (r *Runner) applyFirewallOn(ctx context.Context, host remote.Host, log func(string)) error {
	secs := r.o.Plan.Firewall.RollbackSeconds
	log(fmt.Sprintf("if the next step cannot confirm within %ds, the server restores its previous firewall by itself", secs))
	return remote.ApplyFirewall(ctx, host, secs, log)
}

func (r *Runner) confirmFirewall(ctx context.Context, log func(string)) error {
	p := r.o.Plan
	target := net.JoinHostPort(r.result.AdminAddress, fmt.Sprint(r.facts.SSHPort))
	log("opening a new connection to " + target + " through the new rules")
	// Stop trying before the rollback fires, or we would connect through the
	// restored rules and mistake that for success.
	wait := time.Duration(p.Firewall.RollbackSeconds-10) * time.Second
	if wait < 10*time.Second {
		wait = 10 * time.Second
	}
	fresh, err := r.dialAdminRetry(ctx, target, wait, log)
	if err != nil {
		return r.waitForRollback(ctx, log, err)
	}
	defer fresh.Close()
	if at := r.rollbackMarker(ctx, fresh); at != "" {
		return r.rolledBackError(at, errors.New("the confirmation connection came too late"))
	}
	err = remote.ConfirmFirewall(ctx, fresh, r.facts, p.Firewall.CloudflareSync && len(p.Firewall.WebPorts) > 0, log)
	if errors.Is(err, remote.ErrRolledBack) {
		return r.rolledBackError(r.rollbackMarker(ctx, r.admin), err)
	}
	return err
}

// rollbackMarker returns the UTC time of a fired rollback, or "".
func (r *Runner) rollbackMarker(ctx context.Context, c remote.Host) string {
	out, err := c.Output(ctx, "cat "+remote.RolledBackMarker+" 2>/dev/null || true")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func (r *Runner) rolledBackError(at string, cause error) error {
	when := "a moment ago"
	if at != "" {
		when = "at " + at + " UTC"
	}
	r.attention(7, "the new rules could not be confirmed in time; the server rolled back to its previous firewall "+when)
	return fmt.Errorf("the new firewall could not be confirmed and the server rolled back to its previous rules %s: %w", when, cause)
}

func (r *Runner) waitForRollback(ctx context.Context, log func(string), cause error) error {
	secs := r.o.Plan.Firewall.RollbackSeconds
	r.attention(7, "the new rules block the private connection; waiting for the server to roll back on its own")
	log("reason: " + shortErr(cause))
	wait := time.Duration(secs)*time.Second + 10*time.Second
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
	}
	at := r.rollbackMarker(ctx, r.admin)
	if at == "" {
		log("warning: the rollback marker was not found; check `nft list ruleset` on the server")
		return fmt.Errorf("the new firewall could not be confirmed; the rollback should have fired but left no marker: %w", cause)
	}
	log("the previous firewall state is active again")
	return r.rolledBackError(at, cause)
}

func (r *Runner) verify(ctx context.Context, log func(string)) error {
	p := r.o.Plan
	for _, cmd := range []string{
		`nft list chain inet secure_setup input | grep -c accept | sed 's/^/accept rules in input chain: /'`,
		`systemctl is-enabled nftables 2>/dev/null | sed 's/^/nftables.service at boot: /'`,
		`systemctl is-active secure-setup-rollback.timer 2>/dev/null | sed 's/^/rollback timer: /'`,
	} {
		if out, err := r.admin.Output(ctx, cmd); err == nil && out != "" {
			log(out)
		}
	}
	if p.Firewall.CloudflareSync && len(p.Firewall.WebPorts) > 0 {
		if out, err := r.admin.Output(ctx, `systemctl list-timers secure-setup-cloudflare-sync.timer --no-legend --no-pager 2>/dev/null | awk '{print "next Cloudflare refresh: "$1" "$2" "$3}'`); err == nil && out != "" {
			log(out)
		}
	}

	// A brand-new TCP connection to the public address must now be blocked.
	// (The connection from step 1 survives: it is an established flow.)
	d := net.Dialer{Timeout: 6 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", p.Address())
	if err == nil {
		conn.Close()
		r.result.PublicSSHClosed = false
		r.result.PublicSSHNote = "a new connection to " + p.Address() + " still succeeds. If this address is not the server's internet interface (" + p.Firewall.WANInterface + "), that is expected; otherwise check the WAN interface name."
		r.attention(8, r.result.PublicSSHNote)
		return nil
	}
	r.result.PublicSSHClosed = true
	log("new connection to " + p.Address() + " from here: blocked (" + shortErr(err) + ")")
	return nil
}

// ---- helpers ----

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}
