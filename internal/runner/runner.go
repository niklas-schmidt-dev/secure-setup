// Package runner executes a plan step by step and reports progress through
// events, so the same logic drives the TUI and the non-interactive command.
package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

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
	// Unattended means nobody answers prompts or opens links (`here --yes`,
	// cloud-init). A local unattended run refuses the login-link join.
	Unattended bool
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
	RebootNeeded    bool   // the system update needs a reboot to finish
	RebootChecked   bool   // rebooted, and the lockdown came back on its own
	Tunnel          bool   // web traffic arrives through a Cloudflare Tunnel
	RebootScheduled bool   // local run: reboots shortly; the boot check reports
	TailscaleSSH    string // "on", or why it stayed off; "" when not requested
}

// Runner executes one plan.
type Runner struct {
	o     Options
	steps []step
	cur   int // index of the running step

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
	sshdPrev   string // the sshd drop-in an earlier run left; restored on failure

	tsSSHPaused  bool // Tailscale SSH was on and is off for this run (remote mode)
	viaTailnet   bool // the run's connection itself goes over the tailnet (a locked-down server)
	joined       bool // this run joined the tailnet
	joinedByLink bool // a login link was shown and the tailnet is not yet known to be the operator's
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
	// Event text carries output from the server (journal lines, peer names,
	// command output); it must not drive the operator's terminal.
	report := o.Report
	o.Report = func(e Event) {
		e.Text = Printable(e.Text)
		report(e)
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
		{name: "Update the system", skip: r.skipUpdate, run: r.updateSystem},
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
		{name: "Cloudflare Tunnel", run: func(ctx context.Context, log func(string)) error {
			return r.setupTunnel(ctx, r.admin, log)
		}},
		{name: "Stage the firewall", run: r.stageFirewall},
		{name: "Apply the firewall with a rollback timer", run: r.applyFirewall},
		{name: "Confirm over the private network", run: r.confirmFirewall},
		{name: "Verify from the outside", run: r.verify},
		{name: "Turn on Tailscale SSH", skip: func() string {
			if ts.UseExisting {
				return "no Tailscale"
			}
			if !ts.SSH && !r.tsSSHPaused {
				return "not requested"
			}
			return ""
		}, run: r.finishTailscaleSSH},
		{name: "Reboot and check", skip: r.skipReboot, run: r.rebootAndCheck},
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
		r.cur = i
		r.o.Report(Event{Kind: StepStart, Step: i})
		log := func(line string) { r.o.Report(Event{Kind: Log, Step: i, Text: line}) }
		if err := s.run(ctx, log); err != nil {
			r.o.Report(Event{Kind: StepFailed, Step: i, Text: err.Error()})
			r.revertLocalHardening(log)
			r.resumeTailscaleSSH(log)
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
		r.o.Report(Event{Kind: StepDone, Step: i})
	}
	return &r.result, nil
}

// revertLocalHardening removes the keys-only sshd change after a local run
// failed or rolled back. A local run cannot prove that the operator holds a
// key that works, so it does not leave password login off behind a failure.
func (r *Runner) revertLocalHardening(log func(string)) {
	if r.local == nil || !r.result.Hardened {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := remote.RestoreSSHD(ctx, r.local, r.sshdPrev, log); err != nil {
		log("could not revert the sshd hardening: " + shortErr(err))
		return
	}
	r.result.Hardened = false
	if r.sshdPrev != "" {
		log("sshd is back to the hardening of the earlier run because this run did not complete")
		return
	}
	log("password login restored because the run did not complete")
}

// attention reports something the operator must see, on the running step.
func (r *Runner) attention(text string) {
	r.o.Report(Event{Kind: Attention, Step: r.cur, Text: text})
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
	if err := resolveWAN(ctx, c, p, f, log); err != nil {
		return err
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
		r.attention("an earlier secure-setup run rolled its firewall back at " + f.RolledBack + " UTC; this run starts fresh")
	}
	if f.Tailscale {
		log("tailscale installed, state: " + orUnknown(f.TailscaleState))
		// Tailscale SSH takes over port 22 on the tailnet address, where the
		// run checks sshd; it comes back as the last step. Over a connection
		// that itself runs over the tailnet, switching it would cut that
		// connection, and a refused login afterwards could not be undone.
		r.viaTailnet = !p.Tailscale.UseExisting && tailnetAddr(c.RemoteIP())
		if !p.Tailscale.UseExisting && remote.TailscaleSSHOn(ctx, c) {
			if r.viaTailnet {
				return errors.New("this server runs Tailscale SSH and this connection goes over the tailnet, so pausing it for the run would cut the connection. Turn it off on the server first (`tailscale set --ssh=false`) or run `secure-setup here` there")
			}
			if err := remote.TailscaleSetSSH(ctx, c, false, log); err != nil {
				return err
			}
			r.tsSSHPaused = true
			log("Tailscale SSH is off for this run (it would take over port 22 on the tailnet address) and comes back at the end")
		}
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

func (r *Runner) joinTailnet(ctx context.Context, log func(string)) (err error) {
	p := r.o.Plan
	host := r.server()
	key := p.Tailscale.AuthKey
	if key == "" {
		log("no auth key given: tailscale will print a login link")
		// From here on, anyone who completes the link chooses the tailnet;
		// every failure until it is verified logs the node out again.
		r.joinedByLink = true
		defer func() { err = r.leaveUnverifiedTailnet(host, err, log) }()
	}
	err = remote.TailscaleUp(ctx, host, remote.UpOptions{AuthKey: key, Hostname: p.Tailscale.Hostname}, log,
		func(url string) {
			r.attention("Open this link in your browser to add the server to your tailnet:\n" + url)
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
	r.joined = true
	log("joined the tailnet " + st.Tailnet() + " as " + r.facts.TailscaleIPv4 + " (" + r.result.DNSName + ")")
	if r.local == nil {
		// Over SSH, reaching the node from this computer proves the tailnet
		// (reachAdmin); Tailscale SSH waits until then.
		return nil
	}
	if r.joinedByLink {
		// Whoever completed the login link chose the tailnet.
		ok, err := r.o.Prompt.Confirm(ctx, "Is "+st.Tailnet()+" your tailnet?",
			"This machine joined the tailnet "+st.Tailnet()+" through the login link. Whoever owns that tailnet can reach this machine once the firewall is live. Choose No if it is not yours: the machine logs out of it again.")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("the tailnet " + st.Tailnet() + " is not yours")
		}
		r.joinedByLink = false
	}
	return r.enableTailscaleSSH(ctx, host, log)
}

// leaveUnverifiedTailnet logs the node out after a failure while a login-link
// join is not verified, so it does not stay in a tailnet someone else may
// have chosen. It has its own context: a cancelled run still cleans up.
func (r *Runner) leaveUnverifiedTailnet(host remote.Host, err error, log func(string)) error {
	if err == nil || !r.joinedByLink {
		return err
	}
	r.joinedByLink = false
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if lerr := remote.TailscaleLogout(ctx, host, log); lerr != nil {
		return fmt.Errorf("%w; the login-link join was not verified and `tailscale logout` failed too (%v): run it on the server", err, lerr)
	}
	return fmt.Errorf("%w; the login-link join was not verified, so the server logged out of that tailnet again", err)
}

// enableTailscaleSSH turns Tailscale SSH on for a node this run joined, once
// its tailnet is known to be the operator's.
func (r *Runner) enableTailscaleSSH(ctx context.Context, host remote.Host, log func(string)) error {
	if !r.joined || !r.o.Plan.Tailscale.SSH {
		return nil
	}
	if err := remote.TailscaleSetSSH(ctx, host, true, log); err != nil {
		return err
	}
	r.result.TailscaleSSH = "on"
	return nil
}

func (r *Runner) reachAdmin(ctx context.Context, log func(string)) (err error) {
	// After a login-link join, only reaching the node from this computer
	// shows the tailnet is the operator's; otherwise it leaves it again.
	defer func() { err = r.leaveUnverifiedTailnet(r.pub, err, log) }()
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
	r.joinedByLink = false // reached from this computer: the tailnet is the operator's
	log("private connection works; the rest of the setup uses it")
	return nil
}

// finishTailscaleSSH turns Tailscale SSH on as the last step. It takes over
// port 22 on the tailnet address, so every check above ran against sshd
// first; switched on earlier it cut the private connection. A fresh login
// through it must work, or it goes off again so sshd with the key stays
// reachable over the tailnet.
func (r *Runner) finishTailscaleSSH(ctx context.Context, log func(string)) error {
	if r.viaTailnet {
		r.result.TailscaleSSH = "off: not switched on over a tailnet connection (it would cut that connection, and a refused login could not be undone); run `tailscale set --ssh` on the server"
		log("not turning Tailscale SSH on: this run is connected over the tailnet")
		return nil
	}
	if err := remote.TailscaleSetSSH(ctx, r.pub, true, log); err != nil {
		return err
	}
	r.tsSSHPaused = false
	auth := r.auth()
	auth.Password = ""
	auth.Banner = func(msg string) {
		// The tailnet policy's "check" action asks for a browser login here.
		r.attention("Tailscale SSH: " + strings.TrimSpace(msg))
	}
	// Tailscale SSH answers port 22 only, whatever port sshd uses.
	target := net.JoinHostPort(r.result.AdminAddress, "22")
	log("checking a new login to " + target + " through Tailscale SSH")
	dctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	c, err := sshx.Dial(dctx, target, auth, sshx.HostKeyPolicy{Expect: r.hostKey, Warn: log})
	cancel()
	if err == nil {
		c.Close()
		r.result.TailscaleSSH = "on"
		log("Tailscale SSH works; logins over the tailnet now follow your tailnet policy")
		return nil
	}
	log("a login through Tailscale SSH did not work (" + shortErr(err) + "); switching it off again")
	// Its own context: an interrupted check must still switch it off.
	octx, ocancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer ocancel()
	if oerr := remote.TailscaleSetSSH(octx, r.pub, false, log); oerr != nil {
		return fmt.Errorf("a login through Tailscale SSH failed (%v) and switching it off failed too: %w; run `tailscale set --ssh=false` on the server", err, oerr)
	}
	r.result.TailscaleSSH = "off: a login through it did not work (" + shortErr(err) + "); sshd with your key works. Try `tailscale set --ssh` on the server once your tailnet policy allows you in"
	return nil
}

// resumeTailscaleSSH turns Tailscale SSH back on after a failed run that
// paused it.
func (r *Runner) resumeTailscaleSSH(log func(string)) {
	if !r.tsSSHPaused || r.pub == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := remote.TailscaleSetSSH(ctx, r.pub, true, log); err != nil {
		log("could not turn Tailscale SSH back on: " + shortErr(err) + "; run `tailscale set --ssh` on the server")
		return
	}
	r.tsSSHPaused = false
}

// setupTunnel installs cloudflared and connects the tunnel before the
// firewall changes: with a tunnel no web port is opened at all. A plan
// without one removes the tunnel an earlier run set up.
func (r *Runner) setupTunnel(ctx context.Context, host remote.Host, log func(string)) error {
	if !r.o.Plan.Firewall.CloudflareTunnel {
		return remote.RemoveTunnel(ctx, host, log)
	}
	if err := remote.InstallCloudflared(ctx, host, r.facts, log); err != nil {
		return err
	}
	if err := remote.SetupTunnel(ctx, host, r.o.Plan.Firewall.TunnelToken, log); err != nil {
		return err
	}
	r.result.Tunnel = true
	return nil
}

func (r *Runner) skipReboot() string {
	if !r.o.Plan.Reboot {
		return "not requested"
	}
	return ""
}

func (r *Runner) skipUpdate() string {
	if !r.o.Plan.UpdateSystem {
		return "not requested"
	}
	return ""
}

// updateSystem installs pending package updates before anything is installed.
func (r *Runner) updateSystem(ctx context.Context, log func(string)) error {
	reboot, err := remote.UpdateSystem(ctx, r.server(), r.facts, log)
	if err != nil {
		return err
	}
	if reboot {
		r.result.RebootNeeded = true
		r.attention("the update needs a reboot to finish (new kernel or core libraries); reboot once the setup is done")
	}
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
	prev, err := remote.HardenSSHD(ctx, r.admin, log)
	r.sshdPrev = prev
	if err != nil {
		_ = remote.RestoreSSHD(ctx, r.admin, prev, log)
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
			if rerr := remote.RestoreSSHD(ctx, r.admin, r.sshdPrev, log); rerr != nil {
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
	if err := verifyKeysOnly(ctx, r.admin, r.o.Plan.Server.User, r.result.AdminAddress, r.facts.SSHPort, r.sshdPrev, log); err != nil {
		return err
	}
	r.result.Hardened = true
	return nil
}

// verifyKeysOnly checks sshd's effective per-connection policy after the
// hardening and reverts it when passwords are still accepted anywhere.
func verifyKeysOnly(ctx context.Context, host remote.Host, user, laddr string, port int, prev string, log func(string)) error {
	if user == "" {
		user = "root"
	}
	err := remote.VerifySSHD(ctx, host, user, laddr, port, keysOnlyPeers...)
	if err == nil {
		log("sshd's effective policy: password and keyboard-interactive login off")
		return nil
	}
	log("password login is still possible, reverting the sshd change: " + shortErr(err))
	if rerr := remote.RestoreSSHD(ctx, host, prev, log); rerr != nil {
		return fmt.Errorf("%v, and the revert failed too: %w", err, rerr)
	}
	return fmt.Errorf("sshd hardening did not take effect and was reverted: %w", err)
}

// resolveWAN picks the internet interface for the forward chain. A value in
// the plan that differs from this server's default-route interface (for
// example from a plan saved on another server) must exist here and be
// confirmed with wan_interface_override.
func resolveWAN(ctx context.Context, host remote.Host, p *plan.Plan, f *remote.Facts, log func(string)) error {
	switch {
	case p.Firewall.WANInterface == "" && f.WANIface == "":
		return errors.New("could not find the interface with the default route; set wan_interface in the plan")
	case p.Firewall.WANInterface == "":
		p.Firewall.WANInterface = f.WANIface
	case p.Firewall.WANInterface != f.WANIface:
		if !remote.InterfaceExists(ctx, host, p.Firewall.WANInterface) {
			return fmt.Errorf("the plan's wan_interface %q does not exist on this server (its default route uses %s); remove wan_interface from the plan", p.Firewall.WANInterface, orUnknown(f.WANIface))
		}
		if !p.Firewall.WANOverride {
			return fmt.Errorf("the plan's wan_interface %q differs from this server's default-route interface %s; remove wan_interface from the plan, or set \"wan_interface_override\": true if %q really carries the internet traffic", p.Firewall.WANInterface, orUnknown(f.WANIface), p.Firewall.WANInterface)
		}
		log("using wan_interface " + p.Firewall.WANInterface + " from the plan instead of the default-route interface " + orUnknown(f.WANIface))
	}
	return nil
}

func (r *Runner) stageFirewall(ctx context.Context, log func(string)) error {
	return r.stageFirewallOn(ctx, r.admin, log)
}

// extraWAN lists the other internet-facing devices: those with a default
// route (an IPv6 uplink, a second provider link) and network cards with a
// public address but no default route. Forwarded traffic from them is
// treated like the internet, not like an internal bridge.
func (r *Runner) extraWAN(log func(string)) []string {
	var seen, out []string
	for _, n := range append(slices.Clone(r.facts.WANIfaces), r.facts.PublicNICs...) {
		if slices.Contains(seen, n) {
			continue
		}
		seen = append(seen, n)
		switch n {
		case r.o.Plan.Firewall.WANInterface:
		case r.o.Plan.Tailscale.AdminInterface:
			log("the admin interface " + n + " also faces the internet; it stays trusted for forwarding")
		default:
			out = append(out, n)
		}
	}
	if len(out) > 0 {
		log("further internet-facing interfaces: " + strings.Join(out, ", ") + " (forwarded traffic from them is filtered like " + r.o.Plan.Firewall.WANInterface + ")")
	}
	return out
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
		ExtraWAN:         r.extraWAN(log),
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
	r.attention("the new rules could not be confirmed in time; the server rolled back to its previous firewall " + when)
	return fmt.Errorf("the new firewall could not be confirmed and the server rolled back to its previous rules %s: %w", when, cause)
}

func (r *Runner) waitForRollback(ctx context.Context, log func(string), cause error) error {
	secs := r.o.Plan.Firewall.RollbackSeconds
	r.attention("the new rules block the private connection; waiting for the server to roll back on its own")
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
	open, detail := r.publicSSHOpen(ctx)
	if open {
		r.result.PublicSSHClosed = false
		r.result.PublicSSHNote = "a new connection to " + p.Address() + " still succeeds. If this address is not the server's internet interface (" + p.Firewall.WANInterface + "), that is expected; otherwise check the WAN interface name."
		r.attention(r.result.PublicSSHNote)
		return nil
	}
	r.result.PublicSSHClosed = true
	log("new connection to " + p.Address() + " from here: blocked (" + detail + ")")
	return nil
}

// publicSSHOpen reports whether a brand-new connection to the server's public
// SSH address still succeeds.
func (r *Runner) publicSSHOpen(ctx context.Context) (bool, string) {
	d := net.Dialer{Timeout: 6 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", r.o.Plan.Address())
	if err != nil {
		return false, shortErr(err)
	}
	conn.Close()
	return true, ""
}

// ---- helpers ----

// keysOnlyPeers are the connections whose effective sshd policy is checked:
// a tailnet peer, private ranges and an internet address.
var keysOnlyPeers = []string{"100.64.0.1", "10.0.0.1", "192.168.0.1", "203.0.113.1"}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// Printable replaces control characters other than newline and tab, so text
// that came from the server cannot drive the operator's terminal.
func Printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || !unicode.IsControl(r) {
			return r
		}
		return '?'
	}, s)
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

// tailnetAddr reports whether ip is a Tailscale address (100.64.0.0/10 or
// fd7a:115c:a1e0::/48).
func tailnetAddr(ip netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(ip)
}
