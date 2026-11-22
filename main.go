// secure-setup locks a fresh Linux server down: SSH only over Tailscale,
// HTTPS only from Cloudflare, everything else dropped. Run it without
// arguments for the guided wizard.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/niklas-schmidt-dev/secure-setup/internal/localhost"
	"github.com/niklas-schmidt-dev/secure-setup/internal/nftgen"
	"github.com/niklas-schmidt-dev/secure-setup/internal/plan"
	"github.com/niklas-schmidt-dev/secure-setup/internal/remote"
	"github.com/niklas-schmidt-dev/secure-setup/internal/runner"
	"github.com/niklas-schmidt-dev/secure-setup/internal/sshx"
	"github.com/niklas-schmidt-dev/secure-setup/internal/textui"
	"github.com/niklas-schmidt-dev/secure-setup/internal/tui"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "aborted")
			os.Exit(130)
		}
		fmt.Fprintln(os.Stderr, "error:", runner.Printable(err.Error()))
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		p := plan.Default()
		return tui.Run(ctx, &p, version)
	}
	switch args[0] {
	case "here":
		return cmdHere(ctx, args[1:])
	case "confirm":
		return cmdConfirm(ctx)
	case "apply":
		return cmdApply(ctx, args[1:])
	case "render":
		return cmdRender(args[1:])
	case "boot-check":
		return cmdBootCheck(ctx)
	case "status":
		return cmdStatus(ctx, args[1:])
	case "undo":
		return cmdUndo(ctx, args[1:])
	case "version", "--version", "-v":
		fmt.Println("secure-setup", version)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	}
	usage()
	return fmt.Errorf("unknown command %q", args[0])
}

func usage() {
	fmt.Print(`secure-setup ` + version + `

From your computer:
  secure-setup                      guided setup of a server over SSH (TUI)
  secure-setup apply -f plan.json   run a saved plan without the wizard
                                    (--host ADDR: the same plan for another server)
  secure-setup status --host ADDR   show the lockdown of a server and what is wrong with it
  secure-setup undo --host ADDR     remove the firewall, timers and sshd change again

On the server itself:
  secure-setup here                 guided setup of this machine (TUI)
  secure-setup here --yes           no questions: defaults, confirmed by self-checks
  secure-setup here -f plan.json    run a saved plan on this machine
  secure-setup confirm              in a new tailnet session: confirm a waiting setup
  secure-setup status --here        show the lockdown of this machine (--json for scripts)
  secure-setup undo --here          remove it from this machine again

status and undo also take -f plan.json instead of --host: the address, port,
user and key come from the plan.

  secure-setup render -f plan.json  print the nftables ruleset a plan produces

Secrets are read from the environment in non-interactive mode:
  SECURE_SETUP_PASSWORD, SECURE_SETUP_PASSPHRASE, TS_AUTHKEY, CLOUDFLARE_TUNNEL_TOKEN
`)
}

func cmdHere(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("here", flag.ContinueOnError)
	file := fs.String("f", "", "plan file (JSON) to apply on this machine")
	yes := fs.Bool("yes", false, "do not ask anything: plan defaults, confirmation by self-checks")
	confirm := fs.String("confirm", "", "how the new rules are confirmed: login (a new SSH session over the tailnet) or self (checks only, for unattended runs)")
	noTUI := fs.Bool("no-tui", false, "plain text instead of the wizard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	host, err := localhost.New(ctx)
	if err != nil {
		return err
	}
	interactive := term.IsTerminal(int(os.Stdin.Fd())) && !*yes
	p, loadedFrom := plan.Default(), ""
	if *file != "" {
		if p, err = plan.Load(*file); err != nil {
			return err
		}
	} else if interactive && !*noTUI {
		// The wizard starts from the answers of the last run on this machine.
		if saved, err := plan.Load(plan.LocalSavePath); err == nil && saved.Local {
			p, loadedFrom = saved, plan.LocalSavePath
		}
	}
	p.Local = true
	p.Server.User = localhost.LoginUser()
	p.Tailscale.AuthKey = os.Getenv("TS_AUTHKEY")
	p.Firewall.TunnelToken = os.Getenv("CLOUDFLARE_TUNNEL_TOKEN")
	switch {
	case *confirm != "":
		p.Firewall.ConfirmBy = *confirm
	case p.Firewall.ConfirmBy != "":
	case interactive:
		p.Firewall.ConfirmBy = plan.ConfirmLogin
	default:
		p.Firewall.ConfirmBy = plan.ConfirmSelf
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if interactive && !*noTUI {
		return tui.RunHere(ctx, &p, version, host, loadedFrom)
	}
	return runHereText(ctx, &p, host, *yes || !interactive)
}

func runHereText(ctx context.Context, p *plan.Plan, host *localhost.Host, yes bool) error {
	prompt := textui.Prompter{AssumeYes: yes}
	fmt.Printf("secure-setup %s: locking this machine down\n", version)
	if !yes {
		ok, err := prompt.Confirm(ctx, "Continue?", describe(p))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("not confirmed")
		}
	} else {
		fmt.Print(describe(p))
	}
	opts := runner.Options{Plan: p, Prompt: prompt, Local: host, Unattended: yes}
	log := reportWithLog(&opts, "this-machine")
	defer log.Close()
	res, err := runner.New(opts).Run(ctx)
	return finish(log, "This machine is locked down.", p, res, err)
}

// reportWithLog makes a run print its events and write them to its log file.
func reportWithLog(opts *runner.Options, name string) *textui.Transcript {
	steps := runner.New(*opts).Steps()
	log := textui.OpenTranscript(name, steps)
	print := textui.Reporter(os.Stdout, steps)
	opts.Report = func(e runner.Event) {
		print(e)
		log.Event(e)
	}
	return log
}

// finish prints how a run ended and where its log is.
func finish(log *textui.Transcript, done string, p *plan.Plan, res *runner.Result, err error) error {
	if err != nil {
		if log.Path != "" {
			fmt.Fprintln(os.Stderr, "log of this run:", log.Path)
		}
		return err
	}
	summary := tui.Summary(p, res)
	log.Note(done + "\n" + summary)
	fmt.Println()
	fmt.Println(done)
	fmt.Println()
	fmt.Print(summary)
	if log.Path != "" {
		fmt.Printf("%-24s %s\n", "Log of this run", log.Path)
	}
	return nil
}

// cmdConfirm runs in a fresh SSH session on the server while `here` waits
// for a login. It checks that the session arrived over the private address,
// on a connection opened after the rules went live.
func cmdConfirm(ctx context.Context) error {
	host, err := localhost.New(ctx)
	if err != nil {
		return err
	}
	expect, err := host.Output(ctx, "cat "+runner.ConfirmExpectPath+" 2>/dev/null || true")
	if err != nil {
		return err
	}
	client, server := localhost.SSHSession()
	if expect != "" && !server.IsValid() {
		if os.Getenv("SUDO_USER") != "" {
			return errors.New("sudo dropped SSH_CONNECTION; run it as: sudo --preserve-env=SSH_CONNECTION secure-setup confirm")
		}
		return errors.New("this is not an SSH session; run `secure-setup confirm` in a new SSH login over the tailnet")
	}
	if err := runner.CheckConfirm(expect, client, server); err != nil {
		return err
	}
	if err := host.WriteFile(ctx, runner.ConfirmedPath, []byte(client.String()+"\n"), "0600"); err != nil {
		return err
	}
	fmt.Printf("confirmed: this session arrived over %s from %s; the setup keeps the new rules\n", server.Addr(), client.Addr())
	return nil
}

func cmdApply(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	file := fs.String("f", "", "plan file (JSON); the wizard saves one in ~/.config/secure-setup/")
	yes := fs.Bool("yes", false, "do not ask: accept the plan and first-seen host keys")
	host := fs.String("host", "", "server address to use instead of the plan's: one plan for several servers")
	hostKey := fs.String("host-key", "", "fingerprint the server's host key must have (SHA256:..., as ssh-keygen -lf prints it), instead of trusting the first key seen")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return errors.New("apply needs -f plan.json")
	}
	// Validated below, once the flags and the environment are filled in.
	p, err := plan.Read(*file)
	if err != nil {
		return err
	}
	if *host != "" {
		if p.Local {
			return errors.New("--host does not go with a plan for this machine (\"local\": true)")
		}
		p.Server.Host = *host
	}
	if *hostKey != "" {
		p.Server.HostKey = *hostKey
	}
	p.Server.Password = os.Getenv("SECURE_SETUP_PASSWORD")
	p.Server.Passphrase = os.Getenv("SECURE_SETUP_PASSPHRASE")
	p.Tailscale.AuthKey = os.Getenv("TS_AUTHKEY")
	p.Firewall.TunnelToken = os.Getenv("CLOUDFLARE_TUNNEL_TOKEN")
	// With the secrets from the environment: it takes the tunnel token out of
	// a pasted install command.
	if err := p.Validate(); err != nil {
		return fmt.Errorf("%s: %w", *file, err)
	}
	if p.Local {
		host, err := localhost.New(ctx)
		if err != nil {
			return err
		}
		p.Server.User = localhost.LoginUser()
		if p.Firewall.ConfirmBy == "" {
			p.Firewall.ConfirmBy = plan.ConfirmSelf
		}
		return runHereText(ctx, &p, host, *yes)
	}

	prompt := textui.Prompter{AssumeYes: *yes}
	fmt.Printf("secure-setup %s: applying %s to %s\n", version, *file, p.Address())
	if !*yes {
		ok, err := prompt.Confirm(ctx, "Continue?", describe(&p))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("not confirmed")
		}
	}
	opts := runner.Options{Plan: &p, Prompt: prompt, Unattended: *yes}
	log := reportWithLog(&opts, p.Server.Host)
	defer log.Close()
	res, err := runner.New(opts).Run(ctx)
	return finish(log, "The server is locked down.", &p, res, err)
}

func describe(p *plan.Plan) string {
	var b strings.Builder
	if p.Local {
		fmt.Fprintf(&b, "  server          this machine\n")
	} else {
		fmt.Fprintf(&b, "  server          %s as %s\n", p.Address(), p.Server.User)
		if p.Server.HostKey != "" {
			fmt.Fprintf(&b, "  host key        must be %s\n", p.Server.HostKey)
		}
	}
	if p.Tailscale.UseExisting {
		fmt.Fprintf(&b, "  admin network   existing, %s on %s\n", p.Tailscale.AdminAddress, p.Tailscale.AdminInterface)
	} else {
		fmt.Fprintf(&b, "  tailscale       install and join (hostname %q)\n", p.Tailscale.Hostname)
		if len(p.Tailscale.Tags) > 0 {
			fmt.Fprintf(&b, "  tailscale tags  %s\n", strings.Join(p.Tailscale.Tags, ", "))
		}
		if p.Tailscale.LoginServer != "" {
			fmt.Fprintf(&b, "  login server    %s\n", p.Tailscale.LoginServer)
		}
	}
	fmt.Fprintf(&b, "  tailnet ports   TCP %s\n", plan.FormatPorts(p.Firewall.TailnetPorts))
	if p.Firewall.CloudflareTunnel {
		fmt.Fprintf(&b, "  web             Cloudflare Tunnel, no web port opened\n")
	} else {
		fmt.Fprintf(&b, "  web ports       TCP %s from Cloudflare\n", orNone(plan.FormatPorts(p.Firewall.WebPorts)))
	}
	if public := plan.PublicPorts(p.Firewall); public != "" {
		fmt.Fprintf(&b, "  public ports    %s, open to the whole internet\n", public)
	}
	fmt.Fprintf(&b, "  ping            %v\n", p.Firewall.AllowPing)
	fmt.Fprintf(&b, "  sshd keys only  %v\n", p.SSH.Harden)
	fmt.Fprintf(&b, "  system update   %v\n", p.UpdateSystem)
	fmt.Fprintf(&b, "  auto updates    %v\n", p.AutoUpdates)
	fmt.Fprintf(&b, "  reboot + check  %v\n", p.Reboot)
	fmt.Fprintf(&b, "  rollback        %ds\n", p.Firewall.RollbackSeconds)
	if p.Firewall.WANInterface != "" {
		fmt.Fprintf(&b, "  internet iface  %s (from the plan; checked against the server's default route)\n", p.Firewall.WANInterface)
	}
	if p.Local {
		fmt.Fprintf(&b, "  confirmation    %s\n", map[string]string{plan.ConfirmLogin: "a new login over the tailnet", plan.ConfirmSelf: "self-checks (unattended)"}[p.Firewall.ConfirmBy])
	}
	return b.String()
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func cmdRender(args []string) error {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	file := fs.String("f", "", "plan file (JSON)")
	wan := fs.String("wan", "", "internet interface name (overrides the plan; default eth0)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p := plan.Default()
	if *file != "" {
		var err error
		if p, err = plan.Load(*file); err != nil {
			return err
		}
	}
	if *wan != "" {
		p.Firewall.WANInterface = *wan
	}
	if p.Firewall.WANInterface == "" {
		p.Firewall.WANInterface = "eth0"
	}
	out, err := nftgen.Render(nftgen.Params{
		AdminInterface:   p.Tailscale.AdminInterface,
		AdminAddress:     p.AdminAddr(),
		WANInterface:     p.Firewall.WANInterface,
		ExtraWAN:         p.Firewall.ExtraWANInterfaces,
		TailnetTCPPorts:  p.Firewall.TailnetPorts,
		TailnetAll:       p.Firewall.TailnetAll,
		WebPorts:         p.Firewall.WebPorts,
		PublicTCPPorts:   p.Firewall.PublicTCPPorts,
		PublicUDPPorts:   p.Firewall.PublicUDPPorts,
		AllowPing:        p.Firewall.AllowPing,
		TailscaleUDPPort: p.Tailscale.UDPPort,
	})
	if err != nil {
		return err
	}
	fmt.Print(out)
	return nil
}

const undoScript = `
systemctl disable --now secure-setup-cloudflare-sync.timer >/dev/null 2>&1 || true
systemctl stop secure-setup-rollback.timer >/dev/null 2>&1 || true
rm -f /etc/systemd/system/secure-setup-cloudflare-sync.timer /etc/systemd/system/secure-setup-cloudflare-sync.service /usr/local/sbin/secure-setup-cloudflare-sync
systemctl daemon-reload
if nft list table inet secure_setup >/dev/null 2>&1; then nft delete table inet secure_setup; echo "firewall table removed: all inbound traffic is allowed again"; fi
nft delete table inet ` + remote.TrackTable + ` 2>/dev/null || true
if [ -f /etc/nftables.conf.secure-setup.bak ]; then
	mv -f /etc/nftables.conf.secure-setup.bak /etc/nftables.conf
	echo "restored the previous /etc/nftables.conf"
elif grep -q 'Managed by secure-setup' /etc/nftables.conf 2>/dev/null; then
	rm -f /etc/nftables.conf
	systemctl disable nftables >/dev/null 2>&1 || true
	echo "removed /etc/nftables.conf and disabled nftables.service at boot"
fi
` + remote.NFTBootFileScript + `if [ -n "$boot" ] && [ "$boot" != /etc/nftables.conf ] && [ -f "$boot" ]; then
	sed -i '/^# secure-setup: added the next line$/{N;d;}' "$boot"
	if [ ! -e /etc/nftables.conf ]; then sed -i '\|^include "/etc/nftables.conf"$|d' "$boot"; fi
	echo "removed the include of /etc/nftables.conf from $boot"
fi
if [ -e /var/lib/secure-setup/ufw-retired ]; then
	systemctl enable ufw >/dev/null 2>&1 || true
	if ufw --force enable >/dev/null 2>&1; then echo "ufw re-enabled (it was active before secure-setup)"; else echo "ufw was active before secure-setup; re-enable it with: ufw enable"; fi
fi
if [ -e /var/lib/secure-setup/firewalld-retired ]; then
	systemctl unmask firewalld >/dev/null 2>&1 || true
	echo "firewalld unmasked; it was in use before secure-setup: start it again with: systemctl enable --now firewalld"
fi
systemctl disable secure-setup-bootcheck.service >/dev/null 2>&1 || true
if [ -f /etc/systemd/system/secure-setup-cloudflared.service ]; then
	systemctl disable --now secure-setup-cloudflared.service >/dev/null 2>&1 || true
	rm -f /etc/systemd/system/secure-setup-cloudflared.service
	systemctl daemon-reload
	echo "Cloudflare Tunnel service removed (cloudflared stays installed; delete the tunnel in the Cloudflare dashboard if you no longer need it)"
fi
rm -f /etc/systemd/system/secure-setup-bootcheck.service /etc/motd.d/secure-setup
` + remote.UndoAutoUpdatesScript + `rm -rf /etc/secure-setup /var/lib/secure-setup
if [ -f /etc/ssh/sshd_config.d/00-secure-setup.conf ] || grep -q '^# secure-setup: added the next line$' /etc/ssh/sshd_config 2>/dev/null; then
` + remote.RevertSSHDScript + `	echo "sshd hardening removed"
fi
echo "undo complete; Tailscale was left installed"
`

// cmdBootCheck runs once after a reboot that `secure-setup here` scheduled,
// started by its systemd unit.
func cmdBootCheck(ctx context.Context) error {
	host, err := localhost.New(ctx)
	if err != nil {
		return err
	}
	msg, err := runner.BootCheck(ctx, host)
	fmt.Print(msg)
	return err
}

// printUndoLine shows a line of the undo script's output, which comes from
// the server and must not drive this terminal.
func printUndoLine(line string) { fmt.Println("   ", runner.Printable(line)) }

// target is how status and undo reach a server: this machine, or over SSH
// with the connection from the flags or from a plan file.
type target struct {
	fs              *flag.FlagSet
	host, user, key *string
	file            *string
	port            *int
	here            *bool
}

func targetFlags(fs *flag.FlagSet) *target {
	return &target{
		fs:   fs,
		host: fs.String("host", "", "address to connect to (tailnet IP or name)"),
		here: fs.Bool("here", false, "this machine instead of a server over SSH"),
		port: fs.Int("port", 22, "SSH port"),
		user: fs.String("user", "root", "SSH user"),
		key:  fs.String("key", "", "private key file (default: ssh-agent and ~/.ssh keys)"),
		file: fs.String("f", "", "plan file: take the address, port, user and key from it"),
	}
}

// resolve fills in what a plan file says and no flag overrides. The lockdown
// closed the plan's public address, so the server is reached at its private
// one: the existing network's address, or its name in the tailnet.
func (t *target) resolve() error {
	if *t.file != "" {
		p, err := plan.Load(*t.file)
		if err != nil {
			return err
		}
		set := map[string]bool{}
		t.fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		switch {
		case p.Local && !set["host"]:
			*t.here = true
		case !p.Local:
			if !set["port"] {
				*t.port = p.Server.Port
			}
			if !set["user"] {
				*t.user = p.Server.User
			}
			if !set["key"] {
				*t.key = p.Server.KeyPath
			}
			if !set["host"] && !*t.here {
				switch {
				case p.Tailscale.UseExisting:
					*t.host = p.Tailscale.AdminAddress
				case p.Tailscale.Hostname != "":
					*t.host = p.Tailscale.Hostname
				default:
					return errors.New("the plan does not name the server in the tailnet (tailscale.hostname is empty); add --host with its tailnet address or name")
				}
			}
		}
	}
	if *t.host == "" && !*t.here {
		return errors.New("needs --host ADDR, -f plan.json, or --here on the server itself")
	}
	return nil
}

func (t *target) where() string {
	if *t.here {
		return "this machine"
	}
	return *t.host
}

// connect returns the host to work on and what ends the connection to it.
func (t *target) connect(ctx context.Context, prompt textui.Prompter) (remote.Host, func(), error) {
	if *t.here {
		h, err := localhost.New(ctx)
		if err != nil {
			return nil, nil, err
		}
		return h, func() {}, nil
	}
	auth := sshx.Auth{User: *t.user, KeyPath: *t.key, Password: os.Getenv("SECURE_SETUP_PASSWORD"), Passphrase: os.Getenv("SECURE_SETUP_PASSPHRASE")}
	c, err := sshx.Dial(ctx, net.JoinHostPort(*t.host, strconv.Itoa(*t.port)), auth, sshx.HostKeyPolicy{Prompter: prompt})
	if err != nil {
		return nil, nil, err
	}
	if err := c.EnsureRoot(ctx); err != nil {
		c.Close()
		return nil, nil, err
	}
	return c, func() { c.Close() }, nil
}

// cmdStatus shows what a server has of the lockdown and what is wrong with
// it. It changes nothing and exits with 1 when it finds a problem.
func cmdStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	t := targetFlags(fs)
	asJSON := fs.Bool("json", false, "print the report as JSON")
	yes := fs.Bool("yes", false, "accept a first-seen host key without asking")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := t.resolve(); err != nil {
		return fmt.Errorf("status %w", err)
	}
	// Questions go to stderr, so stdout carries nothing but the report.
	host, done, err := t.connect(ctx, textui.Prompter{AssumeYes: *yes, Out: os.Stderr})
	if err != nil {
		return err
	}
	defer done()
	st, err := runner.ReadStatus(ctx, host)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(st); err != nil {
			return err
		}
	} else {
		fmt.Print(st.Text())
	}
	if !st.OK {
		return fmt.Errorf("%d problem(s) with the lockdown of %s", len(st.Problems), t.where())
	}
	return nil
}

func cmdUndo(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("undo", flag.ContinueOnError)
	t := targetFlags(fs)
	yes := fs.Bool("yes", false, "do not ask")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := t.resolve(); err != nil {
		return fmt.Errorf("undo %w", err)
	}
	prompt := textui.Prompter{AssumeYes: *yes}
	if !*yes {
		ok, err := prompt.Confirm(ctx, "Remove the secure-setup firewall, timers and sshd change on "+t.where()+"?", "The server becomes reachable from the whole internet again.")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("not confirmed")
		}
	}
	host, done, err := t.connect(ctx, prompt)
	if err != nil {
		return err
	}
	defer done()
	return host.Script(ctx, undoScript, printUndoLine)
}
