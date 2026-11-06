// secure-setup locks a fresh Linux server down: SSH only over Tailscale,
// HTTPS only from Cloudflare, everything else dropped. Run it without
// arguments for the guided wizard.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
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
  secure-setup undo --host ADDR     remove the firewall, timers and sshd change again

On the server itself:
  secure-setup here                 guided setup of this machine (TUI)
  secure-setup here --yes           no questions: defaults, confirmed by self-checks
  secure-setup here -f plan.json    run a saved plan on this machine
  secure-setup confirm              in a new tailnet session: confirm a waiting setup
  secure-setup undo --here          remove it from this machine again

  secure-setup render -f plan.json  print the nftables ruleset a plan produces

Secrets are read from the environment in non-interactive mode:
  SECURE_SETUP_PASSWORD, SECURE_SETUP_PASSPHRASE, TS_AUTHKEY
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
	p := plan.Default()
	if *file != "" {
		if p, err = plan.Load(*file); err != nil {
			return err
		}
	}
	p.Local = true
	p.Server.User = localhost.LoginUser()
	p.Tailscale.AuthKey = os.Getenv("TS_AUTHKEY")
	interactive := term.IsTerminal(int(os.Stdin.Fd())) && !*yes
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
		return tui.RunHere(ctx, &p, version, host)
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
	opts.Report = textui.Reporter(os.Stdout, runner.New(opts).Steps())
	res, err := runner.New(opts).Run(ctx)
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("This machine is locked down.")
	fmt.Println()
	fmt.Print(tui.Summary(p, res))
	return nil
}

// cmdConfirm runs in a fresh SSH session on the server while `here` waits
// for a login. It checks that the session arrived over the private address.
func cmdConfirm(ctx context.Context) error {
	host, err := localhost.New(ctx)
	if err != nil {
		return err
	}
	expect, err := host.Output(ctx, "cat "+runner.ConfirmExpectPath+" 2>/dev/null || true")
	if err != nil {
		return err
	}
	if expect == "" {
		return errors.New("nothing to confirm: no `secure-setup here` run is waiting on this machine")
	}
	client, server := localhost.SSHSession()
	if !server.IsValid() {
		if os.Getenv("SUDO_USER") != "" {
			return errors.New("sudo dropped SSH_CONNECTION; run it as: sudo --preserve-env=SSH_CONNECTION secure-setup confirm")
		}
		return errors.New("this is not an SSH session; run `secure-setup confirm` in a new SSH login over the tailnet")
	}
	if server.String() != expect {
		return fmt.Errorf("this session came in over %s, not %s; log in over the tailnet address and run it there", server, expect)
	}
	if err := host.WriteFile(ctx, runner.ConfirmedPath, []byte(client.String()+"\n"), "0600"); err != nil {
		return err
	}
	fmt.Printf("confirmed: this session arrived over %s from %s; the setup keeps the new rules\n", server, client)
	return nil
}

func cmdApply(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	file := fs.String("f", "", "plan file (JSON); the wizard saves one in ~/.config/secure-setup/")
	yes := fs.Bool("yes", false, "do not ask: accept the plan and first-seen host keys")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return errors.New("apply needs -f plan.json")
	}
	p, err := plan.Load(*file)
	if err != nil {
		return err
	}
	p.Server.Password = os.Getenv("SECURE_SETUP_PASSWORD")
	p.Server.Passphrase = os.Getenv("SECURE_SETUP_PASSPHRASE")
	p.Tailscale.AuthKey = os.Getenv("TS_AUTHKEY")
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
	opts := runner.Options{Plan: &p, Prompt: prompt}
	opts.Report = textui.Reporter(os.Stdout, runner.New(opts).Steps())
	r := runner.New(opts)
	res, err := r.Run(ctx)
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("The server is locked down.")
	fmt.Println()
	fmt.Print(tui.Summary(&p, res))
	return nil
}

func describe(p *plan.Plan) string {
	var b strings.Builder
	if p.Local {
		fmt.Fprintf(&b, "  server          this machine\n")
	} else {
		fmt.Fprintf(&b, "  server          %s as %s\n", p.Address(), p.Server.User)
	}
	if p.Tailscale.UseExisting {
		fmt.Fprintf(&b, "  admin network   existing, %s on %s\n", p.Tailscale.AdminAddress, p.Tailscale.AdminInterface)
	} else {
		fmt.Fprintf(&b, "  tailscale       install and join (hostname %q)\n", p.Tailscale.Hostname)
	}
	fmt.Fprintf(&b, "  tailnet ports   TCP %s\n", plan.FormatPorts(p.Firewall.TailnetPorts))
	fmt.Fprintf(&b, "  web ports       TCP %s from Cloudflare\n", orNone(plan.FormatPorts(p.Firewall.WebPorts)))
	fmt.Fprintf(&b, "  ping            %v\n", p.Firewall.AllowPing)
	fmt.Fprintf(&b, "  sshd keys only  %v\n", p.SSH.Harden)
	fmt.Fprintf(&b, "  system update   %v\n", p.UpdateSystem)
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
	fmt.Print(out)
	return nil
}

const undoScript = `
systemctl disable --now secure-setup-cloudflare-sync.timer >/dev/null 2>&1 || true
systemctl stop secure-setup-rollback.timer >/dev/null 2>&1 || true
rm -f /etc/systemd/system/secure-setup-cloudflare-sync.timer /etc/systemd/system/secure-setup-cloudflare-sync.service /usr/local/sbin/secure-setup-cloudflare-sync
systemctl daemon-reload
if nft list table inet secure_setup >/dev/null 2>&1; then nft delete table inet secure_setup; echo "firewall table removed: all inbound traffic is allowed again"; fi
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
rm -rf /etc/secure-setup /var/lib/secure-setup
if [ -f /etc/ssh/sshd_config.d/00-secure-setup.conf ] || grep -q '^# secure-setup: added the next line$' /etc/ssh/sshd_config 2>/dev/null; then
` + remote.RevertSSHDScript + `	echo "sshd hardening removed"
fi
echo "undo complete; Tailscale was left installed"
`

func cmdUndo(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("undo", flag.ContinueOnError)
	host := fs.String("host", "", "address to connect to (tailnet IP or name)")
	here := fs.Bool("here", false, "undo on this machine instead of over SSH")
	port := fs.Int("port", 22, "SSH port")
	user := fs.String("user", "root", "SSH user")
	key := fs.String("key", "", "private key file (default: ssh-agent and ~/.ssh keys)")
	yes := fs.Bool("yes", false, "do not ask")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" && !*here {
		return errors.New("undo needs --host ADDR, or --here on the server itself")
	}
	where := *host
	if *here {
		where = "this machine"
	}
	prompt := textui.Prompter{AssumeYes: *yes}
	if !*yes {
		ok, err := prompt.Confirm(ctx, "Remove the secure-setup firewall, timers and sshd change on "+where+"?", "The server becomes reachable from the whole internet again.")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("not confirmed")
		}
	}
	if *here {
		h, err := localhost.New(ctx)
		if err != nil {
			return err
		}
		return h.Script(ctx, undoScript, func(line string) { fmt.Println("   ", line) })
	}
	auth := sshx.Auth{User: *user, KeyPath: *key, Password: os.Getenv("SECURE_SETUP_PASSWORD"), Passphrase: os.Getenv("SECURE_SETUP_PASSPHRASE")}
	c, err := sshx.Dial(ctx, fmt.Sprintf("%s:%d", *host, *port), auth, sshx.HostKeyPolicy{Prompter: prompt})
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.EnsureRoot(ctx); err != nil {
		return err
	}
	return c.Script(ctx, undoScript, func(line string) { fmt.Println("   ", line) })
}
