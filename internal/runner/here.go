package runner

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/niklas-schmidt-dev/secure-setup/internal/localhost"
	"github.com/niklas-schmidt-dev/secure-setup/internal/plan"
	"github.com/niklas-schmidt-dev/secure-setup/internal/remote"
)

// Marker files a local run and `secure-setup confirm` share.
const (
	ConfirmExpectPath = remote.StateDir + "/confirm-expect" // address a login must arrive on
	ConfirmedPath     = remote.StateDir + "/confirmed"      // written by `secure-setup confirm`
)

// localSteps is the step list for `secure-setup here`: the same work as over
// SSH, but the confirmation comes from a new login or from self-checks.
func (r *Runner) localSteps() []step {
	p := r.o.Plan
	ts := &p.Tailscale
	confirmName := "Confirm with a new login over the tailnet"
	confirm := r.confirmByLogin
	if p.Firewall.ConfirmBy == plan.ConfirmSelf {
		confirmName = "Confirm with self-checks"
		confirm = r.confirmBySelf
	}
	return []step{
		{name: "Look around on this machine", run: r.hereDetect},
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
		{name: "Check the private path to sshd", run: r.hereCheckPath},
		{name: "Harden SSH (keys only)", skip: func() string {
			if !p.SSH.Harden {
				return "not requested"
			}
			if r.result.HardenNote != "" {
				return r.result.HardenNote
			}
			return ""
		}, run: r.hereHardenSSH},
		{name: "Cloudflare Tunnel", run: func(ctx context.Context, log func(string)) error {
			return r.setupTunnel(ctx, r.local, log)
		}},
		{name: "Stage the firewall", run: func(ctx context.Context, log func(string)) error {
			return r.stageFirewallOn(ctx, r.local, log)
		}},
		{name: "Apply the firewall with a rollback timer", run: r.hereApplyFirewall},
		{name: confirmName, run: confirm},
		{name: "Verify", run: r.hereVerify},
		{name: "Reboot and check after the boot", skip: r.skipReboot, run: r.hereReboot},
	}
}

func (r *Runner) hereDetect(ctx context.Context, log func(string)) error {
	p := r.o.Plan
	f, err := remote.Detect(ctx, r.local)
	if err != nil {
		return err
	}
	r.facts = f
	r.result.Facts = f
	if r.local.Sudo {
		log("not root; using passwordless sudo")
	}
	log(fmt.Sprintf("%s, host %s, sshd on port %d, internet interface %s", f.PrettyName, f.Hostname, f.SSHPort, orUnknown(f.WANIface)))
	if !f.Systemd {
		return errors.New("this machine does not run systemd; secure-setup relies on it for the rollback timer and services")
	}
	if f.PkgMgr == "" {
		return errors.New("no supported package manager found (apt-get, dnf, yum, pacman, zypper)")
	}
	if r.o.Unattended && !p.Tailscale.UseExisting && p.Tailscale.AuthKey == "" && f.TailscaleState != "Running" {
		return errors.New("an unattended run cannot join the tailnet with a login link: nobody is there to open it, and anyone who reads the pending link could add this machine to their own tailnet. Set TS_AUTHKEY, or run `secure-setup here` in a terminal")
	}
	if err := resolveWAN(ctx, r.local, p, f, log); err != nil {
		return err
	}
	r.result.PublicAddress = f.WANIPv4
	r.result.SSHPort = f.SSHPort
	if !containsInt(p.Firewall.TailnetPorts, f.SSHPort) {
		p.Firewall.TailnetPorts = append(p.Firewall.TailnetPorts, f.SSHPort)
		log(fmt.Sprintf("added sshd port %d to the tailnet ports", f.SSHPort))
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
	}

	// Where does this session come from? It survives the firewall change
	// either way (established flow); the note is for the user's expectations.
	client, server := localhost.SSHSession()
	switch {
	case !server.IsValid():
		log("no SSH session detected (console, cloud-init, or sudo without SSH_CONNECTION)")
	default:
		iface, _ := r.local.Output(ctx, "ip -o addr show to "+server.String()+" 2>/dev/null | awk '{print $2; exit}'")
		where := "over " + orUnknown(iface)
		if iface == p.Firewall.WANInterface {
			where += " (the public interface)"
		}
		log(fmt.Sprintf("this SSH session: %s -> %s %s; it stays open while the firewall changes", client, server, where))
	}

	// Key-only sshd is safe only when a key can still log in.
	if p.SSH.Harden {
		user := localhost.LoginUser()
		if p.Server.User == "" {
			p.Server.User = user
		}
		keys, err := remote.AuthorizedKeys(ctx, r.local, user)
		if err != nil {
			return err
		}
		if n := usableKeys(keys); n == 0 {
			// Only `tailscale up --ssh` in the Join step turns Tailscale SSH
			// on, and that step is skipped for a node that is already Running.
			if p.Tailscale.SSH && !p.Tailscale.UseExisting && f.TailscaleState != "Running" {
				log("no usable public key in authorized_keys for " + user + "; Tailscale SSH (enabled in the next steps) keeps you in after password login is disabled")
			} else {
				r.result.HardenNote = "no usable public key in ~" + user + "/.ssh/authorized_keys; add one first, or enable Tailscale SSH"
			}
		} else {
			log(fmt.Sprintf("%d usable public key(s) authorized for %s", n, user))
		}
	}
	return nil
}

// usableKeys counts authorized_keys entries that parse as public keys and
// carry no option that limits where or how they log in.
func usableKeys(authorized string) int {
	n := 0
	rest := []byte(authorized)
	for len(rest) > 0 {
		_, _, opts, next, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break
		}
		rest = next
		ok := true
		for _, o := range opts {
			name, _, _ := strings.Cut(strings.ToLower(o), "=")
			switch name {
			case "command", "from", "cert-authority", "principals", "expiry-time", "restrict":
				ok = false
			}
		}
		if ok {
			n++
		}
	}
	return n
}

func (r *Runner) hereCheckPath(ctx context.Context, log func(string)) error {
	p := r.o.Plan
	addr := p.Tailscale.AdminAddress
	if !p.Tailscale.UseExisting {
		st, err := remote.TailscaleStatus(ctx, r.local)
		if err != nil {
			return err
		}
		r.tsState = st
		if st.BackendState != "Running" {
			return fmt.Errorf("tailscale is in state %s, not Running", st.BackendState)
		}
		addr = r.facts.TailscaleIPv4
		for _, ip := range st.Self.TailscaleIPs {
			if !strings.Contains(ip, ":") {
				addr = ip
			}
		}
		if addr == "" {
			ip, err := remote.TailscaleIPv4(ctx, r.local)
			if err != nil {
				return err
			}
			addr = ip
		}
		r.result.DNSName = strings.TrimSuffix(st.Self.DNSName, ".")
		for _, h := range st.Health {
			log("tailscale health: " + h)
		}
	}
	if !remote.InterfaceExists(ctx, r.local, p.Tailscale.AdminInterface) {
		return fmt.Errorf("interface %s does not exist on this machine", p.Tailscale.AdminInterface)
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return fmt.Errorf("private address %q: %w", addr, err)
	}
	ok, listeners, err := remote.SSHDListensOn(ctx, r.local, a, r.facts.SSHPort)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("sshd does not accept connections on %s:%d (it listens on %s); fix ListenAddress in sshd_config first", addr, r.facts.SSHPort, orUnknown(listeners))
	}
	r.result.AdminAddress = addr
	log(fmt.Sprintf("sshd accepts connections on %s:%d over %s (%s)", addr, r.facts.SSHPort, p.Tailscale.AdminInterface, listeners))
	return nil
}

func (r *Runner) hereHardenSSH(ctx context.Context, log func(string)) error {
	prev, err := remote.HardenSSHD(ctx, r.local, log)
	r.sshdPrev = prev
	if err != nil {
		_ = remote.RestoreSSHD(ctx, r.local, prev, log)
		return err
	}
	// sshd -t ran before the reload; make sure the daemon is still there.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := r.local.Output(ctx, "systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd"); err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			log("sshd is not running after the reload, reverting the change")
			if rerr := remote.RestoreSSHD(ctx, r.local, r.sshdPrev, log); rerr != nil {
				return fmt.Errorf("sshd did not come back and the revert failed too: %w", rerr)
			}
			return errors.New("sshd did not come back after the reload; the hardening was reverted")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	log("sshd reloaded with password login off")
	if err := verifyKeysOnly(ctx, r.local, r.o.Plan.Server.User, r.result.AdminAddress, r.facts.SSHPort, r.sshdPrev, log); err != nil {
		return err
	}
	r.result.Hardened = true
	return nil
}

func (r *Runner) hereApplyFirewall(ctx context.Context, log func(string)) error {
	before, err := remote.Sessions(ctx, r.local, r.facts.SSHPort)
	if err != nil {
		return err
	}
	r.before = before
	epoch, err := r.local.Output(ctx, "date +%s")
	if err != nil {
		return err
	}
	r.applyEpoch, _ = strconv.ParseInt(strings.TrimSpace(epoch), 10, 64)
	if err := r.local.WriteFile(ctx, ConfirmExpectPath, []byte(r.result.AdminAddress+"\n"), "0600"); err != nil {
		return err
	}
	if _, err := r.local.Output(ctx, "rm -f "+ConfirmedPath); err != nil {
		return err
	}
	return r.applyFirewallOn(ctx, r.local, log)
}

func (r *Runner) confirmByLogin(ctx context.Context, log func(string)) error {
	p := r.o.Plan
	secs := p.Firewall.RollbackSeconds
	addr := r.result.AdminAddress
	target := addr
	if r.result.DNSName != "" {
		target = r.result.DNSName
	}
	port := ""
	if r.facts.SSHPort != 22 {
		port = fmt.Sprintf(" -p %d", r.facts.SSHPort)
	}
	user := p.Server.User
	if user == "" {
		user = localhost.LoginUser()
	}
	r.attention(fmt.Sprintf("Now prove the new rules let you in. From ANOTHER device on your tailnet, open a new terminal and log in:\n\n    ssh%s %s@%s\n\nThat login confirms the firewall. You have %d seconds; otherwise this machine restores its previous firewall by itself.\nIf you use Tailscale SSH, run `secure-setup confirm` in the new session.", port, user, target, secs))
	adminAddr, err := netip.ParseAddr(addr)
	if err != nil {
		return err
	}
	// Stop before the timer fires, or a login through restored rules would count.
	wait := time.Duration(secs-10) * time.Second
	if wait < 10*time.Second {
		wait = 10 * time.Second
	}
	deadline := time.Now().Add(wait)
	lastNote := time.Now()
	arrived := false
	self := remote.LocalAddrs(ctx, r.local)
	for {
		if at := r.rollbackMarker(ctx, r.local); at != "" {
			return r.rolledBackError(at, errors.New("the rollback fired before a login arrived"))
		}
		if by, _ := r.local.Output(ctx, "cat "+ConfirmedPath+" 2>/dev/null || true"); by != "" {
			r.result.ConfirmedBy = "`secure-setup confirm` from " + by
			log("confirmed by `secure-setup confirm` in a session from " + by)
			return r.keepFirewall(ctx, log)
		}
		// Only connections that came in through the admin rule count (its
		// counter is above zero); a local process reaching the admin address
		// goes over lo and proves nothing. Then either a session from another
		// machine is visible right now, or sshd logged an accepted login since
		// the apply (short sessions end between polls).
		now, err := remote.Sessions(ctx, r.local, r.facts.SSHPort)
		if err != nil {
			return err
		}
		if n, _ := r.adminRuleCounter(ctx); n > 0 {
			if fresh := remote.NewSessionsTo(r.before, now, adminAddr, self...); len(fresh) > 0 {
				peer := fresh[0].Peer.Addr().String()
				r.result.ConfirmedBy = "login from " + peer
				log("new SSH session from " + peer + " through the " + p.Tailscale.AdminInterface + " rule: the rules let you in")
				return r.keepFirewall(ctx, log)
			}
			if !arrived {
				arrived = true
				log(fmt.Sprintf("a connection arrived over %s through the new rule; waiting for the login to complete", p.Tailscale.AdminInterface))
			}
			if logins := acceptedLoginsSince(ctx, r.local, r.applyEpoch); len(logins) > 0 {
				l := logins[len(logins)-1]
				r.result.ConfirmedBy = "login by " + l.User + " from " + l.From
				log("sshd accepted a login by " + l.User + " from " + l.From + " after the rules went live: they let you in")
				return r.keepFirewall(ctx, log)
			}
		}
		left := time.Until(deadline)
		if left <= 0 {
			return r.waitForLocalRollback(ctx, log, errors.New("no login over the private network arrived in time"))
		}
		if time.Since(lastNote) >= 15*time.Second {
			log(fmt.Sprintf("waiting for a login to %s:%d ... %ds left", addr, r.facts.SSHPort, int(left.Seconds())))
			lastNote = time.Now()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// adminRuleCounter reads the packet counter of the admin-interface rule in
// the input chain: new connections that came in through it.
func (r *Runner) adminRuleCounter(ctx context.Context) (int, error) {
	cmd := fmt.Sprintf(`nft list chain inet secure_setup input 2>/dev/null | grep -F 'iifname "%s"' | grep -o 'counter packets [0-9]*' | awk '{print $3; exit}'`, r.o.Plan.Tailscale.AdminInterface)
	out, err := r.local.Output(ctx, cmd)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(out))
}

// AcceptedLogin is one "Accepted <method> for <user> from <ip> port <port>" line of sshd.
type AcceptedLogin struct {
	Method, User, From string
}

var (
	acceptedRe  = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+`)
	loginUserRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}\$?$`)
)

// acceptedLoginsSince reads sshd's accepted logins from the journal. Only
// entries journald attributes to root count: _UID is set from the sender's
// credentials, so `logger -t sshd` from another user does not match.
func acceptedLoginsSince(ctx context.Context, host remote.Host, epoch int64) []AcceptedLogin {
	if epoch == 0 {
		return nil
	}
	cmd := fmt.Sprintf(`journalctl -q --no-pager -o cat --since=@%d _UID=0 _COMM=sshd + _UID=0 SYSLOG_IDENTIFIER=sshd 2>/dev/null | grep -E '^Accepted ' || true`, epoch-1)
	out, err := host.Output(ctx, cmd)
	if err != nil {
		return nil
	}
	return parseAcceptedLogins(out)
}

// parseAcceptedLogins keeps only well-formed lines: a plain user name and an
// IP address without a zone.
func parseAcceptedLogins(out string) []AcceptedLogin {
	var logins []AcceptedLogin
	for _, line := range strings.Split(out, "\n") {
		m := acceptedRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil || !loginUserRe.MatchString(m[2]) {
			continue
		}
		a, err := netip.ParseAddr(m[3])
		if err != nil || a.Zone() != "" {
			continue
		}
		logins = append(logins, AcceptedLogin{Method: m[1], User: m[2], From: a.Unmap().String()})
	}
	return logins
}

func (r *Runner) confirmBySelf(ctx context.Context, log func(string)) error {
	p := r.o.Plan
	var checks []string
	if at := r.rollbackMarker(ctx, r.local); at != "" {
		return r.rolledBackError(at, errors.New("the rollback fired before the checks ran"))
	}
	rule := fmt.Sprintf(`nft list chain inet %s input | grep -q 'iifname "%s"'`, "secure_setup", p.Tailscale.AdminInterface)
	if _, err := r.local.Output(ctx, rule); err != nil {
		return fmt.Errorf("the loaded ruleset has no rule for %s; not keeping it", p.Tailscale.AdminInterface)
	}
	checks = append(checks, "rule for "+p.Tailscale.AdminInterface+" loaded")
	a, _ := netip.ParseAddr(r.result.AdminAddress)
	ok, _, err := remote.SSHDListensOn(ctx, r.local, a, r.facts.SSHPort)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("sshd no longer listens on %s:%d; not keeping the rules", r.result.AdminAddress, r.facts.SSHPort)
	}
	checks = append(checks, fmt.Sprintf("sshd listens on %s:%d", r.result.AdminAddress, r.facts.SSHPort))
	if !p.Tailscale.UseExisting {
		st, err := remote.TailscaleStatus(ctx, r.local)
		if err != nil {
			return fmt.Errorf("tailscale status after the firewall change: %w", err)
		}
		if st.BackendState != "Running" || !st.Self.Online {
			return fmt.Errorf("tailscale is %s and online=%v after the firewall change; not keeping the rules", st.BackendState, st.Self.Online)
		}
		checks = append(checks, "tailscale running and online")
		for _, h := range st.Health {
			log("tailscale health: " + h)
		}
		pinged, detail, err := remote.TailscalePingPeer(ctx, r.local, st)
		switch {
		case err != nil:
			return fmt.Errorf("a tailnet peer did not answer through the new rules: %w", err)
		case pinged:
			checks = append(checks, "peer ping ok ("+detail+")")
		default:
			log("note: " + detail + "; the tailnet data path could not be exercised")
		}
	}
	for _, c := range checks {
		log("check: " + c)
	}
	r.result.ConfirmedBy = "self-checks: " + strings.Join(checks, ", ")
	log("self-checks passed; keeping the rules. Nobody logged in through them yet: test `ssh " + r.result.AdminAddress + "` from another device.")
	return r.keepFirewall(ctx, log)
}

func (r *Runner) keepFirewall(ctx context.Context, log func(string)) error {
	p := r.o.Plan
	err := remote.ConfirmFirewall(ctx, r.local, r.facts, p.Firewall.CloudflareSync && len(p.Firewall.WebPorts) > 0, log)
	if errors.Is(err, remote.ErrRolledBack) {
		return r.rolledBackError(r.rollbackMarker(ctx, r.local), err)
	}
	if err != nil {
		return err
	}
	_, _ = r.local.Output(ctx, "rm -f "+ConfirmExpectPath+" "+ConfirmedPath)
	return nil
}

func (r *Runner) waitForLocalRollback(ctx context.Context, log func(string), cause error) error {
	r.attention("no login arrived; waiting for this machine to restore its previous firewall")
	log("reason: " + shortErr(cause))
	deadline := time.Now().Add(25 * time.Second)
	for {
		if at := r.rollbackMarker(ctx, r.local); at != "" {
			log("the previous firewall state is active again")
			return r.rolledBackError(at, cause)
		}
		if time.Now().After(deadline) {
			log("warning: the rollback marker was not found; check `nft list ruleset`")
			return fmt.Errorf("the new firewall was not confirmed; the rollback should have fired but left no marker: %w", cause)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (r *Runner) hereVerify(ctx context.Context, log func(string)) error {
	p := r.o.Plan
	for _, cmd := range []string{
		`nft list chain inet secure_setup input | grep -c accept | sed 's/^/accept rules in input chain: /'`,
		`systemctl is-enabled nftables 2>/dev/null | sed 's/^/nftables.service at boot: /'`,
		`systemctl is-active secure-setup-rollback.timer 2>/dev/null | sed 's/^/rollback timer: /'`,
	} {
		if out, err := r.local.Output(ctx, cmd); err == nil && out != "" {
			log(out)
		}
	}
	if p.Firewall.CloudflareSync && len(p.Firewall.WebPorts) > 0 {
		if out, err := r.local.Output(ctx, `systemctl list-timers secure-setup-cloudflare-sync.timer --no-legend --no-pager 2>/dev/null | awk '{print "next Cloudflare refresh: "$1" "$2" "$3}'`); err == nil && out != "" {
			log(out)
		}
	}
	if r.result.PublicAddress != "" {
		r.result.PublicSSHNote = fmt.Sprintf("from another device, `nc -zv %s %d` must now fail", r.result.PublicAddress, r.facts.SSHPort)
		log("a machine cannot test its own public port from inside; " + r.result.PublicSSHNote)
	}
	return nil
}
