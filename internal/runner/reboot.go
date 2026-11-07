package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/niklas-schmidt-dev/secure-setup/internal/remote"
	"github.com/niklas-schmidt-dev/secure-setup/internal/sshx"
)

// BootExpect is what the server showed just before the reboot, and must show
// again afterwards without anyone touching it.
type BootExpect struct {
	Tailscale    bool   `json:"tailscale"`
	TailscaleSSH bool   `json:"tailscale_ssh"`
	Hardened     bool   `json:"hardened"`
	Tunnel       bool   `json:"tunnel,omitempty"`
	User         string `json:"user"`
	AdminAddress string `json:"admin_address"`
	SSHPort      int    `json:"ssh_port"`
}

func (r *Runner) bootExpect(ctx context.Context, host remote.Host) BootExpect {
	p := r.o.Plan
	user := p.Server.User
	if user == "" {
		user = "root"
	}
	e := BootExpect{
		Tailscale:    !p.Tailscale.UseExisting,
		Hardened:     r.result.Hardened,
		Tunnel:       r.result.Tunnel,
		User:         user,
		AdminAddress: r.result.AdminAddress,
		SSHPort:      r.facts.SSHPort,
	}
	if e.Tailscale {
		e.TailscaleSSH = remote.TailscaleSSHOn(ctx, host)
	}
	return e
}

// CheckLockdown lists what is wrong with the lockdown on host; empty means
// the rules are loaded and enabled at boot, Tailscale is up in the expected
// SSH mode, and sshd still refuses passwords.
func CheckLockdown(ctx context.Context, host remote.Host, e BootExpect) []string {
	var problems []string
	if _, err := host.Output(ctx, "nft list table inet secure_setup"); err != nil {
		problems = append(problems, "the firewall rules are not loaded")
	}
	if out, _ := host.Output(ctx, "systemctl is-enabled nftables 2>/dev/null || true"); strings.TrimSpace(out) != "enabled" {
		problems = append(problems, "nftables.service is not enabled at boot")
	}
	if e.Tailscale {
		st, err := remote.TailscaleStatus(ctx, host)
		switch {
		case err != nil:
			problems = append(problems, "tailscale does not answer ("+shortErr(err)+")")
		case st.BackendState != "Running":
			problems = append(problems, "tailscale is in state "+st.BackendState)
		}
		if on := remote.TailscaleSSHOn(ctx, host); on != e.TailscaleSSH {
			problems = append(problems, fmt.Sprintf("Tailscale SSH is %s, it was %s before the reboot", onOff(on), onOff(e.TailscaleSSH)))
		}
	}
	if e.Hardened {
		if err := remote.VerifySSHD(ctx, host, e.User, e.AdminAddress, e.SSHPort, keysOnlyPeers...); err != nil {
			problems = append(problems, shortErr(err))
		}
	}
	if e.Tunnel && !remote.TunnelReady(ctx, host) {
		problems = append(problems, "the Cloudflare Tunnel is not connected")
	}
	return problems
}

// checkUntil repeats CheckLockdown for up to wait: services such as
// Tailscale and cloudflared need a moment after a boot.
func checkUntil(ctx context.Context, host remote.Host, e BootExpect, wait time.Duration) ([]string, error) {
	deadline := time.Now().Add(wait)
	for {
		problems := CheckLockdown(ctx, host, e)
		if len(problems) == 0 || time.Now().After(deadline) {
			return problems, nil
		}
		if err := sleepCtx(ctx, 5*time.Second); err != nil {
			return problems, err
		}
	}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// rebootAndCheck reboots the server as the last step and checks, over the
// private network and from the outside, that the lockdown came back on its
// own. A reboot is the real test of what was persisted.
func (r *Runner) rebootAndCheck(ctx context.Context, log func(string)) error {
	expect := r.bootExpect(ctx, r.pub)
	before, err := remote.BootMark(ctx, r.pub)
	if err != nil {
		return err
	}
	if err := remote.ScheduleReboot(ctx, r.pub, 3, log); err != nil {
		return err
	}
	r.admin.Close()
	r.pub.Close()
	port := r.facts.SSHPort
	if expect.TailscaleSSH {
		port = 22 // Tailscale SSH answers on the tailnet address
	}
	target := net.JoinHostPort(r.result.AdminAddress, fmt.Sprint(port))
	log("waiting for the server to come back on " + target)
	auth := r.auth()
	if r.result.Hardened {
		auth.Password = "" // password login is off now
	}
	if expect.TailscaleSSH {
		auth.Banner = func(msg string) { r.attention("Tailscale SSH: " + strings.TrimSpace(msg)) }
	}
	// One deadline for the whole wait; every attempt, including the commands
	// on a connection, ends with it.
	wctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	start, lastNote := time.Now(), time.Now()
	var last error
	for {
		// Refused or timed-out connections log nothing of their own.
		if time.Since(lastNote) >= 15*time.Second {
			log(fmt.Sprintf("still waiting for the server: %ds so far, up to 5 minutes", int(time.Since(start).Seconds())))
			lastNote = time.Now()
		}
		if err := sleepCtx(wctx, 5*time.Second); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("the server did not come back over the private network within 5 minutes after the reboot (last: %v); check it in the provider's console", last)
		}
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(wctx, "tcp", target)
		if err != nil {
			last = err
			continue
		}
		conn.Close()
		c, err := sshx.Dial(wctx, target, auth, sshx.HostKeyPolicy{Expect: r.hostKey, Warn: log})
		if err != nil {
			last = err
			log("not back yet: " + shortErr(err))
			lastNote = time.Now()
			continue
		}
		stop := context.AfterFunc(wctx, func() { c.Close() })
		mark := ""
		err = c.EnsureRoot(wctx)
		if err == nil {
			mark, err = remote.BootMark(wctx, c)
		}
		if !stop() || err != nil || mark == before {
			// Out of time, the old boot shutting down, or not rebooted yet.
			if err != nil {
				last = err
			}
			c.Close()
			continue
		}
		r.admin = c
		break
	}
	log(fmt.Sprintf("the server rebooted and is reachable over the private network again (after %s)", time.Since(start).Round(time.Second)))
	problems, err := checkUntil(ctx, r.admin, expect, time.Minute)
	if err != nil {
		return err
	}
	checked := []string{"rules loaded", "nftables enabled at boot"}
	if expect.Tailscale {
		checked = append(checked, "Tailscale running")
	}
	if expect.Hardened {
		checked = append(checked, "sshd keys only")
	}
	if expect.Tunnel {
		checked = append(checked, "Cloudflare Tunnel connected")
	}
	// Public SSH is tested again only when the run could test it before.
	if r.result.PublicSSHClosed {
		switch res, detail := r.probePublicSSH(ctx); res {
		case probeOpen:
			problems = append(problems, "a new connection to "+r.o.Plan.Address()+" succeeds again")
		case probeBlocked:
			checked = append(checked, "public SSH blocked")
		default:
			r.result.PublicSSHClosed = false
			r.result.PublicSSHNote = "blocked before the reboot, not tested again after it: a new connection to " + r.o.Plan.Address() + " could not be tried from here (" + detail + ")"
			r.attention("public SSH " + r.result.PublicSSHNote)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("after the reboot: %s. The server stays in this state; check it over the tailnet or in the provider's console", strings.Join(problems, "; "))
	}
	r.result.RebootChecked = true
	r.result.RebootNeeded = false
	log("after the reboot: " + strings.Join(checked, ", "))
	return nil
}

// hereReboot sets up the check that runs once after the next boot and then
// reboots this machine: this process cannot watch its own reboot.
func (r *Runner) hereReboot(ctx context.Context, log func(string)) error {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return fmt.Errorf("find the secure-setup binary: %w", err)
	}
	expect, err := json.Marshal(r.bootExpect(ctx, r.local))
	if err != nil {
		return err
	}
	if err := remote.InstallBootCheck(ctx, r.local, exe, expect, log); err != nil {
		return err
	}
	if err := remote.ScheduleReboot(ctx, r.local, 15, log); err != nil {
		return err
	}
	r.result.RebootScheduled = true
	r.result.RebootNeeded = false
	r.attention("this machine reboots in 15 seconds. The check after the boot writes " + remote.BootCheckLog + " and the message shown at your next login")
	return nil
}

// BootCheck runs once after a reboot that a local run scheduled (`secure-setup
// boot-check`, started by its systemd unit). It repeats the checks until they
// pass or two minutes are up, records the result in the log and the login
// message, and disables itself.
func BootCheck(ctx context.Context, host remote.Host) (string, error) {
	data, err := os.ReadFile(bootCheckExpectPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", bootCheckExpectPath, err)
	}
	var e BootExpect
	if err := json.Unmarshal(data, &e); err != nil {
		return "", fmt.Errorf("parse %s: %w", bootCheckExpectPath, err)
	}
	problems, err := checkUntil(ctx, host, e, bootCheckWait)
	if err != nil {
		return "", err
	}
	msg := "secure-setup: after the reboot (" + time.Now().UTC().Format(time.RFC3339) + "): "
	if len(problems) == 0 {
		msg += "all checks passed: rules loaded, nftables enabled at boot"
		if e.Tailscale {
			msg += ", Tailscale running"
		}
		if e.Hardened {
			msg += ", sshd keys only"
		}
		if e.Tunnel {
			msg += ", Cloudflare Tunnel connected"
		}
	} else {
		msg += "PROBLEMS: " + strings.Join(problems, "; ")
	}
	msg += "\n"
	if err := host.WriteFile(ctx, remote.BootCheckLog, []byte(msg), "0644"); err != nil {
		return msg, err
	}
	if err := host.WriteFile(ctx, remote.BootCheckMotd, []byte(msg), "0644"); err != nil {
		return msg, err
	}
	_, _ = host.Output(ctx, "systemctl disable "+remote.BootCheckUnit+".service")
	if len(problems) > 0 {
		return msg, errors.New(strings.TrimSpace(msg))
	}
	return msg, nil
}

// Overridden in tests.
var (
	bootCheckExpectPath = remote.BootCheckExpectPath
	bootCheckWait       = 2 * time.Minute
)

func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
