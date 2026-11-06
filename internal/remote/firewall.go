package remote

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/niklas-schmidt-dev/secure-setup/internal/nftgen"
	"github.com/niklas-schmidt-dev/secure-setup/internal/sshx"
)

// ErrRolledBack means the rollback timer fired before the confirmation.
var ErrRolledBack = errors.New("the rollback already fired")

const (
	StateDir         = "/var/lib/secure-setup"
	PendingPath      = StateDir + "/pending.nft"
	PreviousPath     = StateDir + "/previous.nft"
	RollbackScript   = StateDir + "/rollback.sh"
	RolledBackMarker = StateDir + "/rolled-back"
	RollbackUnit     = "secure-setup-rollback"

	SyncScriptPath = "/usr/local/sbin/secure-setup-cloudflare-sync"
	SyncUnit       = "secure-setup-cloudflare-sync"
	unitDir        = "/etc/systemd/system/"
)

// FirewallFiles is what PrepareFirewall installs.
type FirewallFiles struct {
	Ruleset        string // full nftables.conf
	Elements       string // Cloudflare set elements include file
	CloudflareSync bool   // install the daily refresh timer
}

// PrepareFirewall installs nftables, retires ufw/firewalld, stages the new
// ruleset, validates it and records the current state for rollback. Nothing
// is applied yet.
func PrepareFirewall(ctx context.Context, c *sshx.Client, f *Facts, files FirewallFiles, onLine func(string)) error {
	var pkgs []string
	if !f.NFT {
		pkgs = append(pkgs, "nftables")
	}
	if files.CloudflareSync {
		pkgs = append(pkgs, "curl", "ca-certificates")
	}
	if err := InstallPackages(ctx, c, f, onLine, pkgs...); err != nil {
		return err
	}
	f.NFT = true

	if f.UFWActive {
		onLine("disabling ufw (nftables takes over)")
		if err := c.Script(ctx, "ufw --force disable\nsystemctl disable --now ufw >/dev/null 2>&1 || true", onLine); err != nil {
			return fmt.Errorf("disable ufw: %w", err)
		}
		f.UFWActive = false
	}
	if f.FirewalldActive {
		onLine("disabling firewalld (nftables takes over)")
		if err := c.Script(ctx, "systemctl disable --now firewalld", onLine); err != nil {
			return fmt.Errorf("disable firewalld: %w", err)
		}
		f.FirewalldActive = false
	}

	writes := []struct {
		path, data, mode string
	}{
		{nftgen.ElementsPath, files.Elements, "0644"},
		{PendingPath, files.Ruleset, "0600"},
		{RollbackScript, asset("rollback.sh"), "0700"},
	}
	if files.CloudflareSync {
		writes = append(writes,
			struct{ path, data, mode string }{SyncScriptPath, asset("cloudflare-sync.sh"), "0755"},
			struct{ path, data, mode string }{unitDir + SyncUnit + ".service", asset("cloudflare-sync.service"), "0644"},
			struct{ path, data, mode string }{unitDir + SyncUnit + ".timer", asset("cloudflare-sync.timer"), "0644"},
		)
	}
	for _, w := range writes {
		if err := c.WriteFile(ctx, w.path, []byte(w.data), w.mode); err != nil {
			return err
		}
		onLine("wrote " + w.path)
	}
	if files.CloudflareSync {
		if err := c.Script(ctx, "systemctl daemon-reload", onLine); err != nil {
			return err
		}
	}

	check := fmt.Sprintf(`nft -c -f %s
echo "ruleset syntax ok"
{
	echo "table inet %s"
	echo "delete table inet %s"
	nft list table inet %s 2>/dev/null || true
} > %s
chmod 600 %s
if [ "$(wc -l < %s)" -gt 2 ]; then echo "saved the current secure-setup table for rollback"; else echo "no previous secure-setup table; rollback removes the new one"; fi
`, PendingPath, nftgen.TableName, nftgen.TableName, nftgen.TableName, PreviousPath, PreviousPath, PreviousPath)
	if err := c.Script(ctx, check, onLine); err != nil {
		return fmt.Errorf("validate ruleset: %w", err)
	}
	return nil
}

// ApplyFirewall arms the rollback timer and loads the staged ruleset. The
// caller must confirm over a fresh tailnet connection before the timer fires.
func ApplyFirewall(ctx context.Context, c *sshx.Client, rollbackSeconds int, onLine func(string)) error {
	script := fmt.Sprintf(`
systemctl stop %[1]s.timer >/dev/null 2>&1 || true
systemctl stop %[1]s.service >/dev/null 2>&1 || true
systemctl reset-failed %[1]s.service >/dev/null 2>&1 || true
systemctl reset-failed %[1]s.timer >/dev/null 2>&1 || true
rm -f %[2]s
systemd-run --quiet --unit=%[1]s --on-active=%[3]d --timer-property=AccuracySec=1s --description="secure-setup firewall rollback" /bin/sh %[4]s
echo "rollback timer armed: fires in %[3]ds unless confirmed"
if ! nft -f %[5]s; then
	systemctl stop %[1]s.timer >/dev/null 2>&1 || true
	echo "applying the ruleset failed; nothing changed" >&2
	exit 1
fi
echo "new firewall rules are live"
`, RollbackUnit, RolledBackMarker, rollbackSeconds, RollbackScript, PendingPath)
	if err := c.Script(ctx, script, onLine); err != nil {
		return fmt.Errorf("apply firewall: %w", err)
	}
	return nil
}

// ConfirmFirewall must run over a connection opened after ApplyFirewall. It
// cancels the rollback, persists the ruleset and enables the services.
func ConfirmFirewall(ctx context.Context, c *sshx.Client, f *Facts, cloudflareSync bool, onLine func(string)) error {
	rhelInclude := ""
	if f.Family() == "rhel" {
		rhelInclude = `touch /etc/sysconfig/nftables.conf
grep -q '^include "/etc/nftables.conf"' /etc/sysconfig/nftables.conf || echo 'include "/etc/nftables.conf"' >> /etc/sysconfig/nftables.conf
`
	}
	sync := ""
	if cloudflareSync {
		sync = fmt.Sprintf(`systemctl enable --now %s.timer >/dev/null 2>&1
echo "daily Cloudflare range refresh enabled (%s.timer)"
%s
`, SyncUnit, SyncUnit, SyncScriptPath)
	}
	script := fmt.Sprintf(`
if [ -e %[1]s ]; then echo "the rollback already fired at $(cat %[1]s)" >&2; exit 2; fi
systemctl stop %[2]s.timer
systemctl stop %[2]s.service >/dev/null 2>&1 || true
echo "rollback timer cancelled"
nft list table inet %[3]s >/dev/null
if [ -f %[4]s ] && ! grep -q '%[5]s' %[4]s; then
	cp -a %[4]s %[4]s.secure-setup.bak
	echo "kept the previous %[4]s as %[4]s.secure-setup.bak"
fi
install -m 0644 %[6]s %[4]s
%[7]ssystemctl enable --now nftables >/dev/null 2>&1
echo "ruleset persisted in %[4]s; nftables.service enabled at boot"
%[8]s`, RolledBackMarker, RollbackUnit, nftgen.TableName, nftgen.ConfigPath, nftgen.Marker, PendingPath, rhelInclude, sync)
	if err := c.Script(ctx, script, onLine); err != nil {
		var exit *ssh.ExitError
		if errors.As(err, &exit) && exit.ExitStatus() == 2 {
			return ErrRolledBack
		}
		return fmt.Errorf("confirm firewall: %w", err)
	}
	return nil
}
