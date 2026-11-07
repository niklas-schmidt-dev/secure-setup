package remote

import (
	"context"
	"errors"
	"fmt"

	"github.com/niklas-schmidt-dev/secure-setup/internal/nftgen"
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
	// DecidedDir is created, atomically, by whichever claims an apply's
	// outcome first: ConfirmFirewall or the rollback timer's run of
	// rollback.sh. The other then leaves the firewall alone, so a late
	// confirmation never cuts a rollback short or persists over it.
	DecidedDir = StateDir + "/decided"

	// Host firewalls that were running when the run started. They are stopped
	// only while the rollback timer is armed, restarted by a rollback or a
	// failed apply, and retired for good only in ConfirmFirewall.
	UFWWasActive       = StateDir + "/ufw-was-active"
	FirewalldWasActive = StateDir + "/firewalld-was-active"
	// firewalld enabled at boot but not running: it would replace the
	// confirmed rules at the next boot, so ConfirmFirewall masks it.
	FirewalldWasEnabled = StateDir + "/firewalld-was-enabled"
	UFWRetired          = StateDir + "/ufw-retired"
	FirewalldRetired    = StateDir + "/firewalld-retired"

	SyncScriptPath = "/usr/local/sbin/secure-setup-cloudflare-sync"
	SyncUnit       = "secure-setup-cloudflare-sync"
	unitDir        = "/etc/systemd/system/"
)

// NFTBootFileScript sets $boot to the file nftables.service loads at boot
// (the -f argument of its ExecStart), or to "" when there is none. The rules
// survive a reboot only through that file.
const NFTBootFileScript = `boot=$(systemctl show -p ExecStart --value nftables.service 2>/dev/null | sed -n -e 's/.*argv\[\]=[^;]* -f \([^ ;]*\).*/\1/p' -e 's/.*argv\[\]=[^;]* --file \([^ ;]*\).*/\1/p' | head -n 1)
`

// bootIncludeMarker precedes the include line ConfirmFirewall adds to a boot
// file other than /etc/nftables.conf, so undo removes exactly that line.
const bootIncludeMarker = "# secure-setup: added the next line"

// ufwInitScript sets $ufw_init to ufw's init helper. ufw-init stop drops ufw's
// rules but leaves it enabled at boot, unlike `ufw disable`; ufw-init start
// loads them again.
const ufwInitScript = `ufw_init=; for p in /lib/ufw/ufw-init /usr/lib/ufw/ufw-init; do if [ -x "$p" ]; then ufw_init=$p; break; fi; done
`

// FirewallFiles is what PrepareFirewall installs.
type FirewallFiles struct {
	Ruleset        string // full nftables.conf
	Elements       string // Cloudflare set elements include file
	CloudflareSync bool   // install the daily refresh timer
}

// PrepareFirewall installs nftables, stages the new ruleset, validates it and
// records the current state (secure_setup table, running ufw/firewalld) for
// rollback. Nothing is applied or stopped yet.
func PrepareFirewall(ctx context.Context, c Host, f *Facts, files FirewallFiles, onLine func(string)) error {
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

	// Record which host firewall is running; it keeps running until the
	// rollback timer is armed (ApplyFirewall).
	// The rules must be able to survive a reboot before they go live.
	record := NFTBootFileScript + `if [ -z "$boot" ]; then echo "nftables.service loads no ruleset file on this system, so the new rules could not survive a reboot" >&2; exit 1; fi
echo "nftables.service loads $boot at boot"
`
	record += fmt.Sprintf("mkdir -p %s\nrm -f %s %s %s\n", StateDir, UFWWasActive, FirewalldWasActive, FirewalldWasEnabled)
	if f.UFWActive {
		record += "touch " + UFWWasActive + "\n"
		onLine("ufw is active: it stops when the new rules go live and comes back if they roll back")
	}
	if f.FirewalldActive {
		record += "touch " + FirewalldWasActive + "\n"
		onLine("firewalld is active: it stops when the new rules go live and comes back if they roll back")
	} else if f.FirewalldEnabled {
		record += "touch " + FirewalldWasEnabled + "\n"
		onLine("firewalld is enabled at boot but not running: it is masked once the new rules are confirmed")
	}
	if err := c.Script(ctx, record, onLine); err != nil {
		return fmt.Errorf("record host firewall state: %w", err)
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
func ApplyFirewall(ctx context.Context, c Host, rollbackSeconds int, onLine func(string)) error {
	script := fmt.Sprintf(`
systemctl stop %[1]s.timer >/dev/null 2>&1 || true
systemctl stop %[1]s.service >/dev/null 2>&1 || true
systemctl reset-failed %[1]s.service >/dev/null 2>&1 || true
systemctl reset-failed %[1]s.timer >/dev/null 2>&1 || true
rm -rf %[2]s %[9]s
systemd-run --quiet --unit=%[1]s --on-active=%[3]d --timer-property=AccuracySec=1s --description="secure-setup firewall rollback" /bin/sh %[4]s --timer
echo "rollback timer armed: fires in %[3]ds unless confirmed"
%[8]sif [ -e %[6]s ]; then
	if [ -n "$ufw_init" ]; then "$ufw_init" stop >/dev/null; else ufw --force disable >/dev/null; fi
	echo "ufw stopped (comes back if the rules roll back)"
fi
if [ -e %[7]s ]; then systemctl stop firewalld; echo "firewalld stopped (comes back if the rules roll back)"; fi
if ! nft -f %[5]s; then
	systemctl stop %[1]s.timer >/dev/null 2>&1 || true
	if [ -e %[6]s ]; then if [ -n "$ufw_init" ]; then "$ufw_init" start >/dev/null || true; else ufw --force enable >/dev/null || true; fi; fi
	if [ -e %[7]s ]; then systemctl start firewalld || true; fi
	echo "applying the ruleset failed; the previous firewall is back" >&2
	exit 1
fi
echo "new firewall rules are live"
`, RollbackUnit, RolledBackMarker, rollbackSeconds, RollbackScript, PendingPath, UFWWasActive, FirewalldWasActive, ufwInitScript, DecidedDir)
	if err := c.Script(ctx, script, onLine); err != nil {
		return fmt.Errorf("apply firewall: %w", err)
	}
	return nil
}

// ConfirmFirewall cancels the rollback, persists the ruleset and enables the
// services. Over SSH it must run on a connection opened after ApplyFirewall;
// locally the caller proves reachability first (see Sessions).
func ConfirmFirewall(ctx context.Context, c Host, f *Facts, cloudflareSync bool, onLine func(string)) error {
	// nftables.service loads $boot; when that is another file (Fedora and RHEL
	// use /etc/sysconfig/nftables.conf), it must include /etc/nftables.conf.
	// Checked with the new rules while the rollback timer still runs.
	preflight := fmt.Sprintf(`if [ -z "$boot" ]; then echo "nftables.service loads no ruleset file, so the rules could not survive a reboot; not keeping them (the rollback restores the previous firewall)" >&2; exit 1; fi
if [ "$boot" = %[1]s ]; then check=%[2]s; else
	check=%[3]s/boot-check.nft
	sed 's|include "%[1]s"|include "%[2]s"|g' "$boot" > "$check" 2>/dev/null || : > "$check"
	grep -q 'include "%[2]s"' "$check" || echo 'include "%[2]s"' >> "$check"
fi
if ! nft -c -f "$check" >/dev/null; then
	echo "nft cannot load $boot with the new rules, so they could not survive a reboot; not keeping them (the rollback restores the previous firewall)" >&2
	exit 1
fi
`, nftgen.ConfigPath, PendingPath, StateDir)
	bootWiring := fmt.Sprintf(`if [ "$boot" != %[1]s ]; then
	touch "$boot"
	if ! grep -q '^include "%[1]s"' "$boot"; then
		printf '%%s\n%%s\n' '%[2]s' 'include "%[1]s"' >> "$boot"
		echo "added an include of %[1]s to $boot"
	fi
fi
if ! nft -c -f "$boot" >/dev/null; then
	echo "nft cannot load $boot, which nftables.service reads at boot: the rules are live now; ufw/firewalld stay enabled at boot" >&2
	exit 1
fi
systemctl enable nftables >/dev/null 2>&1 || { echo "could not enable nftables.service at boot: the rules are live now; ufw/firewalld stay enabled at boot" >&2; exit 1; }
systemctl start nftables >/dev/null 2>&1 || { echo "nftables.service could not load $boot: the rules are live now; ufw/firewalld stay enabled at boot" >&2; exit 1; }
`, nftgen.ConfigPath, bootIncludeMarker)
	retireScript := fmt.Sprintf(`if [ -e %[1]s ]; then
	ufw --force disable >/dev/null 2>&1 || true
	systemctl disable ufw >/dev/null 2>&1 || true
	mv -f %[1]s %[2]s
	echo "ufw retired (nftables takes over)"
fi
if [ -e %[3]s ] || [ -e %[4]s ]; then
	systemctl disable firewalld >/dev/null 2>&1 || true
	systemctl mask firewalld >/dev/null 2>&1 || true
	rm -f %[3]s %[4]s
	touch %[5]s
	echo "firewalld disabled and masked so it cannot replace the rules at boot (nftables takes over)"
fi
`, UFWWasActive, UFWRetired, FirewalldWasActive, FirewalldWasEnabled, FirewalldRetired)
	sync := ""
	if cloudflareSync {
		sync = fmt.Sprintf(`systemctl enable --now %s.timer >/dev/null 2>&1
echo "daily Cloudflare range refresh enabled (%s.timer)"
%s
`, SyncUnit, SyncUnit, SyncScriptPath)
	}
	// Claiming the outcome comes first: a rollback that already started runs
	// to its end, and the confirmation then fails as rolled back. The host
	// firewall is retired last: if persisting fails, it is still enabled at
	// boot.
	script := fmt.Sprintf(`
if [ -e %[1]s ]; then echo "the rollback already fired at $(cat %[1]s)" >&2; exit 2; fi
%[10]s%[11]sif ! mkdir %[12]s 2>/dev/null; then echo "the rollback timer fired before the confirmation; it restores the previous firewall" >&2; exit 2; fi
systemctl stop %[2]s.timer
echo "rollback timer cancelled"
nft list table inet %[3]s >/dev/null
if [ -f %[4]s ] && ! grep -q '%[5]s' %[4]s; then
	cp -a %[4]s %[4]s.secure-setup.bak
	echo "kept the previous %[4]s as %[4]s.secure-setup.bak"
fi
install -m 0644 %[6]s %[4]s
%[7]secho "ruleset persisted in %[4]s; nftables.service loads it at boot ($boot)"
%[9]s%[8]s`, RolledBackMarker, RollbackUnit, nftgen.TableName, nftgen.ConfigPath, nftgen.Marker, PendingPath, bootWiring, sync, retireScript, NFTBootFileScript, preflight, DecidedDir)
	if err := c.Script(ctx, script, onLine); err != nil {
		if exitStatus(err) == 2 {
			return ErrRolledBack
		}
		return fmt.Errorf("confirm firewall: %w", err)
	}
	return nil
}
