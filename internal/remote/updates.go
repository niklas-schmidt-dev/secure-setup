package remote

import (
	"context"
	"fmt"
)

const (
	// AutoUpdatesAPT is the apt configuration secure-setup adds. It sorts
	// after the distribution's own 20auto-upgrades, so its values win; undo
	// removes it.
	AutoUpdatesAPT = "/etc/apt/apt.conf.d/52secure-setup-auto-upgrades"
	// AutoUpdatesDNF5 turns on installing for dnf5's automatic plugin, which
	// has one timer and decides by its configuration. Written only when the
	// file does not exist.
	AutoUpdatesDNF5 = "/etc/dnf/dnf5-plugins/automatic.conf"
	// AutoUpdatesTimer names the dnf timer this tool enabled, so undo
	// disables that one and no timer that was already on.
	AutoUpdatesTimer = StateDir + "/auto-updates-timer"
)

const autoUpdatesAPTConf = `// ` + "Managed by secure-setup" + `: install security updates automatically.
// Remove this file (or run secure-setup undo) to switch that off again.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`

// dnf 4 ships a timer that installs whatever its configuration says
// (dnf-automatic-install.timer). dnf 5 has one timer, which installs only
// with apply_updates = yes.
const autoUpdatesDNFScript = `conf=` + AutoUpdatesDNF5 + `
if systemctl cat dnf-automatic-install.timer >/dev/null 2>&1; then
	timer=dnf-automatic-install.timer
elif systemctl cat dnf5-automatic.timer >/dev/null 2>&1; then
	timer=dnf5-automatic.timer
	if [ ! -e "$conf" ]; then
		mkdir -p "$(dirname "$conf")"
		printf '%s\n' '# Managed by secure-setup: install updates automatically.' '[commands]' 'apply_updates = yes' > "$conf"
		echo "wrote $conf"
	elif ! grep -Eq '^[[:space:]]*apply_updates[[:space:]]*=[[:space:]]*(yes|true|1)' "$conf"; then
		echo "$conf exists and does not set apply_updates = yes; set it there to have updates installed" >&2
		exit 1
	fi
else
	echo "dnf-automatic has no timer on this system" >&2
	exit 1
fi
mkdir -p ` + StateDir + `
if ! systemctl is-enabled --quiet "$timer" 2>/dev/null; then echo "$timer" > ` + AutoUpdatesTimer + `; fi
systemctl enable --now "$timer" >/dev/null 2>&1
systemctl is-active --quiet "$timer"
echo "updates install by themselves ($timer)"
`

// EnableAutoUpdates turns on the distribution's own unattended updates:
// unattended-upgrades on Debian and Ubuntu, which installs security updates
// every day, and dnf-automatic on Fedora and the RHEL family, which installs
// all updates. For another package manager it changes nothing and returns
// why in note.
func EnableAutoUpdates(ctx context.Context, c Host, f *Facts, onLine func(string)) (note string, err error) {
	switch f.PkgMgr {
	case "apt-get":
		if _, err := c.Output(ctx, "command -v unattended-upgrade"); err != nil {
			if err := InstallPackages(ctx, c, f, onLine, "unattended-upgrades"); err != nil {
				return "", err
			}
		}
		if err := c.WriteFile(ctx, AutoUpdatesAPT, []byte(autoUpdatesAPTConf), "0644"); err != nil {
			return "", err
		}
		onLine("wrote " + AutoUpdatesAPT)
		// The two timers that run it are part of apt and usually on already.
		script := `systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
systemctl is-active --quiet apt-daily-upgrade.timer || { echo "apt-daily-upgrade.timer is not running, so nothing would start the updates" >&2; exit 1; }
apt-config dump | grep -q '^APT::Periodic::Unattended-Upgrade "1";' || { echo "apt does not see the setting in ` + AutoUpdatesAPT + `" >&2; exit 1; }
echo "security updates install by themselves every day (unattended-upgrades)"
`
		if err := c.Script(ctx, script, onLine); err != nil {
			return "", fmt.Errorf("set up automatic updates: %w", err)
		}
		return "", nil
	case "dnf":
		if _, err := c.Output(ctx, "systemctl cat dnf-automatic-install.timer >/dev/null 2>&1 || systemctl cat dnf5-automatic.timer >/dev/null 2>&1"); err != nil {
			if err := InstallPackages(ctx, c, f, onLine, "dnf-automatic"); err != nil {
				return "", err
			}
		}
		if err := c.Script(ctx, autoUpdatesDNFScript, onLine); err != nil {
			return "", fmt.Errorf("set up automatic updates: %w", err)
		}
		return "", nil
	}
	return "secure-setup sets them up with apt and dnf only; this system uses " + orNone(f.PkgMgr), nil
}

// AutoUpdatesOnTest is a shell test that succeeds when the automatic updates
// EnableAutoUpdates sets up are on.
const AutoUpdatesOnTest = `{ { [ -f ` + AutoUpdatesAPT + ` ] && command -v unattended-upgrade >/dev/null 2>&1; } || systemctl is-enabled --quiet dnf-automatic-install.timer 2>/dev/null || systemctl is-enabled --quiet dnf5-automatic.timer 2>/dev/null; }`

// UndoAutoUpdatesScript switches off what EnableAutoUpdates switched on. The
// packages stay installed.
const UndoAutoUpdatesScript = `if [ -f ` + AutoUpdatesAPT + ` ]; then
	rm -f ` + AutoUpdatesAPT + `
	echo "automatic security updates switched off (unattended-upgrades stays installed)"
fi
if [ -s ` + AutoUpdatesTimer + ` ]; then
	timer=$(cat ` + AutoUpdatesTimer + `)
	case $timer in dnf-automatic-install.timer | dnf5-automatic.timer)
		systemctl disable --now "$timer" >/dev/null 2>&1 || true
		if grep -q 'Managed by secure-setup' ` + AutoUpdatesDNF5 + ` 2>/dev/null; then rm -f ` + AutoUpdatesDNF5 + `; fi
		echo "automatic updates switched off ($timer; dnf-automatic stays installed)" ;;
	esac
fi
`
