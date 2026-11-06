package remote

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Files of the check that runs once after a reboot a local run scheduled.
const (
	BootCheckUnit       = "secure-setup-bootcheck"
	BootCheckExpectPath = StateDir + "/bootcheck.json"
	BootCheckLog        = "/var/log/secure-setup-bootcheck.log"
	BootCheckMotd       = "/etc/motd.d/secure-setup"
)

// BootMark identifies the running boot: the absolute start time of PID 1.
// It changes with every reboot, also when the "server" is a container whose
// kernel, and so whose boot_id, stays the same.
func BootMark(ctx context.Context, c Host) (string, error) {
	out, err := c.Output(ctx, `echo $(( $(awk '/^btime/{print $2}' /proc/stat) + $(awk '{print $22}' /proc/1/stat) / $(getconf CLK_TCK) ))`)
	if err != nil {
		return "", fmt.Errorf("read the boot time: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// ScheduleReboot reboots after delay seconds through a transient systemd
// timer, so it outlives the session that asked for it.
func ScheduleReboot(ctx context.Context, c Host, delay int, onLine func(string)) error {
	script := fmt.Sprintf(`systemctl stop secure-setup-reboot.timer >/dev/null 2>&1 || true
systemctl reset-failed secure-setup-reboot.timer secure-setup-reboot.service >/dev/null 2>&1 || true
systemd-run --quiet --unit=secure-setup-reboot --on-active=%d --timer-property=AccuracySec=1s /bin/systemctl reboot
echo "rebooting in %d seconds"
`, delay, delay)
	if err := c.Script(ctx, script, onLine); err != nil {
		return fmt.Errorf("schedule the reboot: %w", err)
	}
	return nil
}

var exePathRe = regexp.MustCompile(`^/[A-Za-z0-9/._-]+$`)

// InstallBootCheck installs a one-shot service that runs `<exe> boot-check`
// at the next boot with the expectations in expect (JSON).
func InstallBootCheck(ctx context.Context, c Host, exe string, expect []byte, onLine func(string)) error {
	if !exePathRe.MatchString(exe) {
		return fmt.Errorf("secure-setup runs from %q; copy it to /usr/local/bin to check the server after the reboot", exe)
	}
	unit := fmt.Sprintf(`[Unit]
Description=secure-setup: check the lockdown after the reboot
Wants=network-online.target
After=network-online.target nftables.service tailscaled.service ssh.service sshd.service

[Service]
Type=oneshot
ExecStart=%s boot-check

[Install]
WantedBy=multi-user.target
`, exe)
	if err := c.WriteFile(ctx, BootCheckExpectPath, expect, "0600"); err != nil {
		return err
	}
	if err := c.WriteFile(ctx, unitDir+BootCheckUnit+".service", []byte(unit), "0644"); err != nil {
		return err
	}
	script := fmt.Sprintf("systemctl daemon-reload\nsystemctl enable %s.service >/dev/null 2>&1\necho \"the check after the reboot is set up (%s.service)\"\n", BootCheckUnit, BootCheckUnit)
	if err := c.Script(ctx, script, onLine); err != nil {
		return fmt.Errorf("set up the check after the reboot: %w", err)
	}
	return nil
}
