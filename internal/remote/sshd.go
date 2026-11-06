package remote

import (
	"context"
	"fmt"
	"strings"

	"github.com/niklas-schmidt-dev/secure-setup/internal/sshx"
)

const dropInPath = "/etc/ssh/sshd_config.d/00-secure-setup.conf"

// AuthorizedKeys returns the user's current authorized_keys content.
func AuthorizedKeys(ctx context.Context, c Host, user string) (string, error) {
	script := fmt.Sprintf(`home=$(getent passwd %s | cut -d: -f6); cat "$home/.ssh/authorized_keys" 2>/dev/null || true`, sshx.Quote(user))
	return c.Output(ctx, script)
}

// AddAuthorizedKey appends one public key line for user.
func AddAuthorizedKey(ctx context.Context, c Host, user, line string, onLine func(string)) error {
	script := fmt.Sprintf(`
user=%s
home=$(getent passwd "$user" | cut -d: -f6)
[ -n "$home" ] || { echo "no home directory for $user" >&2; exit 1; }
mkdir -p "$home/.ssh"
chmod 700 "$home/.ssh"
touch "$home/.ssh/authorized_keys"
chmod 600 "$home/.ssh/authorized_keys"
printf '%%s\n' %s >> "$home/.ssh/authorized_keys"
chown -R "$user": "$home/.ssh"
echo "added public key to $home/.ssh/authorized_keys"
`, sshx.Quote(user), sshx.Quote(strings.TrimSpace(line)))
	if err := c.Script(ctx, script, onLine); err != nil {
		return fmt.Errorf("add authorized key: %w", err)
	}
	return nil
}

const applySSHDScript = `
if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
	tmp=$(mktemp)
	{ echo 'Include /etc/ssh/sshd_config.d/*.conf'; cat /etc/ssh/sshd_config; } > "$tmp"
	cat "$tmp" > /etc/ssh/sshd_config
	rm -f "$tmp"
	echo "added Include for sshd_config.d to /etc/ssh/sshd_config"
fi
sshd_bin=$(command -v sshd || echo /usr/sbin/sshd)
"$sshd_bin" -t
systemctl reload-or-restart ssh 2>/dev/null || systemctl reload-or-restart sshd
"$sshd_bin" -T 2>/dev/null | awk '$1=="passwordauthentication"||$1=="permitrootlogin"||$1=="kbdinteractiveauthentication"{print "sshd: "$1" "$2}'
`

// HardenSSHD installs the key-only drop-in and reloads sshd.
func HardenSSHD(ctx context.Context, c Host, onLine func(string)) error {
	if err := c.WriteFile(ctx, dropInPath, []byte(asset("sshd-hardening.conf")), "0644"); err != nil {
		return err
	}
	onLine("wrote " + dropInPath)
	if err := c.Script(ctx, applySSHDScript, onLine); err != nil {
		return fmt.Errorf("apply sshd hardening: %w", err)
	}
	return nil
}

// RevertSSHD removes the drop-in again and reloads sshd.
func RevertSSHD(ctx context.Context, c Host, onLine func(string)) error {
	script := "rm -f " + dropInPath + "\nsystemctl reload-or-restart ssh 2>/dev/null || systemctl reload-or-restart sshd\necho \"removed " + dropInPath + "\""
	if err := c.Script(ctx, script, onLine); err != nil {
		return fmt.Errorf("revert sshd hardening: %w", err)
	}
	return nil
}
