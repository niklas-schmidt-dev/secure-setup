package remote

import (
	"context"
	"fmt"
	"strings"

	"github.com/niklas-schmidt-dev/secure-setup/internal/sshx"
)

const dropInPath = "/etc/ssh/sshd_config.d/00-secure-setup.conf"

// RevertSSHDScript undoes HardenSSHD; undo runs it too.
const RevertSSHDScript = "rm -f " + dropInPath + "\n" +
	"sed -i '/^" + includeMarker + "$/{N;d;}' /etc/ssh/sshd_config 2>/dev/null || true\n" +
	"systemctl reload-or-restart ssh 2>/dev/null || systemctl reload-or-restart sshd\n"

// AuthorizedKeys returns the user's authorized_keys content as sshd would
// read it: as that user, and empty when a symlink or a group- or
// world-writable home, ~/.ssh or file would make sshd ignore it.
func AuthorizedKeys(ctx context.Context, c Host, user string) (string, error) {
	script := fmt.Sprintf(`u=%s
home=$(getent passwd "$u" | cut -d: -f6)
[ -n "$home" ] || exit 0
f="$home/.ssh/authorized_keys"
[ -f "$f" ] && [ ! -L "$f" ] && [ ! -L "$home/.ssh" ] || exit 0
[ -z "$(find "$home" "$home/.ssh" "$f" -maxdepth 0 -perm /022 2>/dev/null)" ] || exit 0
if command -v runuser >/dev/null 2>&1; then
	runuser -u "$u" -- head -c 1048576 -- "$f" 2>/dev/null || true
else
	head -c 1048576 -- "$f" 2>/dev/null || true
fi`, sshx.Quote(user))
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

// includeMarker precedes the Include line secure-setup adds, so revert and
// undo can remove exactly that line again.
const includeMarker = "# secure-setup: added the next line"

// applySSHDScript validates the configuration with the drop-in in place and
// reloads sshd. If sshd rejects it, the drop-in and the Include line are
// removed again so the next sshd start sees the previous configuration.
const applySSHDScript = `
added=0
if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
	tmp=$(mktemp)
	{ echo '` + includeMarker + `'; echo 'Include /etc/ssh/sshd_config.d/*.conf'; cat /etc/ssh/sshd_config; } > "$tmp"
	cat "$tmp" > /etc/ssh/sshd_config
	rm -f "$tmp"
	added=1
	echo "added Include for sshd_config.d to /etc/ssh/sshd_config"
fi
sshd_bin=$(command -v sshd || echo /usr/sbin/sshd)
if ! "$sshd_bin" -t; then
	rm -f ` + dropInPath + `
	if [ "$added" = 1 ]; then sed -i '/^` + includeMarker + `$/{N;d;}' /etc/ssh/sshd_config; fi
	echo "sshd rejected the hardened configuration; it was left unchanged" >&2
	exit 1
fi
systemctl reload-or-restart ssh 2>/dev/null || systemctl reload-or-restart sshd
"$sshd_bin" -T 2>/dev/null | awk '$1=="passwordauthentication"||$1=="permitrootlogin"||$1=="kbdinteractiveauthentication"{print "sshd: "$1" "$2}'
`

// HardenSSHD installs the key-only drop-in and reloads sshd. It only
// tightens: a stricter PermitRootLogin already in effect is kept. prev is
// the drop-in an earlier run left behind ("" if there was none); pass it to
// RestoreSSHD to undo only this run's change.
func HardenSSHD(ctx context.Context, c Host, onLine func(string)) (prev string, err error) {
	old, err := c.Output(ctx, "if [ -f "+dropInPath+" ]; then echo present; cat "+dropInPath+"; fi")
	if err != nil {
		return "", fmt.Errorf("read the current sshd drop-in: %w", err)
	}
	if rest, ok := strings.CutPrefix(old, "present\n"); ok {
		prev = rest
	}
	cur, err := c.Output(ctx, `sshd_bin=$(command -v sshd || echo /usr/sbin/sshd); "$sshd_bin" -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2; exit}'`)
	if err != nil {
		return prev, fmt.Errorf("read the current sshd policy: %w", err)
	}
	conf := asset("sshd-hardening.conf")
	switch cur = strings.TrimSpace(cur); cur {
	case "no", "forced-commands-only":
		conf = strings.Replace(conf, "PermitRootLogin prohibit-password", "PermitRootLogin "+cur, 1)
		onLine("keeping the stricter PermitRootLogin " + cur)
	}
	if err := c.WriteFile(ctx, dropInPath, []byte(conf), "0644"); err != nil {
		return prev, err
	}
	onLine("wrote " + dropInPath)
	if err := c.Script(ctx, applySSHDScript, onLine); err != nil {
		if prev != "" {
			// The script removed the rejected drop-in; put the earlier one back.
			_ = c.WriteFile(ctx, dropInPath, []byte(prev), "0644")
		}
		return prev, fmt.Errorf("apply sshd hardening: %w", err)
	}
	return prev, nil
}

// RestoreSSHD undoes one HardenSSHD call: it puts back the drop-in an
// earlier run left (prev), or removes the drop-in and Include line when
// there was none.
func RestoreSSHD(ctx context.Context, c Host, prev string, onLine func(string)) error {
	if prev == "" {
		return RevertSSHD(ctx, c, onLine)
	}
	if err := c.WriteFile(ctx, dropInPath, []byte(prev), "0644"); err != nil {
		return fmt.Errorf("restore sshd drop-in: %w", err)
	}
	if err := c.Script(ctx, "systemctl reload-or-restart ssh 2>/dev/null || systemctl reload-or-restart sshd\necho \"restored the earlier "+dropInPath+"\"", onLine); err != nil {
		return fmt.Errorf("restore sshd drop-in: %w", err)
	}
	return nil
}

// VerifySSHD checks the policy sshd applies to a login by user from each
// peer address on laddr:port, Match blocks included, and fails when any of
// them still allows password or keyboard-interactive authentication.
func VerifySSHD(ctx context.Context, c Host, user, laddr string, port int, peers ...string) error {
	for _, peer := range peers {
		spec := fmt.Sprintf("user=%s,host=%s,addr=%s,laddr=%s,lport=%d", user, peer, peer, laddr, port)
		out, err := c.Output(ctx, `sshd_bin=$(command -v sshd || echo /usr/sbin/sshd); "$sshd_bin" -T -C `+sshx.Quote(spec))
		if err != nil {
			return fmt.Errorf("sshd -T -C %s: %w", spec, err)
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && (f[0] == "passwordauthentication" || f[0] == "kbdinteractiveauthentication") && f[1] != "no" {
				return fmt.Errorf("sshd still allows %s for %s from %s (an earlier directive or a Match block overrides the drop-in)", f[0], user, peer)
			}
		}
	}
	// The probes only see the connections they describe; a Match block for
	// another user or address range would stay invisible to them.
	out, err := c.Output(ctx, matchPasswordScript("/etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"))
	if err != nil {
		return fmt.Errorf("check sshd_config for Match blocks: %w", err)
	}
	if found := strings.TrimSpace(out); found != "" {
		return fmt.Errorf("a Match block may still allow password login (%s); remove it or set it to no", strings.ReplaceAll(found, "\n", "; "))
	}
	return nil
}

// matchPasswordScript prints every line in files (a shell word list, globs
// allowed) that turns password or keyboard-interactive login on inside a
// Match block. Include targets outside sshd_config.d are scanned too, one
// level deep; an Include inside a Match block, a deeper or a quoted Include
// is printed as well, because what it pulls in is not checked.
func matchPasswordScript(files string) string {
	return `scan() {
	follow=$1; shift
	for f in "$@"; do
		[ -f "$f" ] || continue
		awk -v f="$f" -v follow="$follow" '{ l = $0; sub(/^[ \t]+/, "", l); gsub(/[ \t]*=[ \t]*/, " ", l); n = split(l, w, /[ \t]+/) }
			tolower(w[1]) == "match" { m = 1; next }
			m && tolower(w[1]) == "include" { print f ":" FNR ": " l " (an Include inside a Match block)"; next }
			tolower(w[1]) == "include" { for (i = 2; i <= n; i++) if (index(w[i], "\"") > 0) print f ":" FNR ": " l " (a quoted Include)"; else if (w[i] != "/etc/ssh/sshd_config.d/*.conf" && w[i] != "sshd_config.d/*.conf") { if (follow == 1) print "INCLUDE " w[i]; else print f ":" FNR ": " l " (a nested Include)" }; next }
			m && n >= 2 && tolower(w[1]) ~ /^(passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication)$/ && tolower(w[2]) != "no" { print f ":" FNR ": " l }' "$f"
	done
}
out=$(scan 1 ` + files + `)
printf '%s\n' "$out" | grep -v '^INCLUDE ' | grep . || true
set --
set -f
for a in $(printf '%s\n' "$out" | sed -n 's/^INCLUDE //p'); do
	case $a in /*) ;; *) a=/etc/ssh/$a ;; esac
	set +f
	for f in $a; do set -- "$@" "$f"; done
	set -f
done
set +f
if [ $# -gt 0 ]; then scan 0 "$@"; fi`
}

// RevertSSHD removes the drop-in and the Include line secure-setup added,
// and reloads sshd.
func RevertSSHD(ctx context.Context, c Host, onLine func(string)) error {
	script := RevertSSHDScript + "echo \"removed " + dropInPath + "\""
	if err := c.Script(ctx, script, onLine); err != nil {
		return fmt.Errorf("revert sshd hardening: %w", err)
	}
	return nil
}
