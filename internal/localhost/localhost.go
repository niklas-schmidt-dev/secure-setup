// Package localhost runs the server-side steps on this machine, for
// `secure-setup here`: the same scripts the SSH client would run, through
// /bin/sh, as root or through passwordless sudo.
package localhost

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Host executes on the local machine. It satisfies remote.Host.
type Host struct {
	Sudo bool // commands run through sudo -n
}

// New checks that this is Linux and that commands can run as root.
func New(ctx context.Context) (*Host, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("`secure-setup here` runs on the server itself (Linux); this is %s. Run `secure-setup` to set a server up from here", runtime.GOOS)
	}
	h := &Host{}
	if os.Geteuid() == 0 {
		return h, nil
	}
	if err := exec.CommandContext(ctx, "sudo", "-n", "true").Run(); err != nil {
		return nil, errors.New("not root and passwordless sudo is not available; run it as root or with sudo")
	}
	h.Sudo = true
	return h, nil
}

func (h *Host) cmd(ctx context.Context, script string) *exec.Cmd {
	if h.Sudo {
		return exec.CommandContext(ctx, "sudo", "-n", "/bin/sh", "-c", script)
	}
	return exec.CommandContext(ctx, "/bin/sh", "-c", script)
}

// Output runs cmd and returns its trimmed stdout.
func (h *Host) Output(ctx context.Context, cmd string) (string, error) {
	c := h.cmd(ctx, cmd)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		return strings.TrimSpace(out.String()), fmt.Errorf("%s: %w%s", firstLine(cmd), err, tailOf(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// Script runs a multi-line script with set -eu and streams its output lines.
func (h *Host) Script(ctx context.Context, script string, onLine func(string)) error {
	c := h.cmd(ctx, "set -eu\n"+script)
	pr, pw := io.Pipe()
	c.Stdout, c.Stderr = pw, pw
	if err := c.Start(); err != nil {
		pw.Close()
		return fmt.Errorf("start command: %w", err)
	}
	waitErr := make(chan error, 1)
	go func() {
		err := c.Wait()
		pw.Close()
		waitErr <- err
	}()
	var recent []string
	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	sc.Split(scanLines)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t")
		if line == "" {
			continue
		}
		recent = append(recent, line)
		if len(recent) > 15 {
			recent = recent[1:]
		}
		if onLine != nil {
			onLine(line)
		}
	}
	err := <-waitErr
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("command failed: %w\n%s", err, strings.Join(recent, "\n"))
	}
	return nil
}

// WriteFile writes data to path atomically, creating parent directories.
func (h *Host) WriteFile(ctx context.Context, path string, data []byte, mode string) error {
	q := quote(path)
	script := fmt.Sprintf(`umask 022; d=$(dirname -- %s); mkdir -p -- "$d"; cat > %s.tmp && mv -f %s.tmp %s && chmod %s %s`, q, q, q, q, mode, q)
	c := h.cmd(ctx, script)
	c.Stdin = bytes.NewReader(data)
	var errb bytes.Buffer
	c.Stderr = &errb
	if err := c.Run(); err != nil {
		return fmt.Errorf("write %s: %w%s", path, err, tailOf(errb.String()))
	}
	return nil
}

func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// scanLines splits on \n and \r so progress output arrives line by line.
func scanLines(data []byte, atEOF bool) (int, []byte, error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		adv := i + 1
		if data[i] == '\r' && i+1 < len(data) && data[i+1] == '\n' {
			adv = i + 2
		}
		return adv, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " ..."
	}
	return s
}

func tailOf(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	lines := strings.Split(stderr, "\n")
	if len(lines) > 8 {
		lines = lines[len(lines)-8:]
	}
	return "\n" + strings.Join(lines, "\n")
}

// LoginUser is the user who started secure-setup: the sudo caller, or root.
func LoginUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" && os.Geteuid() != 0 {
		return u
	}
	return "root"
}

// SSHSession parses SSH_CONNECTION ("client port server port") into the
// client and server addresses of the session secure-setup runs in. Both are
// invalid when there is no SSH session (console, cloud-init) or when sudo
// dropped the variable.
func SSHSession() (client, server netip.Addr) {
	f := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(f) != 4 {
		return netip.Addr{}, netip.Addr{}
	}
	c, err1 := netip.ParseAddr(f[0])
	s, err2 := netip.ParseAddr(f[2])
	if err1 != nil || err2 != nil {
		return netip.Addr{}, netip.Addr{}
	}
	return c.Unmap(), s.Unmap()
}
