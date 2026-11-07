// Package sshx is a small SSH client wrapper: key, agent and password
// authentication, host key verification with a prompt on first contact, and
// helpers to run scripts and write files on the server (through passwordless
// sudo when the login user is not root).
package sshx

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const dialTimeout = 20 * time.Second

// plainHostKeyAlgos is x/crypto's default host key preference without
// certificate, DSA and SHA-1 RSA algorithms.
var plainHostKeyAlgos = []string{
	ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoED25519,
}

// Auth describes how to log in.
type Auth struct {
	User       string
	KeyPath    string // explicit private key; empty means ssh-agent plus the default keys in ~/.ssh
	Passphrase string
	Password   string
	// Banner, when set, receives the server's login banner (Tailscale SSH
	// sends its browser check there) and the login may take until the
	// context's deadline instead of the usual dial timeout.
	Banner func(message string)
}

// HostKeyPrompter is asked when a server is not in known_hosts yet.
type HostKeyPrompter interface {
	ConfirmHostKey(ctx context.Context, addr, keyType, fingerprint string) (bool, error)
}

// HostKeyPolicy decides which server keys are acceptable.
type HostKeyPolicy struct {
	KnownHostsPath string          // defaults to ~/.ssh/known_hosts
	Prompter       HostKeyPrompter // asked for unknown hosts; nil rejects them
	Expect         ssh.PublicKey   // when set, the server must present exactly this key
	Warn           func(string)    // optional, for non-fatal notes
}

var (
	ErrPassphraseRequired = errors.New("the private key is encrypted and needs a passphrase")
	ErrHostKeyMismatch    = errors.New("host key mismatch")
	ErrHostKeyRejected    = errors.New("host key rejected")
)

// Client is one SSH connection.
type Client struct {
	Addr    string
	User    string
	HostKey ssh.PublicKey
	Sudo    bool // commands are run through sudo -n
	conn    *ssh.Client
}

// Dial connects and verifies the host key.
func Dial(ctx context.Context, addr string, auth Auth, policy HostKeyPolicy) (*Client, error) {
	methods, err := authMethods(auth)
	if err != nil {
		return nil, err
	}
	var hostKey ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: auth.User,
		Auth: methods,
		// Plain host keys only, in x/crypto's default order, so a server cannot
		// steer verification into the certificate path, and keys remembered
		// by earlier runs keep matching.
		HostKeyAlgorithms: plainHostKeyAlgos,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if err := policy.check(ctx, hostname, remote, key); err != nil {
				return err
			}
			hostKey = key
			return nil
		},
		Timeout: dialTimeout,
	}
	loginDeadline := time.Now().Add(dialTimeout)
	if auth.Banner != nil {
		cfg.BannerCallback = func(message string) error {
			auth.Banner(message)
			return nil
		}
		if d, ok := ctx.Deadline(); ok && d.After(loginDeadline) {
			loginDeadline = d
		}
	}
	d := net.Dialer{Timeout: dialTimeout, KeepAlive: 15 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	_ = nc.SetDeadline(loginDeadline)
	// Cancelling ctx interrupts the handshake and login instead of waiting
	// for the deadline.
	stop := context.AfterFunc(ctx, func() { nc.Close() })
	sc, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if !stop() {
		if err == nil {
			sc.Close()
		}
		return nil, fmt.Errorf("ssh %s@%s: %w", auth.User, addr, ctx.Err())
	}
	if err != nil {
		nc.Close()
		for _, sentinel := range []error{ErrHostKeyMismatch, ErrHostKeyRejected, context.Canceled} {
			if errors.Is(err, sentinel) {
				return nil, err
			}
		}
		return nil, fmt.Errorf("ssh %s@%s: %w", auth.User, addr, err)
	}
	_ = nc.SetDeadline(time.Time{})
	return &Client{Addr: addr, User: auth.User, HostKey: hostKey, conn: ssh.NewClient(sc, chans, reqs)}, nil
}

// Close ends the connection.
// RemoteIP is the server address this connection goes to.
func (c *Client) RemoteIP() netip.Addr {
	if c == nil || c.conn == nil {
		return netip.Addr{}
	}
	ap, err := netip.ParseAddrPort(c.conn.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// EnsureRoot checks that commands can run as root, directly or via sudo -n.
func (c *Client) EnsureRoot(ctx context.Context) error {
	out, _, err := c.run(ctx, "id -u", nil)
	if err != nil {
		return fmt.Errorf("id -u: %w", err)
	}
	if strings.TrimSpace(out) == "0" {
		c.Sudo = false
		return nil
	}
	if _, stderr, err := c.run(ctx, "sudo -n true", nil); err != nil {
		return fmt.Errorf("%q is not root and passwordless sudo is not available: %w%s", c.User, err, tailOf(stderr))
	}
	c.Sudo = true
	return nil
}

// Output runs cmd with /bin/sh and returns its trimmed stdout.
func (c *Client) Output(ctx context.Context, cmd string) (string, error) {
	stdout, stderr, err := c.run(ctx, c.wrap("/bin/sh -c "+Quote(cmd)), nil)
	if err != nil {
		return strings.TrimSpace(stdout), fmt.Errorf("%s: %w%s", firstLine(cmd), err, tailOf(stderr))
	}
	return strings.TrimSpace(stdout), nil
}

// Script runs a multi-line shell script with set -eu, streaming every output
// line to onLine. The error of a failed script carries its last output lines.
func (c *Client) Script(ctx context.Context, script string, onLine func(string)) error {
	return c.stream(ctx, c.wrap("/bin/sh -c "+Quote("set -eu\n"+script)), onLine)
}

// WriteFile writes data to path atomically, creating parent directories.
func (c *Client) WriteFile(ctx context.Context, path string, data []byte, mode string) error {
	script := WriteFileScript(path, mode)
	_, stderr, err := c.run(ctx, c.wrap("/bin/sh -c "+Quote(script)), bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("write %s: %w%s", path, err, tailOf(stderr))
	}
	return nil
}

func (c *Client) wrap(cmd string) string {
	if c.Sudo {
		return "sudo -n " + cmd
	}
	return cmd
}

// MaxOutput bounds what one command may print on stdout or stderr before it
// is stopped: far more than any command secure-setup runs prints, and little
// enough that a server cannot fill this computer's memory.
const MaxOutput = 16 << 20

// ErrOutputTooLarge means a command printed more than MaxOutput, or a line
// longer than its streaming limit.
var ErrOutputTooLarge = errors.New("the server sent more output than secure-setup accepts")

func (c *Client) run(ctx context.Context, cmd string, stdin io.Reader) (stdout, stderr string, err error) {
	sess, err := c.conn.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()
	full := make(chan struct{})
	var once sync.Once
	out := &cappedBuffer{max: MaxOutput, full: func() { once.Do(func() { close(full) }) }}
	errb := &cappedBuffer{max: MaxOutput, full: out.full}
	sess.Stdout, sess.Stderr, sess.Stdin = out, errb, stdin
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		return out.String(), errb.String(), ctx.Err()
	case <-full:
		// Nothing reads the session any more, so it would never end.
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return "", "", fmt.Errorf("%w (%d MiB)", ErrOutputTooLarge, MaxOutput>>20)
	case err := <-done:
		return out.String(), errb.String(), err
	}
}

// cappedBuffer keeps up to max bytes. A write past that fails and calls full.
type cappedBuffer struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	max  int
	full func()
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len()+len(p) > b.max {
		b.full()
		return 0, ErrOutputTooLarge
	}
	return b.buf.Write(p)
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (c *Client) stream(ctx context.Context, cmd string, onLine func(string)) error {
	sess, err := c.conn.NewSession()
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()
	pr, pw := io.Pipe()
	sess.Stdout, sess.Stderr = pw, pw
	if err := sess.Start(cmd); err != nil {
		pw.Close()
		return fmt.Errorf("start remote command: %w", err)
	}
	waitErr := make(chan error, 1)
	go func() {
		err := sess.Wait()
		pw.Close()
		waitErr <- err
	}()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Signal(ssh.SIGKILL)
			_ = sess.Close()
		case <-stop:
		}
	}()

	recent := newRing(15)
	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)
	sc.Split(scanLines)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t")
		if line == "" {
			continue
		}
		recent.add(line)
		if onLine != nil {
			onLine(line)
		}
	}
	if serr := sc.Err(); serr != nil {
		// Nothing reads the pipe any more, so the session would never end:
		// stop it instead of waiting for it.
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		pr.CloseWithError(serr)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("remote command stopped: %w (a line longer than %d KiB)\n%s", ErrOutputTooLarge, maxLine>>10, recent.String())
	}
	err = <-waitErr
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("remote command failed: %w\n%s", err, recent.String())
	}
	return nil
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

// WriteFileScript is the shell both Host implementations run to write a file
// from stdin. The temp file is created under umask 077 by mktemp in the
// target directory and gets its final mode before the rename, so another
// user can never open the contents of a 0600 file. New parent directories
// are created 0700.
func WriteFileScript(path, mode string) string {
	q := Quote(path)
	return fmt.Sprintf(`umask 077; d=$(dirname -- %s); mkdir -p -- "$d" || exit 1; t=$(mktemp %s.XXXXXX) || exit 1; trap 'rm -f "$t"' EXIT; cat > "$t" && chmod %s "$t" && mv -f "$t" %s`, q, q, mode, q)
}

// Quote wraps s in single quotes for POSIX sh.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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

// maxLine is the longest line a streamed command may print.
const maxLine = 1024 * 1024

type ring struct {
	lines []string
	n     int
}

func newRing(n int) *ring { return &ring{n: n} }

// add keeps s for an error message, cut to 500 bytes.
func (r *ring) add(s string) {
	if len(s) > 500 {
		s = strings.ToValidUTF8(s[:500], "") + "..."
	}
	r.lines = append(r.lines, s)
	if len(r.lines) > r.n {
		r.lines = r.lines[1:]
	}
}

func (r *ring) String() string { return strings.Join(r.lines, "\n") }

// ---- host keys ----

func (p HostKeyPolicy) path() string {
	if p.KnownHostsPath != "" {
		return p.KnownHostsPath
	}
	return filepath.Join(homeDir(), ".ssh", "known_hosts")
}

func (p HostKeyPolicy) check(ctx context.Context, hostname string, remote net.Addr, key ssh.PublicKey) error {
	if _, ok := key.(*ssh.Certificate); ok {
		return fmt.Errorf("%w: %s presented a host certificate, which secure-setup does not verify", ErrHostKeyRejected, hostname)
	}
	known, mismatch, err := p.lookup(hostname, remote, key)
	if err != nil {
		return err
	}
	if p.Expect != nil {
		if !bytes.Equal(p.Expect.Marshal(), key.Marshal()) {
			return fmt.Errorf("%w for %s: expected %s, got %s", ErrHostKeyMismatch, hostname,
				ssh.FingerprintSHA256(p.Expect), ssh.FingerprintSHA256(key))
		}
		if mismatch {
			if p.Warn != nil {
				host := knownhosts.Normalize(hostname)
				p.Warn(fmt.Sprintf("~/.ssh/known_hosts has an older, different key for %s (probably a previous machine). Plain ssh will complain until you run: ssh-keygen -R %s", host, host))
			}
			return nil
		}
		if !known {
			_ = p.remember(hostname, key)
		}
		return nil
	}
	if known {
		return nil
	}
	if mismatch {
		host := knownhosts.Normalize(hostname)
		return fmt.Errorf("%w for %s: the key in %s differs from what the server presents (%s). Only if you know why, remove it with: ssh-keygen -R %s",
			ErrHostKeyMismatch, host, p.path(), ssh.FingerprintSHA256(key), host)
	}
	if p.Prompter == nil {
		return fmt.Errorf("%w: %s is unknown (%s %s)", ErrHostKeyRejected, hostname, key.Type(), ssh.FingerprintSHA256(key))
	}
	ok, err := p.Prompter.ConfirmHostKey(ctx, knownhosts.Normalize(hostname), key.Type(), ssh.FingerprintSHA256(key))
	if err != nil {
		return err
	}
	if !ok {
		return ErrHostKeyRejected
	}
	return p.remember(hostname, key)
}

// lookup reports whether known_hosts knows this exact key, or holds a
// different one for the host. Only a missing file or a host without any entry
// counts as unknown; an unreadable or unparsable file and a revoked key are
// errors, never a first contact.
func (p HostKeyPolicy) lookup(hostname string, remote net.Addr, key ssh.PublicKey) (known, mismatch bool, err error) {
	cb, err := knownhosts.New(p.path())
	if errors.Is(err, fs.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("%w: cannot use %s (%v); fix or move that file before connecting", ErrHostKeyRejected, p.path(), err)
	}
	var ke *knownhosts.KeyError
	switch err := cb(hostname, remote, key); {
	case err == nil:
		return true, false, nil
	case errors.As(err, &ke) && len(ke.Want) > 0:
		return false, true, nil
	case errors.As(err, &ke):
		return false, false, nil
	default: // *knownhosts.RevokedError and anything else
		return false, false, fmt.Errorf("%w for %s: %v", ErrHostKeyRejected, knownhosts.Normalize(hostname), err)
	}
}

func (p HostKeyPolicy) remember(hostname string, key ssh.PublicKey) error {
	path := p.path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key))
	return err
}

// ---- authentication ----

var defaultKeyNames = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

func authMethods(a Auth) ([]ssh.AuthMethod, error) {
	var signers []ssh.Signer
	if a.KeyPath != "" {
		s, err := loadKey(ExpandHome(a.KeyPath), a.Passphrase)
		if err != nil {
			return nil, err
		}
		signers = append(signers, s)
	}
	signers = append(signers, agentSigners()...)
	if a.KeyPath == "" {
		for _, name := range defaultKeyNames {
			p := filepath.Join(homeDir(), ".ssh", name)
			if _, err := os.Stat(p); err != nil {
				continue
			}
			if s, err := loadKey(p, ""); err == nil {
				signers = append(signers, s)
			}
		}
	}
	var methods []ssh.AuthMethod
	if signers = dedupeSigners(signers); len(signers) > 0 {
		methods = append(methods, ssh.PublicKeys(signers...))
	}
	if a.Password != "" {
		pw := a.Password
		methods = append(methods,
			ssh.Password(pw),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			}),
		)
	}
	if len(methods) == 0 {
		return nil, errors.New("no SSH credentials: no key file, no keys in ssh-agent, no default key in ~/.ssh and no password")
	}
	return methods, nil
}

func agentSigners() []ssh.Signer {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil
	}
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		return nil
	}
	return signers
}

func dedupeSigners(in []ssh.Signer) []ssh.Signer {
	seen := map[string]bool{}
	var out []ssh.Signer
	for _, s := range in {
		k := string(s.PublicKey().Marshal())
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

func loadKey(path, passphrase string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
	}
	s, err := ssh.ParsePrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return nil, fmt.Errorf("%s: %w", path, ErrPassphraseRequired)
	}
	if err != nil {
		return nil, fmt.Errorf("parse key %s: %w", path, err)
	}
	return s, nil
}

// KeyNeedsPassphrase reports whether the key file is encrypted.
func KeyNeedsPassphrase(path string) bool {
	_, err := loadKey(ExpandHome(path), "")
	return errors.Is(err, ErrPassphraseRequired)
}

// LocalPublicKeys returns candidate authorized_keys lines in order of
// preference: an explicit public key, the explicit key's .pub, ssh-agent keys,
// then the default ~/.ssh/*.pub files.
func LocalPublicKeys(a Auth, pubKeyPath string) []string {
	var out []string
	add := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return
		}
		canon := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
		for _, have := range out {
			if strings.HasPrefix(have, canon) {
				return
			}
		}
		out = append(out, line)
	}
	readPub := func(p string) {
		if data, err := os.ReadFile(ExpandHome(p)); err == nil {
			add(string(data))
		}
	}
	if pubKeyPath != "" {
		readPub(pubKeyPath)
	}
	if a.KeyPath != "" {
		readPub(a.KeyPath + ".pub")
	}
	for _, s := range agentSigners() {
		add(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
	}
	for _, name := range defaultKeyNames {
		readPub(filepath.Join(homeDir(), ".ssh", name+".pub"))
	}
	return out
}

// PublicKeyBlob returns the base64 part of an authorized_keys line.
func PublicKeyBlob(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

// ExpandHome replaces a leading ~ with the home directory.
func ExpandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		return filepath.Join(homeDir(), strings.TrimPrefix(p, "~"))
	}
	return p
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return h
}
