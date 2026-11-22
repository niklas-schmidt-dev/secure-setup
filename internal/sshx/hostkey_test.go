package sshx

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// testServer is a loopback SSH server that records every password it is sent.
type testServer struct {
	addr      string
	mu        sync.Mutex
	passwords []string
	banner    string
}

func (s *testServer) got() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.passwords...)
}

func startServer(t *testing.T, hostKey ssh.Signer, more ...ssh.Signer) *testServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &testServer{addr: ln.Addr().String()}
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		s.mu.Lock()
		s.passwords = append(s.passwords, string(pw))
		s.mu.Unlock()
		return &ssh.Permissions{}, nil
	}}
	cfg.BannerCallback = func(ssh.ConnMetadata) string {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.banner
	}
	cfg.AddHostKey(hostKey)
	for _, k := range more {
		cfg.AddHostKey(k)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					c.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					ch.Reject(ssh.Prohibited, "test server")
				}
			}()
		}
	}()
	return s
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type countingPrompter struct{ calls int }

func (p *countingPrompter) ConfirmHostKey(context.Context, string, string, string) (bool, error) {
	p.calls++
	return true, nil // like textui.Prompter{AssumeYes: true}
}

func writeKnownHosts(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func dialFor(t *testing.T, addr, kh string, pr HostKeyPrompter) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, addr, Auth{User: "root", Password: "dummy-password"}, HostKeyPolicy{KnownHostsPath: kh, Prompter: pr})
	if err == nil {
		c.Close()
	}
	return err
}

// A server whose real key is in known_hosts must never be treated as a first
// contact, whatever the impostor presents, and must never get the password.
func TestHostKeyFailsClosed(t *testing.T) {
	real := newSigner(t)
	attacker := newSigner(t)
	ca := newSigner(t)

	cert := &ssh.Certificate{Key: attacker.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: []string{"127.0.0.1"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(cert, attacker)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		presented ssh.Signer
		extra     []string
	}{
		{"plain key mismatch", attacker, nil},
		{"host certificate from an attacker CA", certSigner, nil},
		{"revoked attacker key", attacker, []string{"@revoked * " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(attacker.PublicKey())))}},
		{"unparsable known_hosts line", attacker, []string{"other.example ssh-ed25519 !!!not-base64!!!"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startServer(t, tc.presented)
			kh := writeKnownHosts(t, append([]string{knownhosts.Line([]string{knownhosts.Normalize(srv.addr)}, real.PublicKey())}, tc.extra...)...)
			pr := &countingPrompter{}
			err := dialFor(t, srv.addr, kh, pr)
			if err == nil {
				t.Fatal("connection accepted")
			}
			if pr.calls != 0 {
				t.Fatalf("treated as a first contact (prompter called %d times)", pr.calls)
			}
			if got := srv.got(); len(got) != 0 {
				t.Fatalf("password sent to the impostor: %v", got)
			}
		})
	}
}

// A genuine first contact still reaches the prompter and is remembered.
func TestHostKeyFirstContact(t *testing.T) {
	srv := startServer(t, newSigner(t))
	kh := filepath.Join(t.TempDir(), "known_hosts") // does not exist yet
	pr := &countingPrompter{}
	if err := dialFor(t, srv.addr, kh, pr); err != nil {
		t.Fatal(err)
	}
	if pr.calls != 1 {
		t.Fatalf("prompter called %d times, want 1", pr.calls)
	}
	if err := dialFor(t, srv.addr, kh, pr); err != nil {
		t.Fatalf("remembered key not accepted: %v", err)
	}
	if pr.calls != 1 {
		t.Fatal("known key prompted again")
	}
}

// A pinned fingerprint answers the first-contact question: the named key is
// accepted and remembered without a prompt, any other key is refused before
// the password is sent.
func TestPinnedHostKey(t *testing.T) {
	key := newSigner(t)
	srv := startServer(t, key)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	dial := func(fp string, pr HostKeyPrompter) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := Dial(ctx, srv.addr, Auth{User: "root", Password: "dummy-password"}, HostKeyPolicy{KnownHostsPath: kh, Prompter: pr, Fingerprint: fp})
		if err == nil {
			c.Close()
		}
		return err
	}
	pr := &countingPrompter{}
	if err := dial(ssh.FingerprintSHA256(newSigner(t).PublicKey()), pr); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("another key than the pinned one: %v", err)
	}
	if got := srv.got(); len(got) != 0 || pr.calls != 0 {
		t.Fatalf("password sent (%v) or question asked (%d) for a key that is not the pinned one", got, pr.calls)
	}
	if _, err := os.Stat(kh); err == nil {
		t.Fatal("a refused key was remembered")
	}
	if err := dial(ssh.FingerprintSHA256(key.PublicKey()), nil); err != nil {
		t.Fatalf("the pinned key was refused: %v", err)
	}
	if err := dial("", nil); err != nil {
		t.Fatalf("the pinned key was not remembered: %v", err)
	}
}

// The pinned key may be any of the server's host keys, not only the one a
// connection asks for first; the rest of a run then keeps asking for it.
func TestPinnedHostKeyOfAnyKind(t *testing.T) {
	ed := newSigner(t)
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ssh.NewSignerFromKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	srv := startServer(t, ec, ed)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	dial := func(p HostKeyPolicy) (ssh.PublicKey, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		p.KnownHostsPath = kh
		c, err := Dial(ctx, srv.addr, Auth{User: "root", Password: "dummy-password"}, p)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		return c.HostKey, nil
	}
	for _, want := range []ssh.Signer{ed, ec} {
		got, err := dial(HostKeyPolicy{Fingerprint: ssh.FingerprintSHA256(want.PublicKey())})
		if err != nil || got.Type() != want.PublicKey().Type() {
			t.Fatalf("pinned %s key: %v", want.PublicKey().Type(), err)
		}
		if _, err := dial(HostKeyPolicy{Expect: got}); err != nil {
			t.Fatalf("a later connection that expects the %s key: %v", got.Type(), err)
		}
	}
	if _, err := dial(HostKeyPolicy{Fingerprint: ssh.FingerprintSHA256(newSigner(t).PublicKey())}); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("a key the server does not have: %v", err)
	}
	// Only the Ed25519 key is on record now. A plain connection asks for
	// that kind first, as OpenSSH does, instead of getting the ECDSA key and
	// calling it a mismatch.
	pr := &countingPrompter{}
	if got, err := dial(HostKeyPolicy{Prompter: pr}); err != nil || got.Type() != ssh.KeyAlgoED25519 || pr.calls != 0 {
		t.Fatalf("a plain connection with one of two keys on record: %v, %d questions", err, pr.calls)
	}
}

func TestWriteFileScriptOrder(t *testing.T) {
	s := WriteFileScript("/var/lib/secure-setup/tailscale.authkey", "0600")
	for _, want := range []string{"umask 077", "mktemp", `chmod 0600 "$t" && mv -f "$t"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("script lacks %q: %s", want, s)
		}
	}
	if strings.Contains(s, "umask 022") || strings.Index(s, "chmod") > strings.Index(s, "mv -f") {
		t.Fatalf("mode applied after the file is in place: %s", s)
	}
}

// A login banner (Tailscale SSH's browser check) reaches Auth.Banner.
func TestBannerReachesCaller(t *testing.T) {
	key := newSigner(t)
	srv := startServer(t, key)
	srv.mu.Lock()
	srv.banner = "To authenticate, visit: https://login.tailscale.com/a/check"
	srv.mu.Unlock()
	var got string
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := Dial(ctx, srv.addr, Auth{User: "root", Password: "pw", Banner: func(m string) { got = m }}, HostKeyPolicy{Expect: key.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if !strings.Contains(got, "login.tailscale.com/a/check") {
		t.Fatalf("banner %q", got)
	}
}

// Cancelling the context interrupts a login that waits on the server (a
// Tailscale SSH check nobody approves) instead of waiting for the deadline.
func TestDialStopsOnCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(time.Minute) // never answers
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	time.AfterFunc(300*time.Millisecond, cancel)
	start := time.Now()
	_, err = Dial(ctx, ln.Addr().String(), Auth{User: "root", Password: "x", Banner: func(string) {}}, HostKeyPolicy{Expect: newSigner(t).PublicKey()})
	if !errors.Is(err, context.Canceled) || time.Since(start) > 5*time.Second {
		t.Fatalf("err %v after %s", err, time.Since(start))
	}
}
