package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
}

func (s *testServer) got() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.passwords...)
}

func startServer(t *testing.T, hostKey ssh.Signer) *testServer {
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
	cfg.AddHostKey(hostKey)
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
