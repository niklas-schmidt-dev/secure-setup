package sshx

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startExecServer is a loopback SSH server that answers every command with
// write(channel) and never sends an exit status.
func startExecServer(t *testing.T, write func(ssh.Channel)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return &ssh.Permissions{}, nil }}
	cfg.AddHostKey(newSigner(t))
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
				for nc := range chans {
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range creqs {
							req.Reply(req.Type == "exec", nil)
							if req.Type == "exec" {
								go write(ch)
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func dialExec(t *testing.T, write func(ssh.Channel)) (*Client, context.Context) {
	t.Helper()
	addr := startExecServer(t, write)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	c, err := Dial(ctx, addr, Auth{User: "root", Password: "dummy-password"}, HostKeyPolicy{KnownHostsPath: writeKnownHosts(t), Prompter: &countingPrompter{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, ctx
}

// A server that never stops printing cannot fill this computer's memory: the
// command is stopped once it passes MaxOutput.
func TestOutputIsBounded(t *testing.T) {
	c, ctx := dialExec(t, func(ch ssh.Channel) {
		chunk := bytes.Repeat([]byte("0\n"), 16<<10)
		for {
			if _, err := ch.Write(chunk); err != nil {
				return
			}
		}
	})
	if _, err := c.Output(ctx, "id -u"); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("err %v, want ErrOutputTooLarge", err)
	}
}

// A line longer than the stream accepts ends the command with an error
// instead of leaving it waiting on a pipe nobody reads.
func TestScriptStopsOnOverlongLine(t *testing.T) {
	c, ctx := dialExec(t, func(ch ssh.Channel) {
		chunk := bytes.Repeat([]byte("x"), 64<<10)
		for {
			if _, err := ch.Write(chunk); err != nil {
				return
			}
		}
	})
	var lines int
	err := c.Script(ctx, "true", func(string) { lines++ })
	if !errors.Is(err, ErrOutputTooLarge) || ctx.Err() != nil || lines != 0 {
		t.Fatalf("err %v, ctx %v, lines %d", err, ctx.Err(), lines)
	}
}
