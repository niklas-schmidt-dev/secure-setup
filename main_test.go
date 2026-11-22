package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resolved(t *testing.T, args ...string) (*target, error) {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	tg := targetFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return tg, tg.resolve()
}

// status and undo reach a locked-down server at its private address. With a
// plan file that is the existing network's address or the name in the
// tailnet, never the plan's public address; flags win over the plan.
func TestTargetFromPlan(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tailnet := write("ts.json", `{"server":{"host":"203.0.113.10","port":2222,"user":"deploy","key_path":"/k"},"tailscale":{"hostname":"web-1"}}`)
	existing := write("net.json", `{"server":{"host":"203.0.113.10"},"tailscale":{"use_existing_network":true,"admin_interface":"eth1","admin_address":"10.0.0.5"}}`)
	unnamed := write("unnamed.json", `{"server":{"host":"203.0.113.10"}}`)
	local := write("local.json", `{"local":true}`)

	tg, err := resolved(t, "-f", tailnet)
	if err != nil || *tg.host != "web-1" || *tg.port != 2222 || *tg.user != "deploy" || *tg.key != "/k" || *tg.here {
		t.Fatalf("tailnet plan: %v host %q port %d user %q key %q", err, *tg.host, *tg.port, *tg.user, *tg.key)
	}
	if tg, err = resolved(t, "-f", tailnet, "--host", "100.64.0.5", "--user", "root"); err != nil || *tg.host != "100.64.0.5" || *tg.user != "root" || *tg.port != 2222 {
		t.Fatalf("flags over the plan: %v host %q user %q port %d", err, *tg.host, *tg.user, *tg.port)
	}
	if tg, err = resolved(t, "-f", existing); err != nil || *tg.host != "10.0.0.5" || *tg.user != "root" || *tg.port != 22 {
		t.Fatalf("existing network: %v host %q", err, *tg.host)
	}
	if _, err = resolved(t, "-f", unnamed); err == nil || !strings.Contains(err.Error(), "--host") {
		t.Fatalf("a plan without a tailnet name: %v", err)
	}
	if tg, err = resolved(t, "-f", local); err != nil || !*tg.here || tg.where() != "this machine" {
		t.Fatalf("local plan: %v here %v", err, *tg.here)
	}
	if _, err = resolved(t); err == nil {
		t.Fatal("no target accepted")
	}
	if tg, err = resolved(t, "--host", "fd7a:115c:a1e0::5"); err != nil || tg.where() != "fd7a:115c:a1e0::5" {
		t.Fatalf("--host alone: %v", err)
	}
}
