package plan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultValidates(t *testing.T) {
	p := Default()
	p.Server.Host = "203.0.113.10"
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCatchesMistakes(t *testing.T) {
	p := Default()
	p.Server.Host = "bad host!"
	p.Firewall.RollbackSeconds = 5
	p.Firewall.WebPorts = []int{99999}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"not a hostname", "rollback window", "99999"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

// The admin rule of an existing private network is bound to its address, so
// that must be an IP address.
func TestValidateAdminAddress(t *testing.T) {
	for addr, ok := range map[string]bool{"10.0.0.5": true, "fd00::5": true, "": false, "vpn.example.com": false, "fe80::1%eth1": false} {
		p := Default()
		p.Server.Host = "203.0.113.10"
		p.Tailscale.UseExisting, p.Tailscale.AdminInterface, p.Tailscale.AdminAddress = true, "eth1", addr
		if err := p.Validate(); (err == nil) != ok {
			t.Errorf("admin address %q: %v", addr, err)
		}
		if ok && p.AdminAddr().String() != addr {
			t.Errorf("AdminAddr() = %v, want %s", p.AdminAddr(), addr)
		}
	}
	if p := Default(); p.AdminAddr().IsValid() {
		t.Error("Tailscale has an admin address")
	}
}

func TestValidateExtraWAN(t *testing.T) {
	p := Default()
	p.Server.Host = "203.0.113.10"
	p.Firewall.ExtraWANInterfaces = []string{"ens10", "eth0.100"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"eth0; reboot", "tailscale0", ""} {
		p.Firewall.ExtraWANInterfaces = []string{bad}
		if err := p.Validate(); err == nil {
			t.Errorf("extra_wan_interfaces %q accepted", bad)
		}
	}
}

func TestSaveLoadDropsSecrets(t *testing.T) {
	p := Default()
	p.Server.Host = "vps.example.com"
	p.Server.Password = "hunter2"
	p.Tailscale.AuthKey = "tskey-auth-secret"
	path := filepath.Join(t.TempDir(), "p.json")
	if err := p.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Server.Password != "" || got.Tailscale.AuthKey != "" {
		t.Error("secrets were persisted")
	}
	if got.Server.Host != "vps.example.com" || got.Firewall.RollbackSeconds != 120 {
		t.Errorf("round trip lost data: %+v", got)
	}
}

// A misspelt field must stop the plan instead of leaving the default in
// force: "web_port": [] would keep HTTPS open from Cloudflare.
func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"server":{"host":"203.0.113.10"},"firewall":{"web_ports":[]}}`)
	p, err := Load(path)
	if err != nil || len(p.Firewall.WebPorts) != 0 {
		t.Fatalf("web_ports: [] did not close the web ports: %v, %v", p.Firewall.WebPorts, err)
	}
	write(`{"server":{"host":"203.0.113.10"},"firewall":{"web_port":[]}}`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), `"web_port"`) {
		t.Fatalf("the misspelt field was accepted: %v", err)
	}
}

// A pinned host key is a SHA256 fingerprint; anything else is refused before
// a connection is made.
func TestValidateHostKey(t *testing.T) {
	for key, ok := range map[string]bool{
		"": true,
		"SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8":                               true,
		"SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8=":                              false,
		"MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48":                              false,
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHHT9zwfT6widjbTcsKOGGlmx58L4skpUKesGUJ0u4kk": false,
	} {
		p := Default()
		p.Server.Host, p.Server.HostKey = "203.0.113.10", key
		if err := p.Validate(); (err == nil) != ok {
			t.Errorf("host key %q: %v", key, err)
		}
	}
}

// Read leaves validation to a caller that still fills in values: a plan for
// several servers has no host of its own.
func TestReadDoesNotValidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.json")
	if err := os.WriteFile(path, []byte(`{"firewall":{"web_ports":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a plan without a server host loaded")
	}
	p, err := Read(path)
	if err != nil || p.Server.Port != 22 || len(p.Firewall.WebPorts) != 0 {
		t.Fatalf("Read: %+v, %v", p.Server, err)
	}
	p.Server.Host = "203.0.113.10"
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Public ports are open to everyone, so they can be neither a web port (that
// one is for Cloudflare only) nor the SSH port.
func TestValidatePublicPorts(t *testing.T) {
	p := Default()
	p.Server.Host = "203.0.113.10"
	p.Firewall.PublicTCPPorts, p.Firewall.PublicUDPPorts = []int{25, 587}, []int{51820}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := PublicPorts(p.Firewall); got != "TCP 25, 587 and UDP 51820" {
		t.Fatalf("PublicPorts = %q", got)
	}
	if PublicPorts(Default().Firewall) != "" {
		t.Fatal("the default plan opens a public port")
	}
	for name, ports := range map[string][]int{"a web port": {443}, "the SSH port": {22}, "out of range": {70000}} {
		p.Firewall.PublicTCPPorts = ports
		if err := p.Validate(); err == nil {
			t.Errorf("public_tcp_ports with %s accepted", name)
		}
	}
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("8080, 22;22 443")
	if err != nil || FormatPorts(got) != "22, 443, 8080" {
		t.Errorf("got %v, %v", got, err)
	}
	if _, err := ParsePorts("22, abc"); err == nil {
		t.Error("accepted garbage")
	}
	if got, _ := ParsePorts(""); len(got) != 0 {
		t.Error("empty input must give no ports")
	}
}
