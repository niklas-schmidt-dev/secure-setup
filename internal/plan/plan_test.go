package plan

import (
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
