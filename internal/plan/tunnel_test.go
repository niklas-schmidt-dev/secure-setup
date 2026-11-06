package plan

import "testing"

// A tunnel opens no web port, so web ports next to it are a mistake.
func TestTunnelReplacesWebPorts(t *testing.T) {
	p := Default()
	p.Server.Host = "203.0.113.10"
	p.Firewall.CloudflareTunnel = true
	if err := p.Validate(); err == nil {
		t.Fatal("tunnel with web ports accepted")
	}
	p.Firewall.WebPorts = nil
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}
