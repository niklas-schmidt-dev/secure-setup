package plan

import "testing"

// The dashboard has no copy button for the bare token, only for whole
// commands: any of them, or the token alone, yields the token.
func TestTunnelTokenFromPastedCommand(t *testing.T) {
	const tok = "eyJhIjoiMTIzNDU2Nzg5MGFiY2RlZiIsInQiOiJhYmMiLCJzIjoiWlhoaGJYQnNaUT09In0="
	for _, in := range []string{
		tok,
		"  " + tok + "\n",
		"sudo cloudflared service install " + tok,
		"cloudflared tunnel run --token " + tok,
		"docker run cloudflare/cloudflared:latest tunnel --no-autoupdate run --token " + tok,
		"cloudflared.exe service install " + tok,
	} {
		got, err := TunnelToken(in)
		if err != nil || got != tok {
			t.Fatalf("%q: got %q, %v", in, got, err)
		}
	}
	for _, in := range []string{
		"sudo mkdir -p --mode=0755 /usr/share/keyrings && curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg",
		"cloudflared service install " + tok + " && cloudflared tunnel run --token eyJhIjoiYW5vdGhlciIsInQiOiJ0dW5uZWwiLCJzIjoieCJ9",
		"   ",
	} {
		if got, err := TunnelToken(in); err == nil {
			t.Fatalf("%q: accepted, got %q", in, got)
		}
	}
	p := Default()
	p.Server.Host = "203.0.113.10"
	p.Firewall.CloudflareTunnel, p.Firewall.WebPorts = true, nil
	p.Firewall.TunnelToken = "sudo cloudflared service install " + tok
	if err := p.Validate(); err != nil || p.Firewall.TunnelToken != tok {
		t.Fatalf("Validate left %q, %v", p.Firewall.TunnelToken, err)
	}
}

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
