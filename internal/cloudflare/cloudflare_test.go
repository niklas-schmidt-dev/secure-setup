package cloudflare

import "testing"

func TestParseList(t *testing.T) {
	v4, err := ParseList("173.245.48.0/20\n\n103.21.244.0/22\r\n", true)
	if err != nil || len(v4) != 2 {
		t.Fatalf("got %v, %v", v4, err)
	}
	if _, err := ParseList("2400:cb00::/32\n", true); err == nil {
		t.Error("IPv6 prefix accepted in the IPv4 list")
	}
	if _, err := ParseList("<html>", true); err == nil {
		t.Error("garbage accepted")
	}
	if _, err := ParseList("", false); err == nil {
		t.Error("empty list accepted")
	}
}
