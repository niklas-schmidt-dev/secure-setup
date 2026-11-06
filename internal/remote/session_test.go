package remote

import (
	"net/netip"
	"testing"
)

func TestParseSessionsAndNew(t *testing.T) {
	before := ParseSessions(`0      0      10.250.100.2:22   10.250.100.3:51234
0      0      [::ffff:10.250.100.2]:22   [::ffff:10.250.100.3]:51235
`)
	if len(before) != 2 {
		t.Fatalf("want 2 sessions, got %d: %+v", len(before), before)
	}
	if before[1].Local.Addr() != netip.MustParseAddr("10.250.100.2") {
		t.Fatalf("v4-mapped address not unmapped: %v", before[1].Local)
	}
	now := ParseSessions(`0      0      10.250.100.2:22   10.250.100.3:51234
0      0      [::ffff:10.250.100.2]:22   [::ffff:10.250.100.3]:51235
0      0      100.64.0.5:22     100.64.0.9:40000
0      0      [fd7a:115c:a1e0::1]%tailscale0:22  [fd7a:115c:a1e0::2]:40001
garbage line
`)
	fresh := NewSessionsTo(before, now, netip.MustParseAddr("100.64.0.5"))
	if len(fresh) != 1 || fresh[0].Peer.Addr() != netip.MustParseAddr("100.64.0.9") {
		t.Fatalf("want the one new tailnet session, got %+v", fresh)
	}
	if n := NewSessionsTo(before, now, netip.MustParseAddr("fd7a:115c:a1e0::1")); len(n) != 1 {
		t.Fatalf("scoped v6 listener not parsed: %+v", n)
	}
	if n := NewSessionsTo(before, now, netip.MustParseAddr("10.250.100.2")); len(n) != 0 {
		t.Fatalf("old sessions reported as new: %+v", n)
	}
}
