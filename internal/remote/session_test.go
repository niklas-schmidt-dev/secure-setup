package remote

import (
	"net/netip"
	"strings"
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

func TestNewSessionsToIgnoresLocalPeers(t *testing.T) {
	admin := netip.MustParseAddr("100.101.102.103")
	now := ParseSessions(`0 0 100.101.102.103:22 100.101.102.103:51234
0 0 [::ffff:100.101.102.103]:22 [::ffff:127.0.0.1]:51235
0 0 100.101.102.103:22 10.0.0.7:51236
0 0 100.101.102.103:22 100.90.1.2:51237
`)
	fresh := NewSessionsTo(nil, now, admin, netip.MustParseAddr("10.0.0.7"))
	if len(fresh) != 1 || fresh[0].Peer.Addr() != netip.MustParseAddr("100.90.1.2") {
		t.Fatalf("want only the other machine's session, got %+v", fresh)
	}
}

func TestListenerIgnoresOtherUsersSockets(t *testing.T) {
	admin := netip.MustParseAddr("100.64.0.5")
	ok, detail, _ := listenerFor("LISTEN 0 128 203.0.113.7:2222 0.0.0.0:* ino:2 sk:2 cgroup:/ <->\n"+
		"LISTEN 0 4096 100.64.0.5:2222 0.0.0.0:* uid:65534 ino:1 sk:1 cgroup:/ <->", admin)
	if ok {
		t.Fatal("a uid 65534 listener on the admin address was taken for sshd")
	}
	if !strings.Contains(detail, "owned by uid:65534") {
		t.Fatalf("foreign listener not reported: %s", detail)
	}
	for _, out := range []string{
		"LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* ino:3 sk:3 cgroup:/ <->",
		"LISTEN 0 128 100.64.0.5:2222 0.0.0.0:* ino:4 sk:4 cgroup:/ <->",
	} {
		if ok, _, _ := listenerFor(out, admin); !ok {
			t.Fatalf("root-owned listener not accepted: %s", out)
		}
	}
}
