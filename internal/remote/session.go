package remote

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var scopeRe = regexp.MustCompile(`%[^\]:]+`)

// Session is one established TCP connection to sshd.
type Session struct {
	Local, Peer netip.AddrPort
}

// Sessions lists established connections to the given local TCP port.
func Sessions(ctx context.Context, c Host, port int) ([]Session, error) {
	out, err := c.Output(ctx, fmt.Sprintf("ss -Htn state established '( sport = :%d )' 2>/dev/null || true", port))
	if err != nil {
		return nil, err
	}
	return ParseSessions(out), nil
}

// ParseSessions reads `ss -Htn` output: "recv-q send-q local:port peer:port ...".
func ParseSessions(out string) []Session {
	var sessions []Session
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		local, err1 := parseAddrPort(f[2])
		peer, err2 := parseAddrPort(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		sessions = append(sessions, Session{Local: local, Peer: peer})
	}
	return sessions
}

func parseAddrPort(s string) (netip.AddrPort, error) {
	// ss prints [v6]:port, v4:port and scoped v6 as [fe80::1]%eth0:22 or [fe80::1%eth0]:22.
	host, port, err := net.SplitHostPort(scopeRe.ReplaceAllString(s, ""))
	if err != nil {
		return netip.AddrPort{}, err
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	a = a.Unmap()
	p, err := strconv.Atoi(port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(a, uint16(p)), nil
}

// NewSessionsTo returns the sessions in now whose local address is addr,
// that were not in before, and whose peer is another machine. A local
// process reaching addr goes over lo and proves nothing about the rules, so
// loopback peers, addr itself and every address in self are ignored.
func NewSessionsTo(before, now []Session, addr netip.Addr, self ...netip.Addr) []Session {
	seen := map[Session]bool{}
	for _, s := range before {
		seen[s] = true
	}
	local := map[netip.Addr]bool{addr: true}
	for _, a := range self {
		local[a.Unmap()] = true
	}
	var out []Session
	for _, s := range now {
		p := s.Peer.Addr()
		if seen[s] || s.Local.Addr() != addr || p.IsLoopback() || local[p] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// LocalAddrs lists every address configured on the host.
func LocalAddrs(ctx context.Context, c Host) []netip.Addr {
	out, err := c.Output(ctx, "ip -o addr show 2>/dev/null | awk '{print $4}'")
	if err != nil {
		return nil
	}
	var addrs []netip.Addr
	for _, f := range strings.Fields(out) {
		if p, err := netip.ParsePrefix(scopeRe.ReplaceAllString(f, "")); err == nil {
			addrs = append(addrs, p.Addr().Unmap())
		}
	}
	return addrs
}

// SSHDListensOn reports whether sshd accepts connections on addr:port: a
// wildcard listener or one bound to that address. Only root-owned sockets
// count: ss -e prints "uid:N" for a socket another user opened, and such a
// listener is reported but never taken for sshd.
func SSHDListensOn(ctx context.Context, c Host, addr netip.Addr, port int) (bool, string, error) {
	out, err := c.Output(ctx, fmt.Sprintf("ss -Htlne '( sport = :%d )' 2>/dev/null || true", port))
	if err != nil {
		return false, "", err
	}
	return listenerFor(out, addr)
}

func listenerFor(out string, addr netip.Addr) (bool, string, error) {
	var listeners []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		if owner := socketOwner(f[4:]); owner != "" {
			listeners = append(listeners, f[3]+" (owned by "+owner+", not sshd)")
			continue
		}
		listeners = append(listeners, f[3])
		l, err := parseAddrPort(f[3])
		if err != nil {
			// "*:22" is how ss prints a wildcard on some versions
			if strings.HasPrefix(f[3], "*:") {
				return true, f[3], nil
			}
			continue
		}
		if l.Addr().IsUnspecified() || l.Addr() == addr {
			return true, f[3], nil
		}
	}
	return false, strings.Join(listeners, " "), nil
}

// socketOwner returns the "uid:N" field ss -e prints for a socket root does
// not own, or "".
func socketOwner(fields []string) string {
	for _, x := range fields {
		if strings.HasPrefix(x, "uid:") && x != "uid:0" {
			return x
		}
	}
	return ""
}
