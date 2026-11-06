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

// NewSessionsTo returns the sessions in now whose local address is addr and
// that were not in before.
func NewSessionsTo(before, now []Session, addr netip.Addr) []Session {
	seen := map[Session]bool{}
	for _, s := range before {
		seen[s] = true
	}
	var out []Session
	for _, s := range now {
		if !seen[s] && s.Local.Addr() == addr {
			out = append(out, s)
		}
	}
	return out
}

// SSHDListensOn reports whether sshd accepts connections on addr:port: a
// wildcard listener or one bound to that address.
func SSHDListensOn(ctx context.Context, c Host, addr netip.Addr, port int) (bool, string, error) {
	out, err := c.Output(ctx, fmt.Sprintf("ss -Htln '( sport = :%d )' 2>/dev/null || true", port))
	if err != nil {
		return false, "", err
	}
	var listeners []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
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
