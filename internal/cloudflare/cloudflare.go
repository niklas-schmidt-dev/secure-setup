// Package cloudflare fetches Cloudflare's published edge IP ranges.
package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const (
	V4URL = "https://www.cloudflare.com/ips-v4"
	V6URL = "https://www.cloudflare.com/ips-v6"

	minV4 = 5
	minV6 = 3
)

// Fetch downloads both lists and validates them.
func Fetch(ctx context.Context) (v4, v6 []netip.Prefix, err error) {
	client := &http.Client{Timeout: 20 * time.Second}
	if v4, err = fetchList(ctx, client, V4URL, true); err != nil {
		return nil, nil, err
	}
	if v6, err = fetchList(ctx, client, V6URL, false); err != nil {
		return nil, nil, err
	}
	if len(v4) < minV4 || len(v6) < minV6 {
		return nil, nil, fmt.Errorf("cloudflare: unexpectedly short lists (%d IPv4, %d IPv6 prefixes)", len(v4), len(v6))
	}
	return v4, v6, nil
}

func fetchList(ctx context.Context, client *http.Client, url string, want4 bool) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "secure-setup")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudflare: %s returned %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("cloudflare: read %s: %w", url, err)
	}
	return ParseList(string(body), want4)
}

// ParseList parses one prefix per line and checks the address family.
func ParseList(text string, want4 bool) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("cloudflare: bad prefix %q: %w", line, err)
		}
		if p.Addr().Is4() != want4 {
			return nil, fmt.Errorf("cloudflare: %q has the wrong address family", line)
		}
		out = append(out, p.Masked())
	}
	if len(out) == 0 {
		return nil, errors.New("cloudflare: empty list")
	}
	return out, nil
}
