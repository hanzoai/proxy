package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ErrClosed means the target is inside the fence rather than out on the web.
//
// This is the difference between an agentic scraping platform and a way into our
// own cluster. A guest names a URL, which is the job — but a URL can name
// 10.0.0.144:6443, or the metadata address that hands out credentials. Neither
// is the web, and a proxy that dials them is a hole with an HTTP interface.
var ErrClosed = errors.New("destination is not public")

// Fence refuses destinations that are not out on the web. A Rule, so it applies
// once around whatever it wraps and every route underneath inherits it —
// there is no exit that can be added later and quietly miss the check.
func Fence(ok func(addr string) error) Rule {
	return func(e Exit) Exit {
		return func(ctx context.Context, n Need, addr string) (net.Conn, error) {
			if err := ok(addr); err != nil {
				return nil, err
			}
			return e(ctx, n, addr)
		}
	}
}

// Anywhere places no fence. Naming it is the point: there is no flag that
// quietly does this, so removing the fence appears in the code that removed it.
func Anywhere(string) error { return nil }

// cgnat is carrier-grade NAT, which netip does not count as private and which is
// where a good deal of private infrastructure actually lives.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// inside names that can only resolve to something of ours. A single-label name
// is included because it resolves through the resolver's search domains, which
// on a cluster node means straight into the cluster.
var inside = []string{".local", ".internal", ".localdomain", ".svc", ".cluster.local", ".arpa"}

// Public reports whether addr is somewhere out on the web.
//
// Deliberately a check on what was ASKED for rather than on what the name
// resolves to. Resolving here would leak every target to our own resolver and
// answer the wrong question: the exit resolves from where the exit stands.
func Public(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %q is not host:port", ErrClosed, addr)
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return publicName(host)
	}
	a = a.Unmap()
	switch {
	case a.IsLoopback(), a.IsPrivate(), a.IsUnspecified(), a.IsMulticast(),
		a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast(),
		cgnat.Contains(a):
		return fmt.Errorf("%w: %s", ErrClosed, a)
	}
	return nil
}

func publicName(host string) error {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" {
		return fmt.Errorf("%w: empty host", ErrClosed)
	}
	if !strings.Contains(h, ".") {
		return fmt.Errorf("%w: %q has no public suffix", ErrClosed, host)
	}
	for _, s := range inside {
		if strings.HasSuffix(h, s) {
			return fmt.Errorf("%w: %q", ErrClosed, host)
		}
	}
	return nil
}
