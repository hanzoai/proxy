package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"text/template"
)

// Gate is one upstream's coordinates. Data, and only data — what to do with it
// is Exit, so a deployment can hold a table of these in config without the
// config format having to describe behaviour.
//
// There is one shape because the market has one. NodeMaven, ProxyEmpire, Bright
// Data, Oxylabs, Smartproxy and IPRoyal all present a single gateway address and
// carry the routing in the USERNAME, differing only in the words they spell it
// with. So a vendor is a row, not a driver.
type Gate struct {
	// Name appears in errors and metrics. Never shown to a caller, who has no
	// business knowing who served them.
	Name string
	// Addr is scheme://host:port, scheme http or socks5.
	Addr string
	// User is a text/template over Need, which is what lets one driver speak
	// every dialect including the conditional parts:
	//
	//	acct-4471{{with .Country}}-country-{{.}}{{end}}{{with .Session}}-sid-{{.}}{{end}}
	//
	// A field the caller left empty drops its whole segment, because sending a
	// provider a bare "country-" is an error, not a wildcard.
	User string
	// Pass is resolved from KMS when the table is loaded. Never logged, never
	// returned in an error, never visible to a caller.
	Pass string
	// Zones translates a Kind into this vendor's own word for it.
	Zones map[Kind]string
}

// Exit compiles the gate. It fails here rather than at the first dial, so a
// typo in a template surfaces at load instead of under traffic.
func (g Gate) Exit() (Exit, error) {
	if g.Addr == "" {
		return nil, fmt.Errorf("gate %q: no address", g.Name)
	}
	t, err := template.New(g.Name).Parse(g.User)
	if err != nil {
		return nil, fmt.Errorf("gate %q: user template: %w", g.Name, err)
	}
	return func(ctx context.Context, n Need, addr string) (net.Conn, error) {
		c, err := g.dial(ctx, t, n, addr)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", g.Name, err)
		}
		return c, nil
	}, nil
}

// name renders the upstream username for this need.
func (g Gate) name(t *template.Template, n Need) (string, error) {
	zone := g.Zones[n.Kind]
	if zone == "" {
		zone = n.Kind.String()
	}
	var b strings.Builder
	err := t.Execute(&b, struct{ Country, Kind, Session string }{n.Country, zone, n.Session})
	return b.String(), err
}

func (k Kind) String() string {
	switch k {
	case Datacenter:
		return "datacenter"
	case Residential:
		return "residential"
	case Mobile:
		return "mobile"
	}
	return "any"
}

var kinds = map[string]Kind{
	"any": Any, "datacenter": Datacenter, "residential": Residential, "mobile": Mobile,
}
