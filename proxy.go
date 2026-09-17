// Package proxy gives an agent the web without giving it the network.
//
// Research, scraping and browsing all need to reach the internet from a place
// that is not obviously a datacenter, often from a named country, and often
// from the SAME address twice in a row. The usual way to arrange that is to
// hand the workload a provider's credentials and let it dial out. That is the
// thing to avoid: credentials in a sandbox are credentials you have published,
// and a workload that can open a socket can open any socket.
//
// So the sandbox gets no network at all, and this is the network. A caller
// says what it needs of an exit — country, kind, and whether to stay put — and
// gets a connection. It never learns which provider served it, never holds a
// provider password, and cannot address anything but the host it asked for.
//
// The same capability fits both execution hosts: a WASM guest reaches it
// through a host function, a Visor container through this CONNECT listener.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"text/template"
)

// Kind is how an exit reaches the internet.
//
// It is the axis callers actually care about, because it decides who lets you
// in: a datacenter address is fast, cheap and refused by anything with a bot
// policy; a mobile address shares a carrier NAT with thousands of real phones
// and is refused by almost nothing, at several times the price.
type Kind uint8

const (
	Any Kind = iota
	Datacenter
	Residential
	Mobile
)

var kinds = map[string]Kind{
	"any": Any, "datacenter": Datacenter, "residential": Residential, "mobile": Mobile,
}

func (k Kind) String() string {
	for s, v := range kinds {
		if v == k {
			return s
		}
	}
	return "any"
}

// Need is what a caller requires of an exit. The zero Need means "anywhere
// that works", which is the right ask for most single fetches.
type Need struct {
	// Country is ISO 3166-1 alpha-2, lowercase. Empty means any.
	Country string
	Kind    Kind
	// Session ties a run of requests to one address. A login and the page
	// behind it have to arrive from the same place or the site sees two
	// visitors and shows neither the content; an empty Session lets every
	// request take a fresh address, which is what breadth-first crawling
	// wants. The string is opaque and is never logged.
	Session string
}

// Pool is one upstream that supplies exits.
//
// There is one implementation because the market has one shape. NodeMaven,
// ProxyEmpire, Bright Data, Oxylabs, Smartproxy and IPRoyal all present a
// single gateway address and carry the routing in the USERNAME; they differ
// only in the words they spell it with. So a provider here is a table row, not
// a driver, and supporting the next one is config.
type Pool struct {
	// Label names the upstream in metrics and errors. It is not a secret and
	// is never shown to a caller, who has no business knowing who served them.
	Label string
	// Addr is scheme://host:port, scheme http or socks5.
	Addr string
	// User is a text/template over Need, which is what lets one driver speak
	// every provider's dialect including the conditional parts:
	//
	//	acct-4471{{with .Country}}-country-{{.}}{{end}}{{with .Session}}-sid-{{.}}{{end}}
	//
	// A field the caller left empty drops its whole segment, because sending
	// a provider a bare "country-" is an error, not a wildcard.
	User string
	// Pass is resolved from KMS when the table is loaded. It is never written
	// to a log, an error, or a caller-visible surface.
	Pass string
	// Kinds this upstream can serve; empty means every kind.
	Kinds []Kind
	// Countries it can serve, ISO 3166-1 alpha-2 lowercase; empty means every.
	Countries []string
	// Zones translates a Kind into the provider's own word for it, for
	// templates that name the kind.
	Zones map[Kind]string

	tmpl *template.Template
	// fails counts consecutive failures. It orders selection and nothing
	// else: a provider having a bad minute should be tried last, not removed,
	// because the alternative to a degraded exit is usually no exit.
	fails atomic.Int64
}

// Serves reports whether this upstream can answer the need at all. It is a
// filter on what was configured, not a promise the dial will work.
func (p *Pool) Serves(n Need) bool {
	if n.Kind != Any && len(p.Kinds) > 0 && !has(p.Kinds, n.Kind) {
		return false
	}
	if n.Country != "" && len(p.Countries) > 0 && !has(p.Countries, n.Country) {
		return false
	}
	return true
}

func has[T comparable](xs []T, x T) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// name renders the upstream username for this need.
func (p *Pool) name(n Need) (string, error) {
	if p.tmpl == nil {
		return p.User, nil
	}
	zone := p.Zones[n.Kind]
	if zone == "" {
		zone = n.Kind.String()
	}
	var b strings.Builder
	err := p.tmpl.Execute(&b, struct {
		Country, Kind, Session string
	}{n.Country, zone, n.Session})
	return b.String(), err
}

// Proxy composes upstreams and chooses between them.
type Proxy struct {
	pools []*Pool
	seed  maphash.Seed
}

// ErrNoExit means nothing configured can serve the need. It is distinct from a
// dial failure on purpose: one is a gap in the table that an operator fixes,
// the other is a bad minute that retrying fixes.
var ErrNoExit = errors.New("no exit serves that need")

// New compiles the table. It fails on a bad username template rather than at
// the first dial, so a typo surfaces at load instead of under traffic.
func New(pools ...*Pool) (*Proxy, error) {
	for _, p := range pools {
		if p.Addr == "" {
			return nil, fmt.Errorf("pool %q: no address", p.Label)
		}
		t, err := template.New(p.Label).Parse(p.User)
		if err != nil {
			return nil, fmt.Errorf("pool %q: user template: %w", p.Label, err)
		}
		p.tmpl = t
	}
	return &Proxy{pools: pools, seed: maphash.MakeSeed()}, nil
}

// Dial opens a connection to addr through an exit that satisfies n.
//
// It tries every upstream that could serve the need before giving up, because
// a caller asked for a property of the exit and does not care which vendor
// provides it — that is the whole point of the indirection.
func (x *Proxy) Dial(ctx context.Context, n Need, addr string) (net.Conn, error) {
	order := x.order(n)
	if len(order) == 0 {
		return nil, fmt.Errorf("%w: %+v", ErrNoExit, n)
	}
	var errs []error
	for _, p := range order {
		c, err := p.dial(ctx, n, addr)
		if err == nil {
			p.fails.Store(0)
			return c, nil
		}
		p.fails.Add(1)
		errs = append(errs, fmt.Errorf("%s: %w", p.Label, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

// order returns the upstreams that can serve n, best first.
//
// A sticky session pins to one upstream by hashing the session, so the same
// run keeps landing on the same vendor and therefore the same address — that
// is what the caller asked for and no amount of health-based reordering may
// override it. Everything else sorts by consecutive failures.
func (x *Proxy) order(n Need) []*Pool {
	var fit []*Pool
	for _, p := range x.pools {
		if p.Serves(n) {
			fit = append(fit, p)
		}
	}
	if len(fit) < 2 {
		return fit
	}
	if n.Session != "" {
		i := int(maphash.String(x.seed, n.Session) % uint64(len(fit)))
		fit[0], fit[i] = fit[i], fit[0]
		return fit
	}
	sort.SliceStable(fit, func(a, b int) bool { return fit[a].fails.Load() < fit[b].fails.Load() })
	return fit
}
