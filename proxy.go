// Package proxy gives an agent the web without giving it the network.
//
// A caller says what it needs of an exit — country, kind, whether to stay put —
// and gets a connection. It never learns which vendor served it, never holds a
// vendor password, and cannot address anything but the host it asked for.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"net"
	"net/http"
	"sort"
	"sync/atomic"
	"time"
)

// Need is what a caller requires of an exit. The zero Need means "anywhere that
// works", which is the right ask for most single fetches.
type Need struct {
	// Country is ISO 3166-1 alpha-2, lowercase. Empty means any.
	Country string
	Kind    Kind
	// Session ties a run of requests to one address. A login and the page
	// behind it have to arrive from the same place or the site sees two
	// visitors; empty lets every request take a fresh address, which is what
	// breadth-first crawling wants. Opaque, and never logged.
	Session string
}

// Kind is how an exit reaches the internet — the axis that decides who lets you
// in. A datacenter address is fast, cheap and refused by anything with a bot
// policy; a mobile one shares a carrier NAT with thousands of real phones and is
// refused by almost nothing, at several times the price.
type Kind uint8

const (
	Any Kind = iota
	Datacenter
	Residential
	Mobile
)

// Exit reaches addr through somewhere that satisfies n.
//
// This is the whole interface, and everything else in the package is a function
// that returns one. A vendor, our own egress, a test double, and the composition
// of a dozen of them are all this same type — so there is nothing to implement,
// nothing to register, and no struct whose fields decide what a caller may
// compose. What used to be a Pool's fields are now separate functions that each
// answer one question.
type Exit func(ctx context.Context, n Need, addr string) (net.Conn, error)

// Rule transforms an Exit. Fencing and capability are each one of these, so a
// deployment states what it wants by composing rather than by filling in a
// struct somebody else designed.
type Rule func(Exit) Exit

// Chain composes, left to right: Chain(f, g)(x) is g(f(x)).
//
// Generic because composing endomorphisms is not a fact about proxies, and a
// second copy of it for the next function type would be the same five lines
// with one word changed.
func Chain[T any](fs ...func(T) T) func(T) T {
	return func(x T) T {
		for _, f := range fs {
			x = f(x)
		}
		return x
	}
}

// ErrNoExit means nothing can serve the need. It is distinct from a dial failure
// on purpose: one is a gap an operator fixes, the other is a bad minute that
// retrying fixes.
var ErrNoExit = errors.New("no exit serves that need")

// Only refuses needs an exit cannot serve, so capability is a rule rather than
// two more fields every exit has to carry whether or not it constrains anything.
func Only(can func(Need) bool) Rule {
	return func(e Exit) Exit {
		return func(ctx context.Context, n Need, addr string) (net.Conn, error) {
			if !can(n) {
				return nil, fmt.Errorf("%w: %+v", ErrNoExit, n)
			}
			return e(ctx, n, addr)
		}
	}
}

// In is the predicate for a fixed set of countries and kinds; empty means any.
func In(countries []string, kinds []Kind) func(Need) bool {
	return func(n Need) bool {
		if n.Kind != Any && len(kinds) > 0 && !has(kinds, n.Kind) {
			return false
		}
		return n.Country == "" || len(countries) == 0 || has(countries, n.Country)
	}
}

func has[T comparable](xs []T, x T) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// Order decides which exits to try, and in what order, for one need.
type Order func(Need, []Exit) []Exit

// Try returns an Exit that walks the others in the order's order until one
// answers. Trying and ordering are separate because every ordering below shares
// the same walk, and the walk has the only part worth getting right: a caller
// that went away ends the attempt, and a gap in the table reads differently from
// a bad minute.
func Try(order Order, exits ...Exit) Exit {
	return func(ctx context.Context, n Need, addr string) (net.Conn, error) {
		try := order(n, exits)
		if len(try) == 0 {
			return nil, fmt.Errorf("%w: %+v", ErrNoExit, n)
		}
		var errs []error
		for _, e := range try {
			c, err := e(ctx, n, addr)
			if err == nil {
				return c, nil
			}
			errs = append(errs, err)
			if ctx.Err() != nil {
				break
			}
		}
		return nil, errors.Join(errs...)
	}
}

// Fixed keeps the order it was given.
func Fixed(_ Need, es []Exit) []Exit { return es }

// Pin sends a session to the same exit every time, by hash. What a sticky
// session asks for IS one address, so no other ordering may override it.
func Pin(seed maphash.Seed) Order {
	return func(n Need, es []Exit) []Exit {
		if n.Session == "" || len(es) < 2 {
			return es
		}
		i := int(maphash.String(seed, n.Session) % uint64(len(es)))
		out := append([]Exit(nil), es...)
		out[0], out[i] = out[i], out[0]
		return out
	}
}

// Health orders by consecutive failures, fewest first, and returns the Order
// together with the Rule that feeds it. They are returned as a pair because
// health is one fact observed in two places — counted where a dial fails, read
// where the next dial is ordered — and handing back only the Order would leave
// a caller to wire the counting by hand and silently get it wrong.
func Health() (Order, Rule) {
	var n atomic.Int64 // index handed to the next Watch call
	var fails []*atomic.Int64
	rank := map[int]*atomic.Int64{}

	watch := func(e Exit) Exit {
		i := int(n.Add(1) - 1)
		c := &atomic.Int64{}
		fails = append(fails, c)
		rank[i] = c
		return func(ctx context.Context, need Need, addr string) (net.Conn, error) {
			conn, err := e(ctx, need, addr)
			if err != nil {
				c.Add(1)
			} else {
				c.Store(0)
			}
			return conn, err
		}
	}
	order := func(_ Need, es []Exit) []Exit {
		if len(es) < 2 || len(fails) < len(es) {
			return es
		}
		idx := make([]int, len(es))
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool {
			return fails[idx[a]].Load() < fails[idx[b]].Load()
		})
		out := make([]Exit, len(es))
		for i, j := range idx {
			out[i] = es[j]
		}
		return out
	}
	return order, watch
}

// Then runs orders in sequence, so a pin can survive a health sort: the last
// order wins the first position, which is why Pin belongs last.
func Then(os ...Order) Order {
	return func(n Need, es []Exit) []Exit {
		for _, o := range os {
			es = o(n, es)
		}
		return es
	}
}

// negotiate bounds a handshake when the caller named no deadline of its own. A
// proxy that answers at all answers quickly; one that does not must still give
// the socket back.
const negotiate = 30 * time.Second

// Client returns an http.Client whose every request leaves through e satisfying
// n.
//
// This is how the rest of the platform holds a route: a WASM guest's fetch
// capability and an ordinary Go caller are the same client, so nothing has to
// learn a second way to make a request.
func Client(e Exit, n Need) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return e(ctx, n, addr)
		},
		// The tunnel is per-exit, and a pooled connection is an exit already
		// chosen. Reusing one across a rotating need would silently pin what the
		// caller asked to rotate.
		DisableKeepAlives: n.Session == "",
		ForceAttemptHTTP2: true,
	}}
}
