package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// upstream is a real proxy on a real socket, so the transports below are
// exercised over TCP rather than against a hand-written transcript. It records
// the username each caller presented, which is how a test sees that a Need was
// carried all the way out to the provider.
type upstream struct {
	t     *testing.T
	ln    net.Listener
	socks bool
	deny  bool

	mu   sync.Mutex
	saw  []string
	hits int
}

func serveUp(t *testing.T, socks bool) *upstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &upstream{t: t, ln: ln, socks: socks}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go u.one(c)
		}
	}()
	return u
}

func (u *upstream) addr() string {
	if u.socks {
		return "socks5://" + u.ln.Addr().String()
	}
	return "http://" + u.ln.Addr().String()
}

func (u *upstream) seen() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.saw...)
}

func (u *upstream) one(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	var target, user string
	var err error
	if u.socks {
		target, user, err = u.socksIn(c, r)
	} else {
		target, user, err = u.connectIn(c, r)
	}
	if err != nil {
		return
	}
	u.mu.Lock()
	u.saw = append(u.saw, user)
	u.hits++
	u.mu.Unlock()

	// Dial the real target and splice, so a test can drive an origin server
	// end to end through both hops.
	out, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer out.Close()
	go io.Copy(out, r)
	io.Copy(c, out)
}

func (u *upstream) connectIn(c net.Conn, r *bufio.Reader) (target, user string, err error) {
	req, err := http.ReadRequest(r)
	if err != nil {
		return "", "", err
	}
	if req.Method != "CONNECT" {
		io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return "", "", errors.New("not connect")
	}
	if h := req.Header.Get("Proxy-Authorization"); strings.HasPrefix(h, "Basic ") {
		raw, _ := base64.StdEncoding.DecodeString(h[6:])
		user, _, _ = strings.Cut(string(raw), ":")
	}
	if u.deny {
		io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
		return "", "", errors.New("denied")
	}
	if _, err := io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n"); err != nil {
		return "", "", err
	}
	return req.URL.Host, user, nil
}

func (u *upstream) socksIn(c net.Conn, r *bufio.Reader) (target, user string, err error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return "", "", err
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(r, methods); err != nil {
		return "", "", err
	}
	if _, err := c.Write([]byte{5, 2}); err != nil { // demand password auth
		return "", "", err
	}
	var v [1]byte
	if _, err := io.ReadFull(r, v[:]); err != nil {
		return "", "", err
	}
	read := func() (string, error) {
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		b := make([]byte, n[0])
		_, err := io.ReadFull(r, b)
		return string(b), err
	}
	if user, err = read(); err != nil {
		return "", "", err
	}
	if _, err = read(); err != nil {
		return "", "", err
	}
	if u.deny {
		c.Write([]byte{1, 1})
		return "", "", errors.New("denied")
	}
	if _, err := c.Write([]byte{1, 0}); err != nil {
		return "", "", err
	}
	var req [4]byte
	if _, err := io.ReadFull(r, req[:]); err != nil {
		return "", "", err
	}
	host, err := read()
	if err != nil {
		return "", "", err
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", "", err
	}
	// Reply with a bound address the client has to skip correctly.
	if _, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return "", "", err
	}
	return net.JoinHostPort(host, itoa(int(port[0])<<8|int(port[1]))), user, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// origin is the site being fetched. It answers one line so a test can tell a
// real end-to-end tunnel from a handshake that merely returned 200.
func origin(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				bufio.NewReader(c).ReadString('\n')
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
			}()
		}
	}()
	return ln.Addr().String()
}

func mustNew(t *testing.T, pools ...*Pool) *Proxy {
	t.Helper()
	x, err := New(pools...)
	if err != nil {
		t.Fatal(err)
	}
	// These tests dial an origin they started on loopback, which the default
	// fence refuses and is right to. TestFence covers the fence itself.
	x.Reach = Anywhere
	return x
}

// Both transports must carry a Need out to the provider and return a tunnel
// that actually reaches the origin.
func TestDialBothSchemes(t *testing.T) {
	site := origin(t)
	for _, socks := range []bool{false, true} {
		name := "connect"
		if socks {
			name = "socks5"
		}
		t.Run(name, func(t *testing.T) {
			up := serveUp(t, socks)
			x := mustNew(t, &Pool{
				Label: "vendor",
				Addr:  up.addr(),
				User:  `acct{{with .Country}}-country-{{.}}{{end}}{{with .Session}}-sid-{{.}}{{end}}`,
				Pass:  "secret",
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := x.Dial(ctx, Need{Country: "de", Session: "cart42"}, site)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()

			io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
			body, err := io.ReadAll(io.LimitReader(c, 64))
			if err != nil && err != io.EOF {
				t.Fatal(err)
			}
			if !strings.HasSuffix(string(body), "hello") {
				t.Fatalf("tunnel did not reach the origin: %q", body)
			}
			if got := up.seen(); len(got) != 1 || got[0] != "acct-country-de-sid-cart42" {
				t.Fatalf("provider saw %q, want the need rendered into the username", got)
			}
		})
	}
}

// A field the caller left empty must take its whole segment with it: providers
// read a bare "country-" as an error, not as a wildcard.
func TestEmptyFieldDropsItsSegment(t *testing.T) {
	site := origin(t)
	up := serveUp(t, false)
	x := mustNew(t, &Pool{
		Label: "vendor", Addr: up.addr(),
		User: `acct{{with .Country}}-country-{{.}}{{end}}{{with .Session}}-sid-{{.}}{{end}}`,
	})
	c, err := x.Dial(context.Background(), Need{}, site)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := up.seen(); len(got) != 1 || got[0] != "acct" {
		t.Fatalf("provider saw %q, want bare %q", got, "acct")
	}
}

// A need nothing serves is a gap in the table, and must be distinguishable
// from a bad minute so an operator knows to fix config rather than retry.
func TestNoExitIsItsOwnError(t *testing.T) {
	x := mustNew(t, &Pool{Label: "dc-only", Addr: "http://127.0.0.1:1", Kinds: []Kind{Datacenter}})
	_, err := x.Dial(context.Background(), Need{Kind: Mobile}, "example.com:443")
	if !errors.Is(err, ErrNoExit) {
		t.Fatalf("got %v, want ErrNoExit", err)
	}
}

// One vendor being down must not fail a request another vendor can serve: the
// caller asked for a property of the exit, not for a company.
func TestFailoverAcrossVendors(t *testing.T) {
	site := origin(t)
	good := serveUp(t, false)
	x := mustNew(t,
		&Pool{Label: "down", Addr: "http://127.0.0.1:1", User: "a"},
		&Pool{Label: "up", Addr: good.addr(), User: "b"},
	)
	c, err := x.Dial(context.Background(), Need{}, site)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(good.seen()) != 1 {
		t.Fatal("the working vendor was never tried")
	}
	// And the dead one must now sort last, so the next call does not pay for
	// its timeout again.
	if x.order(Need{})[0].Label != "up" {
		t.Fatal("a failing vendor stayed first in line")
	}
}

// An upstream that refuses the credential is a failure, not a tunnel. Getting
// this wrong hands the caller a socket that reads EOF and looks like the site.
func TestRefusedCredentialIsAnError(t *testing.T) {
	for _, socks := range []bool{false, true} {
		up := serveUp(t, socks)
		up.deny = true
		x := mustNew(t, &Pool{Label: "v", Addr: up.addr(), User: "a", Pass: "wrong"})
		if _, err := x.Dial(context.Background(), Need{}, "example.com:443"); err == nil {
			t.Fatalf("socks=%v: a refused credential returned a usable tunnel", socks)
		}
	}
}

// A sticky session must keep landing on the same vendor. Rotating it would
// hand the caller a different address mid-flow, which is the one thing the
// session was asked for.
func TestSessionPinsToOneVendor(t *testing.T) {
	x := mustNew(t,
		&Pool{Label: "a", Addr: "http://127.0.0.1:1"},
		&Pool{Label: "b", Addr: "http://127.0.0.1:2"},
		&Pool{Label: "c", Addr: "http://127.0.0.1:3"},
	)
	first := x.order(Need{Session: "cart42"})[0].Label
	for i := 0; i < 50; i++ {
		if got := x.order(Need{Session: "cart42"})[0].Label; got != first {
			t.Fatalf("session moved vendor: %s then %s", first, got)
		}
	}
	// Health must not override it either — that is what "sticky" means.
	for _, p := range x.pools {
		if p.Label == first {
			p.fails.Store(99)
		}
	}
	if got := x.order(Need{Session: "cart42"})[0].Label; got != first {
		t.Fatalf("a failure count moved a pinned session from %s to %s", first, got)
	}
}

// A bad template must fail at load. Deferring it to the first dial turns a
// config typo into an outage under traffic.
func TestBadTemplateFailsAtLoad(t *testing.T) {
	if _, err := New(&Pool{Label: "v", Addr: "http://x:1", User: "{{.Nope"}); err == nil {
		t.Fatal("a malformed username template loaded clean")
	}
	if _, err := New(&Pool{Label: "v"}); err == nil {
		t.Fatal("a pool with no address loaded clean")
	}
}

func TestServes(t *testing.T) {
	p := &Pool{Kinds: []Kind{Residential, Mobile}, Countries: []string{"de", "fr"}}
	for _, c := range []struct {
		n    Need
		want bool
	}{
		{Need{}, true},
		{Need{Country: "de", Kind: Mobile}, true},
		{Need{Country: "us"}, false},
		{Need{Kind: Datacenter}, false},
		{Need{Kind: Any, Country: "fr"}, true},
	} {
		if got := p.Serves(c.n); got != c.want {
			t.Errorf("Serves(%+v) = %v, want %v", c.n, got, c.want)
		}
	}
	// An unconstrained pool serves everything.
	if !(&Pool{}).Serves(Need{Country: "jp", Kind: Mobile}) {
		t.Error("an unconstrained pool refused a need")
	}
}
