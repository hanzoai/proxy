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

// exit compiles one gate for a live upstream, failing the test rather than the
// dial if the template is wrong.
func exit(t *testing.T, g Gate) Exit {
	t.Helper()
	e, err := g.Exit()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// open is the composition these tests use: a real route with the fence lifted,
// because they dial an origin they started on loopback. TestFence covers the
// fence itself. Naming it here is the point — nothing implicitly turns it off.
func open(t *testing.T, gs ...Gate) Exit {
	t.Helper()
	es := make([]Exit, len(gs))
	for i, g := range gs {
		es[i] = exit(t, g)
	}
	return Chain(Fence(Anywhere))(Try(Fixed, es...))
}

// Both transports must carry a Need out to the vendor and return a tunnel that
// actually reaches the origin.
func TestDialBothSchemes(t *testing.T) {
	site := origin(t)
	for _, socks := range []bool{false, true} {
		name := "connect"
		if socks {
			name = "socks5"
		}
		t.Run(name, func(t *testing.T) {
			up := serveUp(t, socks)
			e := open(t, Gate{
				Name: "vendor", Addr: up.addr(), Pass: "secret",
				User: `acct{{with .Country}}-country-{{.}}{{end}}{{with .Session}}-sid-{{.}}{{end}}`,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := e(ctx, Need{Country: "de", Session: "cart42"}, site)
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
				t.Fatalf("vendor saw %q, want the need rendered into the username", got)
			}
		})
	}
}

// A field the caller left empty takes its whole segment with it: vendors read a
// bare "country-" as an error, not as a wildcard.
func TestEmptyFieldDropsItsSegment(t *testing.T) {
	site := origin(t)
	up := serveUp(t, false)
	e := open(t, Gate{Name: "vendor", Addr: up.addr(),
		User: `acct{{with .Country}}-country-{{.}}{{end}}{{with .Session}}-sid-{{.}}{{end}}`})
	c, err := e(context.Background(), Need{}, site)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if got := up.seen(); len(got) != 1 || got[0] != "acct" {
		t.Fatalf("vendor saw %q, want bare %q", got, "acct")
	}
}

// Capability is a rule, and a need nothing serves is a gap in the table —
// distinguishable from a bad minute so an operator knows which to fix.
func TestOnlyRefusesWhatItCannotServe(t *testing.T) {
	up := serveUp(t, false)
	dc := Only(In(nil, []Kind{Datacenter}))(exit(t, Gate{Name: "dc", Addr: up.addr()}))
	if _, err := dc(context.Background(), Need{Kind: Mobile}, "example.com:443"); !errors.Is(err, ErrNoExit) {
		t.Fatalf("got %v, want ErrNoExit", err)
	}
	if len(up.seen()) != 0 {
		t.Fatal("an unservable need still reached the vendor")
	}
	// And Try over nothing servable says the same thing.
	none := Try(Fixed)
	if _, err := none(context.Background(), Need{}, "example.com:443"); !errors.Is(err, ErrNoExit) {
		t.Fatalf("got %v, want ErrNoExit", err)
	}
}

func TestIn(t *testing.T) {
	can := In([]string{"de", "fr"}, []Kind{Residential, Mobile})
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
		if got := can(c.n); got != c.want {
			t.Errorf("In(%+v) = %v, want %v", c.n, got, c.want)
		}
	}
	if !In(nil, nil)(Need{Country: "jp", Kind: Mobile}) {
		t.Error("an unconstrained predicate refused a need")
	}
}

// One vendor being down must not fail a request another can serve: the caller
// asked for a property of the exit, not for a company.
func TestFailoverAcrossVendors(t *testing.T) {
	site := origin(t)
	good := serveUp(t, false)
	e := open(t,
		Gate{Name: "down", Addr: "http://127.0.0.1:1", User: "a"},
		Gate{Name: "up", Addr: good.addr(), User: "b"},
	)
	c, err := e(context.Background(), Need{}, site)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(good.seen()) != 1 {
		t.Fatal("the working vendor was never tried")
	}
}

// An upstream that refuses the credential is a failure, not a tunnel. Getting
// this wrong hands the caller a socket that reads EOF and looks like the site.
func TestRefusedCredentialIsAnError(t *testing.T) {
	for _, socks := range []bool{false, true} {
		up := serveUp(t, socks)
		up.deny = true
		e := open(t, Gate{Name: "v", Addr: up.addr(), User: "a", Pass: "wrong"})
		if _, err := e(context.Background(), Need{}, "example.com:443"); err == nil {
			t.Fatalf("socks=%v: a refused credential returned a usable tunnel", socks)
		}
	}
}

// A bad template fails at load. Deferring it to the first dial turns a config
// typo into an outage under traffic.
func TestBadGateFailsAtLoad(t *testing.T) {
	if _, err := (Gate{Name: "v", Addr: "http://x:1", User: "{{.Nope"}).Exit(); err == nil {
		t.Fatal("a malformed username template compiled clean")
	}
	if _, err := (Gate{Name: "v"}).Exit(); err == nil {
		t.Fatal("a gate with no address compiled clean")
	}
}
