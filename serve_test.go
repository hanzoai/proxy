package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// front stands the listener up in front of a live upstream and returns a
// client configured to use it, which is the whole contract: point any HTTP
// client at a URL and it works.
func front(t *testing.T, check func(context.Context, string) error) (*http.Client, *upstream, *url.URL) {
	t.Helper()
	up := serveUp(t, false)
	s := &Server{
		Proxy: mustNew(t, &Pool{
			Label: "vendor", Addr: up.addr(), Pass: "secret",
			User: `acct{{with .Country}}-c-{{.}}{{end}}{{with .Session}}-s-{{.}}{{end}}`,
		}),
		Check: check,
	}
	front := httptest.NewServer(s)
	t.Cleanup(front.Close)
	u, err := url.Parse(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}, up, u
}

// The end-to-end shape: an unmodified http.Client, a proxy URL carrying the
// need in the username, a TLS origin on the far side. TLS matters here — it is
// what proves the tunnel is a tunnel and not something reading the payload.
func TestClientReachesOriginThroughTunnel(t *testing.T) {
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello")
	}))
	defer site.Close()

	c, up, u := front(t, nil)
	u.User = url.UserPassword("de.residential.s-cart42", "token")
	c.Transport.(*http.Transport).Proxy = http.ProxyURL(u)

	resp, err := c.Get(site.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Fatalf("got %q through the tunnel, want %q", body, "hello")
	}
	// And the need the caller wrote in the URL reached the provider.
	if got := up.seen(); len(got) != 1 || got[0] != "acct-c-de-s-cart42" {
		t.Fatalf("provider saw %q; the need did not survive the hop", got)
	}
}

// No credential must be answered with the challenge, not with a tunnel.
func TestAuthRequired(t *testing.T) {
	c, _, _ := front(t, func(context.Context, string) error { return nil })
	resp, err := c.Get("https://example.invalid/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("an unauthenticated CONNECT was tunnelled")
	}
	if !strings.Contains(err.Error(), "Proxy Authentication Required") {
		t.Fatalf("got %v, want the 407 challenge", err)
	}
}

// A rejected token and a malformed one must look identical from outside, so
// the surface cannot be used to sort real tokens from invented ones.
func TestDeniedTokenIsRefused(t *testing.T) {
	c, up, u := front(t, func(_ context.Context, tok string) error {
		if tok != "good" {
			return ErrDenied
		}
		return nil
	})
	u.User = url.UserPassword("", "bad")
	c.Transport.(*http.Transport).Proxy = http.ProxyURL(u)

	if resp, err := c.Get("https://example.invalid/"); err == nil {
		resp.Body.Close()
		t.Fatal("a denied token was tunnelled")
	}
	if len(up.seen()) != 0 {
		t.Fatal("a denied caller reached the provider")
	}
}

// Plain proxied GET is refused on purpose: serving it would put this in the
// middle of unencrypted requests carrying the caller's own credentials.
func TestPlainGetIsRefused(t *testing.T) {
	up := serveUp(t, false)
	s := &Server{Proxy: mustNew(t, &Pool{Label: "v", Addr: up.addr()})}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "http://example.com/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("plain GET got %d, want 405", w.Code)
	}
}

// A need nothing serves must not read as a transient upstream failure.
func TestUnservableNeedIsNotABadGateway(t *testing.T) {
	s := &Server{Proxy: mustNew(t, &Pool{Label: "dc", Addr: "http://127.0.0.1:1", Kinds: []Kind{Datacenter}})}
	// Authority-form, as net/http hands a real CONNECT to a handler.
	r := httptest.NewRequest("CONNECT", "/", nil)
	r.URL = &url.URL{Host: "example.com:443"}
	r.Header.Set("Proxy-Authorization", basic("mobile", "t"))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("got %d, want 501 for a need no pool serves", w.Code)
	}
}

func TestParse(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Need
	}{
		{"", Need{}},
		{"de", Need{Country: "de"}},
		{"DE", Need{Country: "de"}},
		{"mobile", Need{Kind: Mobile}},
		{"de.residential.s-cart42", Need{Country: "de", Kind: Residential, Session: "cart42"}},
		// Order is not significant: the fields name themselves.
		{"s-cart42.mobile.br", Need{Country: "br", Kind: Mobile, Session: "cart42"}},
		// A session may look like anything, including a country or a kind.
		{"s-de", Need{Session: "de"}},
		{"s-", Need{}},
	} {
		got, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Parse(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
	// An unknown field is refused rather than ignored: silently dropping it
	// would serve traffic from the wrong country and look like it worked.
	for _, bad := range []string{"zzz", "resident", "de.nope"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted an unknown field", bad)
		}
	}
}

func TestProxyAuth(t *testing.T) {
	u, p, ok := proxyAuth(basic("de.mobile", "tok"))
	if !ok || u != "de.mobile" || p != "tok" {
		t.Fatalf("got %q %q %v", u, p, ok)
	}
	for _, bad := range []string{"", "Bearer x", "Basic !!!"} {
		if _, _, ok := proxyAuth(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestErrDenied(t *testing.T) {
	if !errors.Is(ErrDenied, ErrDenied) {
		t.Fatal("ErrDenied is not itself")
	}
}

func basic(u, p string) string {
	r := http.Request{Header: http.Header{}}
	r.SetBasicAuth(u, p)
	return r.Header.Get("Authorization")
}
