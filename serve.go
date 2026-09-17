package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// Server answers HTTP CONNECT, which is the one interface every client already
// speaks — curl, Chrome, Go, Rust reqwest, Python requests, a headless browser
// in a container. Nothing has to be taught about us to use us.
//
// The caller states the need in the proxy USERNAME and authenticates with the
// password, so the whole configuration is a URL:
//
//	http://de.residential.s-cart42:<token>@proxy.hanzo.ai:8080
//
// Fields are self-describing and order does not matter: a two-letter code is a
// country, a kind names itself, and s-<id> pins a session.
type Server struct {
	Proxy *Proxy
	// Check authenticates a caller. It is a function rather than a dependency
	// so this package stays free of an identity provider; the cloud passes
	// IAM, and there is no second way to be allowed in.
	Check func(ctx context.Context, token string) error
	Log   *slog.Logger
}

// ErrDenied is returned by Check when the token is not good.
var ErrDenied = errors.New("denied")

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// ServeHTTP handles CONNECT and refuses everything else.
//
// Plain proxied GET is deliberately not served. It would put us in the middle
// of unencrypted requests carrying the caller's own cookies and credentials,
// to read or to log by accident. CONNECT keeps the payload end-to-end between
// the caller and the site, and leaves us with the one thing we need: the host.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "this proxy tunnels; use CONNECT", http.StatusMethodNotAllowed)
		return
	}
	user, token, ok := proxyAuth(r.Header.Get("Proxy-Authorization"))
	if !ok {
		w.Header().Set("Proxy-Authenticate", `Basic realm="hanzo"`)
		http.Error(w, "", http.StatusProxyAuthRequired)
		return
	}
	if s.Check != nil {
		if err := s.Check(r.Context(), token); err != nil {
			// One shape of answer whatever went wrong, so this cannot be used
			// to sort real tokens from made-up ones.
			w.Header().Set("Proxy-Authenticate", `Basic realm="hanzo"`)
			http.Error(w, "", http.StatusProxyAuthRequired)
			return
		}
	}
	need, err := Parse(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	addr := r.URL.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}

	up, err := s.Proxy.Dial(r.Context(), need, addr)
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, ErrNoExit) {
			code = http.StatusNotImplemented
		}
		// The error names which upstreams failed and is for us, not for the
		// caller, who is told only that no exit worked.
		s.log().Warn("no exit", "host", addr, "country", need.Country, "kind", need.Kind.String(), "err", err)
		http.Error(w, "no exit", code)
		return
	}
	defer up.Close()

	down, err := hijack(w)
	if err != nil {
		s.log().Error("hijack", "err", err)
		return
	}
	defer down.Close()
	if _, err := io.WriteString(down, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	pipe(down, up)
}

// hijack takes the raw connection out from under the HTTP server, with
// whatever the client had already sent, so the tunnel starts with no bytes
// stranded in a buffer.
func hijack(w http.ResponseWriter) (net.Conn, error) {
	h, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("connection cannot be hijacked")
	}
	c, buf, err := h.Hijack()
	if err != nil {
		return nil, err
	}
	if n := buf.Reader.Buffered(); n > 0 {
		return nil, fmt.Errorf("%d bytes buffered before the tunnel", n)
	}
	return c, nil
}

// pipe copies both directions and returns when either ends.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
	// Closing both is what unblocks the other copy; the deferred closes in
	// ServeHTTP then run against already-closed sockets, which is harmless.
	a.Close()
	b.Close()
	<-done
}

// Parse reads a Need from a proxy username.
//
// Fields are dot-separated and name themselves, so a caller writes only what
// it cares about and in any order: "de", "mobile.br", "s-cart42", "".
func Parse(s string) (Need, error) {
	var n Need
	for _, f := range strings.Split(s, ".") {
		switch {
		case f == "":
		case len(f) == 2 && isAlpha(f):
			n.Country = strings.ToLower(f)
		case strings.HasPrefix(f, "s-"):
			n.Session = f[2:]
		default:
			k, ok := kinds[strings.ToLower(f)]
			if !ok {
				return Need{}, fmt.Errorf("unknown field %q; want a country, a kind, or s-<id>", f)
			}
			n.Kind = k
		}
	}
	return n, nil
}

func isAlpha(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

// proxyAuth reads a Basic Proxy-Authorization header.
func proxyAuth(h string) (user, pass string, ok bool) {
	const p = "Basic "
	if len(h) < len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", "", false
	}
	// Reuse net/http's decoder rather than writing a second one.
	r := http.Request{Header: http.Header{"Authorization": []string{h}}}
	return r.BasicAuth()
}
