package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// dial opens a tunnel to addr through this gate.
func (g Gate) dial(ctx context.Context, t *template.Template, n Need, addr string) (net.Conn, error) {
	scheme, host, ok := strings.Cut(g.Addr, "://")
	if !ok {
		scheme, host = "http", g.Addr
	}
	user, err := g.name(t, n)
	if err != nil {
		return nil, fmt.Errorf("username: %w", err)
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}

	// Negotiation is bounded two ways, because one is not enough. A DEADLINE
	// stops a handshake that stalls, and the caller's is used when it named one.
	// CANCELLATION is the other, and a net.Conn does not watch a context: the
	// only thing that unblocks a blocked read is closing it, so that is what
	// cancellation is wired to.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(negotiate)
	}
	_ = c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.Close() })

	switch scheme {
	case "http", "https":
		err = connect(c, addr, user, g.Pass)
	case "socks5", "socks5h":
		err = socks(c, addr, user, g.Pass)
	default:
		err = fmt.Errorf("unknown scheme %q", scheme)
	}

	// Unwire before the conn is handed back. A false return means cancellation
	// already ran and this socket is closed or closing, so there is nothing to
	// return but the reason — reporting the handshake error instead would blame
	// the upstream for our own caller going away.
	if !stop() {
		c.Close()
		return nil, context.Cause(ctx)
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	// Past here the conn belongs to the caller and not to ctx, which is exactly
	// what net.Dialer.DialContext promises about the one it returns. The deadline
	// goes with it: it covered NEGOTIATION, and leaving it on would cap the
	// tunnel's whole life at the handshake timeout.
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// connect performs an HTTP CONNECT against an upstream.
func connect(c net.Conn, addr, user, pass string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if user != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n",
			base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(c, b.String()); err != nil {
		return err
	}
	// Read exactly the response head and no further: whatever follows the
	// blank line is the tunnel's first bytes and belongs to the caller.
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, &http.Request{Method: "CONNECT"})
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The upstream's body can carry the account's own credentials back in
		// an error page, so the status is all that travels.
		return fmt.Errorf("upstream refused: %s", resp.Status)
	}
	if n := r.Buffered(); n > 0 {
		return fmt.Errorf("upstream sent %d bytes before the tunnel", n)
	}
	return nil
}

// socks performs a SOCKS5 CONNECT with username/password auth (RFC 1928, 1929).
//
// Worth the forty lines: several providers offer SOCKS only, and it is the one
// way to carry a protocol that is not HTTP.
func socks(c net.Conn, addr, user, pass string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return fmt.Errorf("port %q: %w", port, err)
	}
	if len(host) > 255 {
		return errors.New("host too long for socks5")
	}
	// Greeting. Offer password auth only when there is one, so an open
	// upstream is not told we insist on credentials we do not have.
	greet := []byte{5, 1, 0}
	if user != "" {
		greet = []byte{5, 1, 2}
	}
	if _, err := c.Write(greet); err != nil {
		return err
	}
	r := bufio.NewReader(c)
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return err
	}
	if head[0] != 5 {
		return fmt.Errorf("socks version %d", head[0])
	}
	switch head[1] {
	case 0: // no auth wanted
	case 2:
		if len(user) > 255 || len(pass) > 255 {
			return errors.New("credential too long for socks5")
		}
		msg := []byte{1, byte(len(user))}
		msg = append(msg, user...)
		msg = append(msg, byte(len(pass)))
		msg = append(msg, pass...)
		if _, err := c.Write(msg); err != nil {
			return err
		}
		if _, err := io.ReadFull(r, head[:]); err != nil {
			return err
		}
		if head[1] != 0 {
			return errors.New("upstream rejected the credential")
		}
	default:
		return fmt.Errorf("upstream wants auth method %d", head[1])
	}
	// CONNECT, by NAME. Resolving here would leak the target to our own
	// resolver and, worse, pin the exit to an address chosen from where we
	// stand rather than from where the exit stands.
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(p>>8), byte(p))
	if _, err := c.Write(req); err != nil {
		return err
	}
	var rep [4]byte
	if _, err := io.ReadFull(r, rep[:]); err != nil {
		return err
	}
	if rep[1] != 0 {
		return fmt.Errorf("upstream refused: socks reply %d", rep[1])
	}
	// Drain the bound address so the tunnel starts where the caller expects.
	var skip int
	switch rep[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return err
		}
		skip = int(l[0])
	default:
		return fmt.Errorf("socks address type %d", rep[3])
	}
	if _, err := io.CopyN(io.Discard, r, int64(skip)+2); err != nil {
		return err
	}
	if n := r.Buffered(); n > 0 {
		return fmt.Errorf("upstream sent %d bytes before the tunnel", n)
	}
	return nil
}
