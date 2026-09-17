package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The fence is the difference between a scraping platform and a way into our
// own cluster, so it is tested as its own thing rather than inferred from a
// dial that happened to fail.
func TestFence(t *testing.T) {
	out := []string{
		"example.com:443",
		"8.8.8.8:53",
		"[2606:4700:4700::1111]:443",
		"sub.domain.co.uk:80",
	}
	in := []string{
		"127.0.0.1:8080",        // ourselves
		"[::1]:8080",            //
		"10.0.0.144:6443",       // the cluster's API
		"192.168.1.1:80",        //
		"172.16.0.1:80",         //
		"169.254.169.254:80",    // cloud metadata: hands out credentials
		"[fd00::1]:80",          // unique local
		"[fe80::1]:80",          // link local
		"0.0.0.0:80",            //
		"100.64.0.1:80",         // carrier NAT, where private fleets live
		"[::ffff:10.0.0.1]:443", // a private v4 wearing a v6 hat
		"kubernetes:443",        // resolves through search domains
		"api.svc:443",           //
		"gateway.cluster.local:80",
		"node.local:22",
		"1.0.0.127.in-addr.arpa:80",
	}
	for _, a := range out {
		if err := Public(a); err != nil {
			t.Errorf("Public(%q) refused the web: %v", a, err)
		}
	}
	for _, a := range in {
		err := Public(a)
		if !errors.Is(err, ErrClosed) {
			t.Errorf("Public(%q) = %v, want ErrClosed", a, err)
		}
		// The address must appear in the message, or an operator reading a log
		// cannot tell which target was refused.
		host, _, _ := net.SplitHostPort(a)
		// A v4 address wearing a v6 hat is reported unmapped, which is the
		// address that actually matters.
		if ip, e := netip.ParseAddr(host); e == nil {
			host = ip.Unmap().String()
		}
		if err != nil && !strings.Contains(err.Error(), host) {
			t.Errorf("Public(%q) error does not name the target: %v", a, err)
		}
	}
	for _, bad := range []string{"example.com", "", ":80"} {
		if !errors.Is(Public(bad), ErrClosed) {
			t.Errorf("Public(%q) accepted a malformed target", bad)
		}
	}
}

// A fenced target must be refused BEFORE any upstream is dialled — the point is
// that the request never leaves, not that it fails somewhere downstream.
func TestFenceRefusesBeforeDialling(t *testing.T) {
	up := serveUp(t, false)
	x, err := New(&Pool{Label: "v", Addr: up.addr()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.Dial(context.Background(), Need{}, "169.254.169.254:80"); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v, want ErrClosed", err)
	}
	if len(up.seen()) != 0 {
		t.Fatal("a fenced target reached an upstream")
	}
}

// The default is the fence. A Proxy nobody configured must not be open.
func TestDefaultIsFenced(t *testing.T) {
	x, err := New(&Pool{Label: "v", Addr: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if x.Reach != nil {
		t.Fatal("New set a Reach; nil must mean Public")
	}
	if _, err := x.Dial(context.Background(), Need{}, "10.0.0.144:6443"); !errors.Is(err, ErrClosed) {
		t.Fatalf("an unconfigured Proxy dialled the cluster: %v", err)
	}
}

// A conn does not watch a context, so cancellation during the handshake is
// wired to closing the socket. Without that a cancelled caller waits out the
// negotiation deadline instead of returning, which is the whole point of
// having passed a context at all.
func TestCancelDuringHandshake(t *testing.T) {
	// Accepts, then says nothing — a stalled upstream, which is what makes the
	// handshake block rather than fail.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	x, err := New(&Pool{Label: "stalled", Addr: "http://" + ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	x.Reach = Anywhere

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()

	start := time.Now()
	if _, err := x.Dial(ctx, Need{}, "example.com:443"); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	// Promptly, not after the 30s negotiation deadline.
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("cancellation took %v; the handshake was not watching the context", d)
	}
}

// And a deadline is still honoured when the caller names one.
func TestHandshakeDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	x, err := New(&Pool{Label: "stalled", Addr: "http://" + ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	x.Reach = Anywhere

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := x.Dial(ctx, Need{}, "example.com:443"); err == nil {
		t.Fatal("a stalled handshake returned a usable tunnel")
	}
}
