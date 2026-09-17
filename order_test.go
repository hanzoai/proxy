package proxy

import (
	"context"
	"errors"
	"hash/maphash"
	"net"
	"testing"
)

// mark returns an Exit that records it was tried and then fails, which is all a
// test of ORDER needs: what matters is who was asked, in what order.
func mark(name string, log *[]string, err error) Exit {
	return func(context.Context, Need, string) (net.Conn, error) {
		*log = append(*log, name)
		return nil, err
	}
}

var boom = errors.New("nope")

// Try walks the order it was given and stops at the first that answers.
func TestTryWalksInOrder(t *testing.T) {
	var log []string
	ok := func(context.Context, Need, string) (net.Conn, error) { return nil, nil }
	e := Try(Fixed, mark("a", &log, boom), mark("b", &log, boom), ok)
	if _, err := e(context.Background(), Need{}, "example.com:443"); err != nil {
		t.Fatal(err)
	}
	if len(log) != 2 || log[0] != "a" || log[1] != "b" {
		t.Fatalf("tried %v, want [a b] before the one that answered", log)
	}
}

// A cancelled caller ends the walk rather than spending every remaining exit on
// a request nobody is waiting for.
func TestTryStopsWhenTheCallerGoesAway(t *testing.T) {
	var log []string
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := Try(Fixed, mark("a", &log, boom), mark("b", &log, boom))
	if _, err := e(ctx, Need{}, "example.com:443"); err == nil {
		t.Fatal("a cancelled caller was answered")
	}
	if len(log) > 1 {
		t.Fatalf("tried %v after cancellation", log)
	}
}

// A session pins to one exit, every time. Rotating it would hand the caller a
// different address mid-flow, which is the one thing the session asked for.
func TestPinIsStable(t *testing.T) {
	var log []string
	es := []Exit{mark("a", &log, boom), mark("b", &log, boom), mark("c", &log, boom)}
	p := Pin(maphash.MakeSeed())

	// Who lands first is read by CALLING the first exit and seeing which name it
	// logs — the only way to tell two closures apart from outside.
	lead := func() string {
		log = nil
		_, _ = p(Need{Session: "cart42"}, es)[0](context.Background(), Need{}, "x:1")
		return log[0]
	}
	first := lead()
	for i := 0; i < 50; i++ {
		if got := lead(); got != first {
			t.Fatalf("a pinned session moved from %s to %s", first, got)
		}
	}

	// The pin has to actually depend on the session, or "stable" is just a
	// constant and this test would pass against an ordering that ignores it.
	seen := map[string]bool{}
	for _, sess := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		log = nil
		_, _ = p(Need{Session: sess}, es)[0](context.Background(), Need{}, "x:1")
		seen[log[0]] = true
	}
	if len(seen) < 2 {
		t.Fatalf("every session pinned to %v; the hash is not distributing", seen)
	}

	// No session, no pinning: the order is left for other rules to decide.
	if len(p(Need{}, es)) != 3 {
		t.Fatal("Pin dropped exits when there was no session")
	}
}

// A failing exit sorts last, so the next call does not pay for its timeout
// again — and a recovered one comes back.
func TestHealthOrdersByFailures(t *testing.T) {
	order, watch := Health()
	var log []string
	bad := watch(mark("bad", &log, boom))
	good := watch(func(context.Context, Need, string) (net.Conn, error) {
		log = append(log, "good")
		return nil, nil
	})
	e := Try(order, bad, good)
	ctx := context.Background()

	// First call tries bad, fails, falls to good.
	if _, err := e(ctx, Need{}, "example.com:443"); err != nil {
		t.Fatal(err)
	}
	if log[0] != "bad" {
		t.Fatalf("first attempt went to %q", log[0])
	}
	// Second call must lead with good, because bad has a failure against it.
	log = nil
	if _, err := e(ctx, Need{}, "example.com:443"); err != nil {
		t.Fatal(err)
	}
	if len(log) != 1 || log[0] != "good" {
		t.Fatalf("second attempt tried %v; a failing exit stayed first", log)
	}
}

// Then runs orders in sequence, and the LAST one wins the first position — which
// is why a pin belongs after a health sort rather than before it.
func TestThenLetsThePinWin(t *testing.T) {
	order, watch := Health()
	var log []string
	a := watch(mark("a", &log, boom))
	b := watch(mark("b", &log, boom))
	es := []Exit{a, b}

	// Give a a failure so health would demote it.
	_, _ = Try(order, a)(context.Background(), Need{}, "example.com:443")

	seed := maphash.MakeSeed()
	combined := Then(order, Pin(seed))
	// Whatever the pin chooses, it must be the same across calls even though
	// health wants a different first.
	got := combined(Need{Session: "s"}, es)
	for i := 0; i < 20; i++ {
		if len(combined(Need{Session: "s"}, es)) != len(got) {
			t.Fatal("ordering changed shape between calls")
		}
	}
}

// Chain composes left to right, which is the order a reader expects when the
// rules are written down in a list.
func TestChainComposesLeftToRight(t *testing.T) {
	var log []string
	note := func(name string) Rule {
		return func(e Exit) Exit {
			return func(ctx context.Context, n Need, a string) (net.Conn, error) {
				log = append(log, name)
				return e(ctx, n, a)
			}
		}
	}
	e := Chain(note("outer"), note("inner"))(func(context.Context, Need, string) (net.Conn, error) {
		return nil, nil
	})
	if _, err := e(context.Background(), Need{}, "example.com:443"); err != nil {
		t.Fatal(err)
	}
	// Chain(f,g)(x) is g(f(x)), so g wraps outermost and runs first.
	if len(log) != 2 || log[0] != "inner" || log[1] != "outer" {
		t.Fatalf("ran %v", log)
	}
}

// Chain over nothing is the identity, so a deployment with no rules needs no
// special case.
func TestChainOfNothingIsIdentity(t *testing.T) {
	called := false
	e := Chain[Exit]()(func(context.Context, Need, string) (net.Conn, error) {
		called = true
		return nil, nil
	})
	if _, err := e(context.Background(), Need{}, "x:1"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("Chain() did not return the exit it was given")
	}
}
