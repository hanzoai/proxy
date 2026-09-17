# proxy

Gives an agent the web without giving it the network.

The usual way to let a scraper reach the internet from a residential address in
Germany is to hand it a provider's credentials. That is the thing to avoid:
credentials inside a sandbox are credentials you have published, and a workload
that can open a socket can open any socket.

So the sandbox gets no network. This is the network.

## One type

```go
type Exit func(ctx context.Context, n Need, addr string) (net.Conn, error)
```

A vendor, our own egress, a test double, and the composition of a dozen of them
are all this. There is nothing to implement and nothing to register.

A `Need` is what the caller requires of an exit:

```go
type Need struct {
	Country string // ISO 3166-1 alpha-2; empty means any
	Kind    Kind   // Datacenter, Residential, Mobile
	Session string // same string, same address
}
```

`Session` is the one that earns its place. A login and the page behind it have
to arrive from the same address or the site sees two visitors and shows neither
the content. Leave it empty and every request takes a fresh address, which is
what breadth-first crawling wants.

## Everything else is a function that returns one

```go
type Rule  func(Exit) Exit             // fencing, capability
type Order func(Need, []Exit) []Exit   // health, pinning
```

Capability, health, fencing and failover used to be fields on a struct and
branches inside one `Dial`. They are independent, so they are separate:

```go
order, watch := proxy.Health()

route := proxy.Fence(proxy.Public)(
	proxy.Try(proxy.Then(order, proxy.Pin(seed)),
		watch(vendorA),
		watch(proxy.Only(proxy.In([]string{"de", "fr"}, nil))(vendorB)),
	),
)
```

Read outward: every exit is health-counted, one of them only serves DE and FR,
the set is ordered by health and then pinned by session, and the whole route is
fenced. Adding a vendor is one more line; adding a policy is one more `Rule`,
and nothing it wraps has to know.

A `Rule` is an ordinary function, so one of them applies by calling it.
`Chain` is for two or more:

```go
proxy.Chain(proxy.Fence(proxy.Public), metrics, audit)(route)
```

`Then` runs orders in sequence and the last one wins first position, which is
why a pin belongs after a health sort rather than before it.

`Health` returns its `Order` and the `Rule` that feeds it together, because it
is one fact observed in two places. The exits given to `Try` must be the values
`watch` returned, in that order — the form above guarantees it, since Go
evaluates call arguments left to right. Split them across statements and
reorder them and ordering degrades to the order it was given rather than
ranking the wrong exits.

## Vendors are a table, not a driver

NodeMaven, ProxyEmpire, Bright Data, Oxylabs, Smartproxy and IPRoyal all present
one gateway address and carry the routing in the *username*, differing only in
the words they spell it with. So a vendor is data:

```go
proxy.Gate{
	Name: "vendor-a",
	Addr: "http://gate.vendor-a.example:8000",       // or socks5://
	User: `acct-4471{{with .Country}}-country-{{.}}{{end}}{{with .Session}}-sid-{{.}}{{end}}`,
	Pass: kms.Must("proxy/vendor-a"),
}.Exit()
```

The username is a `text/template` over the need, which is what lets one driver
speak every dialect including the conditional parts. A field the caller left
empty takes its whole segment with it, because a vendor reads a bare `country-`
as an error rather than a wildcard. `Exit()` compiles the template, so a typo
surfaces at load instead of under traffic.

Both upstream transports are here: HTTP `CONNECT` and SOCKS5 with
username/password auth. Several vendors are SOCKS-only, and it is the one way to
carry something that is not HTTP.

Passwords come from KMS at load. Never logged, never returned in an error, never
visible to a caller.

## The fence

```go
proxy.Fence(proxy.Public)
```

A guest names a URL, which is the job — but a URL can name `10.0.0.144:6443`, or
the metadata address that hands out credentials. `Public` refuses loopback,
private, link-local, carrier NAT, and names that only resolve through a
cluster's search domains.

It is a `Rule`, so one of them covers a whole route and an exit added later
cannot miss it. It checks what was ASKED for rather than what the name resolves
to: resolving here would leak every target to our own resolver and answer the
wrong question, since the exit resolves from where the exit stands.

`proxy.Anywhere` places no fence. Naming it is the point — there is no flag that
quietly does this.

## Point anything at it

`CONNECT` is the one interface every client already speaks, so nothing has to be
taught about us. The need rides in the proxy username and the token in the
password, which makes the whole configuration a URL:

```
http://de.residential.s-cart42:<token>@proxy.hanzo.ai:8080
```

Fields name themselves and order does not matter — `de`, `mobile.br`,
`s-cart42`. An unknown field is refused rather than ignored, because silently
dropping one serves traffic from the wrong country and looks like it worked.

```go
&proxy.Server{Exit: route, Check: iam.Verify}
```

Authentication is a function, so this package carries no identity provider.
Plain proxied `GET` is deliberately not served: it would put this in the middle
of unencrypted requests carrying the caller's own cookies. `CONNECT` keeps the
payload end to end and leaves us the one thing we need — the host.

## Both hosts

The same capability fits both ways we run untrusted code. A WASM guest reaches
it through a host function; a Visor container through the `CONNECT` listener,
with no other route off the box. `proxy.Client(route, need)` hands either one an
ordinary `*http.Client`.

```
go test -race ./...
```
