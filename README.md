# proxy

Gives an agent the web without giving it the network.

The usual way to let a scraper reach the internet from a residential address in
Germany is to hand it a provider's credentials. That is the thing to avoid:
credentials inside a sandbox are credentials you have published, and a workload
that can open a socket can open any socket.

So the sandbox gets no network. This is the network. A caller says what it
needs of an exit and gets a connection. It never learns which provider served
it, never holds a provider password, and cannot address anything but the host
it asked for.

```go
c, err := p.Dial(ctx, proxy.Need{Country: "de", Kind: proxy.Residential}, "example.com:443")
```

## The ask

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

## Providers are a table, not a driver

NodeMaven, ProxyEmpire, Bright Data, Oxylabs, Smartproxy and IPRoyal all
present the same shape: one gateway address, and the routing rides in the
*username*. They differ only in the words they spell it with. So a provider is
a row:

```go
proxy.New(
	&proxy.Pool{
		Label: "vendor-a",
		Addr:  "http://gate.vendor-a.example:8000",
		User:  `acct-4471{{with .Country}}-country-{{.}}{{end}}{{with .Session}}-sid-{{.}}{{end}}`,
		Pass:  kms.Must("proxy/vendor-a"),
		Kinds: []proxy.Kind{proxy.Residential, proxy.Mobile},
	},
	&proxy.Pool{
		Label:     "vendor-b",
		Addr:      "socks5://gate.vendor-b.example:1080",
		User:      `user-9930{{with .Country}}-{{.}}{{end}}`,
		Pass:      kms.Must("proxy/vendor-b"),
		Countries: []string{"de", "fr", "nl"},
	},
)
```

The username is a `text/template` over the need, which is what lets one driver
speak every dialect — including the conditional parts. A field the caller left
empty takes its whole segment with it, because a provider reads a bare
`country-` as an error rather than a wildcard. Take the exact field names from
the provider's own docs; the mechanism does not care what they are.

Both upstream transports are here: HTTP `CONNECT` and SOCKS5 with
username/password auth. Several vendors offer SOCKS only, and it is the one way
to carry something that is not HTTP.

Passwords come from KMS at load. They are never logged, never returned in an
error, and never visible to a caller.

## Point anything at it

`CONNECT` is the one interface every client already speaks, so nothing has to
be taught about us. The need rides in the proxy username and the token in the
password, which makes the whole configuration a URL:

```
http://de.residential.s-cart42:<token>@proxy.hanzo.ai:8080
```

Fields name themselves and order does not matter — `de`, `mobile.br`,
`s-cart42`. An unknown field is refused rather than ignored, because silently
dropping one serves traffic from the wrong country and looks like it worked.

```bash
curl -x 'http://de.residential:$TOKEN@proxy.hanzo.ai:8080' https://example.com
```

Plain proxied `GET` is deliberately not served. It would put this in the middle
of unencrypted requests carrying the caller's own cookies, to read or to log by
accident. `CONNECT` keeps the payload end to end and leaves us the one thing we
need: the host.

Authentication is a function, so this package carries no identity provider:

```go
&proxy.Server{Proxy: p, Check: iam.Verify}
```

## Choosing

Every upstream that could serve the need is tried before giving up — the caller
asked for a property of the exit, not for a company. A vendor that just failed
sorts last rather than being removed, because the alternative to a degraded
exit is usually no exit.

A sticky session pins to one vendor by hash, and health does not override it.
Rotating a pinned session would hand the caller a different address mid-flow,
which is the one thing the session was asked for.

`ErrNoExit` is distinct from a dial failure on purpose. One is a gap in the
table that an operator fixes; the other is a bad minute that retrying fixes.

## Both hosts

The same capability fits both ways we run untrusted code. A WASM guest reaches
it through a host function. A Visor container reaches it through the `CONNECT`
listener, with no other route off the box.

```
go test -race ./...
```
