# unblock

A Go HTTP client that **looks like a browser** at the network layer, and **knows when it has been blocked**.

```go
c := unblock.New(unblock.Options{})
resp, err := c.Get(ctx, "https://example.com")
if b := resp.Blocked(); b != nil {
    fmt.Println(b.Kind, b.Hint) // CF_CHALLENGE / CF_BLOCK_1020 / WAF_GENERIC / ...
}
```

Three things are handled, and one deliberately is not.

## 1. TLS/JA3 and HTTP/2 fingerprints

`net/http`, `requests`, and `httpx` all share a recognisable fingerprint. On an HTTPS connection the client sends a TLS ClientHello carrying cipher suites, extension order, elliptic curves, and ALPN — WAFs hash that into JA3/JA4. On top of it sits the HTTP/2 fingerprint: `SETTINGS` values, `WINDOW_UPDATE`, pseudo-header order.

`unblock` uses [`bogdanfinn/tls-client`](https://github.com/bogdanfinn/tls-client) (ClientHello via uTLS, h2 via fhttp) so the fingerprint matches a real Chrome, Safari, or Firefox:

```go
c := unblock.New(unblock.Options{
    Profile: "chrome_133", // empty = newest supported Chrome profile
})
```

Conceptually the same as `curl_cffi` in Python, without a separate process.

## 2. Automatic HTTP/1.1 fallback

Some servers reject HTTP/2 negotiation with `RST_STREAM` (`stream ID 1; INTERNAL_ERROR`) even though TLS succeeded. `unblock` detects that error shape and retries **once** over HTTP/1.1 with the same TLS fingerprint.

The first attempt only gets half the time budget, so the retry is not starved by a hanging first try. `Response.Attempts` and `Response.HTTP1` report which path was used.

```go
resp, _ := c.Get(ctx, url)
fmt.Println(resp.Attempts) // 1, or 2 when the fallback was used
```

Force HTTP/1.1 always with `Options.ForceHTTP1`.

## 3. Block classification

Four different situations hide behind HTTP 403, and each needs a different action. `Classify` tells them apart from headers and body, with no extra requests:

| `Kind` | Marker | What to do |
|---|---|---|
| `CF_CHALLENGE` | `cf-mitigated: challenge`, `_cf_chl_opt`, `Just a moment` | needs a browser that executes JS |
| `CF_BLOCK_1010` | `Error 1010` | browser signature banned: use a TLS profile, not a spoofed UA |
| `CF_BLOCK_1009` | `Error 1009` | country block: needs a local proxy |
| `CF_BLOCK_1015` | `Error 1015` | rate limited: add a cooldown |
| `CF_BLOCK_1020` | `Error 1020` | firewall rule rejected the ASN/datacenter |
| `WAF_GENERIC` | `x-sucuri-id`, `x-datadome`, `x-akamai-request-id`, `x-iinfo` | third-party WAF |

```go
b := unblock.Classify(resp)
if b != nil {
    log.Printf("blocked: %s (ray %s) — %s", b.Kind, b.RayID, b.Hint)
}
if b.Challenge() {
    // the only category a browser can resolve
}
```

A plain 403 from the origin (a normal "forbidden" page, a login wall) is intentionally **not** treated as a block — that is not an anti-bot concern.

## Per-host cooldown

Cloudflare blocks are sticky: hammering the same host within a short window tends to escalate the block. `Cooldown` buys distance:

```go
cd := unblock.NewCooldown(6 * time.Hour)
host := unblock.HostOf(url)

if !cd.Allow(host) {
    return fmt.Errorf("host %s is cooling down for %s", host, cd.Remaining(host))
}
resp, err := c.Get(ctx, url)
if b := resp.Blocked(); b != nil {
    cd.Mark(host)
}
```

## What this does NOT do

**It does not execute JavaScript.** A managed Cloudflare challenge (Turnstile, the "Checking your browser" page that computes a token) still cannot be bypassed — fingerprints only win against rules that are purely TLS/h2 based.

The package tells you that this is what happened (`CF_CHALLENGE`) instead of pretending to solve it. For that you need a real browser: FlareSolverr, [`go-rod`](https://github.com/go-rod/rod), or the end user's own browser.

Also out of scope: IP reputation and behaviour. A datacenter IP is often blocked even with a perfect fingerprint — use `Options.ProxyURL` to leave that IP behind.

## Install

```bash
go get github.com/nyelonong/unblock
```

Requires Go 1.27+ (tracking `tls-client`).

## API

```go
func New(opts Options) *Client
func (c *Client) Get(ctx context.Context, url string) (*Response, error)
func (c *Client) Head(ctx context.Context, url string) (*Response, error)
func (c *Client) Do(ctx context.Context, method, url string) (*Response, error)

func Classify(r *Response) *Block
func HostOf(rawURL string) string
func NewCooldown(window time.Duration) *Cooldown
```

`Options`: `Profile`, `ProxyURL`, `Timeout`, `MaxBody`, `Headers`, `ForceHTTP1`.

`Response`: `StatusCode`, `Header`, `Body`, `FinalURL`, `Attempts`, `HTTP1`, plus `Get(header)` and `Blocked()`.

## Test

```bash
go test ./...
```

Covers a real httptest server, body limits, custom headers, `ForceHTTP1`, 9 block-classification variants, and cooldown behaviour.

## License

MIT — see [LICENSE](LICENSE).
