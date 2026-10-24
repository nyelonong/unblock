// Package unblock is an HTTP client for Go that looks like a browser at the
// network layer (Chrome-like TLS ClientHello and HTTP/2 fingerprint) and knows
// when it has been blocked.
//
// Three things are handled:
//
//  1. TLS/JA3 and HTTP/2 fingerprints — via bogdanfinn/tls-client, so WAF rules
//     based on fingerprints do not reject the request.
//  2. Automatic HTTP/1.1 fallback when a server rejects HTTP/2 (RST_STREAM),
//     reusing the same TLS fingerprint.
//  3. Block classification — Cloudflare challenges, errors 1009/1010/1015/1020,
//     and third-party WAFs are told apart from one another, because each needs a
//     different follow-up action.
//
// This package does NOT execute JavaScript. A Cloudflare challenge that requires
// JS cannot be bypassed here; Classify only reports that this is what happened.
package unblock

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// DefaultTimeout is the per-attempt deadline when Options.Timeout is zero.
const DefaultTimeout = 20 * time.Second

// DefaultMaxBody caps how many body bytes are read (5 MiB).
const DefaultMaxBody = 5 << 20

// ErrNoBody is returned when a response carries no usable payload.
var ErrNoBody = errors.New("unblock: empty body")

// Options configures a Client.
type Options struct {
	// Profile names a TLS preset, e.g. "chrome_133" or "firefox_135".
	// Empty means the package default Chrome profile (the newest supported one).
	// See profiles.MappedTLSClients for the full list.
	Profile string

	// ProxyURL is optional: "http://127.0.0.1:8080" or "socks5://10.0.0.2:1080".
	ProxyURL string

	// Timeout per attempt. Zero means DefaultTimeout.
	Timeout time.Duration

	// MaxBody caps the number of body bytes read. Zero means DefaultMaxBody.
	MaxBody int64

	// Headers are added to every request. Values here override whatever the TLS
	// profile sets (user-agent, accept, and so on).
	Headers map[string]string

	// ForceHTTP1 disables HTTP/2 negotiation entirely. Useful for servers that
	// tarpit or consistently reject h2.
	ForceHTTP1 bool

	// ProtocolRacing races HTTP/3 (QUIC) and HTTP/2 (TCP) and uses whichever
	// connects first, similar to Chrome's Happy Eyeballs. The client then reuses
	// the winning protocol per host.
	//
	// This is the strongest lever against anti-bot rules that target the HTTP/2
	// fingerprint: measured on a Cloudflare-protected page where every recent
	// profile was blocked over HTTP/2, HTTP/3 answered 200 with both
	// chrome_133 and chrome_150. Requires UDP egress; if QUIC is blocked the
	// client falls back to TCP.
	ProtocolRacing bool
}

// Response is a fully-read response, truncated at MaxBody.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	FinalURL   string
	// Proto is the negotiated protocol, e.g. "HTTP/2.0" or "HTTP/3.0".
	Proto string

	// Attempts is 1 for the first try, 2 when the HTTP/1.1 fallback was used.
	Attempts int
	// HTTP1 is true when the response came from the HTTP/1.1 fallback path.
	HTTP1 bool
}

// Get returns the value of a response header.
func (r *Response) Get(name string) string { return r.Header.Get(name) }

// Blocked returns block details, or nil when the response is not a block.
func (r *Response) Blocked() *Block { return Classify(r) }

// Client is a fetcher with a browser fingerprint.
type Client struct {
	opts   Options
	client tlsclient.HttpClient

	mu sync.Mutex
	h1 tlsclient.HttpClient
}

// New builds a Client. An unusable configuration does not make New fail: the
// client falls back to plain net/http so callers never have to handle an error
// on the construction path.
func New(opts Options) *Client {
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxBody == 0 {
		opts.MaxBody = DefaultMaxBody
	}
	c := &Client{opts: opts}
	if tc, err := build(opts, opts.ForceHTTP1); err == nil {
		c.client = tc
	} else {
		c.client = nil // plain net/http path
	}
	return c
}

func build(opts Options, forceH1 bool) (tlsclient.HttpClient, error) {
	o := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(int(opts.Timeout.Seconds()) + 1),
		tlsclient.WithClientProfile(profileByName(opts.Profile)),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
	}
	if forceH1 {
		o = append(o, tlsclient.WithForceHttp1(), tlsclient.WithDisableHttp3())
	} else if opts.ProtocolRacing {
		o = append(o, tlsclient.WithProtocolRacing())
	}
	if opts.ProxyURL != "" {
		o = append(o, tlsclient.WithProxyUrl(opts.ProxyURL))
	}
	return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), o...)
}

func profileByName(name string) profiles.ClientProfile {
	if name != "" {
		if p, ok := profiles.MappedTLSClients[name]; ok {
			return p
		}
	}
	return profiles.DefaultClientProfile
}

// Get fetches a URL. Redirects are followed.
func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	return c.Do(ctx, http.MethodGet, url)
}

// Head sends a HEAD request. Some servers reject HEAD; callers that need a body
// should fall back to Get themselves.
func (c *Client) Head(ctx context.Context, url string) (*Response, error) {
	return c.Do(ctx, http.MethodHead, url)
}

// Do performs the request and returns the full body.
//
// When the first attempt fails because of an HTTP/2 problem (RST_STREAM,
// INTERNAL_ERROR), the request is retried once over HTTP/1.1 with the same TLS
// fingerprint. Half of the time budget is reserved for that second attempt.
func (c *Client) Do(ctx context.Context, method, url string) (*Response, error) {
	if c.opts.ForceHTTP1 {
		return c.attempt(ctx, method, url, c.clientFor(true), 1)
	}

	// Reserve half the budget for the fallback, so a hanging first attempt does
	// not consume the entire deadline.
	primaryCtx := ctx
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 2*time.Second {
			var cancel context.CancelFunc
			primaryCtx, cancel = context.WithTimeout(ctx, remaining/2)
			defer cancel()
		}
	}

	resp, err := c.attempt(primaryCtx, method, url, c.clientFor(false), 1)
	if err == nil {
		return resp, nil
	}
	if !isHTTP2Error(err) {
		return nil, err
	}
	h1 := c.clientFor(true)
	if h1 == nil {
		return nil, err
	}
	return c.attempt(ctx, method, url, h1, 2)
}

func (c *Client) clientFor(forceH1 bool) tlsclient.HttpClient {
	if !forceH1 {
		return c.client
	}
	if c.opts.ForceHTTP1 && c.client != nil {
		return c.client
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.h1 == nil {
		tc, err := build(c.opts, true)
		if err != nil {
			return nil
		}
		c.h1 = tc
	}
	return c.h1
}

func (c *Client) attempt(ctx context.Context, method, url string, client tlsclient.HttpClient, attempt int) (*Response, error) {
	if client == nil {
		return c.stdAttempt(ctx, method, url, attempt)
	}

	req, err := fhttp.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range c.opts.Headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.opts.MaxBody))
	if err != nil {
		return nil, err
	}
	out := &Response{
		StatusCode: resp.StatusCode,
		Header:     http.Header(resp.Header),
		Body:       body,
		FinalURL:   url,
		Proto:      resp.Proto,
		Attempts:   attempt,
		HTTP1:      attempt == 2 || c.opts.ForceHTTP1,
	}
	if resp.Request != nil && resp.Request.URL != nil {
		out.FinalURL = resp.Request.URL.String()
	}
	return out, nil
}

// stdAttempt is the path without impersonation, used when the TLS client could
// not be built (for example an unsupported profile on a given platform).
func (c *Client) stdAttempt(ctx context.Context, method, url string, attempt int) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range c.opts.Headers {
		req.Header.Set(k, v)
	}
	hc := &http.Client{Timeout: c.opts.Timeout}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.opts.MaxBody))
	if err != nil {
		return nil, err
	}
	final := url
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       body,
		FinalURL:   final,
		Proto:      resp.Proto,
		Attempts:   attempt,
	}, nil
}

// isHTTP2Error detects failures typical of HTTP/2 negotiation.
func isHTTP2Error(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "internal_error") ||
		strings.Contains(s, "http/2") ||
		strings.Contains(s, "http2") ||
		strings.Contains(s, "stream id")
}
