package unblock

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bogdanfinn/tls-client/profiles"
)

// Attempt is one fetch strategy: a TLS profile plus the protocol controls that
// matter when a WAF rejects a fingerprint.
type Attempt struct {
	Profile        string `json:"profile"`
	ForceHTTP1     bool   `json:"http1,omitempty"`
	ProtocolRacing bool   `json:"http3,omitempty"`
}

// AttemptResult records what one rung did.
type AttemptResult struct {
	Attempt
	HTTPStatus int    `json:"http_status,omitempty"`
	Proto      string `json:"proto,omitempty"`
	BlockKind  string `json:"block_kind,omitempty"`
	Error      string `json:"error,omitempty"`
	OK         bool   `json:"ok,omitempty"`
}

// Fetcher is the surface the ladder needs. *Client satisfies it.
type Fetcher interface {
	Get(ctx context.Context, url string) (*Response, error)
	Head(ctx context.Context, url string) (*Response, error)
}

// DefaultAttempts is the measured starting order.
//
// Basis: 17 profiles, one WAF-protected page, single GET each.
//   - HTTP/2 was rejected for every recent profile.
//   - Racing HTTP/3 answered 200 for chrome_133 and chrome_150 while HTTP/2 was
//     blocked for both, so the protocol is a stronger lever than the profile.
//   - HTTP/1.1 carried chrome_133, chrome_144, firefox_123, and brave_146.
//   - chrome_144 and chrome_150 share a JA3N hash yet behaved differently, so the
//     HTTP/2 settings fingerprint is part of what the WAF sees.
//
// Order: mainstream Chrome over h2, the same profile racing h3, the same profile
// over h1.1, then another engine for when Chrome-shaped traffic is blocked
// wholesale. Ties break on how common the browser version is in the wild, not on
// release date.
func DefaultAttempts() []Attempt {
	chrome := resolveProfile(preferredChrome, "chrome")
	firefox := resolveProfile(preferredFirefox, "firefox")
	return []Attempt{
		{Profile: chrome},
		{Profile: chrome, ProtocolRacing: true},
		{Profile: chrome, ForceHTTP1: true},
		{Profile: firefox, ForceHTTP1: true},
	}
}

// The measured picks. These are lookup keys, not copies of the profiles: if the
// package drops a version, resolveProfile degrades to the newest preset of the
// same family instead of falling back to an unrelated default.
const (
	preferredChrome  = "chrome_133"
	preferredFirefox = "firefox_123"
)

func resolveProfile(preferred, family string) string {
	if _, ok := profiles.MappedTLSClients[preferred]; ok {
		return preferred
	}
	best, bestMajor := "", -1
	for name, p := range profiles.MappedTLSClients {
		if !strings.HasPrefix(name, family+"_") ||
			strings.Contains(name, "_PSK") || strings.Contains(name, "_PQ") {
			continue
		}
		major, _ := splitVersion(p.GetClientHelloId().Version)
		n, err := strconv.Atoi(major)
		if err != nil {
			continue
		}
		if n > bestMajor {
			best, bestMajor = name, n
		}
	}
	if best != "" {
		return best
	}
	return preferred
}

// ErrBlocked is returned when every rung was blocked by a WAF.
var ErrBlocked = errors.New("unblock: every attempt was blocked")

// BlockedError carries the last block plus the full trail.
type BlockedError struct {
	Block    *Block
	Attempts []AttemptResult
}

func (e *BlockedError) Error() string {
	kind := "unknown"
	if e.Block != nil {
		kind = e.Block.Kind
	}
	return fmt.Sprintf("%s (%s after %d attempt(s))", ErrBlocked.Error(), kind, len(e.Attempts))
}

func (e *BlockedError) Unwrap() error { return ErrBlocked }

// CooldownError is returned when the host is still parked.
type CooldownError struct {
	Host      string
	Remaining time.Duration
}

func (e *CooldownError) Error() string {
	return fmt.Sprintf("unblock: host %s is cooling down for %s", e.Host, e.Remaining.Round(time.Second))
}

// Ladder walks attempts in order and stops at the first answer that is not a
// WAF block. A block means "try the next rung"; any answer from the origin — 200,
// 404, even 500 — means the site responded, so the ladder stops.
type Ladder struct {
	base     Options
	attempts []Attempt
	max      int
	cool     *Cooldown
	factory  func(Attempt) Fetcher

	mu      sync.Mutex
	clients map[string]Fetcher
	last    []AttemptResult
	winner  Fetcher
}

// NewLadder builds a Ladder on top of base options. Attempts that carry an
// empty Profile inherit nothing from base: a ladder rung is a complete strategy,
// so set Profile explicitly, or start from DefaultAttempts.
func NewLadder(base Options, attempts ...Attempt) *Ladder {
	if len(attempts) == 0 {
		attempts = DefaultAttempts()
	}
	return &Ladder{
		base:     base,
		attempts: attempts,
		max:      len(attempts),
		clients:  map[string]Fetcher{},
	}
}

// WithMaxAttempts caps how many rungs are tried.
func (l *Ladder) WithMaxAttempts(n int) *Ladder {
	if n > 0 {
		l.max = n
	}
	return l
}

// WithCooldown parks a host after a block, so repeated checks do not escalate it.
func (l *Ladder) WithCooldown(c *Cooldown) *Ladder {
	l.cool = c
	return l
}

// WithFetcherFactory overrides how a rung is served. Intended for tests.
func (l *Ladder) WithFetcherFactory(f func(Attempt) Fetcher) *Ladder {
	l.factory = f
	return l
}

// Get fetches a URL, walking the ladder.
func (l *Ladder) Get(ctx context.Context, url string) (*Response, error) {
	return l.do(ctx, http.MethodGet, url)
}

// Head sends a HEAD request, walking the ladder.
func (l *Ladder) Head(ctx context.Context, url string) (*Response, error) {
	return l.do(ctx, http.MethodHead, url)
}

// Winner returns the fetcher that produced the last successful response, so
// follow-up requests reuse the same fingerprint.
func (l *Ladder) Winner() Fetcher {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.winner
}

// Last returns the trail of the most recent walk.
func (l *Ladder) Last() []AttemptResult {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]AttemptResult, len(l.last))
	copy(out, l.last)
	return out
}

func (l *Ladder) do(ctx context.Context, method, url string) (*Response, error) {
	host := HostOf(url)
	if l.cool != nil && !l.cool.Allow(host) {
		return nil, &CooldownError{Host: host, Remaining: l.cool.Remaining(host)}
	}

	results := make([]AttemptResult, 0, len(l.attempts))
	var lastBlock *Block
	var lastErr error
	tried := 0

	for _, a := range l.attempts {
		if tried >= l.max {
			break
		}
		// QUIC cannot traverse an HTTP CONNECT tunnel. Racing with an egress
		// configured would connect directly and leak the caller's real IP, so a
		// racing rung is skipped entirely rather than silently downgraded.
		if a.ProtocolRacing && l.base.ProxyURL != "" {
			results = append(results, AttemptResult{
				Attempt: a,
				Error:   "skipped: HTTP/3 cannot travel through a CONNECT proxy",
			})
			continue
		}
		tried++

		f := l.fetcherFor(a)
		ar := AttemptResult{Attempt: a}
		if ar.Profile == "" {
			ar.Profile = "(default)"
		}

		var resp *Response
		var err error
		switch method {
		case http.MethodHead:
			resp, err = f.Head(ctx, url)
		default:
			resp, err = f.Get(ctx, url)
		}

		if err != nil {
			ar.Error = err.Error()
			results = append(results, ar)
			lastErr = err
			continue
		}

		ar.HTTPStatus = resp.StatusCode
		ar.Proto = resp.Proto
		if b := Classify(resp); b != nil {
			ar.BlockKind = b.Kind
			results = append(results, ar)
			lastBlock = b
			lastErr = nil
			continue
		}

		ar.OK = true
		results = append(results, ar)
		l.record(results, f)
		return resp, nil
	}

	l.record(results, nil)
	if l.cool != nil && lastBlock != nil {
		l.cool.Mark(host)
	}
	if lastBlock != nil {
		return nil, &BlockedError{Block: lastBlock, Attempts: results}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("unblock: no attempts configured")
}

func (l *Ladder) record(results []AttemptResult, winner Fetcher) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.last = results
	l.winner = winner
}

func (l *Ladder) fetcherFor(a Attempt) Fetcher {
	if l.factory != nil {
		return l.factory(a)
	}
	key := fmt.Sprintf("%s|%t|%t", a.Profile, a.ForceHTTP1, a.ProtocolRacing)
	l.mu.Lock()
	defer l.mu.Unlock()
	if f, ok := l.clients[key]; ok {
		return f
	}
	opts := l.base
	opts.Profile = a.Profile
	opts.ForceHTTP1 = a.ForceHTTP1
	opts.ProtocolRacing = a.ProtocolRacing
	f := New(opts)
	l.clients[key] = f
	return f
}

// String renders one attempt for logs: profile plus protocol.
func (a Attempt) String() string {
	switch {
	case a.ForceHTTP1:
		return a.Profile + " over HTTP/1.1"
	case a.ProtocolRacing:
		return a.Profile + " racing HTTP/3"
	default:
		return a.Profile + " over HTTP/2"
	}
}
