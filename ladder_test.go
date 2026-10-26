package unblock

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

const ladderURL = "https://client.test/"

type fakeFetcher struct {
	resp  *Response
	err   error
	calls *int
}

func (f *fakeFetcher) Get(_ context.Context, _ string) (*Response, error) {
	if f.calls != nil {
		*f.calls++
	}
	return f.resp, f.err
}

func (f *fakeFetcher) Head(ctx context.Context, url string) (*Response, error) {
	return f.Get(ctx, url)
}

func blockedResp() *Response {
	return &Response{
		StatusCode: 403,
		Header:     http.Header{"Server": []string{"cloudflare"}, "Cf-Ray": []string{"abc-FRA"}},
		Body:       []byte("<title>Attention Required! | Cloudflare</title>Sorry, you have been blocked"),
		FinalURL:   ladderURL,
		Proto:      "HTTP/2.0",
	}
}

func okResp(proto string) *Response {
	return &Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       []byte("<html>ok</html>"),
		FinalURL:   ladderURL,
		Proto:      proto,
	}
}

func TestLadderStopsAtFirstAnswer(t *testing.T) {
	l := NewLadder(Options{}).
		WithFetcherFactory(func(a Attempt) Fetcher {
			if a.ProtocolRacing {
				return &fakeFetcher{resp: okResp("HTTP/3.0")}
			}
			return &fakeFetcher{resp: blockedResp()}
		})

	resp, err := l.Get(context.Background(), ladderURL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if resp.Proto != "HTTP/3.0" {
		t.Errorf("proto = %q", resp.Proto)
	}
	trail := l.Last()
	if len(trail) != 2 {
		t.Fatalf("attempts = %d, want 2", len(trail))
	}
	if trail[0].BlockKind == "" || !trail[1].OK {
		t.Errorf("trail incomplete: %+v", trail)
	}
	if !trail[1].ProtocolRacing {
		t.Error("second rung should be the HTTP/3 one")
	}
	if l.Winner() == nil {
		t.Error("Winner should be set")
	}
}

func TestLadderAllBlocked(t *testing.T) {
	l := NewLadder(Options{}, DefaultAttempts()...).
		WithFetcherFactory(func(a Attempt) Fetcher {
			return &fakeFetcher{resp: blockedResp()}
		})

	_, err := l.Get(context.Background(), ladderURL)
	if err == nil {
		t.Fatal("want an error when every rung is blocked")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Errorf("err = %v, want ErrBlocked", err)
	}
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("err = %T, want *BlockedError", err)
	}
	if be.Block == nil || be.Block.Kind != "CF_BLOCK_GENERIC" {
		t.Errorf("block = %+v", be.Block)
	}
	if len(be.Attempts) != len(DefaultAttempts()) {
		t.Errorf("attempts = %d, want %d", len(be.Attempts), len(DefaultAttempts()))
	}
	if l.Winner() != nil {
		t.Error("Winner must be nil when nothing worked")
	}
}

// An origin answer — even a 404 — ends the walk: the site responded, so changing
// fingerprints cannot help.
func TestLadderStopsOnOriginStatus(t *testing.T) {
	var calls int
	l := NewLadder(Options{}).WithFetcherFactory(func(a Attempt) Fetcher {
		return &fakeFetcher{resp: &Response{StatusCode: 404, Header: http.Header{}, Body: []byte("nf"), FinalURL: ladderURL}, calls: &calls}
	})

	resp, err := l.Get(context.Background(), ladderURL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if len(l.Last()) != 1 {
		t.Errorf("attempts = %d, want 1", len(l.Last()))
	}
}

func TestLadderMaxAttempts(t *testing.T) {
	l := NewLadder(Options{}, DefaultAttempts()...).
		WithMaxAttempts(2).
		WithFetcherFactory(func(a Attempt) Fetcher { return &fakeFetcher{resp: blockedResp()} })

	_, err := l.Get(context.Background(), ladderURL)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v", err)
	}
	if len(l.Last()) != 2 {
		t.Errorf("attempts = %d, want 2", len(l.Last()))
	}
}

func TestLadderCooldown(t *testing.T) {
	cd := NewCooldown(50 * time.Millisecond)
	l := NewLadder(Options{}, DefaultAttempts()...).
		WithMaxAttempts(1).
		WithCooldown(cd).
		WithFetcherFactory(func(a Attempt) Fetcher { return &fakeFetcher{resp: blockedResp()} })

	_, err := l.Get(context.Background(), ladderURL)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("first call: %v", err)
	}
	if cd.Allow(HostOf(ladderURL)) {
		t.Error("host should be parked after a block")
	}

	_, err = l.Get(context.Background(), ladderURL)
	var ce *CooldownError
	if !errors.As(err, &ce) {
		t.Fatalf("second call err = %v, want *CooldownError", err)
	}
}

func TestDefaultAttemptsOrder(t *testing.T) {
	a := DefaultAttempts()
	if len(a) < 4 {
		t.Fatalf("want at least 4 rungs, got %d", len(a))
	}
	if a[0].Profile != "chrome_133" || a[0].ForceHTTP1 || a[0].ProtocolRacing {
		t.Errorf("rung 1 = %+v, want chrome_133 over h2", a[0])
	}
	if !a[1].ProtocolRacing {
		t.Errorf("rung 2 = %+v, want HTTP/3 racing", a[1])
	}
	if !a[2].ForceHTTP1 {
		t.Errorf("rung 3 = %+v, want HTTP/1.1", a[2])
	}
	if a[3].Profile == a[0].Profile {
		t.Errorf("rung 4 = %+v, want a different engine", a[3])
	}
}

func TestAttemptString(t *testing.T) {
	cases := map[string]Attempt{
		"chrome_133 over HTTP/2":    {Profile: "chrome_133"},
		"chrome_133 racing HTTP/3":  {Profile: "chrome_133", ProtocolRacing: true},
		"firefox_123 over HTTP/1.1": {Profile: "firefox_123", ForceHTTP1: true},
	}
	for want, a := range cases {
		if got := a.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}

type fakePoster struct {
	fakeFetcher
	bodies *[]string
}

func (f *fakePoster) Post(ctx context.Context, url, contentType string, body []byte) (*Response, error) {
	*f.bodies = append(*f.bodies, contentType+" "+string(body))
	return f.Get(ctx, url)
}

func TestLadderPostResendsBodyOnNextRung(t *testing.T) {
	var bodies []string
	l := NewLadder(Options{}).
		WithFetcherFactory(func(a Attempt) Fetcher {
			if a.ProtocolRacing {
				return &fakePoster{fakeFetcher: fakeFetcher{resp: okResp("HTTP/3.0")}, bodies: &bodies}
			}
			return &fakePoster{fakeFetcher: fakeFetcher{resp: blockedResp()}, bodies: &bodies}
		})

	resp, err := l.Post(context.Background(), ladderURL, "application/json", []byte(`{"q":1}`))
	if err != nil || resp.Proto != "HTTP/3.0" {
		t.Fatalf("Post = %+v, %v", resp, err)
	}
	if len(bodies) != 2 || bodies[0] != `application/json {"q":1}` || bodies[1] != bodies[0] {
		t.Fatalf("bodies sent = %q, want the same body on both rungs", bodies)
	}
	if trail := l.Last(); len(trail) != 2 || trail[0].BlockKind == "" || !trail[1].OK {
		t.Fatalf("trail = %+v", trail)
	}
}

func TestLadderPostStopsAtOriginAnswer(t *testing.T) {
	var bodies []string
	l := NewLadder(Options{}).
		WithFetcherFactory(func(Attempt) Fetcher {
			return &fakePoster{fakeFetcher: fakeFetcher{resp: &Response{StatusCode: 500, Header: http.Header{}}}, bodies: &bodies}
		})

	resp, err := l.Post(context.Background(), ladderURL, "application/json", nil)
	if err != nil || resp.StatusCode != 500 || len(bodies) != 1 {
		t.Fatalf("Post = %+v, %v after %d requests", resp, err, len(bodies))
	}
}

func TestLadderPostBlockParksHostForGet(t *testing.T) {
	var bodies []string
	l := NewLadder(Options{}).
		WithCooldown(NewCooldown(time.Hour)).
		WithFetcherFactory(func(Attempt) Fetcher {
			return &fakePoster{fakeFetcher: fakeFetcher{resp: blockedResp()}, bodies: &bodies}
		})

	_, err := l.Post(context.Background(), ladderURL, "application/json", nil)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("Post err = %v, want ErrBlocked", err)
	}
	var cool *CooldownError
	if _, err := l.Get(context.Background(), ladderURL); !errors.As(err, &cool) {
		t.Fatalf("Get after blocked Post err = %v, want CooldownError", err)
	}
}

func TestLadderPostNeedsPoster(t *testing.T) {
	calls := 0
	l := NewLadder(Options{}).
		WithFetcherFactory(func(Attempt) Fetcher {
			return &fakeFetcher{resp: okResp("HTTP/2.0"), calls: &calls}
		})

	_, err := l.Post(context.Background(), ladderURL, "application/json", nil)
	if err == nil || calls != 0 {
		t.Fatalf("Post err = %v after %d requests, want an error and no request", err, calls)
	}
}

func TestLadderPostKeepsTrailWhenARungCannotPost(t *testing.T) {
	var bodies []string
	l := NewLadder(Options{}).
		WithCooldown(NewCooldown(time.Hour)).
		WithFetcherFactory(func(a Attempt) Fetcher {
			if a.ProtocolRacing {
				return &fakeFetcher{resp: okResp("HTTP/3.0")}
			}
			return &fakePoster{fakeFetcher: fakeFetcher{resp: blockedResp()}, bodies: &bodies}
		})

	if _, err := l.Post(context.Background(), ladderURL, "application/json", nil); err == nil {
		t.Fatal("Post through a rung without Poster succeeded")
	}
	if trail := l.Last(); len(trail) != 1 || trail[0].BlockKind == "" || l.Winner() != nil {
		t.Fatalf("trail = %+v, winner = %v", trail, l.Winner())
	}
	var cool *CooldownError
	if _, err := l.Get(context.Background(), ladderURL); !errors.As(err, &cool) {
		t.Fatalf("Get after the blocked rung err = %v, want CooldownError", err)
	}
}
