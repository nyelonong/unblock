package unblock

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGetRealServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("X-Test", "yes")
		_, _ = w.Write([]byte("<html>hello</html>"))
	}))
	defer srv.Close()

	c := New(Options{Timeout: 5 * time.Second})
	ctx := context.Background()

	resp, err := c.Get(ctx, srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 200 || string(resp.Body) != "<html>hello</html>" {
		t.Fatalf("unexpected response: %d %q", resp.StatusCode, resp.Body)
	}
	if resp.Get("x-test") != "yes" {
		t.Errorf("header missing: %v", resp.Header)
	}
	if resp.Blocked() != nil {
		t.Errorf("a normal response must not be classified as a block")
	}

	head, err := c.Head(ctx, srv.URL)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if head.StatusCode != 200 {
		t.Errorf("HEAD status = %d", head.StatusCode)
	}
}

func TestMaxBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 10_000)))
	}))
	defer srv.Close()

	c := New(Options{Timeout: 5 * time.Second, MaxBody: 100})
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(resp.Body) != 100 {
		t.Errorf("body = %d bytes, want 100", len(resp.Body))
	}
}

func TestHeadersOption(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("X-Custom")))
	}))
	defer srv.Close()

	c := New(Options{Timeout: 5 * time.Second, Headers: map[string]string{"x-custom": "abc"}})
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(resp.Body) != "abc" {
		t.Errorf("header was not sent, body = %q", resp.Body)
	}
}

func TestForceHTTP1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := New(Options{Timeout: 5 * time.Second, ForceHTTP1: true})
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !resp.HTTP1 {
		t.Error("HTTP1 flag should be true when ForceHTTP1 is set")
	}
}

func TestProtocolRacingOption(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// httptest serves plain TCP, so racing falls back to HTTP/1.1 or HTTP/2.
	// The assertion is that enabling the option does not break normal requests
	// and that the negotiated protocol is reported.
	c := New(Options{Timeout: 5 * time.Second, ProtocolRacing: true})
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if resp.Proto == "" {
		t.Error("Proto should be reported")
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		header   map[string]string
		body     string
		wantKind string
		wantCode string
	}{
		{
			name:     "challenge via cf-mitigated header",
			status:   403,
			header:   map[string]string{"server": "cloudflare", "cf-mitigated": "challenge", "cf-ray": "abc-JKT"},
			body:     "<html>checking your browser</html>",
			wantKind: "CF_CHALLENGE",
		},
		{
			name:     "challenge via body marker",
			status:   503,
			header:   map[string]string{"server": "cloudflare"},
			body:     `<script>window._cf_chl_opt={}</script>`,
			wantKind: "CF_CHALLENGE",
		},
		{
			name:     "firewall rule 1020",
			status:   403,
			header:   map[string]string{"server": "cloudflare", "cf-ray": "abc"},
			body:     "<title>Attention Required! | Cloudflare</title><h2>Error 1020</h2>",
			wantKind: "CF_BLOCK_1020",
			wantCode: "1020",
		},
		{
			name:     "browser signature banned 1010",
			status:   403,
			header:   map[string]string{"server": "cloudflare"},
			body:     "<h2>Error 1010</h2>Access denied",
			wantKind: "CF_BLOCK_1010",
			wantCode: "1010",
		},
		{
			name:     "block without an error code",
			status:   403,
			header:   map[string]string{"server": "cloudflare", "cf-ray": "x"},
			body:     "<title>Attention Required! | Cloudflare</title>",
			wantKind: "CF_BLOCK_GENERIC",
		},
		{
			name:     "sucuri waf",
			status:   403,
			header:   map[string]string{"x-sucuri-id": "1234"},
			body:     "blocked",
			wantKind: "WAF_GENERIC",
		},
		{
			name:     "plain 403 from the origin",
			status:   403,
			header:   map[string]string{},
			body:     "<html>forbidden</html>",
			wantKind: "",
		},
		{
			name:     "403 without a body (HEAD)",
			status:   403,
			header:   map[string]string{"server": "cloudflare", "cf-ray": "abc"},
			body:     "",
			wantKind: "CF_BLOCK_GENERIC",
		},
		{
			name:     "404 is not a block",
			status:   404,
			header:   map[string]string{"server": "cloudflare"},
			body:     "not found",
			wantKind: "",
		},
		{
			name:     "403 behind cloudflare but not a bot block",
			status:   403,
			header:   map[string]string{"server": "cloudflare"},
			body:     "<html>this page is for members only</html>",
			wantKind: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tc.header {
				h.Set(k, v)
			}
			r := &Response{StatusCode: tc.status, Header: h, Body: []byte(tc.body)}
			got := Classify(r)
			if tc.wantKind == "" {
				if got != nil {
					t.Fatalf("Classify = %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("Classify = nil, want %s", tc.wantKind)
			}
			if got.Kind != tc.wantKind {
				t.Errorf("kind = %s, want %s", got.Kind, tc.wantKind)
			}
			if got.Code != tc.wantCode {
				t.Errorf("code = %s, want %s", got.Code, tc.wantCode)
			}
			if got.Hint == "" {
				t.Error("a block must carry a hint")
			}
		})
	}
}

func TestChallenge(t *testing.T) {
	if !(&Block{Kind: "CF_CHALLENGE"}).Challenge() {
		t.Error("CF_CHALLENGE should report Challenge() = true")
	}
	if (&Block{Kind: "CF_BLOCK_1020"}).Challenge() {
		t.Error("CF_BLOCK_1020 is not a challenge a browser can resolve")
	}
	var b *Block
	if b.Challenge() {
		t.Error("a nil Block must not panic and must return false")
	}
}

func TestCooldown(t *testing.T) {
	cd := NewCooldown(50 * time.Millisecond)
	if !cd.Allow("example.id") {
		t.Fatal("a new host should be allowed")
	}
	cd.Mark("example.id")
	if cd.Allow("example.id") {
		t.Error("a marked host should be denied")
	}
	if cd.Remaining("example.id") <= 0 {
		t.Error("Remaining should be positive")
	}
	if !cd.Allow("other.id") {
		t.Error("other hosts must not be affected")
	}
	cd.Reset("example.id")
	if !cd.Allow("example.id") {
		t.Error("after Reset the host should be allowed again")
	}

	cd2 := NewCooldown(10 * time.Millisecond)
	cd2.Mark("x.id")
	time.Sleep(20 * time.Millisecond)
	if !cd2.Allow("x.id") {
		t.Error("the cooldown should have expired")
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://a.b.c/path":      "a.b.c",
		"http://localhost:8080/x": "localhost",
		"not a url":               "not a url",
	}
	for in, want := range cases {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
