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
		t.Errorf("header hilang: %v", resp.Header)
	}
	if resp.Blocked() != nil {
		t.Errorf("respons normal tidak boleh dianggap blokir")
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
		t.Errorf("body = %d byte, want 100", len(resp.Body))
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
		t.Errorf("header tidak terkirim, body = %q", resp.Body)
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
		t.Error("HTTP1 flag seharusnya true saat ForceHTTP1")
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
			name:     "challenge lewat header cf-mitigated",
			status:   403,
			header:   map[string]string{"server": "cloudflare", "cf-mitigated": "challenge", "cf-ray": "abc-JKT"},
			body:     "<html>checking your browser</html>",
			wantKind: "CF_CHALLENGE",
		},
		{
			name:     "challenge lewat penanda body",
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
			name:     "browser signature dibanned 1010",
			status:   403,
			header:   map[string]string{"server": "cloudflare"},
			body:     "<h2>Error 1010</h2>Access denied",
			wantKind: "CF_BLOCK_1010",
			wantCode: "1010",
		},
		{
			name:     "blokir tanpa kode",
			status:   403,
			header:   map[string]string{"server": "cloudflare", "cf-ray": "x"},
			body:     "<title>Attention Required! | Cloudflare</title>",
			wantKind: "CF_BLOCK_GENERIC",
		},
		{
			name:     "waf sucuri",
			status:   403,
			header:   map[string]string{"x-sucuri-id": "1234"},
			body:     "blocked",
			wantKind: "WAF_GENERIC",
		},
		{
			name:     "403 biasa dari origin",
			status:   403,
			header:   map[string]string{},
			body:     "<html>forbidden</html>",
			wantKind: "",
		},
		{
			name:     "404 bukan blokir",
			status:   404,
			header:   map[string]string{"server": "cloudflare"},
			body:     "not found",
			wantKind: "",
		},
		{
			name:     "403 dengan server cloudflare tapi bukan bot block",
			status:   403,
			header:   map[string]string{"server": "cloudflare"},
			body:     "<html>halaman ini hanya untuk member</html>",
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
				t.Error("hint tidak boleh kosong untuk blokir")
			}
		})
	}
}

func TestChallenge(t *testing.T) {
	if !(&Block{Kind: "CF_CHALLENGE"}).Challenge() {
		t.Error("CF_CHALLENGE seharusnya Challenge() = true")
	}
	if (&Block{Kind: "CF_BLOCK_1020"}).Challenge() {
		t.Error("CF_BLOCK_1020 bukan challenge yang bisa diselesaikan browser")
	}
	var b *Block
	if b.Challenge() {
		t.Error("nil Block tidak boleh panic dan harus false")
	}
}

func TestCooldown(t *testing.T) {
	cd := NewCooldown(50 * time.Millisecond)
	if !cd.Allow("contoh.id") {
		t.Fatal("host baru seharusnya boleh dicoba")
	}
	cd.Mark("contoh.id")
	if cd.Allow("contoh.id") {
		t.Error("host yang ditandai seharusnya ditolak")
	}
	if cd.Remaining("contoh.id") <= 0 {
		t.Error("Remaining seharusnya positif")
	}
	if !cd.Allow("lain.id") {
		t.Error("host lain tidak boleh terpengaruh")
	}
	cd.Reset("contoh.id")
	if !cd.Allow("contoh.id") {
		t.Error("setelah Reset, host boleh dicoba lagi")
	}

	cd2 := NewCooldown(10 * time.Millisecond)
	cd2.Mark("x.id")
	time.Sleep(20 * time.Millisecond)
	if !cd2.Allow("x.id") {
		t.Error("cooldown seharusnya kedaluwarsa")
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://a.b.c/path":      "a.b.c",
		"http://localhost:8080/x": "localhost",
		"bukan url":               "bukan url",
	}
	for in, want := range cases {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
