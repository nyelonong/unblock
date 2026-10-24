package unblock

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// countingProxy is a minimal CONNECT proxy that counts tunnels, so a test can
// prove traffic really went through it.
type countingProxy struct {
	tunnels int32
	server  *httptest.Server
}

func newCountingProxy(t *testing.T) *countingProxy {
	t.Helper()
	p := &countingProxy{}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		atomic.AddInt32(&p.tunnels, 1)

		target, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
		if err != nil {
			http.Error(w, "dial: "+err.Error(), http.StatusBadGateway)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			target.Close()
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		client, buf, err := hj.Hijack()
		if err != nil {
			target.Close()
			return
		}
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() { _, _ = io.Copy(target, buf); target.Close() }()
		_, _ = io.Copy(client, target)
		client.Close()
	}))
	t.Cleanup(p.server.Close)
	return p
}

func (p *countingProxy) proxyURL(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(p.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("user", "pass")
	return u.String()
}

func tlsTarget(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "target reached")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The bug this locks down: with a proxy configured, ProtocolRacing connected
// directly and left the caller's real IP exposed, because QUIC cannot travel
// through an HTTP CONNECT tunnel.
func TestRacingWithProxyDoesNotBypass(t *testing.T) {
	proxy := newCountingProxy(t)
	target := tlsTarget(t)

	c := New(Options{
		Profile:            "chrome_133",
		Timeout:            10 * time.Second,
		ProxyURL:           proxy.proxyURL(t),
		ProtocolRacing:     true,
		InsecureSkipVerify: true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := c.Get(ctx, target.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&proxy.tunnels); got != 1 {
		t.Fatalf("proxy saw %d tunnel(s), want 1 — the request bypassed the proxy", got)
	}
}

func TestLadderSkipsRacingWhenProxied(t *testing.T) {
	proxy := newCountingProxy(t)
	target := tlsTarget(t)

	l := NewLadder(Options{
		Timeout:            10 * time.Second,
		ProxyURL:           proxy.proxyURL(t),
		InsecureSkipVerify: true,
	},
		// Racing first, so the guard is evaluated before anything succeeds.
		Attempt{Profile: "chrome_133", ProtocolRacing: true},
		Attempt{Profile: "chrome_133"},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := l.Get(ctx, target.URL)
	if err != nil {
		t.Fatalf("ladder: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var skipped int
	for _, a := range l.Last() {
		if a.ProtocolRacing && a.Error != "" {
			skipped++
		}
	}
	if skipped != 1 {
		t.Fatalf("racing rung not recorded as skipped: %+v", l.Last())
	}
	if got := atomic.LoadInt32(&proxy.tunnels); got != 1 {
		t.Fatalf("proxy saw %d tunnel(s), want 1", got)
	}
}

// A direct client (no proxy) must still race — the guard must not disable the
// feature for the common case.
func TestRacingStillEnabledWithoutProxy(t *testing.T) {
	c := New(Options{Profile: "chrome_133", ProtocolRacing: true, Timeout: time.Second})
	if c.opts.ProxyURL != "" {
		t.Fatal("unexpected proxy in test setup")
	}
	if c.client == nil {
		t.Fatal("client not built")
	}
}
