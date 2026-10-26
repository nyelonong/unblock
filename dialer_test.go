package unblock

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// refusingDialer refuses every address whose port is in blocked and records
// every address it was asked to connect to.
func refusingDialer(blocked ...string) (*net.Dialer, func() []string) {
	var mu sync.Mutex
	var seen []string
	d := &net.Dialer{
		Control: func(_, address string, _ syscall.RawConn) error {
			mu.Lock()
			seen = append(seen, address)
			mu.Unlock()
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			for _, b := range blocked {
				if port == b {
					return errors.New("refused by test dialer")
				}
			}
			return nil
		},
	}
	return d, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func countingServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func portOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestDialerRefusalStopsRequest(t *testing.T) {
	srv, hits := countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	for name, opts := range map[string]Options{
		"default": {},
		"http1":   {ForceHTTP1: true},
		"racing":  {ProtocolRacing: true},
	} {
		t.Run(name, func(t *testing.T) {
			d, seen := refusingDialer(portOf(t, srv))
			opts.Dialer = d
			opts.Timeout = 5 * time.Second

			if _, err := New(opts).Get(context.Background(), srv.URL); err == nil {
				t.Fatal("want an error when the dialer refuses the address")
			}
			if len(seen()) == 0 {
				t.Fatal("dialer was never consulted")
			}
		})
	}
	if got := atomic.LoadInt32(hits); got != 0 {
		t.Fatalf("server saw %d request(s), want 0", got)
	}
}

// Racing only applies to https, so this needs a TLS server to show that a
// Dialer really keeps the request off QUIC and on the guarded TLS path.
func TestDialerGuardsTLSWithRacing(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	t.Cleanup(srv.Close)

	d, seen := refusingDialer(portOf(t, srv))
	c := New(Options{Dialer: d, ProtocolRacing: true, InsecureSkipVerify: true, Timeout: 5 * time.Second})

	if _, err := c.Get(context.Background(), srv.URL); err == nil {
		t.Fatal("want an error when the dialer refuses the address")
	}
	if len(seen()) == 0 {
		t.Fatal("dialer was never consulted on the TLS path")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("server saw %d request(s), want 0", got)
	}
}

func TestDialerSeesRedirectTarget(t *testing.T) {
	target, targetHits := countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("private"))
	})
	start, startHits := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	})

	d, _ := refusingDialer(portOf(t, target))
	c := New(Options{Dialer: d, Timeout: 5 * time.Second})

	if _, err := c.Get(context.Background(), start.URL); err == nil {
		t.Fatal("want an error when the redirect target is refused")
	}
	if atomic.LoadInt32(startHits) != 1 {
		t.Errorf("start server hits = %d, want 1", atomic.LoadInt32(startHits))
	}
	if got := atomic.LoadInt32(targetHits); got != 0 {
		t.Fatalf("redirect target saw %d request(s), want 0", got)
	}
}

func TestDialerAllowsRequest(t *testing.T) {
	srv, _ := countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	d, seen := refusingDialer()

	resp, err := New(Options{Dialer: d, Timeout: 5 * time.Second}).Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(resp.Body) != "ok" {
		t.Fatalf("unexpected response: %d %q", resp.StatusCode, resp.Body)
	}
	if want := srv.Listener.Addr().String(); len(seen()) == 0 || seen()[0] != want {
		t.Errorf("dialer saw %v, want %s", seen(), want)
	}
}

func TestLadderSkipsRacingWithDialer(t *testing.T) {
	srv, _ := countingServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	d, _ := refusingDialer()

	l := NewLadder(Options{Dialer: d, Timeout: 5 * time.Second},
		Attempt{Profile: "chrome_133", ProtocolRacing: true},
		Attempt{Profile: "chrome_133", ForceHTTP1: true},
	)
	resp, err := l.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("ladder: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	trail := l.Last()
	if len(trail) != 2 || trail[0].Error == "" || trail[0].OK || !trail[1].OK {
		t.Fatalf("racing rung not recorded as skipped: %+v", trail)
	}
}

func TestLadderCloseIdleConnections(t *testing.T) {
	var closed int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			atomic.AddInt32(&closed, 1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)

	l := NewLadder(Options{Timeout: 5 * time.Second}, Attempt{Profile: "chrome_133"})
	if _, err := l.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("ladder: %v", err)
	}
	if got := atomic.LoadInt32(&closed); got != 0 {
		t.Fatalf("connection closed before CloseIdleConnections (%d)", got)
	}

	l.CloseIdleConnections()
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&closed) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("server never saw the idle connection close")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
