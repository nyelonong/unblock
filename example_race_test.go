package unblock_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/nyelonong/unblock"
)

// Race HTTP/3 against HTTP/2 and read the protocol that actually answered.
//
// Many anti-bot rules are scoped to the HTTP/2 fingerprint. Racing QUIC in
// parallel with TCP often gets an answer where HTTP/2 alone is blocked, and the
// same TLS profile is reused either way.
//
// Response.Proto tells you which one won, so a "blocked" result is never
// ambiguous about the transport that produced it.
func ExampleClient_protocolRacing() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>hello</html>"))
	}))
	defer srv.Close()

	c := unblock.New(unblock.Options{
		Profile:        "chrome_133",
		Timeout:        5 * time.Second,
		ProtocolRacing: true,
	})

	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println(resp.StatusCode, resp.Proto)

	// Output: 200 HTTP/1.1
}

// Combine both levers: force HTTP/1.1 when QUIC is unavailable in the network
// and HTTP/2 is blocked. The TLS fingerprint is unchanged.
func ExampleClient_forceHTTP1() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := unblock.New(unblock.Options{Timeout: 5 * time.Second, ForceHTTP1: true})
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println(resp.StatusCode, resp.HTTP1)

	// Output: 200 true
}
