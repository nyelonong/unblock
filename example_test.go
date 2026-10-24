package unblock_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/nyelonong/unblock"
)

// Fetch a page with a browser fingerprint.
func ExampleClient_Get() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>hello</html>"))
	}))
	defer srv.Close()

	c := unblock.New(unblock.Options{Profile: "chrome_133", Timeout: 5 * time.Second})

	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(resp.StatusCode, len(resp.Body) > 0, resp.Blocked() == nil)

	// Output: 200 true true
}

// Tell block types apart.
func ExampleClassify() {
	h := http.Header{}
	h.Set("Server", "cloudflare")
	h.Set("Cf-Ray", "8a1b2c3d-JKT")

	resp := &unblock.Response{
		StatusCode: 403,
		Header:     h,
		Body:       []byte("<title>Attention Required!</title><h2>Error 1020</h2>"),
	}

	b := unblock.Classify(resp)
	fmt.Println(b.Kind, b.Code, b.Challenge())
	fmt.Println(b.Hint)

	// Output:
	// CF_BLOCK_1020 1020 false
	// firewall rule rejected the ASN/datacenter: needs a residential proxy
}

// Use a per-host cooldown.
func ExampleCooldown() {
	cd := unblock.NewCooldown(time.Hour)
	host := unblock.HostOf("https://example.com/page")

	fmt.Println(cd.Allow(host))
	cd.Mark(host)
	fmt.Println(cd.Allow(host))

	// Output:
	// true
	// false
}
