package unblock_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/nyelonong/unblock"
)

// Contoh mengambil halaman dengan fingerprint browser.
func ExampleClient_Get() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>halo</html>"))
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

// Contoh membedakan jenis blokir.
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
	// firewall rule menolak ASN/datacenter: perlu proxy residensial
}

// Contoh memakai cooldown per host.
func ExampleCooldown() {
	cd := unblock.NewCooldown(time.Hour)
	host := unblock.HostOf("https://contoh.id/halaman")

	fmt.Println(cd.Allow(host))
	cd.Mark(host)
	fmt.Println(cd.Allow(host))

	// Output:
	// true
	// false
}
