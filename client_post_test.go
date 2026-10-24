package unblock

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Some JSON endpoints behind a WAF (YouTube continuation, GraphQL) need a POST
// body with the same fingerprint as the page fetch.
func TestPostSendsBodyAndType(t *testing.T) {
	type echo struct {
		Method      string `json:"method"`
		ContentType string `json:"content_type"`
		Body        string `json:"body"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(echo{
			Method:      r.Method,
			ContentType: r.Header.Get("Content-Type"),
			Body:        string(b),
		})
	}))
	defer srv.Close()

	c := New(Options{Profile: "chrome_133", Timeout: 10 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := c.Post(ctx, srv.URL, "application/json", []byte(`{"x":1}`))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var got echo
	if err := json.Unmarshal(resp.Body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Method != http.MethodPost {
		t.Errorf("method = %q", got.Method)
	}
	if got.ContentType != "application/json" {
		t.Errorf("content-type = %q", got.ContentType)
	}
	if got.Body != `{"x":1}` {
		t.Errorf("body = %q", got.Body)
	}
}

// A GET must still send no body; the refactor must not turn every request into
// a POST with an empty payload.
func TestGetStillHasNoBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodGet {
			t.Errorf("method = %s", r.Method)
		}
		if len(b) != 0 {
			t.Errorf("GET carried %d bytes", len(b))
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := New(Options{Profile: "chrome_133", Timeout: 5 * time.Second})
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("Get: %v", err)
	}
}
