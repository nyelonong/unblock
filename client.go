// Package unblock adalah HTTP client Go yang menyerupai browser (ClientHello
// dan HTTP/2 fingerprint Chrome) dan tahu kapan dirinya diblokir.
//
// Tiga hal yang ditangani:
//
//  1. TLS/JA3 dan HTTP/2 fingerprint — lewat bogdanfinn/tls-client, sehingga
//     aturan WAF berbasis fingerprint tidak menolak request.
//  2. Fallback HTTP/1.1 otomatis ketika server menolak HTTP/2 (RST_STREAM),
//     dengan fingerprint TLS yang sama.
//  3. Klasifikasi blokir — Cloudflare challenge, error 1009/1010/1015/1020,
//     dan WAF pihak ketiga dibedakan satu sama lain, karena masing-masing
//     butuh tindakan berbeda.
//
// Paket ini TIDAK mengeksekusi JavaScript. Challenge Cloudflare yang butuh JS
// tetap tidak bisa dilewati di sini; Classify hanya memberi tahu bahwa itu
// yang terjadi.
package unblock

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// DefaultTimeout adalah batas waktu per percobaan bila Options.Timeout kosong.
const DefaultTimeout = 20 * time.Second

// DefaultMaxBody adalah batas ukuran body (5 MiB).
const DefaultMaxBody = 5 << 20

// Options mengatur perilaku Client.
type Options struct {
	// Profile adalah nama preset TLS, mis. "chrome_133" atau "firefox_135".
	// Kosong berarti profil Chrome default paket (versi terbaru yang didukung).
	// Lihat profiles.MappedTLSClients untuk daftar lengkap.
	Profile string

	// ProxyURL opsional: "http://127.0.0.1:8080" atau "socks5://10.0.0.2:1080".
	ProxyURL string

	// Timeout per percobaan. Kosong berarti DefaultTimeout.
	Timeout time.Duration

	// MaxBody membatasi jumlah byte body yang dibaca. Kosong berarti DefaultMaxBody.
	MaxBody int64

	// Headers ditambahkan ke setiap request. Header yang sudah diatur profil
	// TLS (user-agent, accept, dsb) akan ditimpa oleh nilai di sini.
	Headers map[string]string

	// ForceHTTP1 mematikan negosiasi HTTP/2 sepenuhnya. Berguna untuk server
	// yang men-tarpit atau menolak h2 secara konsisten.
	ForceHTTP1 bool
}

// Response adalah respons yang sudah dibaca penuh (dibatasi MaxBody).
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	FinalURL   string

	// Attempts berisi 1 untuk percobaan pertama, 2 bila fallback HTTP/1.1 dipakai.
	Attempts int
	// HTTP1 bernilai true bila respons datang dari jalur fallback HTTP/1.1.
	HTTP1 bool
}

// Get mengambil URL dengan metode GET.
func (r *Response) Get(name string) string { return r.Header.Get(name) }

// Blocked mengembalikan detail blokir, atau nil bila respons bukan blokir.
func (r *Response) Blocked() *Block { return Classify(r) }

// Client adalah fetcher dengan fingerprint browser.
type Client struct {
	opts   Options
	client tlsclient.HttpClient

	mu sync.Mutex
	h1 tlsclient.HttpClient
}

// New membuat Client. Konfigurasi yang tidak valid tidak membuat New gagal:
// Client akan memakai fallback tanpa impersonation (net/http) supaya pemanggil
// tidak perlu menangani error di jalur inisialisasi.
func New(opts Options) *Client {
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxBody == 0 {
		opts.MaxBody = DefaultMaxBody
	}
	c := &Client{opts: opts}
	if tc, err := build(opts, opts.ForceHTTP1); err == nil {
		c.client = tc
	} else {
		c.client = nil // pakai jalur net/http
	}
	return c
}

func build(opts Options, forceH1 bool) (tlsclient.HttpClient, error) {
	o := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(int(opts.Timeout.Seconds()) + 1),
		tlsclient.WithClientProfile(profileByName(opts.Profile)),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
	}
	if forceH1 {
		o = append(o, tlsclient.WithForceHttp1())
	}
	if opts.ProxyURL != "" {
		o = append(o, tlsclient.WithProxyUrl(opts.ProxyURL))
	}
	return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), o...)
}

func profileByName(name string) profiles.ClientProfile {
	if name != "" {
		if p, ok := profiles.MappedTLSClients[name]; ok {
			return p
		}
	}
	return profiles.DefaultClientProfile
}

// Get mengambil URL. Request mengikuti redirect secara default.
func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	return c.Do(ctx, http.MethodGet, url)
}

// Head mengirim HEAD. Sebagian server menolak HEAD; pemanggil yang perlu fallback
// ke Get harus melakukannya sendiri.
func (c *Client) Head(ctx context.Context, url string) (*Response, error) {
	return c.Do(ctx, http.MethodHead, url)
}

// Do menjalankan request dan mengembalikan body lengkap.
//
// Bila percobaan pertama gagal karena masalah HTTP/2 (RST_STREAM, INTERNAL_ERROR),
// request diulang sekali lewat HTTP/1.1 dengan fingerprint TLS yang sama.
// Separuh budget waktu disisakan untuk percobaan kedua.
func (c *Client) Do(ctx context.Context, method, url string) (*Response, error) {
	if c.opts.ForceHTTP1 {
		return c.attempt(ctx, method, url, c.clientFor(true), 1)
	}

	// Sisakan separuh budget untuk fallback, supaya percobaan pertama yang
	// menggantung tidak menghabiskan seluruh waktu.
	primaryCtx := ctx
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 2*time.Second {
			var cancel context.CancelFunc
			primaryCtx, cancel = context.WithTimeout(ctx, remaining/2)
			defer cancel()
		}
	}

	resp, err := c.attempt(primaryCtx, method, url, c.clientFor(false), 1)
	if err == nil {
		return resp, nil
	}
	if !isHTTP2Error(err) {
		return nil, err
	}
	h1 := c.clientFor(true)
	if h1 == nil {
		return nil, err
	}
	return c.attempt(ctx, method, url, h1, 2)
}

func (c *Client) clientFor(forceH1 bool) tlsclient.HttpClient {
	if !forceH1 {
		return c.client
	}
	if c.opts.ForceHTTP1 && c.client != nil {
		return c.client
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.h1 == nil {
		tc, err := build(c.opts, true)
		if err != nil {
			return nil
		}
		c.h1 = tc
	}
	return c.h1
}

func (c *Client) attempt(ctx context.Context, method, url string, client tlsclient.HttpClient, attempt int) (*Response, error) {
	if client == nil {
		return c.stdAttempt(ctx, method, url, attempt)
	}

	req, err := fhttp.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range c.opts.Headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.opts.MaxBody))
	if err != nil {
		return nil, err
	}
	out := &Response{
		StatusCode: resp.StatusCode,
		Header:     http.Header(resp.Header),
		Body:       body,
		FinalURL:   url,
		Attempts:   attempt,
		HTTP1:      attempt == 2 || c.opts.ForceHTTP1,
	}
	if resp.Request != nil && resp.Request.URL != nil {
		out.FinalURL = resp.Request.URL.String()
	}
	return out, nil
}

// stdAttempt adalah jalur tanpa impersonation, dipakai bila konstruksi TLS
// client gagal (mis. profil tidak dikenal di platform tertentu).
func (c *Client) stdAttempt(ctx context.Context, method, url string, attempt int) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range c.opts.Headers {
		req.Header.Set(k, v)
	}
	hc := &http.Client{Timeout: c.opts.Timeout}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.opts.MaxBody))
	if err != nil {
		return nil, err
	}
	final := url
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       body,
		FinalURL:   final,
		Attempts:   attempt,
	}, nil
}

// ErrNoBody dipakai saat respons tidak membawa data yang diharapkan.
var ErrNoBody = errors.New("unblock: empty body")

// isHTTP2Error mendeteksi kegagalan khas negosiasi HTTP/2.
func isHTTP2Error(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "internal_error") ||
		strings.Contains(s, "http/2") ||
		strings.Contains(s, "http2") ||
		strings.Contains(s, "stream id")
}
