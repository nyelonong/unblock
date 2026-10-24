# unblock

HTTP client Go yang **menyerupai browser** di level jaringan, dan **tahu kapan dirinya diblokir**.

```go
c := unblock.New(unblock.Options{})
resp, err := c.Get(ctx, "https://contoh.id")
if b := resp.Blocked(); b != nil {
    fmt.Println(b.Kind, b.Hint) // CF_CHALLENGE / CF_BLOCK_1020 / WAF_GENERIC / ...
}
```

Tiga hal yang dikerjakan, dan satu yang tidak.

## 1. Fingerprint TLS/JA3 + HTTP/2

`net/http`, `requests`, dan `httpx` punya sidik jari yang khas dan gampang dikenali. Saat konek HTTPS, client mengirim TLS ClientHello berisi cipher suite, urutan extension, kurva, dan ALPN — WAF menghitung itu jadi hash (JA3/JA4). Ditambah sidik jari HTTP/2: nilai `SETTINGS`, `WINDOW_UPDATE`, urutan pseudo-header.

`unblock` memakai [`bogdanfinn/tls-client`](https://github.com/bogdanfinn/tls-client) (ClientHello via uTLS, h2 via fhttp) sehingga sidik jarinya menyerupai Chrome/Safari/Firefox asli:

```go
c := unblock.New(unblock.Options{
    Profile: "chrome_133", // kosong = profil Chrome default (versi terbaru)
})
```

Setara konsepnya dengan `curl_cffi` di Python, tapi tanpa proses terpisah.

## 2. Fallback HTTP/1.1 otomatis

Sebagian server menolak negosiasi HTTP/2 dengan `RST_STREAM` (`stream ID 1; INTERNAL_ERROR`) walau TLS-nya lolos. `unblock` mendeteksi pola error itu, lalu mengulang **sekali** lewat HTTP/1.1 dengan fingerprint TLS yang sama.

Percobaan pertama diberi separuh budget waktu, supaya retry tidak kehabisan waktu karena percobaan pertama menggantung. `Response.Attempts` dan `Response.HTTP1` melaporkan jalur mana yang dipakai.

```go
resp, _ := c.Get(ctx, url)
fmt.Println(resp.Attempts) // 1, atau 2 kalau fallback dipakai
```

Paksa selalu HTTP/1.1 dengan `Options.ForceHTTP1`.

## 3. Klasifikasi blokir

Empat situasi berbeda bersembunyi di balik HTTP 403, dan masing-masing butuh tindakan berbeda. `Classify` membedakannya dari header + body, tanpa request tambahan:

| `Kind` | Penanda | Tindakan |
|---|---|---|
| `CF_CHALLENGE` | `cf-mitigated: challenge`, `_cf_chl_opt`, `Just a moment` | butuh browser yang mengeksekusi JS |
| `CF_BLOCK_1010` | `Error 1010` | browser signature dibanned: pakai profil TLS, bukan UA palsu |
| `CF_BLOCK_1009` | `Error 1009` | blokir negara: perlu proxy lokal |
| `CF_BLOCK_1015` | `Error 1015` | rate limited: cooldown |
| `CF_BLOCK_1020` | `Error 1020` | firewall rule menolak ASN/datacenter |
| `WAF_GENERIC` | `x-sucuri-id`, `x-datadome`, `x-akamai-request-id`, `x-iinfo` | WAF pihak ketiga |

```go
b := unblock.Classify(resp)
if b != nil {
    log.Printf("diblokir: %s (ray %s) — %s", b.Kind, b.RayID, b.Hint)
}
if b.Challenge() {
    // satu-satunya kategori yang bisa diselesaikan browser
}
```

403 dari origin (`forbidden` biasa, halaman login) sengaja **tidak** dianggap blokir — itu bukan urusan anti-bot.

## Cooldown per host

Blokir Cloudflare bersifat sticky: mengulang request ke host yang sama dalam waktu singkat justru menaikkan level blokir. `Cooldown` memberi jarak:

```go
cd := unblock.NewCooldown(6 * time.Hour)
host := unblock.HostOf(url)

if !cd.Allow(host) {
    return fmt.Errorf("cooldown %s: %s lagi", host, cd.Remaining(host))
}
resp, err := c.Get(ctx, url)
if b := resp.Blocked(); b != nil {
    cd.Mark(host)
}
```

## Yang TIDAK dikerjakan

**Tidak ada eksekusi JavaScript.** Challenge Cloudflare managed (Turnstile, halaman "Checking your browser" yang menghitung token) tetap tidak bisa dilewati — fingerprint hanya menang melawan aturan yang murni berbasis TLS/h2.

Paket ini memberi tahu bahwa itu yang terjadi (`CF_CHALLENGE`), bukan berpura-pura bisa menyelesaikannya. Untuk itu kamu butuh browser sungguhan: FlareSolverr, [`go-rod`](https://github.com/go-rod/rod), atau browser pengguna sendiri.

Juga di luar cakupan: IP reputation dan perilaku. IP datacenter tetap sering diblok walau sidik jarinya sempurna — pakai `Options.ProxyURL` untuk keluar dari IP tersebut.

## Install

```bash
go get github.com/nyelonong/unblock
```

Butuh Go 1.27+ (mengikuti `tls-client`).

## API

```go
func New(opts Options) *Client
func (c *Client) Get(ctx context.Context, url string) (*Response, error)
func (c *Client) Head(ctx context.Context, url string) (*Response, error)
func (c *Client) Do(ctx context.Context, method, url string) (*Response, error)

func Classify(r *Response) *Block
func HostOf(rawURL string) string
func NewCooldown(window time.Duration) *Cooldown
```

`Options`: `Profile`, `ProxyURL`, `Timeout`, `MaxBody`, `Headers`, `ForceHTTP1`.

`Response`: `StatusCode`, `Header`, `Body`, `FinalURL`, `Attempts`, `HTTP1`, plus `Get(header)` dan `Blocked()`.

## Test

```bash
go test ./...
```

Mencakup server sungguhan (httptest), batas body, header kustom, `ForceHTTP1`, 9 varian klasifikasi blokir, dan perilaku cooldown.

## Lisensi

MIT — lihat [LICENSE](LICENSE).
