package unblock

import (
	"regexp"
	"strings"
)

var errCodeRe = regexp.MustCompile(`Error[ ]?(\d{4})`)

// Block menjelaskan satu peristiwa blokir.
type Block struct {
	// Kind adalah kategori: CF_CHALLENGE, CF_BLOCK_1009, CF_BLOCK_1010,
	// CF_BLOCK_1015, CF_BLOCK_1020, CF_BLOCK_GENERIC, WAF_GENERIC.
	Kind string `json:"kind"`
	// Code adalah kode error Cloudflare bila ada (mis. "1020").
	Code string `json:"code,omitempty"`
	// RayID berguna saat menghubungi support penyedia WAF atau pemilik situs.
	RayID string `json:"ray_id,omitempty"`
	// Server adalah nilai header Server.
	Server string `json:"server,omitempty"`
	// Hint menyarankan tindakan berikutnya.
	Hint string `json:"hint,omitempty"`
}

// Challenge melaporkan apakah blokir ini bisa diselesaikan oleh browser yang
// mengeksekusi JavaScript (FlareSolverr, go-rod, atau browser pengguna).
func (b *Block) Challenge() bool { return b != nil && b.Kind == "CF_CHALLENGE" }

// Classify memeriksa apakah respons merupakan blokir WAF/anti-bot.
// Mengembalikan nil bila bukan blokir.
//
// Empat situasi berbeda bersembunyi di balik HTTP 403, dan masing-masing butuh
// respons yang berbeda — jangan pernah memperlakukannya sebagai satu kasus.
func Classify(r *Response) *Block {
	if r == nil {
		return nil
	}
	h := r.Header
	server := h.Get("server")
	ray := h.Get("cf-ray")
	isCF := strings.EqualFold(server, "cloudflare") || ray != ""

	body := string(r.Body)
	if len(body) > 8000 {
		body = body[:8000]
	}

	if isCF && (r.StatusCode == 403 || r.StatusCode == 503) {
		challenge := strings.EqualFold(h.Get("cf-mitigated"), "challenge") ||
			containsFold(body, "_cf_chl_opt") ||
			containsFold(body, "__cf_chl") ||
			containsFold(body, "Just a moment") ||
			containsFold(body, "cf-challenge")
		if challenge {
			return &Block{
				Kind:   "CF_CHALLENGE",
				RayID:  ray,
				Server: server,
				Hint:   "managed challenge: butuh browser yang mengeksekusi JS (FlareSolverr / go-rod), atau verifikasi lewat browser pengguna",
			}
		}

		blockedPage := containsFold(body, "Attention Required") ||
			containsFold(body, "you have been blocked") ||
			containsFold(body, "cf-error-details") ||
			containsFold(body, "Access denied")
		code := ""
		if m := errCodeRe.FindStringSubmatch(body); len(m) == 2 {
			code = m[1]
		}
		if blockedPage || code != "" {
			return &Block{
				Kind:   "CF_BLOCK_" + orDefault(code, "GENERIC"),
				Code:   code,
				RayID:  ray,
				Server: server,
				Hint:   cfHint(code),
			}
		}
	}

	// WAF pihak ketiga.
	if r.StatusCode == 403 || r.StatusCode == 429 {
		for _, k := range []string{"x-sucuri-id", "x-akamai-request-id", "x-datadome", "x-iinfo"} {
			if h.Get(k) != "" {
				return &Block{
					Kind:   "WAF_GENERIC",
					Server: server,
					Hint:   "WAF pihak ketiga menolak request; perlu proxy residensial atau browser asli",
				}
			}
		}
	}
	return nil
}

func cfHint(code string) string {
	switch code {
	case "1009":
		return "blokir per negara: perlu proxy dari negara target"
	case "1010":
		return "browser signature dibanned: pastikan memakai profil TLS browser, bukan user-agent palsu"
	case "1015":
		return "rate limited: tambahkan cooldown per host"
	case "1020":
		return "firewall rule menolak ASN/datacenter: perlu proxy residensial"
	default:
		return "WAF menolak request: coba proxy residensial atau browser asli"
	}
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
