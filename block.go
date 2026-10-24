package unblock

import (
	"regexp"
	"strings"
)

var errCodeRe = regexp.MustCompile(`Error[ ]?(\d{4})`)

// Block describes a single blocking event.
type Block struct {
	// Kind is the category: CF_CHALLENGE, CF_BLOCK_1009, CF_BLOCK_1010,
	// CF_BLOCK_1015, CF_BLOCK_1020, CF_BLOCK_GENERIC, WAF_GENERIC.
	Kind string `json:"kind"`
	// Code is the Cloudflare error code when present (e.g. "1020").
	Code string `json:"code,omitempty"`
	// RayID helps when contacting WAF support or the site owner.
	RayID string `json:"ray_id,omitempty"`
	// Server is the value of the Server header.
	Server string `json:"server,omitempty"`
	// Hint suggests the next action.
	Hint string `json:"hint,omitempty"`
}

// Challenge reports whether this block can be resolved by a browser that
// executes JavaScript (FlareSolverr, go-rod, or the end user's browser).
func (b *Block) Challenge() bool { return b != nil && b.Kind == "CF_CHALLENGE" }

// Classify inspects a response and reports whether it is a WAF/anti-bot block.
// It returns nil when the response is not a block.
//
// Four different situations hide behind HTTP 403, and each needs a different
// response — never treat them as one case.
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
				Hint:   "managed challenge: needs a browser that executes JS (FlareSolverr / go-rod), or verification through the user's own browser",
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

		// Cloudflare answered 403/503 without a body. Normal for HEAD requests
		// and for stripped responses: every other marker lives in the body, so
		// without this the block would be missed entirely.
		if len(strings.TrimSpace(body)) < 32 {
			return &Block{
				Kind:   "CF_BLOCK_GENERIC",
				RayID:  ray,
				Server: server,
				Hint:   "empty body (HEAD or stripped response): retry with GET to tell a challenge from a block",
			}
		}
	}

	// Third-party WAFs.
	if r.StatusCode == 403 || r.StatusCode == 429 {
		for _, k := range []string{"x-sucuri-id", "x-akamai-request-id", "x-datadome", "x-iinfo"} {
			if h.Get(k) != "" {
				return &Block{
					Kind:   "WAF_GENERIC",
					Server: server,
					Hint:   "third-party WAF rejected the request; needs a residential proxy or a real browser",
				}
			}
		}
	}
	return nil
}

func cfHint(code string) string {
	switch code {
	case "1009":
		return "country block: needs a proxy in the target country"
	case "1010":
		return "browser signature banned: use a real TLS profile instead of a spoofed user-agent"
	case "1015":
		return "rate limited: add a per-host cooldown"
	case "1020":
		return "firewall rule rejected the ASN/datacenter: needs a residential proxy"
	default:
		return "WAF rejected the request: try a residential proxy or a real browser"
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
