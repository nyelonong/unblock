package unblock

import (
	"net/http"
	"regexp"
	"strings"
)

// defaultAccept is the navigation Accept header recent Chrome sends.
const defaultAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"

var (
	chromeRe    = regexp.MustCompile(`^chrome_(\d+)`)
	braveRe     = regexp.MustCompile(`^brave_(\d+)`)
	firefoxRe   = regexp.MustCompile(`^firefox_(\d+)`)
	safariRe    = regexp.MustCompile(`^safari_(\d+)_(\d+)`)
	safariIOSRe = regexp.MustCompile(`^safari_ios_(\d+)_(\d+)`)
	operaRe     = regexp.MustCompile(`^opera_(\d+)`)
)

// DefaultHeaders returns a browser-consistent header set for a TLS profile.
//
// tls-client fingerprints the handshake and the HTTP/2 frames but leaves the
// headers alone, so without this the wire says "Go-http-client/2.0" while the
// fingerprint claims Chrome — a mismatch any WAF will flag. Callers can override
// any header through Options.Headers.
func DefaultHeaders(profile string) map[string]string {
	h := map[string]string{
		"accept":                    defaultAccept,
		"accept-language":           "en-US,en;q=0.9",
		"accept-encoding":           "gzip, deflate, br, zstd",
		"sec-fetch-dest":            "document",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-site":            "none",
		"sec-fetch-user":            "?1",
		"upgrade-insecure-requests": "1",
	}

	switch p := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(profile, "_psk"), "_pq")); {
	case safariIOSRe.MatchString(p):
		m := safariIOSRe.FindStringSubmatch(p)
		major, minor := m[1], m[2]
		h["user-agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS " + major + "_" + minor +
			" like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + major + "." + minor +
			" Mobile/15E148 Safari/604.1"
		delete(h, "sec-fetch-user")

	case safariRe.MatchString(p):
		m := safariRe.FindStringSubmatch(p)
		major, minor := m[1], m[2]
		h["user-agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" +
			major + "." + minor + " Safari/605.1.15"

	case firefoxRe.MatchString(p):
		major := firefoxRe.FindStringSubmatch(p)[1]
		h["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + major +
			".0) Gecko/20100101 Firefox/" + major + ".0"

	case braveRe.MatchString(p):
		major := braveRe.FindStringSubmatch(p)[1]
		h["user-agent"] = chromeUA(major)
		h["sec-ch-ua"] = `"Brave";v="` + major + `", "Chromium";v="` + major + `", "Not(A:Brand";v="24"`
		h["sec-ch-ua-mobile"] = "?0"
		h["sec-ch-ua-platform"] = `"Windows"`

	case operaRe.MatchString(p):
		major := operaRe.FindStringSubmatch(p)[1]
		h["user-agent"] = chromeUA(major) + " OPR/" + major + ".0.0.0"
		h["sec-ch-ua"] = `"Opera";v="` + major + `", "Chromium";v="` + major + `", "Not(A:Brand";v="24"`
		h["sec-ch-ua-mobile"] = "?0"
		h["sec-ch-ua-platform"] = `"Windows"`

	case chromeRe.MatchString(p):
		major := chromeRe.FindStringSubmatch(p)[1]
		h["user-agent"] = chromeUA(major)
		h["sec-ch-ua"] = `"Chromium";v="` + major + `", "Not(A:Brand";v="24", "Google Chrome";v="` + major + `"`
		h["sec-ch-ua-mobile"] = "?0"
		h["sec-ch-ua-platform"] = `"Windows"`

	default:
		// Unknown profile: fall back to a mainstream Chrome identity rather than
		// leaking Go's own user agent.
		h["user-agent"] = chromeUA(fallbackChromeMajor)
		h["sec-ch-ua"] = `"Chromium";v="` + fallbackChromeMajor + `", "Not(A:Brand";v="24", "Google Chrome";v="` + fallbackChromeMajor + `"`
		h["sec-ch-ua-mobile"] = "?0"
		h["sec-ch-ua-platform"] = `"Windows"`
	}
	return h
}

// fallbackChromeMajor is used when a profile name carries no browser version.
const fallbackChromeMajor = "133"

func chromeUA(major string) string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" +
		major + ".0.0.0 Safari/537.36"
}

// mergeHeaders returns defaults overridden by user headers.
func mergeHeaders(profile string, user map[string]string) map[string]string {
	out := DefaultHeaders(profile)
	for k, v := range user {
		out[strings.ToLower(k)] = v
	}
	return out
}

func toHTTPHeader(m map[string]string) http.Header {
	h := http.Header{}
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}
