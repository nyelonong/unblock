package unblock

import (
	"strings"

	"github.com/bogdanfinn/tls-client/profiles"
)

// defaultAccept is the navigation Accept header recent Chromium sends.
const defaultAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"

// profileIdentity reads the browser name and version straight out of the
// profiles package. The name string ("chrome_133") is only a lookup key; the
// authoritative Client/Version pair comes from the profile itself, so this keeps
// working when the package adds or renames presets.
func profileIdentity(profile string) (client, version string) {
	p := profiles.DefaultClientProfile
	if v, ok := profiles.MappedTLSClients[profile]; ok {
		p = v
	}
	id := p.GetClientHelloId()
	return id.Client, id.Version
}

// splitVersion turns "16.0" or "146_PSK" into a major/minor pair.
func splitVersion(v string) (major, minor string) {
	v = strings.ToUpper(v)
	v = strings.TrimSuffix(v, "_PSK")
	v = strings.TrimSuffix(v, "_PQ")
	if i := strings.IndexAny(v, "._"); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, "0"
}

// DefaultHeaders returns a browser-consistent header set for a TLS profile.
//
// tls-client fingerprints the handshake and the HTTP/2 frames but leaves the
// headers alone, so without this the wire says "Go-http-client/2.0" while the
// fingerprint claims Chrome — a mismatch any WAF will flag. The browser name and
// version are read from the profile (GetClientHelloId), never guessed from the
// profile string.
//
// accept-encoding is deliberately absent: the transport adds its own and
// decompresses the body. Setting it here leaves the response compressed, which
// silently shrinks the HTML and breaks substring checks.
func DefaultHeaders(profile string) map[string]string {
	client, version := profileIdentity(profile)
	major, minor := splitVersion(version)

	h := map[string]string{
		"accept":                    defaultAccept,
		"accept-language":           "en-US,en;q=0.9",
		"sec-fetch-dest":            "document",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-site":            "none",
		"sec-fetch-user":            "?1",
		"upgrade-insecure-requests": "1",
	}

	switch strings.ToLower(client) {
	case "ios":
		h["user-agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS " + major + "_" + minor +
			" like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + major + "." + minor +
			" Mobile/15E148 Safari/604.1"
		delete(h, "sec-fetch-user")

	case "safari":
		h["user-agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" +
			major + "." + minor + " Safari/605.1.15"

	case "firefox":
		h["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + major +
			".0) Gecko/20100101 Firefox/" + major + ".0"

	case "brave":
		h["user-agent"] = chromeUA(major)
		h["sec-ch-ua"] = `"Brave";v="` + major + `", "Chromium";v="` + major + `", "Not(A:Brand";v="24"`
		h["sec-ch-ua-mobile"] = "?0"
		h["sec-ch-ua-platform"] = `"Windows"`

	case "opera":
		h["user-agent"] = chromeUA(major) + " OPR/" + major + ".0.0.0"
		h["sec-ch-ua"] = `"Opera";v="` + major + `", "Chromium";v="` + major + `", "Not(A:Brand";v="24"`
		h["sec-ch-ua-mobile"] = "?0"
		h["sec-ch-ua-platform"] = `"Windows"`

	case "chrome", "chromium":
		h["user-agent"] = chromeUA(major)
		h["sec-ch-ua"] = `"Chromium";v="` + major + `", "Not(A:Brand";v="24", "Google Chrome";v="` + major + `"`
		h["sec-ch-ua-mobile"] = "?0"
		h["sec-ch-ua-platform"] = `"Windows"`

	default:
		// Non-browser presets (mobile SDKs, cloudscraper, ...) have no honest UA
		// template, so borrow the package default identity instead of inventing one.
		def, defVersion := profiles.DefaultClientProfile.GetClientHelloId().Client, profiles.DefaultClientProfile.GetClientHelloId().Version
		dmajor, _ := splitVersion(defVersion)
		h["user-agent"] = chromeUA(dmajor)
		h["sec-ch-ua"] = `"Chromium";v="` + dmajor + `", "Not(A:Brand";v="24", "Google Chrome";v="` + dmajor + `"`
		h["sec-ch-ua-mobile"] = "?0"
		h["sec-ch-ua-platform"] = `"Windows"`
		_ = def
	}
	return h
}

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
