package unblock

import (
	"strings"
	"testing"

	"github.com/bogdanfinn/tls-client/profiles"
)

// identity returns the authoritative client/version pair for a preset, so tests
// assert against the package instead of hardcoded browser versions.
func identity(name string) (string, string, string) {
	id := profiles.MappedTLSClients[name].GetClientHelloId()
	major, _ := splitVersion(id.Version)
	return id.Client, id.Version, major
}

func TestDefaultHeadersMatchProfile(t *testing.T) {
	for _, name := range []string{"chrome_133", "chrome_144", "brave_146", "opera_90"} {
		client, _, major := identity(name)
		h := DefaultHeaders(name)

		ua := h["user-agent"]
		if ua == "" || strings.Contains(ua, "Go-http-client") {
			t.Errorf("%s: user-agent = %q, must be a browser UA", name, ua)
		}
		if !strings.Contains(ua, "/"+major) {
			t.Errorf("%s: user-agent = %q, want version %s from the profile", name, ua, major)
		}
		// UA and client hints must agree, or the pair looks forged.
		if got := h["sec-ch-ua"]; !strings.Contains(got, `v="`+major+`"`) {
			t.Errorf("%s: sec-ch-ua = %q, want v=%s", name, got, major)
		}
		if got := h["sec-ch-ua"]; !strings.Contains(got, client) {
			t.Errorf("%s: sec-ch-ua = %q, want brand %q", name, got, client)
		}
	}
}

func TestDefaultHeadersFirefoxAndSafari(t *testing.T) {
	ff := DefaultHeaders("firefox_123")
	_, _, ffMajor := identity("firefox_123")
	if !strings.Contains(ff["user-agent"], "Firefox/"+ffMajor) {
		t.Errorf("firefox ua = %q", ff["user-agent"])
	}
	if _, ok := ff["sec-ch-ua"]; ok {
		t.Error("firefox must not send sec-ch-ua")
	}

	sf := DefaultHeaders("safari_16_0")
	id := profiles.MappedTLSClients["safari_16_0"].GetClientHelloId()
	if !strings.Contains(sf["user-agent"], "Version/"+id.Version) {
		t.Errorf("safari ua = %q, want Version/%s", sf["user-agent"], id.Version)
	}

	ios := DefaultHeaders("safari_ios_18_5")
	if !strings.Contains(ios["user-agent"], "iPhone") || !strings.Contains(ios["user-agent"], "Mobile/15E148") {
		t.Errorf("ios ua = %q", ios["user-agent"])
	}
}

func TestDefaultHeadersCommon(t *testing.T) {
	h := DefaultHeaders("chrome_133")
	if h["accept"] == "" || h["accept-language"] == "" {
		t.Error("content negotiation headers must be present")
	}
	// accept-encoding must stay unset: the transport adds it and decompresses.
	// Setting it here leaves the body compressed.
	if _, ok := h["accept-encoding"]; ok {
		t.Error("accept-encoding must be left to the transport")
	}
	if h["sec-fetch-mode"] != "navigate" {
		t.Errorf("sec-fetch-mode = %q", h["sec-fetch-mode"])
	}
}

func TestDefaultHeadersUnknownProfile(t *testing.T) {
	// Non-browser presets must still not leak Go's default user agent.
	for _, name := range []string{"mms_ios_2", "cloudscraper", "tidak_ada_999"} {
		ua := DefaultHeaders(name)["user-agent"]
		if ua == "" || strings.Contains(ua, "Go-http-client") {
			t.Errorf("%s: user-agent = %q", name, ua)
		}
	}
}

func TestDefaultHeadersPSKSuffix(t *testing.T) {
	plain := DefaultHeaders("brave_146")
	psk := DefaultHeaders("brave_146_PSK")
	if plain["user-agent"] != psk["user-agent"] {
		t.Errorf("PSK variant should not change the UA: %q vs %q", plain["user-agent"], psk["user-agent"])
	}
}

func TestMergeHeadersOverride(t *testing.T) {
	h := mergeHeaders("chrome_133", map[string]string{"ACCEPT-LANGUAGE": "id-ID,id;q=0.9"})
	if h["accept-language"] != "id-ID,id;q=0.9" {
		t.Errorf("override ignored: %q", h["accept-language"])
	}
	if !strings.Contains(h["user-agent"], "Chrome/") {
		t.Error("defaults must survive an override of another header")
	}
}

func TestResolveProfileFallsBack(t *testing.T) {
	// A preset that does not exist must degrade to another profile of the same
	// family, never to an empty string.
	got := resolveProfile("chrome_999", "chrome")
	if got == "" {
		t.Fatal("resolveProfile returned an empty name")
	}
	if _, ok := profiles.MappedTLSClients[got]; !ok {
		t.Fatalf("%q is not a known profile", got)
	}
	if client := profiles.MappedTLSClients[got].GetClientHelloId().Client; client != "Chrome" {
		t.Errorf("fallback client = %q, want Chrome", client)
	}
}

func TestDefaultAttemptsUseKnownProfiles(t *testing.T) {
	for _, a := range DefaultAttempts() {
		if _, ok := profiles.MappedTLSClients[a.Profile]; !ok {
			t.Errorf("attempt uses unknown profile %q", a.Profile)
		}
	}
}
