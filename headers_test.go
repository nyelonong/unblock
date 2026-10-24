package unblock

import (
	"strings"
	"testing"
)

func TestDefaultHeadersChrome(t *testing.T) {
	h := DefaultHeaders("chrome_133")

	if got := h["user-agent"]; !strings.Contains(got, "Chrome/133.0.0.0") {
		t.Errorf("user-agent = %q, want Chrome/133", got)
	}
	if strings.Contains(h["user-agent"], "Go-http-client") {
		t.Error("user-agent must never leak Go's default")
	}
	if got := h["sec-ch-ua"]; !strings.Contains(got, `v="133"`) {
		t.Errorf("sec-ch-ua = %q, want version 133", got)
	}
	// The UA major and the client hint must agree, or the pair looks forged.
	if !strings.Contains(h["user-agent"], "133") || !strings.Contains(h["sec-ch-ua"], "133") {
		t.Error("user-agent and sec-ch-ua versions diverged")
	}
	if h["sec-ch-ua-platform"] != `"Windows"` {
		t.Errorf("sec-ch-ua-platform = %q", h["sec-ch-ua-platform"])
	}
	if h["sec-fetch-mode"] != "navigate" {
		t.Errorf("sec-fetch-mode = %q", h["sec-fetch-mode"])
	}
	if h["accept"] == "" || h["accept-language"] == "" || h["accept-encoding"] == "" {
		t.Error("content negotiation headers must be present")
	}
}

func TestDefaultHeadersOtherBrowsers(t *testing.T) {
	ff := DefaultHeaders("firefox_123")
	if !strings.Contains(ff["user-agent"], "Firefox/123.0") {
		t.Errorf("firefox ua = %q", ff["user-agent"])
	}
	if _, ok := ff["sec-ch-ua"]; ok {
		t.Error("firefox must not send sec-ch-ua")
	}

	brave := DefaultHeaders("brave_146")
	if !strings.Contains(brave["sec-ch-ua"], "Brave") {
		t.Errorf("brave sec-ch-ua = %q", brave["sec-ch-ua"])
	}

	safari := DefaultHeaders("safari_16_0")
	if !strings.Contains(safari["user-agent"], "Version/16.0 Safari/605.1.15") {
		t.Errorf("safari ua = %q", safari["user-agent"])
	}

	ios := DefaultHeaders("safari_ios_18_5")
	if !strings.Contains(ios["user-agent"], "iPhone") || !strings.Contains(ios["user-agent"], "Mobile/15E148") {
		t.Errorf("ios ua = %q", ios["user-agent"])
	}

	opera := DefaultHeaders("opera_90")
	if !strings.Contains(opera["user-agent"], "OPR/90.0.0.0") {
		t.Errorf("opera ua = %q", opera["user-agent"])
	}
}

func TestDefaultHeadersUnknownProfile(t *testing.T) {
	h := DefaultHeaders("mms_ios_2")
	ua := h["user-agent"]
	if ua == "" || strings.Contains(ua, "Go-http-client") {
		t.Fatalf("unknown profile must still get a browser UA, got %q", ua)
	}
	if !strings.Contains(ua, "Chrome/") {
		t.Errorf("fallback ua = %q, want a Chrome identity", ua)
	}
}

func TestDefaultHeadersPSKSuffix(t *testing.T) {
	h := DefaultHeaders("chrome_133_PSK")
	if !strings.Contains(h["user-agent"], "Chrome/133") {
		t.Errorf("ua = %q, want the PSK suffix stripped and parsed", h["user-agent"])
	}
}

func TestMergeHeadersOverride(t *testing.T) {
	h := mergeHeaders("chrome_133", map[string]string{"ACCEPT-LANGUAGE": "id-ID,id;q=0.9"})
	if h["accept-language"] != "id-ID,id;q=0.9" {
		t.Errorf("override ignored: %q", h["accept-language"])
	}
	if !strings.Contains(h["user-agent"], "Chrome/133") {
		t.Error("defaults must survive an override of another header")
	}
}
