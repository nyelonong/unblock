package unblock

import (
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultCooldownWindow is used when NewCooldown receives a zero duration.
const DefaultCooldownWindow = 6 * time.Hour

// Cooldown records hosts that just blocked us.
//
// Cloudflare blocks are sticky: repeating a request to the same host within a
// short window tends to escalate the block (challenge becomes block). A
// cooldown buys distance before that host is attempted again.
type Cooldown struct {
	window time.Duration

	mu    sync.Mutex
	until map[string]time.Time
}

// NewCooldown creates a Cooldown with the given window. Zero means
// DefaultCooldownWindow.
func NewCooldown(window time.Duration) *Cooldown {
	if window <= 0 {
		window = DefaultCooldownWindow
	}
	return &Cooldown{window: window, until: make(map[string]time.Time)}
}

// Allow reports whether the host may be attempted now.
func (c *Cooldown) Allow(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.until[hostKey(host)]
	return !ok || time.Now().After(u)
}

// Remaining returns how long the host stays parked (0 when it is allowed).
func (c *Cooldown) Remaining(host string) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.until[hostKey(host)]
	if !ok {
		return 0
	}
	if d := time.Until(u); d > 0 {
		return d
	}
	return 0
}

// Mark parks the host for the cooldown window.
func (c *Cooldown) Mark(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.until[hostKey(host)] = time.Now().Add(c.window)
}

// Reset clears the cooldown marker for a host.
func (c *Cooldown) Reset(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.until, hostKey(host))
}

func hostKey(host string) string { return strings.ToLower(host) }

// HostOf returns the host (without port) of a URL, or the input unchanged when
// it cannot be parsed.
func HostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return raw
	}
	return u.Hostname()
}
