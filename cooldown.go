package unblock

import (
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultCooldownWindow dipakai bila NewCooldown menerima durasi nol.
const DefaultCooldownWindow = 6 * time.Hour

// Cooldown mencatat host yang baru saja memblokir kita.
//
// Blokir Cloudflare bersifat "sticky": mengulang request ke host yang sama
// dalam waktu singkat justru menaikkan level blokir (challenge menjadi block).
// Cooldown memberi jarak sebelum host itu dicoba lagi.
type Cooldown struct {
	window time.Duration

	mu    sync.Mutex
	until map[string]time.Time
}

// NewCooldown membuat Cooldown dengan jendela tertentu. Nol berarti
// DefaultCooldownWindow.
func NewCooldown(window time.Duration) *Cooldown {
	if window <= 0 {
		window = DefaultCooldownWindow
	}
	return &Cooldown{window: window, until: make(map[string]time.Time)}
}

// Allow melaporkan apakah host boleh dicoba sekarang.
func (c *Cooldown) Allow(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.until[hostKey(host)]
	return !ok || time.Now().After(u)
}

// Remaining mengembalikan sisa waktu tunggu untuk host (0 bila boleh dicoba).
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

// Mark menandai host agar tidak dicoba selama jendela cooldown.
func (c *Cooldown) Mark(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.until[hostKey(host)] = time.Now().Add(c.window)
}

// Reset menghapus penanda cooldown untuk host.
func (c *Cooldown) Reset(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.until, hostKey(host))
}

func hostKey(host string) string { return strings.ToLower(host) }

// HostOf mengambil host (tanpa port) dari URL; mengembalikan string apa adanya
// bila URL tidak bisa diparse.
func HostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return raw
	}
	return u.Hostname()
}
