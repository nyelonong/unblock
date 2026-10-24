package unblock_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nyelonong/unblock"
)

// One call walks the whole ladder and stops at the first rung that gets an
// answer: HTTP/2, then HTTP/3 racing, then HTTP/1.1, then another engine.
//
// A block means "try the next rung". Any answer from the origin — 200, 404, even
// 500 — ends the walk, because changing fingerprints cannot fix a page that
// does not exist.
func ExampleLadder_Get() {
	l := unblock.NewLadder(unblock.Options{
		Timeout: 20 * time.Second,
		Headers: map[string]string{"accept-language": "en-US,en;q=0.9"},
	}).WithMaxAttempts(4)

	resp, err := l.Get(context.Background(), "https://example.com/")
	if err != nil {
		var blocked *unblock.BlockedError
		if errors.As(err, &blocked) {
			fmt.Println("every rung blocked, last kind:", blocked.Block.Kind)
			return
		}
		fmt.Println("request failed:", err)
		return
	}

	fmt.Println(resp.StatusCode, resp.Proto)
	for _, a := range l.Last() {
		fmt.Printf("  %-32s %-9s %d\n", a.String(), a.Proto, a.HTTPStatus)
	}
}

// Park a host after a block so repeated checks do not escalate it.
func ExampleLadder_WithCooldown() {
	cd := unblock.NewCooldown(6 * time.Hour)

	l := unblock.NewLadder(unblock.Options{Timeout: 20 * time.Second}).
		WithCooldown(cd).
		WithMaxAttempts(3)

	if _, err := l.Get(context.Background(), "https://example.com/"); err != nil {
		var cooling *unblock.CooldownError
		if errors.As(err, &cooling) {
			fmt.Println("still parked for", cooling.Remaining)
		}
	}

	fmt.Println("cooling down:", !cd.Allow(unblock.HostOf("https://example.com/")))
}
