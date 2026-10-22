package httpapi

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func newTestLimiter() *ipLimiter {
	return &ipLimiter{m: map[string]*visitor{}, rate: 1, burst: 2}
}

func TestLimiterEnforcesBurst(t *testing.T) {
	l, now := newTestLimiter(), time.Now()
	for i := range 2 {
		if !l.allow("1.1.1.1", now) {
			t.Fatalf("request %d within burst was rejected", i)
		}
	}
	if l.allow("1.1.1.1", now) {
		t.Fatal("request over burst was allowed")
	}
	if !l.allow("2.2.2.2", now) {
		t.Fatal("another client must have its own bucket")
	}
}

// A request must never scan the whole map while holding the lock: one allow
// call evicts only a small constant number of idle entries (the bound is a
// literal, not limiterSweepStep, so changing the constant cannot hide a regression),
// yet repeated calls drain them all.
func TestLimiterSweepIsBoundedAndConverges(t *testing.T) {
	l, now := newTestLimiter(), time.Now()
	const stale = 5000
	for i := range stale {
		l.m[fmt.Sprintf("stale-%d", i)] = &visitor{lim: rate.NewLimiter(1, 2), seen: now.Add(-2 * limiterIdleTTL)}
	}
	l.allow("active", now)
	const bound = 64
	if removed := stale + 1 - len(l.m); removed > bound {
		t.Fatalf("one request evicted %d entries, want at most %d", removed, bound)
	}
	for i := 0; len(l.m) > limiterSweepLen && i < stale; i++ {
		l.allow("active", now)
	}
	if len(l.m) > limiterSweepLen {
		t.Fatalf("idle entries not evicted: %d left", len(l.m))
	}
	if _, ok := l.m["active"]; !ok {
		t.Fatal("an active client was evicted")
	}
}
