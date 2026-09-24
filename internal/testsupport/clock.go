package testsupport

import (
	"sync"
	"testing"
	"time"

	"github.com/qredin/qredin/pkg/clock"
)

// Clock is a controllable clock.Clock for tests.
//
// Time-dependent security behaviour is only meaningfully tested at its
// boundaries: the instant an SVID expires, the instant an authority leaves its
// overlap window. A test that reaches for time.Sleep to get there is a test
// that is slow and flaky in exchange for less precision.
//
// Safe for concurrent use, so a test can advance time while goroutines read it.
type Clock struct {
	mu  sync.RWMutex
	now time.Time
}

var _ clock.Clock = (*Clock)(nil)

// NewClock returns a Clock reading now.
func NewClock(tb testing.TB, now time.Time) *Clock {
	tb.Helper()
	if now.IsZero() {
		tb.Fatal("testsupport.NewClock: refusing a zero time; pin an explicit instant " +
			"so the test's expectations are readable")
	}
	return &Clock{now: now}
}

// Now implements clock.Clock.
func (c *Clock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

// Set moves the clock to t.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// Advance moves the clock forward by d. A negative d moves it backwards, which
// is how a test reproduces a host whose clock is behind the issuer's.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
