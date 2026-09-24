// Package clock provides an injectable source of time.
//
// Every security decision in Qredin is time-dependent: an SVID is valid inside
// a window, an authority is active inside a window, a capability token expires,
// an audit record is ordered by when it happened. Code that reads the wall
// clock directly cannot be tested at the boundaries of those windows, and the
// boundaries are precisely where the interesting failures live — a certificate
// that expires one second into a request, an authority rotated out while a
// stream is open.
//
// The .golangci.yml configuration forbids time.Now inside the security-critical
// packages for this reason. Those packages take a Clock instead.
//
// A Clock must be safe for concurrent use.
package clock

import "time"

// Clock reports the current time.
//
// The interface is deliberately one method. Timers and tickers are not part of
// it: faking them correctly requires a scheduler, and the packages that need
// them (rotation loops, backoff) are better served by an explicit Waiter that
// can be swapped for a channel a test drives directly.
type Clock interface {
	Now() time.Time
}

// Func adapts a function to Clock.
type Func func() time.Time

// Now implements Clock.
func (f Func) Now() time.Time { return f() }

type systemClock struct{}

// Now implements Clock, returning the wall-clock time.
func (systemClock) Now() time.Time { return time.Now() }

// System returns the wall clock. This is the only place in Qredin that reads it
// directly; everything else takes a Clock so that it can be tested.
func System() Clock { return systemClock{} }

// OrSystem returns c, or the system clock when c is nil.
//
// Constructors use this so that a zero-valued options struct is usable rather
// than a nil-pointer panic waiting to happen on a code path that only runs in
// production.
func OrSystem(c Clock) Clock {
	if c == nil {
		return System()
	}
	return c
}
