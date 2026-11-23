package vfs

import (
	"strings"
	"sync"
)

// Limiter caps concurrent transfers per user across every connection the
// user holds. Acquire never blocks: a transfer over the cap fails at once.
// A nil Limiter, or one built with a cap of zero or less, is unlimited.
type Limiter struct {
	mu     sync.Mutex
	max    int
	active map[string]int
}

// NewLimiter returns a Limiter that allows maxPerUser concurrent transfers
// for each user.
func NewLimiter(maxPerUser int) *Limiter {
	return &Limiter{max: maxPerUser, active: make(map[string]int)}
}

// Acquire takes one transfer slot for user. It returns a release function
// that gives the slot back; release is safe to call more than once. ok is
// false when the user is at the cap, and release is then nil.
func (l *Limiter) Acquire(user string) (release func(), ok bool) {
	if l == nil || l.max <= 0 {
		return func() {}, true
	}
	key := strings.ToLower(user)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[key] >= l.max {
		return nil, false
	}
	l.active[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.active[key]--
			if l.active[key] <= 0 {
				delete(l.active, key)
			}
		})
	}, true
}
