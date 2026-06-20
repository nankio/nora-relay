package main

import (
	"sync"
	"time"
)

// keyLimiter is a single-key token-bucket rate limiter. Tokens accumulate at
// rate r/sec up to burst, and each allowed call consumes one token. It is safe
// for concurrent use.
type keyLimiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func (l *keyLimiter) allow(rate, burst float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * rate
	l.last = now
	if l.tokens > burst {
		l.tokens = burst
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// rateLimiter holds per-key token-bucket limiters and prunes entries that have
// been idle longer than ttl to keep the map bounded.
type rateLimiter struct {
	mu    sync.Mutex
	keys  map[string]*keyLimiter
	rate  float64
	burst float64
	ttl   time.Duration
}

func newRateLimiter(rate, burst float64, ttl time.Duration) *rateLimiter {
	return &rateLimiter{
		keys:  make(map[string]*keyLimiter),
		rate:  rate,
		burst: burst,
		ttl:   ttl,
	}
}

func (rl *rateLimiter) allow(keyID string) bool {
	rl.mu.Lock()
	kl, ok := rl.keys[keyID]
	if !ok {
		kl = &keyLimiter{tokens: rl.burst, last: time.Now()}
		rl.keys[keyID] = kl
	}
	rl.mu.Unlock()
	return kl.allow(rl.rate, rl.burst)
}

// prune removes limiters that have been idle longer than ttl.
func (rl *rateLimiter) prune() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-rl.ttl)
	for id, kl := range rl.keys {
		kl.mu.Lock()
		idle := kl.last.Before(cutoff)
		kl.mu.Unlock()
		if idle {
			delete(rl.keys, id)
		}
	}
}
