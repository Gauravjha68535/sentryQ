package main

import (
	"sync"
	"time"
)

// ipRateLimiter is a simple sliding-window rate limiter keyed by client IP.
type ipRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
}

// allow returns true when the IP has fewer than maxReqs requests in the last window.
func (rl *ipRateLimiter) allow(ip string, maxReqs int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-window)
	prev := rl.requests[ip]
	var valid []time.Time
	for _, t := range prev {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= maxReqs {
		rl.requests[ip] = valid
		return false
	}
	rl.requests[ip] = append(valid, now)
	return true
}

// cleanup removes entries older than maxAge from the rate limiter map,
// preventing unbounded memory growth on long-running servers.
func (rl *ipRateLimiter) cleanup(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for ip, times := range rl.requests {
		var valid []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = valid
		}
	}
}

// scanRateLimiter limits scan-triggering endpoints to 10 requests/min per IP.
var scanRateLimiter = &ipRateLimiter{requests: make(map[string][]time.Time)}

// reportRateLimiter limits report download endpoints to 30 requests/min per IP.
// Report generation (PDF/HTML/SARIF) is CPU-heavy; this prevents DoS via
// repeated regeneration requests.
var reportRateLimiter = &ipRateLimiter{requests: make(map[string][]time.Time)}

func init() {
	// Cleanup every 90 seconds — must be less than the 2-minute window so stale
	// entries don't accumulate between ticks.
	go func() {
		ticker := time.NewTicker(90 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			scanRateLimiter.cleanup(2 * time.Minute)
			reportRateLimiter.cleanup(2 * time.Minute)
		}
	}()
}
