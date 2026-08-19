package main

import (
	"testing"
	"time"
)

func TestIPRateLimiterAllow(t *testing.T) {
	tests := []struct {
		name      string
		maxReqs   int
		window    time.Duration
		calls     int
		wantAllow []bool
	}{
		{
			name:      "under limit allows all",
			maxReqs:   3,
			window:    time.Minute,
			calls:     3,
			wantAllow: []bool{true, true, true},
		},
		{
			name:      "at limit blocks next",
			maxReqs:   2,
			window:    time.Minute,
			calls:     3,
			wantAllow: []bool{true, true, false},
		},
		{
			name:      "limit of 1 blocks second",
			maxReqs:   1,
			window:    time.Minute,
			calls:     2,
			wantAllow: []bool{true, false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := &ipRateLimiter{requests: make(map[string][]time.Time)}
			ip := "127.0.0.1"
			for i, want := range tt.wantAllow {
				got := rl.allow(ip, tt.maxReqs, tt.window)
				if got != want {
					t.Errorf("call %d: allow() = %v, want %v", i+1, got, want)
				}
			}
		})
	}
}

func TestIPRateLimiterCleanup(t *testing.T) {
	rl := &ipRateLimiter{requests: make(map[string][]time.Time)}
	ip := "10.0.0.1"

	// Add a request and verify it exists
	rl.allow(ip, 10, time.Hour)
	rl.mu.Lock()
	if len(rl.requests[ip]) == 0 {
		t.Fatal("expected request to be recorded")
	}
	rl.mu.Unlock()

	// Cleanup with a very short maxAge removes the entry
	rl.cleanup(time.Nanosecond)
	rl.mu.Lock()
	if len(rl.requests[ip]) != 0 {
		t.Errorf("expected entry to be cleaned up, got %d entries", len(rl.requests[ip]))
	}
	rl.mu.Unlock()
}

func TestIPRateLimiterMultipleIPs(t *testing.T) {
	rl := &ipRateLimiter{requests: make(map[string][]time.Time)}

	// Each IP has its own bucket
	for i := 0; i < 5; i++ {
		if !rl.allow("1.1.1.1", 5, time.Minute) {
			t.Errorf("call %d for IP1 should be allowed", i+1)
		}
		if !rl.allow("2.2.2.2", 5, time.Minute) {
			t.Errorf("call %d for IP2 should be allowed", i+1)
		}
	}
	// Both IPs now at limit
	if rl.allow("1.1.1.1", 5, time.Minute) {
		t.Error("IP1 should be rate-limited")
	}
	if rl.allow("2.2.2.2", 5, time.Minute) {
		t.Error("IP2 should be rate-limited")
	}
}
