package services

import (
	"testing"
	"time"
)

func TestAdminRateLimiterBlocksAfterRepeatedFailures(t *testing.T) {
	limiter := NewAdminRateLimiter()
	base := time.Unix(1700000000, 0)
	limiter.now = func() time.Time { return base }

	for i := 0; i < AdminAuthMaxFailures-1; i++ {
		if allowed, _ := limiter.Allow("login", "127.0.0.1"); !allowed {
			t.Fatalf("unexpected block before reaching failure threshold at attempt %d", i+1)
		}
		limiter.RecordFailure("login", "127.0.0.1")
	}

	if allowed, _ := limiter.Allow("login", "127.0.0.1"); !allowed {
		t.Fatal("limiter should still allow the final pre-ban request")
	}
	if retryAfter := limiter.RecordFailure("login", "127.0.0.1"); retryAfter <= 0 {
		t.Fatal("expected final failure to trigger a ban")
	}

	if allowed, retryAfter := limiter.Allow("login", "127.0.0.1"); allowed || retryAfter <= 0 {
		t.Fatalf("expected limiter to block after repeated failures, got allowed=%v retryAfter=%v", allowed, retryAfter)
	}

	limiter.now = func() time.Time { return base.Add(AdminAuthLimitBanDuration + time.Minute) }
	if allowed, _ := limiter.Allow("login", "127.0.0.1"); !allowed {
		t.Fatal("expected limiter to allow requests after ban expiry")
	}
}
