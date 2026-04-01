package services

import (
	"fmt"
	"sync"
	"time"
)

const (
	AdminAuthLimitWindow      = 15 * time.Minute
	AdminAuthLimitBanDuration = 30 * time.Minute
	AdminAuthMaxFailures      = 5
)

type adminRateLimitEntry struct {
	FailedAt    []time.Time
	LockedUntil time.Time
}

type AdminRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*adminRateLimitEntry
	now     func() time.Time
}

func NewAdminRateLimiter() *AdminRateLimiter {
	return &AdminRateLimiter{
		entries: make(map[string]*adminRateLimitEntry),
		now:     time.Now,
	}
}

func (l *AdminRateLimiter) Allow(scope string, subject string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	entry := l.getEntryLocked(scope, subject)
	l.pruneEntryLocked(entry, now)

	if entry.LockedUntil.After(now) {
		return false, entry.LockedUntil.Sub(now)
	}
	return true, 0
}

func (l *AdminRateLimiter) RecordFailure(scope string, subject string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	entry := l.getEntryLocked(scope, subject)
	l.pruneEntryLocked(entry, now)
	entry.FailedAt = append(entry.FailedAt, now)
	if len(entry.FailedAt) >= AdminAuthMaxFailures {
		entry.FailedAt = nil
		entry.LockedUntil = now.Add(AdminAuthLimitBanDuration)
		return AdminAuthLimitBanDuration
	}
	return 0
}

func (l *AdminRateLimiter) RecordSuccess(scope string, subject string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, l.rateLimitKey(scope, subject))
}

func (l *AdminRateLimiter) rateLimitKey(scope string, subject string) string {
	return fmt.Sprintf("%s:%s", scope, subject)
}

func (l *AdminRateLimiter) getEntryLocked(scope string, subject string) *adminRateLimitEntry {
	key := l.rateLimitKey(scope, subject)
	entry, ok := l.entries[key]
	if !ok {
		entry = &adminRateLimitEntry{}
		l.entries[key] = entry
	}
	return entry
}

func (l *AdminRateLimiter) pruneEntryLocked(entry *adminRateLimitEntry, now time.Time) {
	if entry == nil {
		return
	}
	if entry.LockedUntil.Before(now) {
		entry.LockedUntil = time.Time{}
	}
	if len(entry.FailedAt) == 0 {
		return
	}

	kept := entry.FailedAt[:0]
	for _, failedAt := range entry.FailedAt {
		if now.Sub(failedAt) <= AdminAuthLimitWindow {
			kept = append(kept, failedAt)
		}
	}
	entry.FailedAt = kept
}
