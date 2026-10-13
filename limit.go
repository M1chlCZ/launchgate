package main

import (
	"sync"
	"time"
)

const (
	maxFailuresPerIP         = 20
	maxFailuresPerInvitation = 5
	failureWindow            = 15 * time.Minute
	limiterCapacity          = 4096
)

type failureLimiter struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	capacity int
	now      func() time.Time
	entries  map[string]failureEntry
}

type failureEntry struct {
	count int
	start time.Time
}

func newFailureLimiter(max int, window time.Duration, capacity int, now func() time.Time) *failureLimiter {
	return &failureLimiter{max: max, window: window, capacity: capacity, now: now, entries: map[string]failureEntry{}}
}

func (limiter *failureLimiter) locked(key string) (time.Duration, bool) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	entry, ok := limiter.entries[key]
	if !ok {
		return 0, false
	}
	if now.Sub(entry.start) >= limiter.window {
		delete(limiter.entries, key)
		return 0, false
	}
	if entry.count < limiter.max {
		return 0, false
	}
	return entry.start.Add(limiter.window).Sub(now), true
}

func (limiter *failureLimiter) fail(key string) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	entry, ok := limiter.entries[key]
	if ok && now.Sub(entry.start) >= limiter.window {
		delete(limiter.entries, key)
		ok = false
	}
	if !ok {
		limiter.makeRoom(now)
		entry = failureEntry{start: now}
	}
	entry.count++
	limiter.entries[key] = entry
}

func (limiter *failureLimiter) clear(key string) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	delete(limiter.entries, key)
}

func (limiter *failureLimiter) makeRoom(now time.Time) {
	if len(limiter.entries) < limiter.capacity {
		return
	}
	for key, entry := range limiter.entries {
		if now.Sub(entry.start) >= limiter.window {
			delete(limiter.entries, key)
		}
	}
	for len(limiter.entries) >= limiter.capacity {
		oldestKey, oldestStart := "", now
		for key, entry := range limiter.entries {
			if oldestKey == "" || entry.start.Before(oldestStart) {
				oldestKey, oldestStart = key, entry.start
			}
		}
		delete(limiter.entries, oldestKey)
	}
}
