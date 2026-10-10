package api

import (
	"fmt"
	"testing"
	"time"
)

// fillAuthThrottleWithLiveLockouts12182 fills the tracker to exactly
// authThrottleMaxEntries with live lockouts: 2048 distinct sources each fail
// authThrottleSourceFailures times under the api-key identity (no global
// bucket, so exactly two buckets per identity). Every account bucket locks at
// its 5-failure threshold and every source bucket at its 20-failure threshold,
// all with lockedUntil 5 minutes in the future of the frozen clock.
func fillAuthThrottleWithLiveLockouts12182(t *testing.T, tracker *authFailureTracker, now time.Time) {
	t.Helper()
	const account = authThrottleAPIKeyAccount
	identities := authThrottleMaxEntries / 2
	for i := 0; i < identities; i++ {
		source := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		for range authThrottleSourceFailures {
			tracker.recordFailure(source, account)
		}
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if got := tracker.entryCountLocked(); got != authThrottleMaxEntries {
		t.Fatalf("fixture filled %d entries, want exactly %d", got, authThrottleMaxEntries)
	}
	for key, bucket := range tracker.accounts {
		if !now.Before(bucket.lockedUntil) {
			t.Fatalf("fixture account bucket %q not live-locked: %+v", key, bucket)
		}
	}
	for key, bucket := range tracker.sources {
		if !now.Before(bucket.lockedUntil) {
			t.Fatalf("fixture source bucket %q not live-locked: %+v", key, bucket)
		}
	}
}

// countLiveLockedBuckets12182 counts buckets whose lockout is still live at
// now across all three tracker tables.
func countLiveLockedBuckets12182(tracker *authFailureTracker, now time.Time) (live, total int) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	for _, tables := range []map[string]*authFailureBucket{tracker.accounts, tracker.globalAccounts, tracker.sources} {
		for _, bucket := range tables {
			total++
			if now.Before(bucket.lockedUntil) {
				live++
			}
		}
	}
	return live, total
}

// TestAuthThrottleFullOfLiveLockoutsRefusesAdmission12182 is the #12182
// regression: a table full of live lockouts must refuse new admission without
// erasing any victim's Retry-After. Pre-fix, makeRoomLocked's random phase
// evicts live lockouts (evictable ignores lockedUntil) and the fresh
// reservation succeeds.
func TestAuthThrottleFullOfLiveLockoutsRefusesAdmission12182(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tracker := newAuthFailureTracker(func() time.Time { return now })
	fillAuthThrottleWithLiveLockouts12182(t, tracker, now)

	const victimSource = "198.51.0.0"
	if locked, wait := tracker.locked(victimSource, authThrottleAPIKeyAccount); !locked || wait != authThrottleBaseLockout {
		t.Fatalf("victim lockout before pressure = (%v, %v), want (true, %v)", locked, wait, authThrottleBaseLockout)
	}

	_, retry := tracker.reserve("203.0.113.9", authThrottleAPIKeyAccount)
	if retry <= 0 {
		t.Fatal("reserve on a table full of live lockouts was admitted, want refusal with retry-after")
	}

	live, total := countLiveLockedBuckets12182(tracker, now)
	if total != authThrottleMaxEntries || live != authThrottleMaxEntries {
		t.Fatalf("after refused admission live/total buckets = %d/%d, want %d/%d: live lockouts were evicted",
			live, total, authThrottleMaxEntries, authThrottleMaxEntries)
	}
	if locked, wait := tracker.locked(victimSource, authThrottleAPIKeyAccount); !locked || wait != authThrottleBaseLockout {
		t.Fatalf("victim lockout after pressure = (%v, %v), want (true, %v): Retry-After erased", locked, wait, authThrottleBaseLockout)
	}
}

// TestAuthThrottleFullOfExpiredBucketsStillAdmits12182 guards the anti-OOM
// doctrine against over-refusal: once every bucket's lockout has expired and
// its quiet window has elapsed, the expired-first sweep must still free room
// and admit. Passes both pre- and post-fix.
func TestAuthThrottleFullOfExpiredBucketsStillAdmits12182(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tracker := newAuthFailureTracker(func() time.Time { return now })
	fillAuthThrottleWithLiveLockouts12182(t, tracker, now)

	now = now.Add(authThrottleMaxLockout + authThrottleWindow + time.Minute)
	reservation, retry := tracker.reserve("203.0.113.9", authThrottleAPIKeyAccount)
	if retry != 0 {
		t.Fatalf("reserve on a table of fully-expired buckets refused with retry-after %v, want admission", retry)
	}
	tracker.complete(&reservation, false, "", false)

	tracker.mu.Lock()
	total := tracker.entryCountLocked()
	tracker.mu.Unlock()
	if total > authThrottleMaxEntries {
		t.Fatalf("table holds %d entries after expired sweep, want within budget %d", total, authThrottleMaxEntries)
	}
}

// TestAuthThrottleFullOfLiveLockoutsLegacyInsertionRefuses12182 is the #12182
// R1 fold-in: the legacy recordFailure insertion path must also refuse new
// buckets when the shared table is full of live lockouts, instead of growing
// past authThrottleMaxEntries. Pre-fix, one recordFailure on a full table
// grew it to 4097 entries.
func TestAuthThrottleFullOfLiveLockoutsLegacyInsertionRefuses12182(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tracker := newAuthFailureTracker(func() time.Time { return now })
	fillAuthThrottleWithLiveLockouts12182(t, tracker, now)

	const victimSource = "198.51.0.0"
	// New API-key identity: exercises the account + source legacy accessors.
	tracker.recordFailure("203.0.113.251", authThrottleAPIKeyAccount)
	// New Basic identity: additionally exercises the global-account accessor.
	const pressureBasic = authThrottleBasicAccountPrefix + "pressure-victim"
	tracker.recordFailure("203.0.113.252", pressureBasic)

	live, total := countLiveLockedBuckets12182(tracker, now)
	if total != authThrottleMaxEntries || live != authThrottleMaxEntries {
		t.Fatalf("after legacy pressure live/total buckets = %d/%d, want %d/%d: capacity exceeded or live lockouts evicted",
			live, total, authThrottleMaxEntries, authThrottleMaxEntries)
	}
	tracker.mu.Lock()
	_, accountInserted := tracker.accounts["203.0.113.251\x00"+authThrottleAPIKeyAccount]
	_, sourceInserted := tracker.sources["203.0.113.251"]
	_, globalInserted := tracker.globalAccounts[pressureBasic]
	tracker.mu.Unlock()
	if accountInserted || sourceInserted || globalInserted {
		t.Fatalf("legacy insertion admitted new buckets on a full live table (account=%v source=%v global=%v), want refusal",
			accountInserted, sourceInserted, globalInserted)
	}
	if locked, wait := tracker.locked(victimSource, authThrottleAPIKeyAccount); !locked || wait != authThrottleBaseLockout {
		t.Fatalf("victim lockout after legacy pressure = (%v, %v), want (true, %v): Retry-After erased", locked, wait, authThrottleBaseLockout)
	}

	// Existing identities remain lookup-safe without growing the table; the
	// live lockout drops this failure.
	tracker.recordFailure(victimSource, authThrottleAPIKeyAccount)
	live, total = countLiveLockedBuckets12182(tracker, now)
	if total != authThrottleMaxEntries || live != authThrottleMaxEntries {
		t.Fatalf("after existing-identity failure live/total = %d/%d, want %d/%d",
			live, total, authThrottleMaxEntries, authThrottleMaxEntries)
	}
}
