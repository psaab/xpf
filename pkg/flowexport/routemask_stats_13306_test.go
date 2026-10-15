package flowexport

import (
	"net"
	"testing"
	"time"
)

// #13306 (D6-05): routeMaskCache silently wiped the whole map at the size
// cap, dropped background lookups at the inflight cap, and cached FIB
// lookup failures — all with zero counters. These tests pin the counters.

func mkCache13306(maxSize, maxInflight int, lookup func(net.IP, int) (uint8, bool)) *routeMaskCache {
	return &routeMaskCache{
		ttl:         time.Hour,
		maxSize:     maxSize,
		maxInflight: maxInflight,
		lookup:      lookup,
		entries:     make(map[routeMaskKey]routeMaskEntry),
		pending:     make(map[routeMaskKey]struct{}),
	}
}

func TestRouteMaskCacheStatsCounters_13306(t *testing.T) {
	okLookup := func(net.IP, int) (uint8, bool) { return 24, true }

	t.Run("full clear counted", func(t *testing.T) {
		c := mkCache13306(2, 4, okLookup)
		now := time.Now()
		c.mu.Lock()
		c.storeLocked(routeMaskKey{ip: "a"}, 24, true, now)
		c.storeLocked(routeMaskKey{ip: "b"}, 24, true, now)
		c.storeLocked(routeMaskKey{ip: "c"}, 24, true, now) // at cap, none expired -> clear
		c.mu.Unlock()
		s := c.Stats()
		if s.FullClears != 1 {
			t.Fatalf("FullClears=%d want 1", s.FullClears)
		}
		if _, ok := c.entries[routeMaskKey{ip: "c"}]; !ok {
			t.Fatalf("new entry missing after clear")
		}
	})

	t.Run("inflight drop counted, dedup not", func(t *testing.T) {
		c := mkCache13306(0, 1, okLookup)
		c.mu.Lock()
		c.pending[routeMaskKey{ip: "x"}] = struct{}{}
		c.inflight = 1
		c.scheduleLookupLocked(routeMaskKey{ip: "y"}, net.IPv4(10, 0, 0, 1), 0)
		c.scheduleLookupLocked(routeMaskKey{ip: "x"}, net.IPv4(10, 0, 0, 2), 0) // dedup
		c.mu.Unlock()
		if s := c.Stats(); s.InflightDrops != 1 {
			t.Fatalf("InflightDrops=%d want 1", s.InflightDrops)
		}
	})

	t.Run("lookup error counted", func(t *testing.T) {
		c := mkCache13306(0, 4, func(net.IP, int) (uint8, bool) { return 0, false })
		done := make(chan struct{}, 1)
		c.afterPopulate = func() { done <- struct{}{} }
		if _, ok := c.resolve(net.IPv4(192, 0, 2, 1), 0); ok {
			t.Fatal("cold resolve must be miss")
		}
		<-done
		s := c.Stats()
		if s.LookupErrors != 1 || s.Misses != 1 {
			t.Fatalf("stats=%+v want LookupErrors=1 Misses=1", s)
		}
		if s.Entries != 1 {
			t.Fatalf("Entries=%d want 1 (negative entry cached)", s.Entries)
		}
	})

	t.Run("hit counted", func(t *testing.T) {
		c := mkCache13306(0, 4, okLookup)
		now := time.Now()
		c.mu.Lock()
		c.storeLocked(routeMaskKey{ip: string(net.IPv4(10, 0, 0, 9).To16())}, 24, true, now)
		c.mu.Unlock()
		if m, ok := c.resolve(net.IPv4(10, 0, 0, 9), 0); !ok || m != 24 {
			t.Fatalf("resolve=%d,%v want 24,true", m, ok)
		}
		if s := c.Stats(); s.Hits != 1 {
			t.Fatalf("Hits=%d want 1", s.Hits)
		}
	})
}
