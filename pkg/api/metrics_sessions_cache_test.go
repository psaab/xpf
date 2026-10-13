package api

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane"
)

// countingSessionDP is an apiRuntimeDataPlane whose session iterators emit a
// fixed set of forward entries and count how many times the v4 iterator ran —
// one v4 iteration == one full conntrack walk from collectSessionGauges. It
// backs the #4162 cache tests: they assert the walk count against the scrape
// count to prove the walk rate is decoupled from the scrape rate.
//
// When gate is non-nil the v4 iterator blocks receiving from it before
// enumerating, so a test can hold one walk in flight while other goroutines
// pile up — proving singleflight coalescing (they attach to the in-flight walk
// rather than each starting their own).
type countingSessionDP struct {
	*dataplane.Manager
	walks   atomic.Int64
	entered chan struct{} // signalled once when a v4 walk begins (optional)
	gate    chan struct{} // v4 walk blocks until closed/received (optional)
	v4      []dataplane.SessionValue
	v6      []dataplane.SessionValueV6
}

func (d *countingSessionDP) IsLoaded() bool { return true }

func (d *countingSessionDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	d.walks.Add(1)
	if d.entered != nil {
		select {
		case d.entered <- struct{}{}:
		default:
		}
	}
	if d.gate != nil {
		<-d.gate
	}
	for _, v := range d.v4 {
		if !fn(dataplane.SessionKey{}, v) {
			break
		}
	}
	return nil
}

func (d *countingSessionDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for _, v := range d.v6 {
		if !fn(dataplane.SessionKeyV6{}, v) {
			break
		}
	}
	return nil
}

// drainCollect runs collectSessionGauges and discards the emitted metrics.
func drainCollect(c *xpfCollector, dp apiRuntimeDataPlane) {
	ch := make(chan prometheus.Metric, 32)
	go func() {
		c.collectSessionGauges(ch, dp)
		close(ch)
	}()
	for range ch { //nolint:revive // draining
	}
}

// TestSessionGaugeCacheWalksOncePerTTL asserts the #4162 primary fix: rapid
// repeated scrapes within one TTL window trigger exactly ONE conntrack walk,
// not one per scrape.
//
// FAIL-ON-REVERT: removing the TTL cache (walking on every Collect) makes the
// walk count equal the scrape count (numScrapes), flipping the == 1 assertion.
func TestSessionGaugeCacheWalksOncePerTTL(t *testing.T) {
	c := newSessionGaugeCollector()
	c.sessionGaugeTTLOverride = time.Hour // never expires during the test
	dp := &countingSessionDP{
		Manager: dataplane.New(),
		v4:      []dataplane.SessionValue{{IsReverse: 0}},
	}

	const numScrapes = 25
	for i := 0; i < numScrapes; i++ {
		drainCollect(c, dp)
	}

	if got := dp.walks.Load(); got != 1 {
		t.Fatalf("conntrack walks = %d over %d scrapes within one TTL; want 1 (cache not decoupling walk rate from scrape rate)", got, numScrapes)
	}
}

// TestSessionGaugeCacheRefreshesAfterTTL asserts the cache is a freshness
// window, not a permanent latch: once the snapshot ages past the TTL, the next
// scrape performs a fresh walk.
func TestSessionGaugeCacheRefreshesAfterTTL(t *testing.T) {
	c := newSessionGaugeCollector()
	c.sessionGaugeTTLOverride = time.Hour
	dp := &countingSessionDP{
		Manager: dataplane.New(),
		v4:      []dataplane.SessionValue{{IsReverse: 0}},
	}

	drainCollect(c, dp) // walk 1, snapshot cached
	if got := dp.walks.Load(); got != 1 {
		t.Fatalf("after first scrape walks = %d, want 1", got)
	}
	drainCollect(c, dp) // served from cache
	if got := dp.walks.Load(); got != 1 {
		t.Fatalf("second scrape within TTL walked again: walks = %d, want 1", got)
	}

	// Force the snapshot past its TTL without sleeping (in-package access).
	c.sessionGaugeMu.Lock()
	c.sessionGaugeComputedAt = time.Now().Add(-2 * time.Hour)
	c.sessionGaugeMu.Unlock()

	drainCollect(c, dp) // stale => refresh walk
	if got := dp.walks.Load(); got != 2 {
		t.Fatalf("scrape after TTL expiry did not refresh: walks = %d, want 2", got)
	}
}

// TestSessionGaugeCacheCoalescesConcurrentScrapes asserts singleflight
// coalescing: many concurrent scrapes that all miss the cache collapse onto a
// SINGLE in-flight walk rather than each launching their own.
//
// FAIL-ON-REVERT: removing the singleflight (or the cache) lets each concurrent
// scrape walk independently, so walks jumps toward numGoroutines.
func TestSessionGaugeCacheCoalescesConcurrentScrapes(t *testing.T) {
	c := newSessionGaugeCollector()
	c.sessionGaugeTTLOverride = time.Hour
	dp := &countingSessionDP{
		Manager: dataplane.New(),
		entered: make(chan struct{}, 1),
		gate:    make(chan struct{}),
		v4:      []dataplane.SessionValue{{IsReverse: 0}},
	}

	const numGoroutines = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release all at once
			drainCollect(c, dp)
		}()
	}
	close(start)

	// Wait until the single elected walker is in flight and blocked on the
	// gate, then give stragglers a moment to reach singleflight.Do and attach
	// to the in-flight call before releasing the walk.
	<-dp.entered
	time.Sleep(30 * time.Millisecond)
	close(dp.gate)
	wg.Wait()

	if got := dp.walks.Load(); got != 1 {
		t.Fatalf("concurrent scrapes fanned out to %d walks; want 1 (singleflight not coalescing)", got)
	}
}

// TestSessionGaugeCacheValuesCorrect asserts the cached aggregates equal a
// fresh, cache-bypassing walk of the same table — the cache must not distort
// the seven counts (active/established/ipv4/ipv6/snat/dnat), and reverse
// entries (IsReverse==1) must be excluded exactly as the uncached walk excludes
// them.
func TestSessionGaugeCacheValuesCorrect(t *testing.T) {
	dp := &countingSessionDP{
		Manager: dataplane.New(),
		v4: []dataplane.SessionValue{
			{IsReverse: 0, State: dataplane.SessStateEstablished},
			{IsReverse: 0, State: dataplane.SessStateEstablished, Flags: dataplane.SessFlagSNAT},
			{IsReverse: 0, Flags: dataplane.SessFlagDNAT},
			{IsReverse: 1, State: dataplane.SessStateEstablished}, // reverse: ignored
		},
		v6: []dataplane.SessionValueV6{
			{IsReverse: 0, State: dataplane.SessStateEstablished, Flags: dataplane.SessFlagSNAT | dataplane.SessFlagDNAT},
			{IsReverse: 1}, // reverse: ignored
		},
	}

	// Independent expectation.
	// v4 forward: 3 (2 established, 1 snat, 1 dnat). v6 forward: 1 (established,
	// snat, dnat). Totals: active=4, established=3, ipv4=3, ipv6=1, snat=2,
	// dnat=2.
	want := sessionGaugeSnapshot{active: 4, established: 3, ipv4: 3, ipv6: 1, snat: 2, dnat: 2}

	// Fresh, cache-bypassing walk.
	fresh, err := walkSessionGauges(dp)
	if err != nil {
		t.Fatalf("walkSessionGauges: %v", err)
	}
	if fresh != want {
		t.Fatalf("fresh walk = %+v, want %+v", fresh, want)
	}

	// Cached path must match the fresh walk.
	c := newSessionGaugeCollector()
	c.sessionGaugeTTLOverride = time.Hour
	got, ok := c.sessionGaugeSnapshotCached(dp)
	if !ok {
		t.Fatal("sessionGaugeSnapshotCached returned ok=false on a healthy walk")
	}
	if got != want {
		t.Fatalf("cached snapshot = %+v, want %+v (== fresh walk)", got, want)
	}
}
func TestSessionGaugeCanceledFollowerAbandonsSharedWalk12609(t *testing.T) {
	c := newSessionGaugeCollector()
	c.sessionGaugeTTLOverride = time.Hour
	dp := &countingSessionDP{
		Manager: dataplane.New(),
		entered: make(chan struct{}, 1),
		gate:    make(chan struct{}),
		v4:      []dataplane.SessionValue{{IsReverse: 0}},
	}

	type result struct {
		snapshot sessionGaugeSnapshot
		ok       bool
	}
	leaderDone := make(chan result, 1)
	go func() {
		snapshot, ok := c.sessionGaugeSnapshotCachedContext(context.Background(), dp)
		leaderDone <- result{snapshot: snapshot, ok: ok}
	}()
	<-dp.entered

	ctx, cancel := context.WithCancel(context.Background())
	followerDone := make(chan result, 1)
	go func() {
		snapshot, ok := c.sessionGaugeSnapshotCachedContext(ctx, dp)
		followerDone <- result{snapshot: snapshot, ok: ok}
	}()
	// Let the second scrape join the in-flight refresh before canceling it.
	time.Sleep(30 * time.Millisecond)
	cancel()

	var follower result
	followerReturned := false
	select {
	case follower = <-followerDone:
		followerReturned = true
	case <-time.After(250 * time.Millisecond):
	}

	// Always release the leader, including on the old blocking-Do behavior, so
	// a failed assertion does not leak a goroutine.
	close(dp.gate)
	leader := <-leaderDone
	if !followerReturned {
		<-followerDone
		t.Fatal("canceled follower stayed blocked until the leader's walk finished")
	}
	if follower.ok || follower.snapshot != (sessionGaugeSnapshot{}) {
		t.Fatalf("canceled follower received snapshot %+v with ok=%v, want no successful snapshot", follower.snapshot, follower.ok)
	}
	if !leader.ok || leader.snapshot.active != 1 {
		t.Fatalf("leader result = (%+v, %v), want one successful active session", leader.snapshot, leader.ok)
	}
	if got := dp.walks.Load(); got != 1 {
		t.Fatalf("shared conntrack walks = %d, want one", got)
	}
}
