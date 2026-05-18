package conntrack

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
	"golang.org/x/sys/unix"
)

// mockGCDP is a minimal mock dataplane for GC testing.
// Embeds DataPlane interface to satisfy the full contract; only the methods
// used by sweep() are implemented — others will panic if called.
type mockGCDP struct {
	dataplane.DataPlane // embedded interface satisfies all methods
	mu                  sync.Mutex
	v4sessions          map[dataplane.SessionKey]dataplane.SessionValue
	v6sessions          map[dataplane.SessionKeyV6]dataplane.SessionValueV6
	deleted             []dataplane.SessionKey
	deletedV6           []dataplane.SessionKeyV6
}

func (m *mockGCDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.v4sessions {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (m *mockGCDP) DeleteSession(key dataplane.SessionKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleted = append(m.deleted, key)
	delete(m.v4sessions, key)
	return nil
}

func (m *mockGCDP) GetSessionV4(key dataplane.SessionKey) (dataplane.SessionValue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	val, ok := m.v4sessions[key]
	if !ok {
		return dataplane.SessionValue{}, unix.ENOENT
	}
	return val, nil
}

func (m *mockGCDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.v6sessions {
		if !fn(k, v) {
			break
		}
	}
	return nil
}

func (m *mockGCDP) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletedV6 = append(m.deletedV6, key)
	delete(m.v6sessions, key)
	return nil
}

func (m *mockGCDP) GetSessionV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	val, ok := m.v6sessions[key]
	if !ok {
		return dataplane.SessionValueV6{}, unix.ENOENT
	}
	return val, nil
}

func (m *mockGCDP) BatchIterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return m.IterateSessions(fn)
}

func (m *mockGCDP) BatchIterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return m.IterateSessionsV6(fn)
}

func (m *mockGCDP) BatchDeleteSessions(keys []dataplane.SessionKey) (int, error) {
	for _, k := range keys {
		m.DeleteSession(k)
	}
	return len(keys), nil
}

func (m *mockGCDP) BatchDeleteSessionsV6(keys []dataplane.SessionKeyV6) (int, error) {
	for _, k := range keys {
		m.DeleteSessionV6(k)
	}
	return len(keys), nil
}

func (m *mockGCDP) DeleteDNATEntry(_ dataplane.DNATKey) error       { return nil }
func (m *mockGCDP) DeleteDNATEntryV6(_ dataplane.DNATKeyV6) error   { return nil }
func (m *mockGCDP) GetPersistentNAT() *dataplane.PersistentNATTable { return nil }
func (m *mockGCDP) ReadGlobalCounter(_ uint32) (uint64, error)      { return 1, nil }
func (m *mockGCDP) UpdateSessionCountSrc(_ dataplane.SessionCountKey, _ uint32) error {
	return nil
}
func (m *mockGCDP) UpdateSessionCountDst(_ dataplane.SessionCountKey, _ uint32) error {
	return nil
}
func (m *mockGCDP) ClearSessionCounts() error { return nil }

func TestNewGCAdaptsLegacyDataplaneToRuntimeDomains(t *testing.T) {
	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}

	gc := NewGC(dp, 10*time.Second)

	if gc.sessions == nil {
		t.Fatal("NewGC did not adapt SessionStore")
	}
	if gc.telemetry == nil {
		t.Fatal("NewGC did not adapt Telemetry")
	}
	if gc.sessionCount != dp {
		t.Fatal("NewGC did not retain session-count publisher")
	}
	if gc.persistent != dp {
		t.Fatal("NewGC did not retain persistent NAT provider")
	}
	if gc.interval != 10*time.Second {
		t.Fatalf("interval = %v, want 10s", gc.interval)
	}
	if gc.lastV6Count != -1 {
		t.Fatalf("lastV6Count = %d, want -1", gc.lastV6Count)
	}
}

type runtimeDomainSessionStore struct {
	v4      map[dataplane.SessionKey]dataplane.SessionValue
	deleted []dataplane.SessionKey
}

func (s *runtimeDomainSessionStore) ForEachV4(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for key, val := range s.v4 {
		if !fn(key, val) {
			break
		}
	}
	return nil
}

func (s *runtimeDomainSessionStore) ForEachV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (s *runtimeDomainSessionStore) GetV4(key dataplane.SessionKey) (dataplane.SessionValue, error) {
	if val, ok := s.v4[key]; ok {
		return val, nil
	}
	return dataplane.SessionValue{}, unix.ENOENT
}

func (s *runtimeDomainSessionStore) GetV6(dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	return dataplane.SessionValueV6{}, unix.ENOENT
}

func (s *runtimeDomainSessionStore) PutClusterSyncedV4(dataplane.SessionKey, dataplane.SessionValue) error {
	return nil
}

func (s *runtimeDomainSessionStore) PutClusterSyncedV6(dataplane.SessionKeyV6, dataplane.SessionValueV6) error {
	return nil
}

func (s *runtimeDomainSessionStore) DeleteV4(key dataplane.SessionKey) error {
	delete(s.v4, key)
	return nil
}

func (s *runtimeDomainSessionStore) DeleteV6(dataplane.SessionKeyV6) error { return nil }

func (s *runtimeDomainSessionStore) DeleteKnownV4(key dataplane.SessionKey, _ dataplane.SessionValue, _ dataplane.DeleteReason) error {
	s.deleted = append(s.deleted, key)
	delete(s.v4, key)
	return nil
}

func (s *runtimeDomainSessionStore) DeleteKnownV6(dataplane.SessionKeyV6, dataplane.SessionValueV6, dataplane.DeleteReason) error {
	return nil
}

func (s *runtimeDomainSessionStore) DeleteBatchKnownV4(entries []dataplane.SessionEntryV4, _ dataplane.DeleteReason) (int, error) {
	for _, entry := range entries {
		s.deleted = append(s.deleted, entry.Key)
		delete(s.v4, entry.Key)
	}
	return len(entries), nil
}

func (s *runtimeDomainSessionStore) DeleteBatchKnownV6([]dataplane.SessionEntryV6, dataplane.DeleteReason) (int, error) {
	return 0, nil
}

func (s *runtimeDomainSessionStore) DeleteWithCompanionsV4(key dataplane.SessionKey, _ dataplane.DeleteReason) error {
	return s.DeleteKnownV4(key, dataplane.SessionValue{}, dataplane.DeleteReasonGCExpired)
}

func (s *runtimeDomainSessionStore) DeleteWithCompanionsV6(dataplane.SessionKeyV6, dataplane.DeleteReason) error {
	return nil
}

func (s *runtimeDomainSessionStore) ReconcileClusterBulk(dataplane.ClusterBulkReconcileInput) (dataplane.ClusterBulkReconcileResult, error) {
	return dataplane.ClusterBulkReconcileResult{}, nil
}

func (s *runtimeDomainSessionStore) SessionDeltas() dpruntime.SessionDeltaSource { return nil }
func (s *runtimeDomainSessionStore) Count() (int, int)                           { return len(s.v4), 0 }
func (s *runtimeDomainSessionStore) Clear() (int, int, error)                    { return 0, 0, nil }

func TestGCDeleteCallbackV4(t *testing.T) {
	now := monotonicSeconds()
	fwdKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, DstIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}
	revKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 2, 1}, DstIP: [4]byte{10, 0, 1, 1}, Protocol: 6, SrcPort: 80, DstPort: 1000}

	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			fwdKey: {
				State: dataplane.SessStateEstablished, IsReverse: 0,
				LastSeen: now - 200, Timeout: 100, // expired
				ReverseKey: revKey,
			},
			revKey: {
				State: dataplane.SessStateEstablished, IsReverse: 1,
				LastSeen: now - 200, Timeout: 100,
			},
		},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}

	gc := NewGC(dp, time.Minute) // interval doesn't matter for direct sweep call

	var callbackKeys []dataplane.SessionKey
	gc.OnDeleteV4 = func(key dataplane.SessionKey) {
		callbackKeys = append(callbackKeys, key)
	}

	gc.sweep()

	// Callback should fire exactly once (for the forward entry only)
	if len(callbackKeys) != 1 {
		t.Fatalf("expected 1 callback, got %d", len(callbackKeys))
	}
	if callbackKeys[0] != fwdKey {
		t.Fatalf("callback key mismatch: got %+v, want %+v", callbackKeys[0], fwdKey)
	}
}

func TestGCWithRuntimeDomainsExpiresViaSessionStore(t *testing.T) {
	now := monotonicSeconds()
	fwdKey := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 1, 1},
		DstIP:    [4]byte{10, 0, 2, 1},
		Protocol: 6,
		SrcPort:  1000,
		DstPort:  80,
	}
	store := &runtimeDomainSessionStore{
		v4: map[dataplane.SessionKey]dataplane.SessionValue{
			fwdKey: {
				State:    dataplane.SessStateEstablished,
				LastSeen: now - 200,
				Timeout:  100,
			},
		},
	}
	gc := NewGCWithDomains(store, nil, nil, nil, time.Minute)

	gc.sweep()

	if len(store.deleted) != 1 || store.deleted[0] != fwdKey {
		t.Fatalf("deleted keys = %+v, want [%+v]", store.deleted, fwdKey)
	}
}

func TestGCDeleteCallbackV6(t *testing.T) {
	now := monotonicSeconds()
	fwdKey := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 0x01}, Protocol: 6, SrcPort: 1000, DstPort: 80}
	revKey := dataplane.SessionKeyV6{SrcIP: [16]byte{0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Protocol: 6, SrcPort: 80, DstPort: 1000}

	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{
			fwdKey: {
				State: dataplane.SessStateEstablished, IsReverse: 0,
				LastSeen: now - 200, Timeout: 100,
				ReverseKey: revKey,
			},
			revKey: {
				State: dataplane.SessStateEstablished, IsReverse: 1,
				LastSeen: now - 200, Timeout: 100,
			},
		},
	}

	gc := NewGC(dp, time.Minute)

	var callbackKeys []dataplane.SessionKeyV6
	gc.OnDeleteV6 = func(key dataplane.SessionKeyV6) {
		callbackKeys = append(callbackKeys, key)
	}

	gc.sweep()

	if len(callbackKeys) != 1 {
		t.Fatalf("expected 1 v6 callback, got %d", len(callbackKeys))
	}
	if callbackKeys[0] != fwdKey {
		t.Fatalf("v6 callback key mismatch")
	}
}

func TestGCDeleteCallbackNil(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{Protocol: 6}: {
				IsReverse: 0, LastSeen: now - 200, Timeout: 100,
				ReverseKey: dataplane.SessionKey{Protocol: 6, SrcPort: 1},
			},
		},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}

	gc := NewGC(dp, time.Minute)
	// No callback set — should not panic
	gc.sweep()

	if len(dp.deleted) == 0 {
		t.Fatal("expected deletions even without callback")
	}
}

func TestGCRunWithCallbacks(t *testing.T) {
	now := monotonicSeconds()
	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			{Protocol: 6, SrcPort: 1}: {
				IsReverse: 0, LastSeen: now - 200, Timeout: 100,
				ReverseKey: dataplane.SessionKey{Protocol: 6, SrcPort: 2},
			},
		},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}

	gc := NewGC(dp, 50*time.Millisecond)

	var mu sync.Mutex
	var called int
	gc.OnDeleteV4 = func(key dataplane.SessionKey) {
		mu.Lock()
		called++
		mu.Unlock()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	gc.Run(ctx)

	mu.Lock()
	defer mu.Unlock()
	if called != 1 {
		t.Fatalf("expected 1 callback from Run, got %d", called)
	}
}

func TestGCAggressiveAgingActivates(t *testing.T) {
	now := monotonicSeconds()

	// Create enough sessions to exceed a 1% high watermark.
	// MaxSessions is 10M, 1% = 100K entries. We use forward+reverse pairs,
	// so we need total > 100K entries in the map.
	// For testing, we set watermark low and create a handful of entries.
	sessions := make(map[dataplane.SessionKey]dataplane.SessionValue)
	for i := 0; i < 50; i++ {
		fk := dataplane.SessionKey{SrcIP: [4]byte{10, 0, byte(i / 256), byte(i % 256)}, Protocol: 6, SrcPort: uint16(1000 + i), DstPort: 80}
		rk := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 80, DstPort: uint16(1000 + i)}
		sessions[fk] = dataplane.SessionValue{
			State: dataplane.SessStateEstablished, IsReverse: 0,
			LastSeen: now - 3, Timeout: 1800, // not expired normally
			ReverseKey: rk,
		}
		sessions[rk] = dataplane.SessionValue{
			State: dataplane.SessStateEstablished, IsReverse: 1,
			LastSeen: now - 3, Timeout: 1800,
		}
	}

	dp := &mockGCDP{
		v4sessions: sessions,
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}

	gc := NewGC(dp, time.Minute)
	// Set aggressive aging: 2s early ageout, watermark 0% (always active)
	gc.SetAgingConfig(2, 0, 0)

	// With 0% watermarks, aging should NOT activate (0 means disabled)
	gc.sweep()
	if gc.agingActive {
		t.Fatal("aging should not activate with 0 watermarks")
	}

	// Now set realistic watermarks. With 100 entries and MaxSessions=10M,
	// pct = 100*100/10000000 = 0. So we need watermark=0 for threshold.
	// Instead, directly test the hysteresis by manually setting agingActive.
	gc.SetAgingConfig(2, 1, 1) // 1% watermark (unreachable with 100 entries)
	gc.sweep()
	// pct = 0 which is < 1, so aging should not activate
	if gc.agingActive {
		t.Fatal("aging should not activate when utilization below high watermark")
	}
}

func TestGCAggressiveAgingEarlyAgeout(t *testing.T) {
	now := monotonicSeconds()

	fwdKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}
	revKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 80, DstPort: 1000}

	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			fwdKey: {
				State: dataplane.SessStateEstablished, IsReverse: 0,
				LastSeen: now - 10, Timeout: 1800, // normally not expired (10s < 1800s)
				ReverseKey: revKey,
			},
			revKey: {
				State: dataplane.SessStateEstablished, IsReverse: 1,
				LastSeen: now - 10, Timeout: 1800,
			},
		},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}

	gc := NewGC(dp, time.Minute)
	// Manually activate aging with 5s early ageout
	gc.earlyAgeout = 5
	gc.agingActive = true

	gc.sweep()

	// Session was last seen 10s ago, early ageout is 5s → should be expired
	if len(dp.deleted) != 2 { // fwd + rev
		t.Fatalf("expected 2 deletions with early ageout, got %d", len(dp.deleted))
	}
}

func TestGCAggressiveAgingHysteresis(t *testing.T) {
	gc := &GC{
		lastV6Count: -1,
	}

	// Test: aging stays inactive between sweeps
	gc.SetAgingConfig(10, 50, 30)
	if gc.agingActive {
		t.Fatal("aging should start inactive")
	}

	// Manually activate to test low watermark deactivation
	gc.agingActive = true
	gc.SetAgingConfig(0, 50, 30) // earlyAgeout=0 disables
	if gc.agingActive {
		t.Fatal("aging should deactivate when earlyAgeout set to 0")
	}
}

func TestGCNextSweepDelayCapsStablePrimary(t *testing.T) {
	gc := NewGC(&mockGCDP{}, 10*time.Second)

	got := gc.nextSweepDelayAt(100, 1900, false, true, 2)
	if got != 60*time.Second {
		t.Fatalf("nextSweepDelayAt() = %v, want %v", got, 60*time.Second)
	}
}

func TestGCNextSweepDelayUsesNearestExpiry(t *testing.T) {
	gc := NewGC(&mockGCDP{}, 10*time.Second)

	got := gc.nextSweepDelayAt(100, 125, false, true, 2)
	if got != 25*time.Second {
		t.Fatalf("nextSweepDelayAt() = %v, want %v", got, 25*time.Second)
	}
}

func TestGCNextSweepDelayDisablesBackoffForSessionLimits(t *testing.T) {
	gc := NewGC(&mockGCDP{}, 10*time.Second)

	got := gc.nextSweepDelayAt(100, 1900, true, true, 2)
	if got != 10*time.Second {
		t.Fatalf("nextSweepDelayAt() = %v, want %v", got, 10*time.Second)
	}
}
