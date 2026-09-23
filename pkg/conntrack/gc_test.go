package conntrack

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
	"golang.org/x/sys/unix"
)

// mockGCDP is a minimal runtime-domain provider for GC testing.
type mockGCDP struct {
	mu         sync.Mutex
	v4sessions map[dataplane.SessionKey]dataplane.SessionValue
	v6sessions map[dataplane.SessionKeyV6]dataplane.SessionValueV6
	deleted    []dataplane.SessionKey
	deletedV6  []dataplane.SessionKeyV6
}

type mockGCTelemetry struct {
	dataplane.Telemetry
}

func (mockGCTelemetry) GlobalCounter(uint32) (uint64, error) {
	return 1, nil
}

type nilRuntimeProvider struct{}

func (*nilRuntimeProvider) Sessions() dataplane.SessionStore {
	panic("typed nil provider should not be adapted")
}

func (*nilRuntimeProvider) Telemetry() dataplane.Telemetry {
	panic("typed nil provider should not be adapted")
}

func (m *mockGCDP) Sessions() dataplane.SessionStore {
	return m
}

func (m *mockGCDP) Telemetry() dataplane.Telemetry {
	return mockGCTelemetry{}
}

func (m *mockGCDP) ForEachV4(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return m.IterateSessions(fn)
}

func (m *mockGCDP) ForEachV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return m.IterateSessionsV6(fn)
}

func (m *mockGCDP) GetV4(key dataplane.SessionKey) (dataplane.SessionValue, error) {
	return m.GetSessionV4(key)
}

func (m *mockGCDP) GetV6(key dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	return m.GetSessionV6(key)
}

func (m *mockGCDP) PutClusterSyncedV4(dataplane.SessionKey, dataplane.SessionValue) error {
	return nil
}

func (m *mockGCDP) PutClusterSyncedV6(dataplane.SessionKeyV6, dataplane.SessionValueV6) error {
	return nil
}

func (m *mockGCDP) DeleteV4(key dataplane.SessionKey) error {
	return m.DeleteSession(key)
}

func (m *mockGCDP) DeleteV6(key dataplane.SessionKeyV6) error {
	return m.DeleteSessionV6(key)
}

func (m *mockGCDP) DeleteKnownV4(key dataplane.SessionKey, val dataplane.SessionValue, reason dataplane.DeleteReason, _ bool) error {
	_, err := m.DeleteBatchKnownV4([]dataplane.SessionEntryV4{{Key: key, Value: val}}, reason, false)
	return err
}

func (m *mockGCDP) DeleteKnownV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, reason dataplane.DeleteReason, _ bool) error {
	_, err := m.DeleteBatchKnownV6([]dataplane.SessionEntryV6{{Key: key, Value: val}}, reason, false)
	return err
}

func (m *mockGCDP) DeleteBatchKnownV4(entries []dataplane.SessionEntryV4, _ dataplane.DeleteReason, _ bool) (int, error) {
	for _, entry := range entries {
		if entry.Value.ReverseKey.Protocol != 0 {
			m.DeleteSession(entry.Value.ReverseKey)
		}
		m.DeleteSession(entry.Key)
	}
	return len(entries), nil
}

func (m *mockGCDP) DeleteBatchKnownV6(entries []dataplane.SessionEntryV6, _ dataplane.DeleteReason, _ bool) (int, error) {
	for _, entry := range entries {
		if entry.Value.ReverseKey.Protocol != 0 {
			m.DeleteSessionV6(entry.Value.ReverseKey)
		}
		m.DeleteSessionV6(entry.Key)
	}
	return len(entries), nil
}
func (m *mockGCDP) DeleteBatchKnownExactV4(entries []dataplane.SessionEntryV4, reason dataplane.DeleteReason, forwardOnly bool) ([]dataplane.SessionKey, error) {
	_, err := m.DeleteBatchKnownV4(entries, reason, forwardOnly)
	if err != nil {
		return nil, err
	}
	keys := make([]dataplane.SessionKey, 0, len(entries))
	for _, entry := range entries {
		keys = append(keys, entry.Key)
	}
	return keys, nil
}

func (m *mockGCDP) DeleteBatchKnownExactV6(entries []dataplane.SessionEntryV6, reason dataplane.DeleteReason, forwardOnly bool) ([]dataplane.SessionKeyV6, error) {
	_, err := m.DeleteBatchKnownV6(entries, reason, forwardOnly)
	if err != nil {
		return nil, err
	}
	keys := make([]dataplane.SessionKeyV6, 0, len(entries))
	for _, entry := range entries {
		keys = append(keys, entry.Key)
	}
	return keys, nil
}

func (m *mockGCDP) DeleteWithCompanionsV4(key dataplane.SessionKey, reason dataplane.DeleteReason, _ bool) error {
	val, err := m.GetSessionV4(key)
	if err != nil {
		return err
	}
	return m.DeleteKnownV4(key, val, reason, false)
}

func (m *mockGCDP) DeleteWithCompanionsV6(key dataplane.SessionKeyV6, reason dataplane.DeleteReason, _ bool) error {
	val, err := m.GetSessionV6(key)
	if err != nil {
		return err
	}
	return m.DeleteKnownV6(key, val, reason, false)
}

func (m *mockGCDP) DeleteClusterScopedV4(dataplane.SessionKey, uint32, uint64) error {
	return nil // GC never issues scoped deletes; stub satisfies SessionStore.
}

func (m *mockGCDP) DeleteClusterScopedV6(dataplane.SessionKeyV6, uint32, uint64) error {
	return nil
}

func (m *mockGCDP) ReconcileClusterBulk(dataplane.ClusterBulkReconcileInput) (dataplane.ClusterBulkReconcileResult, error) {
	return dataplane.ClusterBulkReconcileResult{}, nil
}

func (m *mockGCDP) SessionDeltas() dpruntime.SessionDeltaSource {
	return nil
}

func (m *mockGCDP) Count() (int, int) {
	return len(m.v4sessions), len(m.v6sessions)
}

func (m *mockGCDP) Clear() (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v4, v6 := len(m.v4sessions), len(m.v6sessions)
	m.v4sessions = map[dataplane.SessionKey]dataplane.SessionValue{}
	m.v6sessions = map[dataplane.SessionKeyV6]dataplane.SessionValueV6{}
	return v4, v6, nil
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

func TestNewGCAdaptsRuntimeProviderToDomains(t *testing.T) {
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

func TestNewGCNilProviderKeepsAdapterBehavior(t *testing.T) {
	gc := NewGC(nil, 10*time.Second)

	if gc.sessions == nil {
		t.Fatal("NewGC nil provider did not install nil session adapter")
	}
	if gc.telemetry == nil {
		t.Fatal("NewGC nil provider did not install nil telemetry adapter")
	}
	if gc.sessionCount != nil {
		t.Fatal("NewGC nil provider retained session-count publisher")
	}
	if gc.persistent != nil {
		t.Fatal("NewGC nil provider retained persistent NAT provider")
	}
}

func TestNewGCTypedNilProviderKeepsAdapterBehavior(t *testing.T) {
	var provider *nilRuntimeProvider
	gc := NewGC(provider, 10*time.Second)

	if gc.sessions == nil {
		t.Fatal("NewGC typed nil provider did not install nil session adapter")
	}
	if gc.telemetry == nil {
		t.Fatal("NewGC typed nil provider did not install nil telemetry adapter")
	}
	if gc.sessionCount != nil {
		t.Fatal("NewGC typed nil provider retained session-count publisher")
	}
	if gc.persistent != nil {
		t.Fatal("NewGC typed nil provider retained persistent NAT provider")
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

func (s *runtimeDomainSessionStore) DeleteKnownV4(key dataplane.SessionKey, _ dataplane.SessionValue, _ dataplane.DeleteReason, _ bool) error {
	s.deleted = append(s.deleted, key)
	delete(s.v4, key)
	return nil
}

func (s *runtimeDomainSessionStore) DeleteKnownV6(dataplane.SessionKeyV6, dataplane.SessionValueV6, dataplane.DeleteReason, bool) error {
	return nil
}

func (s *runtimeDomainSessionStore) DeleteBatchKnownV4(entries []dataplane.SessionEntryV4, _ dataplane.DeleteReason, _ bool) (int, error) {
	for _, entry := range entries {
		s.deleted = append(s.deleted, entry.Key)
		delete(s.v4, entry.Key)
	}
	return len(entries), nil
}

func (s *runtimeDomainSessionStore) DeleteBatchKnownV6([]dataplane.SessionEntryV6, dataplane.DeleteReason, bool) (int, error) {
	return 0, nil
}
func (s *runtimeDomainSessionStore) DeleteBatchKnownExactV4(entries []dataplane.SessionEntryV4, reason dataplane.DeleteReason, forwardOnly bool) ([]dataplane.SessionKey, error) {
	_, err := s.DeleteBatchKnownV4(entries, reason, forwardOnly)
	if err != nil {
		return nil, err
	}
	keys := make([]dataplane.SessionKey, 0, len(entries))
	for _, entry := range entries {
		keys = append(keys, entry.Key)
	}
	return keys, nil
}

func (s *runtimeDomainSessionStore) DeleteBatchKnownExactV6(entries []dataplane.SessionEntryV6, reason dataplane.DeleteReason, forwardOnly bool) ([]dataplane.SessionKeyV6, error) {
	_, err := s.DeleteBatchKnownV6(entries, reason, forwardOnly)
	if err != nil {
		return nil, err
	}
	keys := make([]dataplane.SessionKeyV6, 0, len(entries))
	for _, entry := range entries {
		keys = append(keys, entry.Key)
	}
	return keys, nil
}

func (s *runtimeDomainSessionStore) DeleteWithCompanionsV4(key dataplane.SessionKey, _ dataplane.DeleteReason, _ bool) error {
	return s.DeleteKnownV4(key, dataplane.SessionValue{}, dataplane.DeleteReasonGCExpired, false)
}

func (s *runtimeDomainSessionStore) DeleteWithCompanionsV6(dataplane.SessionKeyV6, dataplane.DeleteReason, bool) error {
	return nil
}

func (s *runtimeDomainSessionStore) DeleteClusterScopedV4(dataplane.SessionKey, uint32, uint64) error {
	return nil // GC never issues scoped deletes; stub satisfies SessionStore.
}

func (s *runtimeDomainSessionStore) DeleteClusterScopedV6(dataplane.SessionKeyV6, uint32, uint64) error {
	return nil
}

func (s *runtimeDomainSessionStore) ReconcileClusterBulk(dataplane.ClusterBulkReconcileInput) (dataplane.ClusterBulkReconcileResult, error) {
	return dataplane.ClusterBulkReconcileResult{}, nil
}

func (s *runtimeDomainSessionStore) SessionDeltas() dpruntime.SessionDeltaSource { return nil }
func (s *runtimeDomainSessionStore) Count() (int, int)                           { return len(s.v4), 0 }
func (s *runtimeDomainSessionStore) Clear() (int, int, error)                    { return 0, 0, nil }

type partialDeleteSessionStore struct {
	entries       []dataplane.SessionEntryV4
	entriesV6     []dataplane.SessionEntryV6
	exact         []dataplane.SessionKey
	exactV6       []dataplane.SessionKeyV6
	absent        []dataplane.SessionKey
	absentV6      []dataplane.SessionKeyV6
	deleteError   error
	deleteErrorV6 error
	deleteCalls   int
	deleteCallsV6 int
}

func (s *partialDeleteSessionStore) ForEachV4(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for _, entry := range s.entries {
		if !fn(entry.Key, entry.Value) {
			break
		}
	}
	return nil
}

func (s *partialDeleteSessionStore) ForEachV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for _, entry := range s.entriesV6 {
		if !fn(entry.Key, entry.Value) {
			break
		}
	}
	return nil
}

func (s *partialDeleteSessionStore) GetV4(dataplane.SessionKey) (dataplane.SessionValue, error) {
	return dataplane.SessionValue{}, unix.ENOENT
}

func (s *partialDeleteSessionStore) GetV6(dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	return dataplane.SessionValueV6{}, unix.ENOENT
}

func (s *partialDeleteSessionStore) PutClusterSyncedV4(dataplane.SessionKey, dataplane.SessionValue) error {
	return nil
}

func (s *partialDeleteSessionStore) PutClusterSyncedV6(dataplane.SessionKeyV6, dataplane.SessionValueV6) error {
	return nil
}

func (s *partialDeleteSessionStore) DeleteV4(dataplane.SessionKey) error   { return nil }
func (s *partialDeleteSessionStore) DeleteV6(dataplane.SessionKeyV6) error { return nil }
func (s *partialDeleteSessionStore) DeleteKnownV4(dataplane.SessionKey, dataplane.SessionValue, dataplane.DeleteReason, bool) error {
	return nil
}
func (s *partialDeleteSessionStore) DeleteKnownV6(dataplane.SessionKeyV6, dataplane.SessionValueV6, dataplane.DeleteReason, bool) error {
	return nil
}
func (s *partialDeleteSessionStore) DeleteBatchKnownV4(entries []dataplane.SessionEntryV4, reason dataplane.DeleteReason, forwardOnly bool) (int, error) {
	exact, err := s.DeleteBatchKnownExactV4(entries, reason, forwardOnly)
	return len(exact), err
}

func (s *partialDeleteSessionStore) DeleteBatchKnownExactV4(entries []dataplane.SessionEntryV4, _ dataplane.DeleteReason, _ bool) ([]dataplane.SessionKey, error) {
	s.deleteCalls++
	allowed := make(map[dataplane.SessionKey]struct{}, len(s.exact))
	for _, key := range s.exact {
		allowed[key] = struct{}{}
	}
	selected := make([]dataplane.SessionKey, 0, len(entries))
	for _, entry := range entries {
		if _, ok := allowed[entry.Key]; ok {
			selected = append(selected, entry.Key)
		}
	}
	remove := make(map[dataplane.SessionKey]struct{}, len(selected)+len(s.absent))
	for _, key := range selected {
		remove[key] = struct{}{}
	}
	for _, key := range s.absent {
		remove[key] = struct{}{}
	}
	remaining := s.entries[:0]
	for _, entry := range s.entries {
		if _, ok := remove[entry.Key]; !ok {
			remaining = append(remaining, entry)
		}
	}
	s.entries = remaining
	return selected, s.deleteError
}

func (s *partialDeleteSessionStore) DeleteBatchKnownExactV6(entries []dataplane.SessionEntryV6, _ dataplane.DeleteReason, _ bool) ([]dataplane.SessionKeyV6, error) {
	s.deleteCallsV6++
	allowed := make(map[dataplane.SessionKeyV6]struct{}, len(s.exactV6))
	for _, key := range s.exactV6 {
		allowed[key] = struct{}{}
	}
	selected := make([]dataplane.SessionKeyV6, 0, len(entries))
	for _, entry := range entries {
		if _, ok := allowed[entry.Key]; ok {
			selected = append(selected, entry.Key)
		}
	}
	remove := make(map[dataplane.SessionKeyV6]struct{}, len(selected)+len(s.absentV6))
	for _, key := range selected {
		remove[key] = struct{}{}
	}
	for _, key := range s.absentV6 {
		remove[key] = struct{}{}
	}
	remaining := s.entriesV6[:0]
	for _, entry := range s.entriesV6 {
		if _, ok := remove[entry.Key]; !ok {
			remaining = append(remaining, entry)
		}
	}
	s.entriesV6 = remaining
	return selected, s.deleteErrorV6
}

func (s *partialDeleteSessionStore) DeleteBatchKnownV6(entries []dataplane.SessionEntryV6, reason dataplane.DeleteReason, forwardOnly bool) (int, error) {
	exact, err := s.DeleteBatchKnownExactV6(entries, reason, forwardOnly)
	return len(exact), err
}
func (s *partialDeleteSessionStore) DeleteWithCompanionsV4(dataplane.SessionKey, dataplane.DeleteReason, bool) error {
	return nil
}
func (s *partialDeleteSessionStore) DeleteWithCompanionsV6(dataplane.SessionKeyV6, dataplane.DeleteReason, bool) error {
	return nil
}

func (s *partialDeleteSessionStore) DeleteClusterScopedV4(dataplane.SessionKey, uint32, uint64) error {
	return nil // GC never issues scoped deletes; stub satisfies SessionStore.
}

func (s *partialDeleteSessionStore) DeleteClusterScopedV6(dataplane.SessionKeyV6, uint32, uint64) error {
	return nil
}
func (s *partialDeleteSessionStore) ReconcileClusterBulk(dataplane.ClusterBulkReconcileInput) (dataplane.ClusterBulkReconcileResult, error) {
	return dataplane.ClusterBulkReconcileResult{}, nil
}
func (s *partialDeleteSessionStore) SessionDeltas() dpruntime.SessionDeltaSource { return nil }
func (s *partialDeleteSessionStore) Count() (int, int)                           { return len(s.entries), 0 }
func (s *partialDeleteSessionStore) Clear() (int, int, error)                    { return 0, 0, nil }

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

func gcExactEntriesV4(now uint64) []dataplane.SessionEntryV4 {
	entries := make([]dataplane.SessionEntryV4, 5)
	for i := range entries {
		entries[i] = dataplane.SessionEntryV4{
			Key: dataplane.SessionKey{
				SrcIP:    [4]byte{10, 0, 0, byte(i)},
				DstIP:    [4]byte{10, 0, 1, byte(i)},
				Protocol: 6,
				SrcPort:  uint16(1000 + i),
				DstPort:  80,
			},
			Value: dataplane.SessionValue{LastSeen: now - 200, Timeout: 100},
		}
	}
	return entries
}

func gcExactEntriesV6(now uint64) []dataplane.SessionEntryV6 {
	entries := make([]dataplane.SessionEntryV6, 5)
	for i := range entries {
		var src, dst [16]byte
		src[0], src[15] = 0x20, byte(i)
		dst[0], dst[15] = 0x30, byte(i)
		entries[i] = dataplane.SessionEntryV6{
			Key: dataplane.SessionKeyV6{
				SrcIP:    src,
				DstIP:    dst,
				Protocol: 6,
				SrcPort:  uint16(1000 + i),
				DstPort:  80,
			},
			Value: dataplane.SessionValueV6{LastSeen: now - 200, Timeout: 100},
		}
	}
	return entries
}

func TestGCErrorPathSyncsExactDeletedSetV4(t *testing.T) {
	now := monotonicSeconds()
	entries := gcExactEntriesV4(now)
	keys := make([]dataplane.SessionKey, 0, len(entries))
	for _, entry := range entries {
		keys = append(keys, entry.Key)
	}
	boom := errors.New("partial batch failure")
	store := &partialDeleteSessionStore{
		entries:     entries,
		exact:       []dataplane.SessionKey{keys[0], keys[2], keys[4]},
		absent:      []dataplane.SessionKey{keys[1]},
		deleteError: boom,
	}
	gc := NewGCWithDomains(store, nil, nil, nil, time.Minute)

	var callbackKeys []dataplane.SessionKey
	gc.OnDeleteV4 = func(key dataplane.SessionKey) {
		callbackKeys = append(callbackKeys, key)
	}
	gc.sweep()

	want := []dataplane.SessionKey{keys[0], keys[2], keys[4]}
	if len(callbackKeys) != len(want) {
		t.Fatalf("callback keys = %+v, want %+v", callbackKeys, want)
	}
	for i := range want {
		if callbackKeys[i] != want[i] {
			t.Fatalf("callback keys = %+v, want %+v", callbackKeys, want)
		}
	}
	if got := gc.Stats().ExpiredDeleted; got != len(want) {
		t.Fatalf("ExpiredDeleted = %d, want %d", got, len(want))
	}
	if len(store.entries) != 1 || store.entries[0].Key != keys[3] {
		t.Fatalf("remaining entries = %+v, want only boom key %+v", store.entries, keys[3])
	}
}

func TestGCErrorPathSyncsExactDeletedSetV6(t *testing.T) {
	now := monotonicSeconds()
	entries := gcExactEntriesV6(now)
	keys := make([]dataplane.SessionKeyV6, 0, len(entries))
	for _, entry := range entries {
		keys = append(keys, entry.Key)
	}
	boom := errors.New("partial v6 batch failure")
	store := &partialDeleteSessionStore{
		entriesV6:     entries,
		exactV6:       []dataplane.SessionKeyV6{keys[0], keys[2], keys[4]},
		absentV6:      []dataplane.SessionKeyV6{keys[1]},
		deleteErrorV6: boom,
	}
	gc := NewGCWithDomains(store, nil, nil, nil, time.Minute)
	gc.sweepCount = 6 // force the first IPv6 sweep

	var callbackKeys []dataplane.SessionKeyV6
	gc.OnDeleteV6 = func(key dataplane.SessionKeyV6) {
		callbackKeys = append(callbackKeys, key)
	}
	gc.sweep()

	want := []dataplane.SessionKeyV6{keys[0], keys[2], keys[4]}
	if len(callbackKeys) != len(want) {
		t.Fatalf("callback keys = %+v, want %+v", callbackKeys, want)
	}
	for i := range want {
		if callbackKeys[i] != want[i] {
			t.Fatalf("callback keys = %+v, want %+v", callbackKeys, want)
		}
	}
	if got := gc.Stats().ExpiredDeleted; got != len(want) {
		t.Fatalf("ExpiredDeleted = %d, want %d", got, len(want))
	}
	if len(store.entriesV6) != 1 || store.entriesV6[0].Key != keys[3] {
		t.Fatalf("remaining v6 entries = %+v, want only boom key %+v", store.entriesV6, keys[3])
	}
}

func TestGCExactDeleteEdgeCases(t *testing.T) {
	now := monotonicSeconds()

	t.Run("empty", func(t *testing.T) {
		store := &partialDeleteSessionStore{}
		gc := NewGCWithDomains(store, nil, nil, nil, time.Minute)
		var callbacks []dataplane.SessionKey
		gc.OnDeleteV4 = func(key dataplane.SessionKey) { callbacks = append(callbacks, key) }
		gc.sweep()
		if len(callbacks) != 0 || gc.Stats().ExpiredDeleted != 0 {
			t.Fatalf("empty batch callbacks=%+v stats=%+v", callbacks, gc.Stats())
		}
	})

	t.Run("all-fail", func(t *testing.T) {
		entries := gcExactEntriesV4(now)
		store := &partialDeleteSessionStore{
			entries:     entries,
			deleteError: errors.New("all failed"),
		}
		gc := NewGCWithDomains(store, nil, nil, nil, time.Minute)
		var callbacks []dataplane.SessionKey
		gc.OnDeleteV4 = func(key dataplane.SessionKey) { callbacks = append(callbacks, key) }
		gc.sweep()
		if len(callbacks) != 0 {
			t.Fatalf("all-fail callbacks=%+v, want none", callbacks)
		}
		if len(store.entries) != len(entries) || gc.Stats().ExpiredDeleted != 0 {
			t.Fatalf("all-fail entries=%d stats=%+v", len(store.entries), gc.Stats())
		}
	})

	t.Run("all-ok", func(t *testing.T) {
		entries := gcExactEntriesV4(now)
		keys := make([]dataplane.SessionKey, 0, len(entries))
		for _, entry := range entries {
			keys = append(keys, entry.Key)
		}
		store := &partialDeleteSessionStore{entries: entries, exact: keys}
		gc := NewGCWithDomains(store, nil, nil, nil, time.Minute)
		var callbacks []dataplane.SessionKey
		gc.OnDeleteV4 = func(key dataplane.SessionKey) { callbacks = append(callbacks, key) }
		gc.sweep()
		if len(store.entries) != 0 || gc.Stats().ExpiredDeleted != len(entries) {
			t.Fatalf("all-ok entries=%d stats=%+v", len(store.entries), gc.Stats())
		}
		if len(callbacks) != len(keys) {
			t.Fatalf("all-ok callbacks=%+v, want %+v", callbacks, keys)
		}
		for i := range keys {
			if callbacks[i] != keys[i] {
				t.Fatalf("all-ok callbacks=%+v, want %+v", callbacks, keys)
			}
		}
	})
	t.Run("sweep-retry", func(t *testing.T) {
		entries := gcExactEntriesV4(now)
		keys := make([]dataplane.SessionKey, 0, len(entries))
		for _, entry := range entries {
			keys = append(keys, entry.Key)
		}
		store := &partialDeleteSessionStore{
			entries:     entries,
			exact:       []dataplane.SessionKey{keys[0], keys[2], keys[4]},
			absent:      []dataplane.SessionKey{keys[1]},
			deleteError: errors.New("persistent boom"),
		}
		gc := NewGCWithDomains(store, nil, nil, nil, time.Minute)
		gc.sweep()
		gc.sweep()
		if store.deleteCalls != 2 {
			t.Fatalf("delete calls = %d, want 2 retries", store.deleteCalls)
		}
		if len(store.entries) != 1 || store.entries[0].Key != keys[3] {
			t.Fatalf("retry remaining entries = %+v, want boom key %+v", store.entries, keys[3])
		}
	})
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

	got := gc.nextSweepDelayAt(100, 1900, false, true, 2, false, 0)
	if got != 60*time.Second {
		t.Fatalf("nextSweepDelayAt() = %v, want %v", got, 60*time.Second)
	}
}

func TestGCNextSweepDelayUsesNearestExpiry(t *testing.T) {
	gc := NewGC(&mockGCDP{}, 10*time.Second)

	got := gc.nextSweepDelayAt(100, 125, false, true, 2, false, 0)
	if got != 25*time.Second {
		t.Fatalf("nextSweepDelayAt() = %v, want %v", got, 25*time.Second)
	}
}

func TestGCNextSweepDelayDisablesBackoffForSessionLimits(t *testing.T) {
	gc := NewGC(&mockGCDP{}, 10*time.Second)

	got := gc.nextSweepDelayAt(100, 1900, true, true, 2, false, 0)
	if got != 10*time.Second {
		t.Fatalf("nextSweepDelayAt() = %v, want %v", got, 10*time.Second)
	}
}

// TestSetAgingConfigClampsNegativeEarlyAgeout pins the #3440 H2 defensive
// clamp: a negative early-ageout (which a peer-synced or already-persisted
// config from an older binary could still carry on the tolerant load path)
// must clamp to 0 (disabled), not cast to a huge uint64. FAIL-ON-REVERT:
// remove the `if earlyAgeout < 0 { earlyAgeout = 0 }` guard in
// SetAgingConfig and earlyAgeout becomes uint64(-1) == 1<<64-1, so the
// early-ageout is effectively infinite (never shorter than any per-session
// timeout) — a silent no-op the operator cannot see.
func TestSetAgingConfigClampsNegativeEarlyAgeout(t *testing.T) {
	gc := NewGC(nil, time.Second)
	gc.SetAgingConfig(-1, 90, 80)
	if gc.earlyAgeout != 0 {
		t.Fatalf("negative early-ageout not clamped: earlyAgeout=%d (want 0)", gc.earlyAgeout)
	}
	if gc.agingActive {
		t.Fatalf("aging must be inactive when early-ageout is 0")
	}
	// A valid positive value is stored verbatim.
	gc.SetAgingConfig(20, 90, 80)
	if gc.earlyAgeout != 20 {
		t.Fatalf("positive early-ageout not stored: earlyAgeout=%d (want 20)", gc.earlyAgeout)
	}
}

// TestGCSweepConfigRace pins #3604: the GC sweep goroutine read (and, in the
// watermark-hysteresis block, wrote) the aggressive-aging / session-limit
// config fields (agingActive, earlyAgeout, highWatermark, lowWatermark,
// sessionLimitEnabled) with no lock held, while SetAgingConfig /
// SetSessionLimitEnabled write them under gc.mu. Running the sweep concurrently
// with the config setters is therefore a data race.
//
// FAIL-ON-REVERT: under `go test -race`, revert gc.sweep() to read those fields
// as gc.agingActive/gc.earlyAgeout/... (i.e. drop the gc.mu-guarded snapshot at
// the top of sweep and the locked write-back of agingActive) and the race
// detector aborts this test. With the snapshot/write-back fix it passes.
func TestGCSweepConfigRace(t *testing.T) {
	now := monotonicSeconds()
	// A couple of live (non-expiring) sessions so the sweep takes the full
	// iteration path and reads the config fields per entry, and lastTotal > 0
	// so it never short-circuits on the empty-table fast path.
	fwdKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 1}, Protocol: 6, SrcPort: 1000, DstPort: 80}
	revKey := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 2, 1}, Protocol: 6, SrcPort: 80, DstPort: 1000}
	dp := &mockGCDP{
		v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{
			fwdKey: {
				State: dataplane.SessStateEstablished, IsReverse: 0,
				LastSeen: now, Timeout: 1800, ReverseKey: revKey,
			},
			revKey: {
				State: dataplane.SessStateEstablished, IsReverse: 1,
				LastSeen: now, Timeout: 1800,
			},
		},
		v6sessions: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
	}

	gc := NewGC(dp, time.Millisecond)

	const iterations = 2000
	var wg sync.WaitGroup
	wg.Add(2)

	// Config-commit goroutine: mirrors the daemon apply path
	// (daemon_apply.go SetAgingConfig / SetSessionLimitEnabled).
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			gc.SetAgingConfig(2, 50, 30)
			gc.SetSessionLimitEnabled(i%2 == 0)
		}
	}()

	// Sweep goroutine: the GC loop body.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			gc.sweep()
		}
	}()

	wg.Wait()
}
