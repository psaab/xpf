package cluster

import (
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func scopedJournalLen10512(s *SessionSync) int {
	s.deleteJournalMu.Lock()
	defer s.deleteJournalMu.Unlock()
	return len(s.scopedDeleteJournal)
}

func learnScopedCapable10512(t *testing.T, s *SessionSync) {
	t.Helper()
	s.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagScopedPolicyDelete))
	if !s.peerCapabilitiesLearned() || !s.ScopedPolicyDeleteCapable() {
		t.Fatal("FIXTURE: capable learning must land")
	}
}

func learnScopedIncapable10512(t *testing.T, s *SessionSync) {
	t.Helper()
	s.handleMessage(nil, syncMsgPeerCapabilities,
		capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership))
	if !s.peerCapabilitiesLearned() || s.ScopedPolicyDeleteCapable() {
		t.Fatal("FIXTURE: incapable learning must land without the bit")
	}
}

// Withheld at queue time for an incapable peer: no frame, no journal,
// counted.
func TestQueueDeleteScopedWithheldIncapable10512(t *testing.T) {
	s := &SessionSync{}
	learnScopedIncapable10512(t, s)
	s.QueueDeleteScopedV4(100007, scopedCodecKeyV4(), 0xF10512)
	if got := len(s.sendCh); got != 0 {
		t.Fatalf("sendCh holds %d frames, want 0", got)
	}
	if got := scopedJournalLen10512(s); got != 0 {
		t.Fatalf("scoped journal holds %d, want 0 (withheld, not deferred)", got)
	}
	if got := journalLen9714(s); got != 0 {
		t.Fatalf("bare journal holds %d, want 0", got)
	}
	if got := s.stats.DeletesSuppressedScopedPolicy.Load(); got != 1 {
		t.Fatalf("DeletesSuppressedScopedPolicy = %d, want 1", got)
	}
}

// Unlearned queue defers as journal debt (never withheld): a later
// learn-trigger flushes it. Counter stays zero (nothing dropped).
func TestQueueDeleteScopedDefersWhileUnlearned10512(t *testing.T) {
	s := &SessionSync{}
	s.QueueDeleteScopedV4(100007, scopedCodecKeyV4(), 0xF10512)
	if got := len(s.sendCh); got != 0 {
		t.Fatalf("sendCh holds %d frames, want 0", got)
	}
	if got := scopedJournalLen10512(s); got != 1 {
		t.Fatalf("scoped journal holds %d, want 1", got)
	}
	if got := s.stats.DeletesSuppressedScopedPolicy.Load(); got != 0 {
		t.Fatalf("DeletesSuppressedScopedPolicy = %d, want 0", got)
	}
}

// Capable but disconnected: deferred as scoped debt (bare journal untouched).
func TestQueueDeleteScopedDefersWhileDisconnected10512(t *testing.T) {
	s := &SessionSync{}
	learnScopedCapable10512(t, s)
	s.QueueDeleteScopedV4(100007, scopedCodecKeyV4(), 0xF10512)
	if got := scopedJournalLen10512(s); got != 1 {
		t.Fatalf("scoped journal holds %d, want 1", got)
	}
	if got := journalLen9714(s); got != 0 {
		t.Fatalf("bare journal holds %d, want 0", got)
	}
	if got := s.stats.DeletesSuppressedScopedPolicy.Load(); got != 0 {
		t.Fatalf("DeletesSuppressedScopedPolicy = %d, want 0", got)
	}
}

// Capable + connected: a 37-byte scoped frame with the tail values.
func TestQueueDeleteScopedSendsWireFrame10512(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", nil)
	learnScopedCapable10512(t, s)
	s.stats.Connected.Store(true)
	s.QueueDeleteScopedV4(100007, scopedCodecKeyV4(), 0xF10512)
	select {
	case msg := <-s.sendCh:
		payload := msg[syncHeaderSize:]
		if len(payload) != 37 {
			t.Fatalf("queued payload len = %d, want 37", len(payload))
		}
		k, _, _, domain, id, scoped, ok := parseDeleteV4Wire(payload)
		if !ok || !scoped || k != scopedCodecKeyV4() || domain != 100007 || id != 0xF10512 {
			t.Fatal("queued frame must carry key + domain + expected id as scoped")
		}
	default:
		t.Fatal("capable connected queue must emit one frame")
	}
}

// V6 smoke: 61-byte scoped frame queued when capable + connected.
func TestQueueDeleteScopedV6SendsWireFrame10512(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", nil)
	learnScopedCapable10512(t, s)
	s.stats.Connected.Store(true)
	s.QueueDeleteScopedV6(200007, scopedCodecKeyV6(), 0xC10512)
	select {
	case msg := <-s.sendCh:
		if len(msg[syncHeaderSize:]) != 61 {
			t.Fatalf("queued v6 payload len = %d, want 61", len(msg[syncHeaderSize:]))
		}
	default:
		t.Fatal("capable connected v6 queue must emit one frame")
	}
}

// Unlearned flush retains the debt (a later learn-trigger sends it).
func TestScopedJournalFlushRetainsWhileUnlearned10512(t *testing.T) {
	s := &SessionSync{}
	s.journalScopedDelete(encodeDeleteScopedV4(scopedCodecKeyV4(), 9, false, 100007, 0xF10512))
	s.flushScopedDeleteJournal()
	if got := scopedJournalLen10512(s); got != 1 {
		t.Fatalf("unlearned flush must retain the debt, journal holds %d", got)
	}
}

// Learned-incapable flush drops + counts (withhold; the peer never takes it).
func TestScopedJournalFlushDropsWhenIncapable10512(t *testing.T) {
	s := &SessionSync{}
	s.journalScopedDelete(encodeDeleteScopedV4(scopedCodecKeyV4(), 9, false, 100007, 0xF10512))
	learnScopedIncapable10512(t, s)
	s.flushScopedDeleteJournal()
	if got := scopedJournalLen10512(s); got != 0 {
		t.Fatalf("incapable flush must drop the debt, journal holds %d", got)
	}
	if got := s.stats.DeletesSuppressedScopedPolicy.Load(); got != 1 {
		t.Fatalf("DeletesSuppressedScopedPolicy = %d, want 1", got)
	}
}

// Learn-trigger: debt incurred while disconnected flushes as 37-byte
// frames once a capable peer advertises (end-to-end through handleMessage).
func TestScopedJournalFlushesOnCapableLearn10512(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", nil)
	s.journalScopedDelete(encodeDeleteScopedV4(scopedCodecKeyV4(), 9, false, 100007, 0xF10512))
	s.stats.Connected.Store(true)
	learnScopedCapable10512(t, s) // the trigger rides the caps arm
	select {
	case msg := <-s.sendCh:
		if len(msg[syncHeaderSize:]) != 37 {
			t.Fatalf("flushed payload len = %d, want 37", len(msg[syncHeaderSize:]))
		}
	default:
		t.Fatal("capable learn must flush the deferred debt")
	}
	if got := scopedJournalLen10512(s); got != 0 {
		t.Fatalf("journal holds %d after flush, want 0", got)
	}
}

type scopedCallV410512 struct {
	key    dataplane.SessionKey
	domain uint32
	id     uint64
}

type scopedCallV610512 struct {
	key    dataplane.SessionKeyV6
	domain uint32
	id     uint64
}

type scopedRecorderStore10512 struct {
	dataplane.SessionStore
	mu sync.Mutex
	v4 []scopedCallV410512
	v6 []scopedCallV610512
}

func (f *scopedRecorderStore10512) DeleteClusterScopedV4(key dataplane.SessionKey, domain uint32, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.v4 = append(f.v4, scopedCallV410512{key, domain, id})
	return nil
}

func (f *scopedRecorderStore10512) DeleteClusterScopedV6(key dataplane.SessionKeyV6, domain uint32, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.v6 = append(f.v6, scopedCallV610512{key, domain, id})
	return nil
}

// Scoped frame dispatches to the scoped store surface with key + id.
func TestRecvScopedDeleteDispatches10512(t *testing.T) {
	s := &SessionSync{}
	fake := &scopedRecorderStore10512{}
	s.sessions = fake
	key := scopedCodecKeyV4()
	gen := s.takeDeleteGenScopedV4(100007, key)
	s.handleMessage(nil, syncMsgDeleteV4,
		encodeDeleteScopedV4(key, gen, false, 100007, 0xF10512)[syncHeaderSize:])
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.v4) != 1 || fake.v4[0].key != key || fake.v4[0].domain != 100007 || fake.v4[0].id != 0xF10512 {
		t.Fatalf("scoped delete must reach the store with (key, domain, id), got %+v", fake.v4)
	}
}

// Boundary: id-only scope (domain 0) still takes the scoped path.
func TestRecvIDOnlyDeleteTakesScopedPath10512(t *testing.T) {
	s := &SessionSync{}
	fake := &scopedRecorderStore10512{}
	s.sessions = fake
	key := scopedCodecKeyV4()
	gen := s.takeDeleteGenScopedV4(0, key)
	s.handleMessage(nil, syncMsgDeleteV4,
		encodeDeleteScopedV4(key, gen, false, 0, 0xABCDEF)[syncHeaderSize:])
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.v4) != 1 || fake.v4[0].domain != 0 || fake.v4[0].id != 0xABCDEF {
		t.Fatalf("id-only delete must take the scoped path with domain 0, got %+v", fake.v4)
	}
}

// Stale scoped delete: guard refuses, store untouched, counted.
func TestRecvStaleScopedDeleteIgnored10512(t *testing.T) {
	s := &SessionSync{}
	fake := &scopedRecorderStore10512{}
	s.sessions = fake
	key := scopedCodecKeyV4()
	if !s.deleteGenGuardScopedV4(100007, key, 100) {
		t.Fatal("FIXTURE: scoped tombstone must record")
	}
	s.handleMessage(nil, syncMsgDeleteV4,
		encodeDeleteScopedV4(key, 50, false, 100007, 0xF10512)[syncHeaderSize:])
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.v4) != 0 {
		t.Fatalf("stale scoped delete reached the store: %+v", fake.v4)
	}
	if got := s.stats.DeletesStaleIgnored.Load(); got != 1 {
		t.Fatalf("DeletesStaleIgnored = %d, want 1", got)
	}
}

// V6 dispatch twin.
func TestRecvScopedDeleteDispatchesV610512(t *testing.T) {
	s := &SessionSync{}
	fake := &scopedRecorderStore10512{}
	s.sessions = fake
	key := scopedCodecKeyV6()
	gen := s.takeDeleteGenScopedV6(200007, key)
	s.handleMessage(nil, syncMsgDeleteV6,
		encodeDeleteScopedV6(key, gen, false, 200007, 0xC10512)[syncHeaderSize:])
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.v6) != 1 || fake.v6[0].key != key || fake.v6[0].domain != 200007 || fake.v6[0].id != 0xC10512 {
		t.Fatalf("scoped v6 delete must reach the store with (key, domain, id), got %+v", fake.v6)
	}
}

// Race pin (barrier-controlled): a learn-triggered flush blocked before
// its take must still drain an append that lands meanwhile — the
// post-append re-check flushes it — exactly once, never stranded, never
// duplicated.
func TestScopedJournalRaceDrainsEitherOrder10512(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", nil)
	s.stats.Connected.Store(true)
	learnScopedCapable10512(t, s)
	releaseTake := make(chan struct{})
	firstTake := make(chan struct{})
	var once sync.Once
	s.testBeforeScopedJournalTake = func() {
		once.Do(func() { close(firstTake) })
		<-releaseTake
	}
	flushed := make(chan struct{})
	go func() { s.flushScopedDeleteJournal(); close(flushed) }()
	<-firstTake // flush is inside, blocked before take
	s.journalScopedDelete(encodeDeleteScopedV4(scopedCodecKeyV4(), 9, false, 100007, 0xF10512))
	close(releaseTake) // flush resumes; either ordering drains exactly once
	<-flushed
	select {
	case <-s.sendCh:
	default:
		t.Fatal("raced append must drain")
	}
	select {
	case <-s.sendCh:
		t.Fatal("raced append must drain exactly once")
	default:
	}
	if got := scopedJournalLen10512(s); got != 0 {
		t.Fatalf("journal holds %d after race, want 0", got)
	}
}

// Race pin, incapable outcome: a learn-triggered flush blocked before its
// take must not strand an append that lands meanwhile — the post-append
// re-check flushes it into the incapable-drop (counted), exactly once,
// never sent.
func TestScopedJournalRaceDropsWhenIncapable10512(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", nil)
	learnScopedIncapable10512(t, s)
	releaseTake := make(chan struct{})
	firstTake := make(chan struct{})
	var once sync.Once
	s.testBeforeScopedJournalTake = func() {
		once.Do(func() { close(firstTake) })
		<-releaseTake
	}
	flushed := make(chan struct{})
	go func() { s.flushScopedDeleteJournal(); close(flushed) }()
	<-firstTake // flush is inside, blocked before take
	s.journalScopedDelete(encodeDeleteScopedV4(scopedCodecKeyV4(), 9, false, 100007, 0xF10512))
	close(releaseTake) // flush resumes; either ordering settles exactly once
	<-flushed
	select {
	case <-s.sendCh:
		t.Fatal("incapable peer must receive nothing")
	default:
	}
	if got := scopedJournalLen10512(s); got != 0 {
		t.Fatalf("journal holds %d after race, want 0", got)
	}
	if got := s.stats.DeletesSuppressedScopedPolicy.Load(); got != 1 {
		t.Fatalf("DeletesSuppressedScopedPolicy = %d, want 1", got)
	}
}
