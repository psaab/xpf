package dataplane

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

// batchDeleteTailDP is a DataPlane fake whose batch delete emulates cilium/ebpf
// BatchDelete: it stops at the first key marked "already gone" (missing) and
// returns (count_before_stop, ErrKeyNotExist), leaving every subsequent key in
// the chunk unattempted. It records every key a delete was attempted on (batch
// or per-key) so the test can assert the unattempted tail is retried rather
// than dropped (#5448).
type batchDeleteTailDP struct {
	DataPlane

	missingV4 SessionKey
	presentV4 map[SessionKey]bool // false once deleted
	attempted []SessionKey

	missingV6   SessionKeyV6
	presentV6   map[SessionKeyV6]bool
	attemptedV6 []SessionKeyV6
}

func (m *batchDeleteTailDP) BatchDeleteSessions(keys []SessionKey) (int, error) {
	deleted := 0
	for _, k := range keys {
		m.attempted = append(m.attempted, k)
		if k == m.missingV4 {
			// Kernel batch delete stops at the first missing key; the tail is
			// left untouched.
			return deleted, ebpf.ErrKeyNotExist
		}
		m.presentV4[k] = false
		deleted++
	}
	return deleted, nil
}

func (m *batchDeleteTailDP) DeleteSession(k SessionKey) error {
	m.attempted = append(m.attempted, k)
	if k == m.missingV4 {
		return ebpf.ErrKeyNotExist
	}
	m.presentV4[k] = false
	return nil
}

func (m *batchDeleteTailDP) BatchDeleteSessionsV6(keys []SessionKeyV6) (int, error) {
	deleted := 0
	for _, k := range keys {
		m.attemptedV6 = append(m.attemptedV6, k)
		if k == m.missingV6 {
			return deleted, ebpf.ErrKeyNotExist
		}
		m.presentV6[k] = false
		deleted++
	}
	return deleted, nil
}

func (m *batchDeleteTailDP) DeleteSessionV6(k SessionKeyV6) error {
	m.attemptedV6 = append(m.attemptedV6, k)
	if k == m.missingV6 {
		return ebpf.ErrKeyNotExist
	}
	m.presentV6[k] = false
	return nil
}

// TestBatchDeleteV4RetriesTailAfterMissingKey asserts that when the kernel
// batch-delete stops on a missing key in the MIDDLE of a chunk, batchDeleteV4
// still deletes the keys after it (chunk[chunkDeleted+1:]) instead of dropping
// them. Before #5448 the loop advanced by the full chunk width on
// ErrKeyNotExist, so the unattempted tail leaked (stale HA-synced sessions
// after bulk reconcile).
func TestBatchDeleteV4RetriesTailAfterMissingKey(t *testing.T) {
	keys := make([]SessionKey, 5)
	for i := range keys {
		keys[i] = SessionKey{
			Protocol: 6,
			SrcIP:    [4]byte{10, 0, 0, byte(i)},
			DstIP:    [4]byte{10, 0, 1, byte(i)},
			SrcPort:  uint16(1000 + i),
			DstPort:  80,
		}
	}
	const missingIdx = 2 // interleaved missing key with a non-empty tail after it
	missing := keys[missingIdx]

	dp := &batchDeleteTailDP{
		missingV4: missing,
		presentV4: map[SessionKey]bool{},
	}
	for i, k := range keys {
		// Every key is present except the one a concurrent GC already removed.
		dp.presentV4[k] = i != missingIdx
	}
	store := dataPlaneSessionStore{dp: dp}

	// #9364: batchDeleteV4 now takes scoped keys. Domain 0 throughout, which is
	// exactly the bare/default case this cell has always exercised — the #5448
	// retry contract is orthogonal to the domain and must stay so.
	deleted, err := store.batchDeleteV4(scopedV4(keys))
	if err != nil {
		t.Fatalf("batchDeleteV4 returned error: %v", err)
	}

	// Every non-missing key must be gone (tail retried, not dropped).
	for i, k := range keys {
		if i == missingIdx {
			continue
		}
		if dp.presentV4[k] {
			t.Errorf("key index %d (%v) survived — unattempted tail was dropped", i, k)
		}
	}
	// 4 real keys deleted; the missing key is not counted.
	if deleted != len(keys)-1 {
		t.Errorf("deleted count = %d, want %d", deleted, len(keys)-1)
	}
}

// TestBatchDeleteV6RetriesTailAfterMissingKey is the IPv6 sibling.
func TestBatchDeleteV6RetriesTailAfterMissingKey(t *testing.T) {
	keys := make([]SessionKeyV6, 5)
	for i := range keys {
		var src, dst [16]byte
		src[0], src[15] = 0x20, byte(i)
		dst[0], dst[15] = 0x30, byte(i)
		keys[i] = SessionKeyV6{
			Protocol: 6,
			SrcIP:    src,
			DstIP:    dst,
			SrcPort:  uint16(1000 + i),
			DstPort:  80,
		}
	}
	const missingIdx = 2
	missing := keys[missingIdx]

	dp := &batchDeleteTailDP{
		missingV6: missing,
		presentV6: map[SessionKeyV6]bool{},
	}
	for i, k := range keys {
		dp.presentV6[k] = i != missingIdx
	}
	store := dataPlaneSessionStore{dp: dp}

	deleted, err := store.batchDeleteV6(scopedV6(keys))
	if err != nil {
		t.Fatalf("batchDeleteV6 returned error: %v", err)
	}

	for i, k := range keys {
		if i == missingIdx {
			continue
		}
		if dp.presentV6[k] {
			t.Errorf("v6 key index %d survived — unattempted tail was dropped", i)
		}
	}
	if deleted != len(keys)-1 {
		t.Errorf("v6 deleted count = %d, want %d", deleted, len(keys)-1)
	}
}

// TestBatchDeleteV4PropagatesRealError confirms a non-not-found batch error is
// still surfaced (the #5448 fix must not swallow genuine failures).
func TestBatchDeleteV4PropagatesRealError(t *testing.T) {
	realErr := errors.New("map delete failed")
	dp := &batchDeleteErrDP{err: realErr}
	store := dataPlaneSessionStore{dp: dp}
	_, err := store.batchDeleteV4([]ScopedSessionKey{{Key: SessionKey{Protocol: 6, SrcPort: 1}}})
	if !errors.Is(err, realErr) {
		t.Fatalf("batchDeleteV4 error = %v, want %v", err, realErr)
	}
}

type batchDeleteErrDP struct {
	DataPlane
	err error
}

func (m *batchDeleteErrDP) BatchDeleteSessions(keys []SessionKey) (int, error) {
	return 0, m.err
}

func (m *batchDeleteErrDP) BatchDeleteSessionsV6(keys []SessionKeyV6) (int, error) {
	return 0, m.err
}

// scopedV4 / scopedV6 lift bare keys onto the #9364 scoped signature with domain
// 0. Helpers rather than inline literals so this cell keeps reading as a
// statement about the RETRY contract, which is what it is for.
func scopedV4(keys []SessionKey) []ScopedSessionKey {
	out := make([]ScopedSessionKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, ScopedSessionKey{Key: k})
	}
	return out
}

func scopedV6(keys []SessionKeyV6) []ScopedSessionKeyV6 {
	out := make([]ScopedSessionKeyV6, 0, len(keys))
	for _, k := range keys {
		out = append(out, ScopedSessionKeyV6{Key: k})
	}
	return out
}
