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

	missingV4  SessionKey
	presentV4  map[SessionKey]bool // false once deleted
	attempted  []SessionKey
	retryErrV4 map[SessionKey]error

	missingV6   SessionKeyV6
	presentV6   map[SessionKeyV6]bool
	attemptedV6 []SessionKeyV6
	retryErrV6  map[SessionKeyV6]error
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
	if err, ok := m.retryErrV4[k]; ok {
		return err
	}
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
	if err, ok := m.retryErrV6[k]; ok {
		return err
	}
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

func batchDeleteV4Keys10528() []SessionKey {
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
	return keys
}

func batchDeleteV6Keys10528() []SessionKeyV6 {
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
	return keys
}

// TestBatchDeleteV4SurfacesPerKeyErrorAfterNotFound proves a hard per-key
// failure after the batch's missing-key stop is returned, while the rest of
// the tail is still attempted.
func TestBatchDeleteV4SurfacesPerKeyErrorAfterNotFound(t *testing.T) {
	keys := batchDeleteV4Keys10528()
	errBoom := errors.New("per-key v4 delete failed")
	dp := &batchDeleteTailDP{
		missingV4:  keys[1],
		presentV4:  map[SessionKey]bool{},
		retryErrV4: map[SessionKey]error{keys[1]: ebpf.ErrKeyNotExist, keys[3]: errBoom},
	}
	for i, k := range keys {
		dp.presentV4[k] = i != 1
	}

	store := dataPlaneSessionStore{dp: dp}
	deleted, err := store.batchDeleteV4(scopedV4(keys))
	if !errors.Is(err, errBoom) {
		t.Fatalf("batchDeleteV4 error = %v, want %v", err, errBoom)
	}
	if deleted != 3 {
		t.Fatalf("batchDeleteV4 deleted = %d, want 3 successful deletes", deleted)
	}
	// The partial is NOT a prefix: the boom key's row is retained (the hole)
	// while later tail keys were still deleted. Consumers must not treat
	// [:deleted] as the deleted set (#10598).
	if !dp.presentV4[keys[3]] {
		t.Errorf("boom key index 3 was dropped from the table, want retained (failed delete keeps the row)")
	}
	for _, idx := range []int{0, 2, 4} {
		if dp.presentV4[keys[idx]] {
			t.Errorf("key index %d survived, want deleted", idx)
		}
	}

	attempted := make(map[SessionKey]bool, len(dp.attempted))
	for _, k := range dp.attempted {
		attempted[k] = true
	}
	for _, idx := range []int{2, 4} {
		if !attempted[keys[idx]] {
			t.Errorf("key index %d was not attempted after per-key failure", idx)
		}
	}
}

// TestBatchDeleteV6SurfacesPerKeyErrorAfterNotFound is the IPv6 twin.
func TestBatchDeleteV6SurfacesPerKeyErrorAfterNotFound(t *testing.T) {
	keys := batchDeleteV6Keys10528()
	errBoom := errors.New("per-key v6 delete failed")
	dp := &batchDeleteTailDP{
		missingV6:  keys[1],
		presentV6:  map[SessionKeyV6]bool{},
		retryErrV6: map[SessionKeyV6]error{keys[1]: ebpf.ErrKeyNotExist, keys[3]: errBoom},
	}
	for i, k := range keys {
		dp.presentV6[k] = i != 1
	}

	store := dataPlaneSessionStore{dp: dp}
	deleted, err := store.batchDeleteV6(scopedV6(keys))
	if !errors.Is(err, errBoom) {
		t.Fatalf("batchDeleteV6 error = %v, want %v", err, errBoom)
	}
	if deleted != 3 {
		t.Fatalf("batchDeleteV6 deleted = %d, want 3 successful deletes", deleted)
	}
	// Non-prefix partial, V6 twin of the V4 hole pin above (#10598).
	if !dp.presentV6[keys[3]] {
		t.Errorf("v6 boom key index 3 was dropped from the table, want retained (failed delete keeps the row)")
	}
	for _, idx := range []int{0, 2, 4} {
		if dp.presentV6[keys[idx]] {
			t.Errorf("v6 key index %d survived, want deleted", idx)
		}
	}

	attempted := make(map[SessionKeyV6]bool, len(dp.attemptedV6))
	for _, k := range dp.attemptedV6 {
		attempted[k] = true
	}
	for _, idx := range []int{2, 4} {
		if !attempted[keys[idx]] {
			t.Errorf("v6 key index %d was not attempted after per-key failure", idx)
		}
	}
}

// TestBatchDeleteV4IgnoresAllNotFoundPerKey guards the benign recovery case:
// every retry can race with another deleter and still must report success.
func TestBatchDeleteV4IgnoresAllNotFoundPerKey(t *testing.T) {
	keys := batchDeleteV4Keys10528()
	retryErr := make(map[SessionKey]error, len(keys))
	for _, k := range keys {
		retryErr[k] = ebpf.ErrKeyNotExist
	}
	dp := &batchDeleteTailDP{
		missingV4:  keys[0],
		presentV4:  map[SessionKey]bool{},
		retryErrV4: retryErr,
	}
	for i, k := range keys {
		dp.presentV4[k] = i != 0
	}

	store := dataPlaneSessionStore{dp: dp}
	deleted, err := store.batchDeleteV4(scopedV4(keys))
	if err != nil {
		t.Fatalf("batchDeleteV4 returned all-not-found error: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("batchDeleteV4 deleted = %d, want 0", deleted)
	}
}

// TestDeleteBatchKnownV4SurfacesRecoveryLoopFailure proves the public known
// delete boundary preserves a recovery-loop error for its caller.
func TestDeleteBatchKnownV4SurfacesRecoveryLoopFailure(t *testing.T) {
	keys := batchDeleteV4Keys10528()
	errBoom := errors.New("known delete recovery failed")
	dp := &batchDeleteTailDP{
		missingV4:  keys[1],
		presentV4:  map[SessionKey]bool{},
		retryErrV4: map[SessionKey]error{keys[1]: ebpf.ErrKeyNotExist, keys[3]: errBoom},
	}
	for i, k := range keys {
		dp.presentV4[k] = i != 1
	}
	entries := make([]SessionEntryV4, len(keys))
	for i, k := range keys {
		entries[i] = SessionEntryV4{Key: k}
	}

	store := dataPlaneSessionStore{dp: dp}
	deleted, err := store.DeleteBatchKnownV4(entries, DeleteReasonGCExpired, true)
	if !errors.Is(err, errBoom) {
		t.Fatalf("DeleteBatchKnownV4 error = %v, want %v", err, errBoom)
	}
	if deleted != 3 {
		t.Fatalf("DeleteBatchKnownV4 deleted = %d, want 3 successful deletes", deleted)
	}
}

// TestDeleteBatchKnownExactV4ProjectsTheNonPrefixDeletedSet pins the public
// exact projection for the canonical missing@1/boom@3 hole (#10598).
func TestDeleteBatchKnownExactV4ProjectsTheNonPrefixDeletedSet(t *testing.T) {
	keys := batchDeleteV4Keys10528()
	errBoom := errors.New("exact projection boom")
	dp := &batchDeleteTailDP{
		missingV4:  keys[1],
		presentV4:  map[SessionKey]bool{},
		retryErrV4: map[SessionKey]error{keys[1]: ebpf.ErrKeyNotExist, keys[3]: errBoom},
	}
	for i, key := range keys {
		dp.presentV4[key] = i != 1
	}
	entries := make([]SessionEntryV4, len(keys))
	for i, key := range keys {
		entries[i] = SessionEntryV4{Key: key}
	}

	store := dataPlaneSessionStore{dp: dp}
	exact, err := store.DeleteBatchKnownExactV4(entries, DeleteReasonGCExpired, true)
	if !errors.Is(err, errBoom) {
		t.Fatalf("DeleteBatchKnownExactV4 error = %v, want %v", err, errBoom)
	}
	want := []SessionKey{keys[0], keys[2], keys[4]}
	if len(exact) != len(want) {
		t.Fatalf("exact deleted keys = %+v, want %+v", exact, want)
	}
	for i := range want {
		if exact[i] != want[i] {
			t.Fatalf("exact deleted keys = %+v, want %+v", exact, want)
		}
	}
	if dp.presentV4[keys[3]] == false {
		t.Fatalf("boom key survived? present=%v, want retained", dp.presentV4[keys[3]])
	}
}

// TestDeleteBatchKnownExactV6ProjectsTheNonPrefixDeletedSet is the IPv6 twin.
func TestDeleteBatchKnownExactV6ProjectsTheNonPrefixDeletedSet(t *testing.T) {
	keys := batchDeleteV6Keys10528()
	errBoom := errors.New("exact v6 projection boom")
	dp := &batchDeleteTailDP{
		missingV6:  keys[1],
		presentV6:  map[SessionKeyV6]bool{},
		retryErrV6: map[SessionKeyV6]error{keys[1]: ebpf.ErrKeyNotExist, keys[3]: errBoom},
	}
	for i, key := range keys {
		dp.presentV6[key] = i != 1
	}
	entries := make([]SessionEntryV6, len(keys))
	for i, key := range keys {
		entries[i] = SessionEntryV6{Key: key}
	}

	store := dataPlaneSessionStore{dp: dp}
	exact, err := store.DeleteBatchKnownExactV6(entries, DeleteReasonGCExpired, true)
	if !errors.Is(err, errBoom) {
		t.Fatalf("DeleteBatchKnownExactV6 error = %v, want %v", err, errBoom)
	}
	want := []SessionKeyV6{keys[0], keys[2], keys[4]}
	if len(exact) != len(want) {
		t.Fatalf("exact deleted v6 keys = %+v, want %+v", exact, want)
	}
	for i := range want {
		if exact[i] != want[i] {
			t.Fatalf("exact deleted v6 keys = %+v, want %+v", exact, want)
		}
	}
	if dp.presentV6[keys[3]] == false {
		t.Fatalf("v6 boom key survived? present=%v, want retained", dp.presentV6[keys[3]])
	}
}

// TestDeleteBatchKnownExactV4ProjectsMultiChunkSet pins exact-set accumulation
// across the 64-key boundary: missing@64, hard error@66, and successful tail.
func TestDeleteBatchKnownExactV4ProjectsMultiChunkSet(t *testing.T) {
	keys := make([]SessionKey, 70)
	for i := range keys {
		keys[i] = SessionKey{
			SrcIP:    [4]byte{10, 0, 0, byte(i)},
			DstIP:    [4]byte{10, 0, 1, byte(i)},
			Protocol: 6,
			SrcPort:  uint16(1000 + i),
			DstPort:  80,
		}
	}
	errBoom := errors.New("multi-chunk exact projection boom")
	dp := &batchDeleteTailDP{
		missingV4:  keys[64],
		presentV4:  map[SessionKey]bool{},
		retryErrV4: map[SessionKey]error{keys[64]: ebpf.ErrKeyNotExist, keys[66]: errBoom},
	}
	for i, key := range keys {
		dp.presentV4[key] = i != 64
	}
	entries := make([]SessionEntryV4, len(keys))
	for i, key := range keys {
		entries[i] = SessionEntryV4{Key: key}
	}

	exact, err := (dataPlaneSessionStore{dp: dp}).DeleteBatchKnownExactV4(entries, DeleteReasonGCExpired, true)
	if !errors.Is(err, errBoom) {
		t.Fatalf("DeleteBatchKnownExactV4 error = %v, want %v", err, errBoom)
	}
	want := make([]SessionKey, 0, len(keys)-2)
	for i, key := range keys {
		if i != 64 && i != 66 {
			want = append(want, key)
		}
	}
	if len(exact) != len(want) {
		t.Fatalf("exact deleted keys length = %d, want %d", len(exact), len(want))
	}
	for i := range want {
		if exact[i] != want[i] {
			t.Fatalf("exact deleted keys[%d] = %+v, want %+v", i, exact[i], want[i])
		}
	}
	if !dp.presentV4[keys[66]] {
		t.Fatalf("boom key deleted, want retained: %+v", keys[66])
	}
}

// TestDeleteBatchKnownExactV6ProjectsMultiChunkSet is the IPv6 twin.
func TestDeleteBatchKnownExactV6ProjectsMultiChunkSet(t *testing.T) {
	keys := make([]SessionKeyV6, 70)
	for i := range keys {
		var src, dst [16]byte
		src[0], src[15] = 0x20, byte(i)
		dst[0], dst[15] = 0x30, byte(i)
		keys[i] = SessionKeyV6{
			SrcIP:    src,
			DstIP:    dst,
			Protocol: 6,
			SrcPort:  uint16(1000 + i),
			DstPort:  80,
		}
	}
	errBoom := errors.New("multi-chunk v6 exact projection boom")
	dp := &batchDeleteTailDP{
		missingV6:  keys[64],
		presentV6:  map[SessionKeyV6]bool{},
		retryErrV6: map[SessionKeyV6]error{keys[64]: ebpf.ErrKeyNotExist, keys[66]: errBoom},
	}
	for i, key := range keys {
		dp.presentV6[key] = i != 64
	}
	entries := make([]SessionEntryV6, len(keys))
	for i, key := range keys {
		entries[i] = SessionEntryV6{Key: key}
	}

	exact, err := (dataPlaneSessionStore{dp: dp}).DeleteBatchKnownExactV6(entries, DeleteReasonGCExpired, true)
	if !errors.Is(err, errBoom) {
		t.Fatalf("DeleteBatchKnownExactV6 error = %v, want %v", err, errBoom)
	}
	want := make([]SessionKeyV6, 0, len(keys)-2)
	for i, key := range keys {
		if i != 64 && i != 66 {
			want = append(want, key)
		}
	}
	if len(exact) != len(want) {
		t.Fatalf("exact deleted v6 keys length = %d, want %d", len(exact), len(want))
	}
	for i := range want {
		if exact[i] != want[i] {
			t.Fatalf("exact deleted v6 keys[%d] = %+v, want %+v", i, exact[i], want[i])
		}
	}
	if !dp.presentV6[keys[66]] {
		t.Fatalf("v6 boom key deleted, want retained: %+v", keys[66])
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
