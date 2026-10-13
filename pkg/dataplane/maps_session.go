package dataplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// IsKeyNotFound reports whether err is a map "key does not exist" error
// from a session/DNAT/companion delete or lookup. It keeps the
// github.com/cilium/ebpf sentinel behind the dataplane boundary so
// operator packages (pkg/cli, pkg/grpcapi) can classify a delete result
// without importing the BPF-artifact package directly (the
// retirement-boundary canary forbids that import). It treats both
// ebpf.ErrKeyNotExist and unix.ENOENT as not-found.
//
// Used by the session-clear paths (#2468): a NAT'd session's reverse
// companion is keyed on the TRANSLATED tuple, so the naive-swap reverse
// key and the DNAT companion key are frequently absent on an otherwise
// successful clear — a benign idempotent not-found, not a failure.
func IsKeyNotFound(err error) bool {
	return errors.Is(err, ebpf.ErrKeyNotExist) || errors.Is(err, unix.ENOENT)
}

// Conntrack session-table map accessors.
// Same-package split of maps.go (#1686): iterate/batch/get/set/delete for the
// v4 and v6 session maps, session counting, full-table clear (which also drops
// the associated dynamic DNAT entries — see ClearAllSessions), and the
// node-scoped session-ID counter seed.

// IterateSessions iterates all session entries, calling fn for each.
// fn receives the key and value; return false to stop iteration.
//
// When the userspace dataplane is active, this map contains mirrored
// sessions written by the Rust helper's publish_bpf_conntrack_entry —
// since #6965 that includes ordinary TRANSIT sessions, which previously
// had no row here at all and were therefore invisible to every caller
// of this function.
// The helper periodically refreshes LastSeen (~10s) so callers see
// reasonably accurate idle times.  Session lifetime is owned by the
// helper, not Go GC (GC.SkipSweep is set).  See #333.
func (m *Manager) IterateSessions(fn func(SessionKey, SessionValue) bool) error {
	sm, present, st := m.lookupMapLocked("sessions")
	if st == registryFresh {
		return fmt.Errorf("%w: sessions", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("sessions map not found")
	}

	var key SessionKey
	var val bpfSessionValue
	iter := sm.Iterate()
	for iter.Next(&key, &val) {
		if !fn(key, val.sessionValue()) {
			break
		}
	}
	return iter.Err()
}

// DeleteSession deletes a session entry by key.
func (m *Manager) DeleteSession(key SessionKey) error {
	sm, present, st := m.lookupMapLocked("sessions")
	if st == registryFresh {
		return fmt.Errorf("%w: sessions", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("sessions map not found")
	}
	return sm.Delete(key)
}

// SetSessionV4 writes a v4 session entry (used by cluster sync to install sessions from peer).
func (m *Manager) SetSessionV4(key SessionKey, val SessionValue) error {
	sm, present, st := m.lookupMapLocked("sessions")
	if st == registryFresh {
		return fmt.Errorf("%w: sessions", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("sessions map not found")
	}
	return sm.Update(key, val.toBPF(), ebpf.UpdateAny)
}

// GetSessionV4 looks up a single v4 session entry by key.
func (m *Manager) GetSessionV4(key SessionKey) (SessionValue, error) {
	sm, present, st := m.lookupMapLocked("sessions")
	if st == registryFresh {
		return SessionValue{}, fmt.Errorf("%w: sessions", ErrDataplaneNotArmed)
	}
	if !present {
		return SessionValue{}, fmt.Errorf("sessions map not found")
	}
	var val bpfSessionValue
	if err := sm.Lookup(key, &val); err != nil {
		return SessionValue{}, err
	}
	return val.sessionValue(), nil
}

// GetSessionV6 looks up a single v6 session entry by key.
func (m *Manager) GetSessionV6(key SessionKeyV6) (SessionValueV6, error) {
	sm, present, st := m.lookupMapLocked("sessions_v6")
	if st == registryFresh {
		return SessionValueV6{}, fmt.Errorf("%w: sessions_v6", ErrDataplaneNotArmed)
	}
	if !present {
		return SessionValueV6{}, fmt.Errorf("sessions_v6 map not found")
	}
	var val bpfSessionValueV6
	if err := sm.Lookup(key, &val); err != nil {
		return SessionValueV6{}, err
	}
	return val.sessionValue(), nil
}

// IterateSessionsV6 iterates all IPv6 session entries, calling fn for each.
func (m *Manager) IterateSessionsV6(fn func(SessionKeyV6, SessionValueV6) bool) error {
	sm, present, st := m.lookupMapLocked("sessions_v6")
	if st == registryFresh {
		return fmt.Errorf("%w: sessions_v6", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("sessions_v6 map not found")
	}

	var key SessionKeyV6
	var val bpfSessionValueV6
	iter := sm.Iterate()
	for iter.Next(&key, &val) {
		if !fn(key, val.sessionValue()) {
			break
		}
	}
	return iter.Err()
}

// IterateSessionsFrom iterates v4 session entries starting after cursorKey.
// If cursorKey is nil, iteration starts from the beginning.
// fn returns false to stop iteration.
func (m *Manager) IterateSessionsFrom(cursorKey *SessionKey, fn func(SessionKey, SessionValue) bool) error {
	sm, present, st := m.lookupMapLocked("sessions")
	if st == registryFresh {
		return fmt.Errorf("%w: sessions", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("sessions map not found")
	}

	var nextKey SessionKey
	var startKey interface{} = cursorKey
	if cursorKey == nil {
		startKey = nil
	}

	// Get the first key to iterate from.
	if err := sm.NextKey(startKey, &nextKey); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil // no entries or cursor at end
		}
		return fmt.Errorf("sessions NextKey: %w", err)
	}

	for {
		var val bpfSessionValue
		if err := sm.Lookup(nextKey, &val); err != nil {
			// Entry may have been deleted between NextKey and Lookup; skip.
			var next SessionKey
			if err := sm.NextKey(nextKey, &next); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					return nil
				}
				return fmt.Errorf("sessions NextKey: %w", err)
			}
			nextKey = next
			continue
		}
		if !fn(nextKey, val.sessionValue()) {
			return nil
		}
		var next SessionKey
		if err := sm.NextKey(nextKey, &next); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil // end of map
			}
			return fmt.Errorf("sessions NextKey: %w", err)
		}
		nextKey = next
	}
}

// IterateSessionsV6From iterates v6 session entries starting after cursorKey.
// If cursorKey is nil, iteration starts from the beginning.
// fn returns false to stop iteration.
func (m *Manager) IterateSessionsV6From(cursorKey *SessionKeyV6, fn func(SessionKeyV6, SessionValueV6) bool) error {
	sm, present, st := m.lookupMapLocked("sessions_v6")
	if st == registryFresh {
		return fmt.Errorf("%w: sessions_v6", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("sessions_v6 map not found")
	}

	var nextKey SessionKeyV6
	var startKey interface{} = cursorKey
	if cursorKey == nil {
		startKey = nil
	}

	if err := sm.NextKey(startKey, &nextKey); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("sessions_v6 NextKey: %w", err)
	}

	for {
		var val bpfSessionValueV6
		if err := sm.Lookup(nextKey, &val); err != nil {
			var next SessionKeyV6
			if err := sm.NextKey(nextKey, &next); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					return nil
				}
				return fmt.Errorf("sessions_v6 NextKey: %w", err)
			}
			nextKey = next
			continue
		}
		if !fn(nextKey, val.sessionValue()) {
			return nil
		}
		var next SessionKeyV6
		if err := sm.NextKey(nextKey, &next); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil
			}
			return fmt.Errorf("sessions_v6 NextKey: %w", err)
		}
		nextKey = next
	}
}

// BatchIterateSessions iterates sessions using batch lookup for reduced
// kernel lock contention.  Yields between batches so BPF datapath isn't
// starved of hash-table bucket locks.
func (m *Manager) BatchIterateSessions(fn func(SessionKey, SessionValue) bool) error {
	sm, present, st := m.lookupMapLocked("sessions")
	if st == registryFresh {
		return fmt.Errorf("%w: sessions", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("sessions map not found")
	}

	const batchSize = 256
	keys := make([]SessionKey, batchSize)
	vals := make([]bpfSessionValue, batchSize)
	var cursor ebpf.MapBatchCursor

	for {
		n, err := sm.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			if !fn(keys[i], vals[i].sessionValue()) {
				return nil
			}
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil // done
		}
		if err != nil {
			return fmt.Errorf("batch lookup sessions: %w", err)
		}
		runtime.Gosched() // yield to reduce lock contention with BPF datapath
	}
}

// BatchIterateSessionsV6 is the IPv6 variant of BatchIterateSessions.
func (m *Manager) BatchIterateSessionsV6(fn func(SessionKeyV6, SessionValueV6) bool) error {
	sm, present, st := m.lookupMapLocked("sessions_v6")
	if st == registryFresh {
		return fmt.Errorf("%w: sessions_v6", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("sessions_v6 map not found")
	}

	const batchSize = 256
	keys := make([]SessionKeyV6, batchSize)
	vals := make([]bpfSessionValueV6, batchSize)
	var cursor ebpf.MapBatchCursor

	for {
		n, err := sm.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			if !fn(keys[i], vals[i].sessionValue()) {
				return nil
			}
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("batch lookup sessions_v6: %w", err)
		}
		runtime.Gosched()
	}
}

// BatchDeleteSessions deletes multiple session entries in a single syscall.
func (m *Manager) BatchDeleteSessions(keys []SessionKey) (int, error) {
	sm, present, st := m.lookupMapLocked("sessions")
	if st == registryFresh {
		return 0, fmt.Errorf("%w: sessions", ErrDataplaneNotArmed)
	}
	if !present {
		return 0, fmt.Errorf("sessions map not found")
	}
	if len(keys) == 0 {
		return 0, nil
	}
	return sm.BatchDelete(keys, nil)
}

// BatchDeleteSessionsV6 deletes multiple IPv6 session entries in a single syscall.
func (m *Manager) BatchDeleteSessionsV6(keys []SessionKeyV6) (int, error) {
	sm, present, st := m.lookupMapLocked("sessions_v6")
	if st == registryFresh {
		return 0, fmt.Errorf("%w: sessions_v6", ErrDataplaneNotArmed)
	}
	if !present {
		return 0, fmt.Errorf("sessions_v6 map not found")
	}
	if len(keys) == 0 {
		return 0, nil
	}
	return sm.BatchDelete(keys, nil)
}

// DeleteSessionV6 deletes an IPv6 session entry by key.
func (m *Manager) DeleteSessionV6(key SessionKeyV6) error {
	sm, present, st := m.lookupMapLocked("sessions_v6")
	if st == registryFresh {
		return fmt.Errorf("%w: sessions_v6", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("sessions_v6 map not found")
	}
	return sm.Delete(key)
}

// SetSessionV6 writes a v6 session entry (used by cluster sync to install sessions from peer).
func (m *Manager) SetSessionV6(key SessionKeyV6, val SessionValueV6) error {
	sm, present, st := m.lookupMapLocked("sessions_v6")
	if st == registryFresh {
		return fmt.Errorf("%w: sessions_v6", ErrDataplaneNotArmed)
	}
	if !present {
		return fmt.Errorf("sessions_v6 map not found")
	}
	return sm.Update(key, val.toBPF(), ebpf.UpdateAny)
}

// SessionCount returns the number of active IPv4 and IPv6 sessions.
// Only forward entries are counted (IsReverse == 0).
func (m *Manager) SessionCount() (v4, v6 int) {
	if sm, present, _ := m.lookupMapLocked("sessions"); present {
		var key SessionKey
		var val bpfSessionValue
		iter := sm.Iterate()
		for iter.Next(&key, &val) {
			if val.IsReverse == 0 {
				v4++
			}
		}
	}
	if sm, present, _ := m.lookupMapLocked("sessions_v6"); present {
		var key SessionKeyV6
		var val bpfSessionValueV6
		iter := sm.Iterate()
		for iter.Next(&key, &val) {
			if val.IsReverse == 0 {
				v6++
			}
		}
	}
	return
}

// SessionCountContext counts forward-only sessions and stops when ctx is
// cancelled. It returns zero counts on cancellation so callers cannot mistake a
// partial walk for a successful total.
func (m *Manager) SessionCountContext(ctx context.Context) (v4, v6 int, err error) {
	if err = ctx.Err(); err != nil {
		return 0, 0, err
	}
	if sm, present, _ := m.lookupMapLocked("sessions"); present {
		var key SessionKey
		var val bpfSessionValue
		iter := sm.Iterate()
		visited := 0
		for iter.Next(&key, &val) {
			visited++
			if visited%1024 == 0 {
				if err = ctx.Err(); err != nil {
					return 0, 0, err
				}
			}
			if val.IsReverse == 0 {
				v4++
			}
		}
		if err = iter.Err(); err != nil {
			return 0, 0, err
		}
	}
	if err = ctx.Err(); err != nil {
		return 0, 0, err
	}
	if sm, present, _ := m.lookupMapLocked("sessions_v6"); present {
		var key SessionKeyV6
		var val bpfSessionValueV6
		iter := sm.Iterate()
		visited := 0
		for iter.Next(&key, &val) {
			visited++
			if visited%1024 == 0 {
				if err = ctx.Err(); err != nil {
					return 0, 0, err
				}
			}
			if val.IsReverse == 0 {
				v6++
			}
		}
		if err = iter.Err(); err != nil {
			return 0, 0, err
		}
	}
	if err = ctx.Err(); err != nil {
		return 0, 0, err
	}
	return v4, v6, nil
}

// sessionClearBatchObserver, when non-nil, is invoked with the number of keys
// passed to each BPF_MAP_DELETE_BATCH syscall issued by the full-table clear
// path (clearSessionsV4/clearSessionsV6). It is a test-only seam that lets a
// unit test assert the batched delete path is taken so a regression back to a
// per-key delete loop (#4719) is detectable. Production leaves it nil (a single
// non-hot-path nil check per chunk).
var sessionClearBatchObserver func(batchKeys int)

// sessionClearSnapshotObserver, when non-nil, is invoked once per collected key
// CHUNK with the number of keys in that chunk (bounded by
// sessionClearSnapshotChunk). It is a test-only seam that lets a unit test
// assert the clear collects keys in bounded chunks instead of snapshotting the
// entire table into one N-sized slice (#5304). A revert to the collect-all
// clear stops invoking it, so a bounded-working-set test goes RED. Production
// leaves it nil.
var sessionClearSnapshotObserver func(chunkKeys int)

// sessionClearSnapshotChunk bounds the working set of the full-table clear. The
// session table can hold up to ~10M entries per family; snapshotting every key
// (v4 + v6) plus the dynamic DNAT key lists into slices before any delete
// stacks them all in RSS at once — ~1 GB on a max-loaded table, enough for the
// supported-max recovery command (`clear security flow session all`) to stall
// or OOM-kill the daemon (#5304). The clear instead collects at most this many
// keys, deletes that chunk (and its DNAT entries), then re-scans for the next
// chunk, so peak key-slice memory is O(chunk), not O(table). It is a var (not
// const) so a test can shrink it to exercise the multi-chunk path with a small
// table.
var sessionClearSnapshotChunk = 4096

// ClearAllSessions deletes all IPv4 and IPv6 sessions, plus associated
// dynamic DNAT table entries for SNAT sessions. Returns (v4_deleted, v6_deleted, err).
func (m *Manager) ClearAllSessions() (int, int, error) {
	return m.ClearAllSessionsChunked(nil, nil)
}

// ClearAllSessionsChunked is the bounded-memory implementation of
// ClearAllSessions. onV4Chunk / onV6Chunk, when non-nil, are invoked with each
// deleted key chunk (bounded by sessionClearSnapshotChunk) so a caller — the
// userspace wrapper — can issue its authoritative Rust-helper delete per chunk
// WITHOUT building a second full-table key snapshot of its own (the #5304
// double snapshot). The slices handed to the callbacks are valid only for the
// duration of the call; the backing array is reused across chunks.
//
// The full table can hold up to ~10M sessions, so the clear must neither
// monopolize the controller goroutine — a multi-second synchronous stall can
// starve the HA peer watchdog/heartbeat and trip a spurious failover (#4719) —
// nor spike RSS by snapshotting the whole table at once (#5304). Collection and
// deletion are therefore both cooperative AND bounded: collection uses the
// batch-lookup iterators (BatchIterateSessions{,V6}, which yield via
// runtime.Gosched between batches) but stops at sessionClearSnapshotChunk keys
// and re-scans for the remainder, and deletion uses chunked
// BPF_MAP_DELETE_BATCH syscalls that yield between chunks
// (clearSessionsV4/clearSessionsV6). Semantics are unchanged: every session —
// both the forward and the reverse conntrack entry — present at the start is
// still removed, plus the dynamic dnat_table entries for SNAT sessions.
func (m *Manager) ClearAllSessionsChunked(onV4Chunk func([]SessionKey), onV6Chunk func([]SessionKeyV6)) (int, int, error) {
	v4Deleted, err := m.clearSessionsChunkedV4(onV4Chunk)
	if err != nil {
		return v4Deleted, 0, err
	}
	v6Deleted, err := m.clearSessionsChunkedV6(onV6Chunk)
	if err != nil {
		return v4Deleted, v6Deleted, err
	}
	return v4Deleted, v6Deleted, nil
}

// clearSessionsChunkedV4 drains the IPv4 session map in bounded chunks: it
// collects up to sessionClearSnapshotChunk keys (plus the SNAT sessions' DNAT
// keys) from a fresh batch scan, deletes that chunk and its DNAT entries, hands
// the chunk to onChunk, then re-scans for the remainder until the map is empty.
// Because every collected key is deleted before the next scan, a fresh scan
// never re-returns it, so the loop converges — every key present at the start
// is removed — while holding only O(chunk) keys in memory (#5304).
func (m *Manager) clearSessionsChunkedV4(onChunk func([]SessionKey)) (int, error) {
	deleted := 0
	keys := make([]SessionKey, 0, sessionClearSnapshotChunk)
	var snatDNATKeys []DNATKey
	for {
		keys = keys[:0]
		snatDNATKeys = snatDNATKeys[:0]
		full := false
		if err := m.BatchIterateSessions(func(key SessionKey, val SessionValue) bool {
			keys = append(keys, key)
			// Track dynamic SNAT sessions for dnat_table cleanup.
			if val.IsReverse == 0 &&
				val.Flags&SessFlagSNAT != 0 &&
				val.Flags&SessFlagStaticNAT == 0 {
				// Must match the write-side key encoding (#2406: host-order port).
				snatDNATKeys = append(snatDNATKeys, dnatKeyForSessionV4(key, val))
			}
			if len(keys) >= sessionClearSnapshotChunk {
				full = true
				return false // chunk full — stop and re-scan for the remainder
			}
			return true
		}); err != nil {
			return deleted, fmt.Errorf("iterate sessions: %w", err)
		}
		if len(keys) == 0 {
			break // table drained
		}
		if sessionClearSnapshotObserver != nil {
			sessionClearSnapshotObserver(len(keys))
		}
		before := deleted
		deleted += m.clearSessionsV4(keys)
		for i, dk := range snatDNATKeys {
			m.DeleteDNATEntry(dk)
			if (i+1)%sessionDeleteBatchSize == 0 {
				runtime.Gosched()
			}
		}
		if onChunk != nil {
			onChunk(keys)
		}
		if !full {
			break // this scan drained the remaining keys
		}
		if deleted == before {
			// A full chunk that deleted nothing means these keys are
			// un-deletable; a fresh scan would return them forever. Break
			// rather than spin (defensive — a live map always makes progress).
			break
		}
	}
	return deleted, nil
}

// clearSessionsChunkedV6 is the IPv6 variant of clearSessionsChunkedV4.
func (m *Manager) clearSessionsChunkedV6(onChunk func([]SessionKeyV6)) (int, error) {
	deleted := 0
	keys := make([]SessionKeyV6, 0, sessionClearSnapshotChunk)
	var snatDNATKeys []DNATKeyV6
	for {
		keys = keys[:0]
		snatDNATKeys = snatDNATKeys[:0]
		full := false
		if err := m.BatchIterateSessionsV6(func(key SessionKeyV6, val SessionValueV6) bool {
			keys = append(keys, key)
			if val.IsReverse == 0 &&
				val.Flags&SessFlagSNAT != 0 &&
				val.Flags&SessFlagStaticNAT == 0 {
				// Must match the write-side key encoding (#2406: host-order port).
				snatDNATKeys = append(snatDNATKeys, dnatKeyForSessionV6(key, val))
			}
			if len(keys) >= sessionClearSnapshotChunk {
				full = true
				return false
			}
			return true
		}); err != nil {
			return deleted, fmt.Errorf("iterate sessions_v6: %w", err)
		}
		if len(keys) == 0 {
			break
		}
		if sessionClearSnapshotObserver != nil {
			sessionClearSnapshotObserver(len(keys))
		}
		before := deleted
		deleted += m.clearSessionsV6(keys)
		for i, dk := range snatDNATKeys {
			m.DeleteDNATEntryV6(dk)
			if (i+1)%sessionDeleteBatchSize == 0 {
				runtime.Gosched()
			}
		}
		if onChunk != nil {
			onChunk(keys)
		}
		if !full {
			break
		}
		if deleted == before {
			break
		}
	}
	return deleted, nil
}

// clearSessionsV4 deletes every key in keys from the v4 session map using
// chunked BPF_MAP_DELETE_BATCH syscalls (sessionDeleteBatchSize keys per
// syscall) instead of one syscall per key, yielding between chunks so a
// full-table clear cannot monopolize the controller goroutine (#4719). It
// returns the number of entries deleted.
//
// A key removed concurrently (GC/datapath) between collection and delete is
// tolerated: the kernel stops the batch at the first missing key, so the chunk
// remainder is retried one key at a time to guarantee every key is attempted
// and the clear stays complete (never a partial clear reported as done). The
// same per-key fallback covers a map that does not support batch delete.
func (m *Manager) clearSessionsV4(keys []SessionKey) int {
	deleted := 0
	for len(keys) > 0 {
		n := sessionDeleteBatchSize
		if len(keys) < n {
			n = len(keys)
		}
		chunk := keys[:n]
		cnt, err := m.BatchDeleteSessions(chunk)
		if cnt < 0 {
			cnt = 0
		} else if cnt > len(chunk) {
			cnt = len(chunk)
		}
		deleted += cnt
		if sessionClearBatchObserver != nil {
			sessionClearBatchObserver(n)
		}
		if err != nil {
			// Batch stopped early (a key vanished, or batch delete is
			// unsupported): finish the chunk remainder per-key so the clear
			// is complete. The first cnt keys were already deleted above.
			for _, k := range chunk[cnt:] {
				if delErr := m.DeleteSession(k); delErr == nil {
					deleted++
				}
			}
		}
		keys = keys[n:]
		runtime.Gosched()
	}
	return deleted
}

// clearSessionsV6 is the IPv6 variant of clearSessionsV4.
func (m *Manager) clearSessionsV6(keys []SessionKeyV6) int {
	deleted := 0
	for len(keys) > 0 {
		n := sessionDeleteBatchSize
		if len(keys) < n {
			n = len(keys)
		}
		chunk := keys[:n]
		cnt, err := m.BatchDeleteSessionsV6(chunk)
		if cnt < 0 {
			cnt = 0
		} else if cnt > len(chunk) {
			cnt = len(chunk)
		}
		deleted += cnt
		if sessionClearBatchObserver != nil {
			sessionClearBatchObserver(n)
		}
		if err != nil {
			for _, k := range chunk[cnt:] {
				if delErr := m.DeleteSessionV6(k); delErr == nil {
					deleted++
				}
			}
		}
		keys = keys[n:]
		runtime.Gosched()
	}
	return deleted
}

// SeedSessionIDCounter seeds the session_id_gen PERCPU map with a
// node-specific base to avoid collisions between cluster nodes.
// Each CPU gets base = (nodeID << 48) | (cpuIndex << 32).
func (m *Manager) SeedSessionIDCounter(nodeID int) {
	zm, present, _ := m.lookupMapLocked("session_id_gen")
	if !present {
		return
	}
	numCPUs, err := ebpf.PossibleCPU()
	if err != nil || numCPUs <= 0 {
		return
	}
	vals := make([]uint64, numCPUs)
	for i := range vals {
		vals[i] = (uint64(nodeID) << 48) | (uint64(i) << 32)
	}
	if err := zm.Update(uint32(0), vals, ebpf.UpdateAny); err != nil {
		slog.Warn("failed to seed session ID counter", "err", err)
		return
	}
	slog.Info("seeded session ID counter", "nodeID", nodeID, "cpus", numCPUs)
}
