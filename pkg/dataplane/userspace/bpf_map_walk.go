package userspace

import "log/slog"

// bpfKeyWalker is the part of *ebpf.Map a walk-and-delete needs. It is an
// interface so the walk can be proven linear against a model of the kernel's
// hash-map iteration (bpf_map_walk_18696_test.go).
type bpfKeyWalker interface {
	KeySize() uint32
	MaxEntries() uint32
	NextKey(key, nextKeyOut interface{}) error
	Delete(key interface{}) error
}

// walkDeleteBPFKeys visits every key in m and deletes each one drop accepts
// (every key when drop is nil). It returns the deletion attempts and the
// number of keys kept. Deletion is best-effort, like the loops it replaced:
// a failed Delete still counts as an attempt.
//
// #18696: the NEXT key is read BEFORE the current key is deleted. The kernel
// hash-map get_next_key (htab_map_get_next_key) looks its argument up first.
// For a key that is no longer in the map, it falls back to find_first_elem: a
// scan from bucket 0. The replaced loops deleted a key and then asked for the
// key after it, so every step rescanned the map from the start. That costs
// about buckets x rows / 2 bucket checks: about 225 s for 50,002 rows in the
// 8,388,608-bucket userspace_sessions map, measured at a helper respawn on tcp.
// Asking while the key still exists makes each step continue from that key's
// bucket, so a whole walk is O(buckets + rows).
//
// The walk starts from NextKey(nil), the first key. The replaced loops
// started from an all-zero key, which skips a real all-zero key.
//
// A concurrent delete of the key the walk is standing on can still restart it
// from the first element and revisit kept keys. The step count is therefore
// bounded at twice the map's capacity, so the walk always terminates.
func walkDeleteBPFKeys(m bpfKeyWalker, drop func(key []byte) bool) (deleted, kept int) {
	size := int(m.KeySize())
	cur := make([]byte, size)
	next := make([]byte, size)
	if err := m.NextKey(nil, cur); err != nil {
		return 0, 0
	}
	limit := 2*int(m.MaxEntries()) + 1
	for step := 1; ; step++ {
		more := m.NextKey(cur, next) == nil
		if drop == nil || drop(cur) {
			_ = m.Delete(cur)
			deleted++
		} else {
			kept++
		}
		if !more {
			return deleted, kept
		}
		if step >= limit {
			slog.Warn("userspace: BPF map walk stopped at its step bound; the map changed under the walk",
				"steps", step, "deleted", deleted, "kept", kept)
			return deleted, kept
		}
		cur, next = next, cur
	}
}
