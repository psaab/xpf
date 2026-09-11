package cluster

import "container/list"

// genTombstoneOrder records, oldest first, the keys whose receiver-side stored generation is a
// TOMBSTONE (#2221: an applied non-zero delete) (#9719).
//
// A tombstone never frees its map entry, so on a long-lived connection the receiver map filled with
// tombstones of closed sessions. Once it reached genGuardMapCap, every NEW key was skip-recorded, and
// the #2170/#2221 ordering guards were off for every new session until the next bulk. The order lets a
// full map make room for a new key by evicting the OLDEST tombstone instead. A live entry is never
// evicted (#2198 F1).
//
// Evicting the oldest tombstone re-opens only that key's reorder window. That is the key least likely
// to still have a reordered install in flight, because a reorder is bounded by the frames in transit
// when the stream moved or the enqueue race ran.
//
// Invariant, under recvGenMu: every key in the order is present in the generation map, with its
// tombstone as the stored value.
//   - A re-install or a gen-0 delete removes the key (forget).
//   - evictOldest removes it from both the order and the map.
//   - So the order can never outgrow the map.
type genTombstoneOrder[K comparable] struct {
	order *list.List
	elems map[K]*list.Element
}

// mark records key as the NEWEST tombstone, moving it to the back if it is already one.
func (o *genTombstoneOrder[K]) mark(key K) {
	if o.order == nil {
		o.order = list.New()
		o.elems = make(map[K]*list.Element)
	}
	if e, ok := o.elems[key]; ok {
		o.order.MoveToBack(e)
		return
	}
	o.elems[key] = o.order.PushBack(key)
}

// forget removes key from the order, because the key is live again or its entry is gone.
func (o *genTombstoneOrder[K]) forget(key K) {
	if o.elems == nil {
		return
	}
	if e, ok := o.elems[key]; ok {
		o.order.Remove(e)
		delete(o.elems, key)
	}
}

// evictOldest deletes the oldest tombstone from m and from the order, and reports whether there was
// one to evict.
func (o *genTombstoneOrder[K]) evictOldest(m map[K]uint64) bool {
	if o.order == nil || o.order.Len() == 0 {
		return false
	}
	e := o.order.Front()
	key := e.Value.(K)
	o.order.Remove(e)
	delete(o.elems, key)
	delete(m, key)
	return true
}

// size reports how many tombstones are recorded.
func (o *genTombstoneOrder[K]) size() int {
	if o.order == nil {
		return 0
	}
	return o.order.Len()
}

// reset forgets every tombstone. The caller resets the generation map with it.
func (o *genTombstoneOrder[K]) reset() {
	o.order = nil
	o.elems = nil
}

// putGenEvictingTombstones records gen for key the way putGenBounded does, with one difference (#9719).
// When the map is full and key is NEW, it first evicts the oldest tombstone to make room. It never
// evicts a live entry, and it never clears the map (#2198 F1).
//
// It reports whether gen was stored and whether a tombstone was evicted. The caller holds the map's
// mutex.
func putGenEvictingTombstones[K comparable](m map[K]uint64, tombs *genTombstoneOrder[K], key K, gen uint64) (stored, evicted bool) {
	if _, exists := m[key]; !exists && len(m) >= genGuardMapCap {
		evicted = tombs.evictOldest(m)
	}
	return putGenBounded(m, key, gen), evicted
}
