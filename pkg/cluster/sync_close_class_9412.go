package cluster

// sentCloseClass is one session incarnation's last-sent TCP close class (#9412).
type sentCloseClass struct {
	sessionID uint64
	class     uint8
}

// stampCloseClassLocked (#9412) keeps a resend from regressing the TCP close class
// this node already announced for the SAME session incarnation.
//
// WHY. TCPCloseClass is sync-only, so the BPF conntrack mirror cannot carry it.
// The helper's delta path sends the real class, but the periodic sweep and the
// store-mirror bulk walk rebuild values FROM the mirror. Without this they resend
// 0, and the peer's closing copy goes back to the established window. That was
// measured on the live cluster: a flow that opened and closed inside one 15 s
// sweep window sent Open(0), Update(1), then a sweep resend with class 0.
//
// IDENTITY. The record is kept per tuple and matched on SessionID, the helper's
// stable per-incarnation id. The delta path adopts it
// (adoptedOrLocalSyncedSessionID), and the conntrack publisher stamps the same id
// into the mirror row the sweep reads.
//   - A reused tuple has a new id. Its frames never inherit the old
//     incarnation's class, in any arrival order.
//   - SessionID 0 means "no identity". Nothing is recorded or applied, which
//     fails toward class 0 (the pre-#9412 window), never toward an early reap of
//     a live session.
//   - The install generation cannot be the key: it is drawn fresh on every send.
//
// ORDERING. Identity cannot see one case: an OLD incarnation's own frame arriving
// after a reused tuple's newer frame. Redundant fabric connections can reorder
// (#5706). The receiver's installGenGuard refuses that frame, because every send
// path stamps from one monotonic nextInstallGen, so the older frame carries a
// strictly lower generation (#2170/#2221).
// TestLateOldIncarnationCloseFrameIsRefused9412 delivers that order. The guard
// degrades to unconditional only past genGuardMapCap keys, which is its existing
// bound.
//
// MONOTONE. Close classes only progress within an incarnation (CLOSING,
// TIME_WAIT, RST), so a matched frame carries the higher of its own class and
// the recorded one.
//
// The caller holds genSentMu. Generic over the two wire-key types.
func stampCloseClassLocked[K comparable](m map[K]sentCloseClass, key K, sessionID uint64, class *uint8) {
	if sessionID == 0 {
		return
	}
	rec, ok := m[key]
	if ok && rec.sessionID != sessionID {
		// A different incarnation of this tuple: the old record is dead.
		delete(m, key)
		ok = false
	}
	if ok && rec.class > *class {
		*class = rec.class
	}
	if *class == 0 {
		return
	}
	if !ok && len(m) >= genGuardMapCap {
		// Skip-record-on-full, like putGenBounded: no memo for this key, which
		// degrades to the pre-#9412 window, never to an early reap.
		return
	}
	m[key] = sentCloseClass{sessionID: sessionID, class: *class}
}
