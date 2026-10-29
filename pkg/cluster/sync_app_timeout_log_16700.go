package cluster

// appTimeoutLogMemo preserves one session incarnation's per-application
// inactivity timeout (#3227/#15207, seconds; 86401 = never) and per-policy
// then-log flags (#2785) across mirror-sourced resends (#16700). The Rust
// publish path now writes both into the BPF mirror, but a legacy helper,
// a stamp-less frame from an old sender, or any future mirror projection
// that drops them must not wipe the standby's values — the same #14359
// doctrine that protects policy identity. Records are keyed per tuple and
// matched on SessionID; a new incarnation never inherits and SessionID 0
// records/restores nothing.
//
// #17780: `recorded` distinguishes an explicitly stated (0,0) from an absent
// pair. The pair's value alone cannot tell a correction from a stamp-less
// resend; the explicit marker is carried from the helper's session delta
// through the cluster wire. Once recorded, a stamp-less resend preserves the
// stated pair (including zero).
type appTimeoutLogMemo struct {
	sessionID  uint64
	appTimeout uint32
	logFlags   uint8
	recorded   bool
}

// stampAppTimeoutLogLocked records an explicitly stated pair or restores it
// on a stamp-less resend. Non-zero pairs are self-evidently stated for legacy
// peers; an explicit marker is required to state (0,0). Returns false when a
// new record cannot be stored at the current cap.
func stampAppTimeoutLogLocked[K comparable](m map[K]appTimeoutLogMemo, key K, sessionID uint64, appTimeout *uint32, logFlags *uint8, stated *bool, maxEntries int) bool {
	if sessionID == 0 {
		return true
	}
	rec, ok := m[key]
	if ok && rec.sessionID != sessionID {
		delete(m, key)
		ok = false
	}
	if *stated || *appTimeout != 0 || *logFlags != 0 {
		if !ok && len(m) >= maxEntries {
			return false
		}
		m[key] = appTimeoutLogMemo{
			sessionID: sessionID, appTimeout: *appTimeout, logFlags: *logFlags, recorded: true,
		}
		*stated = true
		return true
	}
	if ok && rec.recorded {
		*appTimeout, *logFlags = rec.appTimeout, rec.logFlags
		// Re-emit presence so a current peer and any further resend retain
		// an explicitly stated (0,0). Non-zero legacy values need no marker,
		// but setting it lets the same memo path carry one uniform contract.
		*stated = true
	}
	// An absent pair on first contact remains absent: do not create a
	// zero-valued memo entry that could later masquerade as a correction.
	return true
}

func lookupAppTimeoutLogLocked[K comparable](m map[K]appTimeoutLogMemo, key K, sessionID uint64) (uint32, uint8, bool, bool) {
	if sessionID == 0 {
		return 0, 0, false, false
	}
	rec, ok := m[key]
	if !ok || rec.sessionID != sessionID || !rec.recorded {
		return 0, 0, false, false
	}
	return rec.appTimeout, rec.logFlags, true, true
}
