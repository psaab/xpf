package cluster

// appTimeoutLogMemo preserves one session incarnation's per-application
// inactivity timeout (#3227/#15207, seconds; 86401 = never) and per-policy
// then-log flags (#2785) across mirror-sourced resends (#16700). The Rust
// publish path now writes both into the BPF mirror, but a legacy helper,
// a stamp-less frame from an old sender, or any future mirror projection
// that drops them must not wipe the standby's values — the same #14359
// doctrine that protects policy identity. Records are keyed per tuple and
// matched on SessionID; a new incarnation never inherits, SessionID 0
// records/restores nothing, and any stated (non-zero) field records both
// as stated so a corrected binding wins over the record.
type appTimeoutLogMemo struct {
	sessionID  uint64
	appTimeout uint32
	logFlags   uint8
}

func stampAppTimeoutLogLocked[K comparable](m map[K]appTimeoutLogMemo, key K, sessionID uint64, appTimeout *uint32, logFlags *uint8, maxEntries int) bool {
	if sessionID == 0 {
		return true
	}
	rec, ok := m[key]
	if ok && rec.sessionID != sessionID {
		delete(m, key)
		ok = false
	}
	if *appTimeout == 0 && *logFlags == 0 {
		if ok && (rec.appTimeout != 0 || rec.logFlags != 0) {
			*appTimeout, *logFlags = rec.appTimeout, rec.logFlags
		}
		return true
	}
	if !ok && len(m) >= maxEntries {
		return false
	}
	m[key] = appTimeoutLogMemo{sessionID: sessionID, appTimeout: *appTimeout, logFlags: *logFlags}
	return true
}

func lookupAppTimeoutLogLocked[K comparable](m map[K]appTimeoutLogMemo, key K, sessionID uint64) (uint32, uint8, bool) {
	if sessionID == 0 {
		return 0, 0, false
	}
	rec, ok := m[key]
	if !ok || rec.sessionID != sessionID || (rec.appTimeout == 0 && rec.logFlags == 0) {
		return 0, 0, false
	}
	return rec.appTimeout, rec.logFlags, true
}
