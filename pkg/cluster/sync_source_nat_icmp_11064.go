package cluster

// sourceNatICMPMemo preserves the source packet identity for one session
// incarnation. The BPF mirror cannot carry this sync-only value, so sweeps and
// bulk resends recover it from the sender or receiver memo.
type sourceNatICMPMemo struct {
	sessionID uint64
	valid     bool
	typ       uint8
	code      uint8
}

// stampSourceNatICMPLocked records a typed source-NAT identity or restores it
// when a mirror-sourced resend has lost the sync-only fields. The caller holds
// the corresponding sender/receiver generation mutex. Returns false when a
// new valid identity cannot be recorded at the current cap.
func stampSourceNatICMPLocked[K comparable](m map[K]sourceNatICMPMemo, key K, sessionID uint64, valid *bool, typ, code *uint8, maxEntries int) bool {
	if sessionID == 0 {
		return true
	}
	rec, ok := m[key]
	if ok && rec.sessionID != sessionID {
		delete(m, key)
		ok = false
	}
	if ok && !*valid && rec.valid {
		*valid, *typ, *code = true, rec.typ, rec.code
	}
	if !*valid {
		return true
	}
	if !ok && len(m) >= maxEntries {
		return false
	}
	m[key] = sourceNatICMPMemo{sessionID: sessionID, valid: true, typ: *typ, code: *code}
	return true
}

func lookupSourceNatICMPLocked[K comparable](m map[K]sourceNatICMPMemo, key K, sessionID uint64) (uint8, uint8, bool) {
	if sessionID == 0 {
		return 0, 0, false
	}
	rec, ok := m[key]
	if !ok || rec.sessionID != sessionID || !rec.valid {
		return 0, 0, false
	}
	return rec.typ, rec.code, true
}
