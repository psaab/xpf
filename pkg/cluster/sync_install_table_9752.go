package cluster

// sentInstallTable is one session incarnation's last-sent installing-table
// identity (#9752).
type sentInstallTable struct {
	sessionID uint64
	domain    uint32
	check     uint32
}

// stampInstallTableLocked (#9752) keeps a resend from regressing the
// installing-table identity this node already announced for the SAME session
// incarnation.
//
// WHY. InstallTableDomain/Check are sync-only, so the BPF conntrack mirror
// cannot carry them (bpf_session_value.go reconstruction drops them, exactly
// as it drops TCPCloseClass). The helper's delta path sends the real stamp,
// but the periodic sweep and the store-mirror bulk walk rebuild values FROM
// the mirror. Without this they resend (0,0), and the peer's stamped copy
// goes back to the default table — re-resolving in inet.0 after failover.
//
// IDENTITY. The record is kept per tuple and matched on SessionID, the
// helper's stable per-incarnation id, exactly as stampCloseClassLocked.
//   - A reused tuple has a new id. Its frames never inherit the old
//     incarnation's stamp, in any arrival order.
//   - SessionID 0 means "no identity". Nothing is recorded or applied, which
//     fails toward (0,0) (the pre-#9752 window), never toward a wrong table
//     for a live session.
//   - The install generation cannot be the key: it is drawn fresh on every send.
//
// ORDERING. Same composition as the close-class memo: a late old-incarnation
// frame is refused by the receiver's installGenGuard on generation, never by
// this memo.
//
// STABLE (not monotone: close classes climb, stamps do not). The stamp is
// fixed at install for an incarnation — no path re-stamps — so a matched
// frame with a nonzero stamp overwrites the record, and a matched frame
// with (0,0) (a mirror-sourced resend) is restored from it.
//
// The caller holds genSentMu. Generic over the two wire-key types.
func stampInstallTableLocked[K comparable](m map[K]sentInstallTable, key K, sessionID uint64, domain, check *uint32) {
	if sessionID == 0 {
		return
	}
	rec, ok := m[key]
	if ok && rec.sessionID != sessionID {
		// A different incarnation of this tuple: the old record is dead.
		delete(m, key)
		ok = false
	}
	if ok && *domain == 0 && *check == 0 && (rec.domain != 0 || rec.check != 0) {
		*domain, *check = rec.domain, rec.check
	}
	if *domain == 0 && *check == 0 {
		return
	}
	if !ok && len(m) >= genGuardMapCap {
		// Skip-record-on-full, like putGenBounded: no memo for this key, which
		// degrades to the pre-#9752 window, never to a wrong table for a
		// stamped session the receiver already holds (the install guard keeps
		// the recorded stamp there).
		return
	}
	m[key] = sentInstallTable{sessionID: sessionID, domain: *domain, check: *check}
}
