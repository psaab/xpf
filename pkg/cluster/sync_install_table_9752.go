package cluster

import "github.com/psaab/xpf/pkg/dataplane"

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
// ROUND 5 ITEM 1: records EVERYTHING announced, including (0,0) — so
// memo-membership means "announced" and a sweep/bulk (0,0) with NO record
// is provably never-announced (in-race delta, foreign row, or post-cap),
// never a forgotten genuine default. The fence withholds THOSE from
// incapable peers on PBR-active nodes (see
// suppressUnannouncedForPBRActivePeer). Recording a zero can never clobber
// a stamp: the restore above runs first, so a same-incarnation (0,0)
// arrives here already restored.
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
	if !ok && len(m) >= genGuardMapCap {
		// Skip-record-on-full, like putGenBounded: no memo for this key.
		// A sweep resend for it stays (0,0) and is fenced as unannounced
		// on PBR-active nodes (fail-closed) instead of passing as
		// genuine-default.
		return
	}
	m[key] = sentInstallTable{sessionID: sessionID, domain: *domain, check: *check}
}

// recvInstallTable is one session incarnation's last-RECEIVED installing-table
// identity (#9752 round 3).
type recvInstallTable struct {
	sessionID uint64
	domain    uint32
	check     uint32
}

// restoreInstallTableLocked (#9752 round 3) keeps a stamp-less resend from an
// OLD sender from erasing the installing-table identity this node already
// holds for the SAME session incarnation.
//
// WHY NOT THE MIRROR. The first shape of this rule read the existing row back
// from the dataplane and kept its stamp. That passes against full-struct test
// doubles — and is dead in production, where GetSessionV4 rebuilds from the
// BPF map and the BPF conversion drops every sync-only field. The record must
// live in Go memory, beside the install generations, never in the lossy
// mirror. Nothing here reads the dataplane.
//
// DISCIPLINE (mirror of stampInstallTableLocked, receive direction):
//   - A (0,0) frame over a recorded nonzero stamp for the SAME SessionID is
//     an old sender's resend — absence decodes as zero — never a genuine
//     re-stamp (stamps are install-stable per incarnation). Restore.
//   - A nonzero frame records (overwrites): the sender stated an identity.
//   - A different SessionID replaces the record (new incarnation); a
//     stamp-less new incarnation applies as (0,0), never inheriting.
//   - SessionID 0 means "no identity": nothing recorded or applied.
//
// The caller holds recvGenMu (taken under applyMu on the install path, under
// genSentMu on the send-side delete path — both leaf-ward, no cycle).
// Generic over the two wire-key types.
func restoreInstallTableLocked[K comparable](m map[K]recvInstallTable, key K, sessionID uint64, domain, check *uint32) {
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
		// Skip-record-on-full, like the send memo: degrades to the pre-#9752
		// window, never to a wrong table.
		return
	}
	m[key] = recvInstallTable{sessionID: sessionID, domain: *domain, check: *check}
}

// lookupRecvInstallTableLocked (#9752 round 3 item 5) returns the received
// installing-table identity for this tuple's incarnation, if any. The send
// path consults it when a frame is still (0,0) after the send memo: a node
// that RECEIVED the incarnation (standby after failover) resends the true
// stamp instead of the mirror's (0,0). Read-only — the receive record stays
// the single source of received truth. The caller holds recvGenMu.
func lookupRecvInstallTableLocked[K comparable](m map[K]recvInstallTable, key K, sessionID uint64) (uint32, uint32, bool) {
	if sessionID == 0 {
		return 0, 0, false
	}
	rec, ok := m[key]
	if !ok || rec.sessionID != sessionID {
		return 0, 0, false
	}
	return rec.domain, rec.check, rec.domain != 0 || rec.check != 0
}

// installTableAnnouncedV4 reports whether this node announced key (a memo
// record exists, stamped or zero) (#9752 round 5 item 1). The sweep and the
// store-walk bulk capture this BEFORE stamping: stamping records, which
// would destroy the miss signal the unannounced fence judges.
func (s *SessionSync) installTableAnnouncedV4(key dataplane.SessionKey) bool {
	s.genSentMu.Lock()
	defer s.genSentMu.Unlock()
	_, ok := s.installTableSentV4[key]
	return ok
}

// installTableAnnouncedV6 is the IPv6 twin.
func (s *SessionSync) installTableAnnouncedV6(key dataplane.SessionKeyV6) bool {
	s.genSentMu.Lock()
	defer s.genSentMu.Unlock()
	_, ok := s.installTableSentV6[key]
	return ok
}
