package cluster

import (
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"unsafe"
)

// #17097: peer-incarnation retirement was three hand-written reset lists.
// The capability triple was replicated to the advance paths (#10512/#14161)
// while nine fields documented as "same incarnation scoping" were reset only
// on full disconnect, so an incarnation reached by same-slot supersession,
// epoch raise, or boot-ID switch inherited silenced one-shot warnings, a
// stale PBR-announced latch, and suppress debts it did not owe.
//
// These cells are the guard: setEveryField17097 sets EVERY field of
// peerIncarnationState to 1 via reflection, fires each production trigger,
// and asserts every field is zero or seeded. A new field added to
// peerIncarnationState is covered automatically (reflection enumerates it);
// a field added OUTSIDE the struct is caught by
// TestIncarnationScopedFieldsLiveInPeerIncarnationState17097, which pins
// that no incarnation-scoped name remains directly on SessionSync.
//
// RED on revert (pre-fix shape): the supersession, epoch-raise, and switch
// cells fail for deleteSuppressionWarned, purgeRetirementSuppressionWarned,
// installTableSuppressionWarned, bulkFencedForPeer, bulkFencedForIpsecPeer,
// pbrAnnouncedForFence, installTableSuppressDebt, and
// ipsecDiscriminatorSuppressDebt — exactly the eight fields only the
// full-disconnect list reset. (scopedPolicySuppressionWarned was already
// reset at all three sites; deleteSuppressionWarned's doc claimed it
// travelled "with the peer capability flags" while it did not.)

// setEveryField17097 sets every field of st to 1 via reflection and returns
// the field names it set. Adding a field to peerIncarnationState extends
// coverage without touching this helper — that is the point.
func setEveryField17097(t *testing.T, st *peerIncarnationState) []string {
	t.Helper()
	v := reflect.ValueOf(st).Elem()
	typ := v.Type()
	var names []string
	for i := range typ.NumField() {
		f := typ.Field(i)
		fv := reflect.NewAt(f.Type, unsafe.Pointer(v.Field(i).UnsafeAddr())).Elem()
		switch a := fv.Addr().Interface().(type) {
		case *atomic.Bool:
			a.Store(true)
		case *atomic.Uint32:
			a.Store(1)
		case *atomic.Uint64:
			a.Store(1)
		case *atomic.Int64:
			a.Store(1)
		default:
			t.Fatalf("peerIncarnationState field %s has type %s with no non-zero setter in "+
				"setEveryField17097: add one, or the #17097 retirement guard cannot prove "+
				"this field is reset", f.Name, f.Type)
		}
		if !incarnationFieldNonZero17097(fv) {
			t.Fatalf("FIXTURE: field %s did not read back non-zero after set", f.Name)
		}
		names = append(names, f.Name)
	}
	if len(names) == 0 {
		t.Fatal("FIXTURE: peerIncarnationState has no fields")
	}
	return names
}

// incarnationFieldValue17097 reads one field of st as a uint64 (bools as 0/1).
func incarnationFieldValue17097(t *testing.T, st *peerIncarnationState, name string) uint64 {
	t.Helper()
	v := reflect.ValueOf(st).Elem()
	f := v.FieldByName(name)
	if !f.IsValid() {
		t.Fatalf("peerIncarnationState has no field %s", name)
	}
	fv := reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
	switch a := fv.Addr().Interface().(type) {
	case *atomic.Bool:
		if a.Load() {
			return 1
		}
		return 0
	case *atomic.Uint32:
		return uint64(a.Load())
	case *atomic.Uint64:
		return a.Load()
	case *atomic.Int64:
		return uint64(a.Load())
	default:
		t.Fatalf("peerIncarnationState field %s has unhandled type %s", name, f.Type())
		return 0
	}
}

func incarnationFieldNonZero17097(fv reflect.Value) bool {
	switch a := fv.Addr().Interface().(type) {
	case *atomic.Bool:
		return a.Load()
	case *atomic.Uint32:
		return a.Load() != 0
	case *atomic.Uint64:
		return a.Load() != 0
	case *atomic.Int64:
		return a.Load() != 0
	}
	return false
}

// assertRetired17097 fails for every field of the CURRENT incarnation state
// that is neither zero nor present in seeded with the seeded value. It also
// asserts the snapshot protocol + generation pair, which lives on
// peerSnapshotState (#16159) but is retired by the same helper.
func assertRetired17097(t *testing.T, ss *SessionSync, seeded map[string]uint64, genBefore uint64) {
	t.Helper()
	st := ss.peerIncarnationState()
	v := reflect.ValueOf(st).Elem()
	typ := v.Type()
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		got := incarnationFieldValue17097(t, st, name)
		if want, ok := seeded[name]; ok {
			if got != want {
				t.Errorf("field %s = %d after retirement, want seeded %d (#17097: the new "+
					"incarnation must start from the priming connection's proven set only)", name, got, want)
			}
			continue
		}
		if got != 0 {
			t.Errorf("field %s = %d after retirement, want 0: it survived into the new peer "+
				"incarnation. Before #17097 only the full-disconnect list reset it, so a "+
				"supersession/epoch-raise/boot-ID switch carried a silenced warn latch, a "+
				"stale bulk/PBR fence, or a suppress debt the new incarnation did not owe", name, got)
		}
	}
	if snap, want := ss.peerSnaps.peerSnapshotProtocol.Load(), seeded["__snapshotProtocol"]; snap != uint32(want) {
		t.Errorf("peerSnapshotProtocol = %d after retirement, want %d", snap, want)
	}
	if ss.peerSnaps.peerSnapshotProtocolGeneration == genBefore {
		t.Errorf("peerSnapshotProtocolGeneration did not advance (%d): the retirement did not "+
			"run through retirePeerIncarnationLocked", genBefore)
	}
}

// primeIncarnation17097 dirties every incarnation-scoped field and returns
// the snapshot generation before retirement.
func primeIncarnation17097(t *testing.T, ss *SessionSync) uint64 {
	t.Helper()
	setEveryField17097(t, ss.peerIncarnationState())
	ss.peerSnaps.peerSnapshotProtocol.Store(7)
	ss.mu.Lock()
	gen := ss.peerSnaps.peerSnapshotProtocolGeneration
	ss.mu.Unlock()
	return gen
}

// Same-slot supersession: the replacement lands in the slot the live
// connection occupies, so handleDisconnect never sees a full disconnect.
func TestSupersessionRetiresEveryIncarnationField17097(t *testing.T) {
	for _, fabric := range []int{0, 1} {
		ss := newAckTestSync(t)
		old := pipeConn(t)
		ss.installConn(fabric, old)
		genBefore := primeIncarnation17097(t, ss)

		repl := pipeConn(t)
		ss.installConn(fabric, repl)

		assertRetired17097(t, ss, nil, genBefore)
	}
}

// Epoch raise on the empty alternate slot (#7762 shape): no supersession,
// no disconnect — installConn's epoch arm alone retires the incarnation.
func TestEpochRaiseRetiresEveryIncarnationField17097(t *testing.T) {
	ss := newAckTestSync(t)
	src := &epochSource{epoch: 100, latched: true}
	ss.PeerBootEpochFn = src.fn

	corpse := pipeConn(t)
	ss.installConn(0, corpse)
	genBefore := primeIncarnation17097(t, ss)

	src.epoch = 101
	repl := pipeConn(t)
	ss.installConn(1, repl)

	assertRetired17097(t, ss, nil, genBefore)
}

// Boot-ID switch through the real BulkStart arm (#6910/#14161 wiring): the
// priming connection never advertised capabilities, so the new incarnation
// must come up unlearned AND with every latch/debt cleared.
func TestBootIDSwitchRetiresEveryIncarnationField17097(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local0, remote0 := net.Pipe()
	defer local0.Close()
	defer remote0.Close()
	local1, remote1 := net.Pipe()
	defer local1.Close()
	defer remote1.Close()
	ac0 := &authConn{Conn: local0}
	ac1 := &authConn{Conn: local1}
	ss.installConn(0, ac0)
	ss.handleMessage(ac0, syncMsgBulkStart, bulkStartPayload6910(1, incarnation6910(0xA1)))
	genBefore := primeIncarnation17097(t, ss)

	ss.installConn(1, ac1)
	ss.handleMessage(ac1, syncMsgBulkStart, bulkStartPayload6910(2, incarnation6910(0xB2)))

	assertRetired17097(t, ss, nil, genBefore)
}

// Boot-ID switch with a priming connection that DID advertise: exactly its
// set is seeded into the fresh state (#14161 provenance), and every other
// field is still cleared. Same harness as the #14161 positive cell, extended
// from the capability quadruple to every field.
func TestBootIDSwitchSeedsOnlyPrimingConnSet17097(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local0, remote0 := net.Pipe()
	defer local0.Close()
	defer remote0.Close()
	local1, remote1 := net.Pipe()
	defer local1.Close()
	defer remote1.Close()
	ac0 := &authConn{Conn: local0}
	ac1 := &authConn{Conn: local1}
	ss.installConn(0, ac0)
	// Old boot advertises, primes; then the replacement advertises the NEW
	// boot's set on its own connection before priming with a new boot id.
	ss.handleMessage(ac0, syncMsgPeerCapabilities,
		capabilityFrame14161(t, 8, capFlagFenceAck, SessionSyncWireVersion))
	ss.handleMessage(ac0, syncMsgBulkStart, bulkStartPayload6910(1, incarnation6910(0xA1)))
	genBefore := primeIncarnation17097(t, ss)

	ss.installConn(1, ac1)
	const newSnap = 3
	const newFlags = capFlagFenceAck | capFlagPeerDeleteOwnership | capFlagInstallTableIdentity
	ss.handleMessage(ac1, syncMsgPeerCapabilities,
		capabilityFrame14161(t, newSnap, newFlags, SessionSyncWireVersion))
	// handlePeerCapabilities stored the new advertisement into the globals;
	// re-dirty so the assertion measures the switch's seeding, not the
	// advertisement's. Keep the per-connection record (that is the seed).
	st := ss.peerIncarnationState()
	st.peerCapabilityFlags.Store(1)
	st.deleteSuppressionWarned.Store(true)
	st.pbrAnnouncedForFence.Store(true)
	ss.peerSnaps.peerSnapshotProtocol.Store(7)

	ss.handleMessage(ac1, syncMsgBulkStart, bulkStartPayload6910(2, incarnation6910(0xB2)))

	assertRetired17097(t, ss, map[string]uint64{
		"peerCapabilityFlags": uint64(newFlags),
		"peerSessionSyncWire": uint64(SessionSyncWireVersion),
		"__snapshotProtocol":  uint64(newSnap),
	}, genBefore)
	// Positive control: the seeded set is the priming connection's, not the
	// retired 1-valued dirt and not the old boot's frame.
	if got := ss.peerIncarnationState().peerCapabilityFlags.Load(); got != uint32(newFlags) {
		t.Fatalf("capability flags = %#x, want the priming connection's %#x", got, uint32(newFlags))
	}
}

// Full disconnect: both fabrics drop. This is the one site whose hand-written
// list was complete pre-#17097, so it is the control cell — it must stay
// green identically through the shared helper.
func TestFullDisconnectRetiresEveryIncarnationField17097(t *testing.T) {
	ss := newAckTestSync(t)
	c0 := pipeConn(t)
	c1 := pipeConn(t)
	ss.installConn(0, c0)
	ss.installConn(1, c1)
	genBefore := primeIncarnation17097(t, ss)

	ss.handleDisconnect(c0)
	// Partial disconnect must NOT retire: the survivor is the same process.
	if got := ss.peerIncarnationState().deleteSuppressionWarned.Load(); !got {
		t.Fatal("CONTROL: a partial disconnect retired the incarnation — the surviving " +
			"fabric is the same peer process and its latches must stand")
	}
	ss.handleDisconnect(c1)

	assertRetired17097(t, ss, nil, genBefore)
}

// TestIncarnationScopedFieldsLiveInPeerIncarnationState17097 pins the
// structural claim: every incarnation-scoped field name lives on
// peerIncarnationState and none remains directly on SessionSync, so the next
// field of this class cannot be added where the three trigger sites would
// miss it. It also pins the single-sourcing: retirePeerIncarnationLocked is
// the only peerIncarnationState constructor outside the lazy accessor, and
// all three trigger sites call it.
func TestIncarnationScopedFieldsLiveInPeerIncarnationState17097(t *testing.T) {
	names := []string{
		"peerCapabilityFlags", "peerCapabilityFlags2", "peerSessionSyncWire",
		"peerHeartbeatAckEver", "peerClockOffset",
		"lastSentConfigAckCapable16756", "peerConfigNackedGen16756",
		"deleteSuppressionWarned", "purgeRetirementSuppressionWarned",
		"scopedPolicySuppressionWarned", "installTableSuppressionWarned",
		"bulkFencedForPeer", "bulkFencedForIpsecPeer", "pbrAnnouncedForFence",
		"installTableSuppressDebt", "ipsecDiscriminatorSuppressDebt",
	}
	stateTyp := reflect.TypeOf(peerIncarnationState{})
	for _, n := range names {
		if _, ok := stateTyp.FieldByName(n); !ok {
			t.Errorf("peerIncarnationState is missing incarnation-scoped field %s", n)
		}
	}
	flat := sessionSyncFieldNames(t)
	for _, n := range names {
		if _, ok := flat[n]; ok {
			t.Errorf("incarnation-scoped field %s is back directly on SessionSync; it belongs "+
				"on peerIncarnationState so retirePeerIncarnationLocked resets it at every site", n)
		}
	}
	if _, ok := flat["peerIncarnationStatePtr"]; !ok {
		t.Error("SessionSync has no peerIncarnationStatePtr: the incarnation state is not " +
			"installed as one replaceable value (#17097)")
	}

	src := readClusterSource(t, "sync_conn.go")
	for _, call := range []string{
		"s.retirePeerIncarnationLocked(primingConn)", // boot-ID switch, seeded
		"s.retirePeerIncarnationLocked(nil)",         // installConn advance + full disconnect
	} {
		if !sourceContainsFlat(src, call) {
			t.Errorf("sync_conn.go does not call %s: a retirement site bypasses the shared reset", call)
		}
	}
	helper := readClusterSource(t, "sync_peer_incarnation.go")
	if !sourceContainsFlat(helper, "func (s *SessionSync) retirePeerIncarnationLocked(seed net.Conn)") {
		t.Error("retirePeerIncarnationLocked is missing from sync_peer_incarnation.go")
	}
}
