// #6650 wire half: the session-sync capability advertisement that lets a
// primary learn what its peer's config-snapshot protocol can represent.
//
// The advertisement rides this connection rather than the heartbeat because it
// is the SAME connection the config push goes over — so "peer reachable" and
// "peer capability known" share one lifecycle — and because the heartbeat's
// optional sections are located by back-indexing from a fixed-size auth
// trailer (the #6169 boot epoch sits at len-68), which makes a second tail
// section's offset depend on whether the first is present, and requires a PSK
// that an unkeyed cluster does not have.
//
// FAIL-ON-REVERT: drop the peerSnapshotProtocol.Store(0) from handleDisconnect
// and the incarnation test goes RED; drop the sendCapabilities call from the
// connection install and the wiring test names it.
package cluster

import (
	"encoding/binary"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestPeerSnapshotProtocolAccessorDefaultsToIncapable6650(t *testing.T) {
	var s *SessionSync
	if got := s.PeerSnapshotProtocolVersion(); got != 0 {
		t.Fatalf("nil SessionSync reported peer version %d, want 0", got)
	}
	ss := &SessionSync{}
	if got := ss.PeerSnapshotProtocolVersion(); got != 0 {
		t.Fatalf("fresh SessionSync reported peer version %d, want 0 — a peer that has "+
			"advertised nothing must read as INCAPABLE, never as some default capability", got)
	}
}

func TestSetLocalSnapshotProtocolVersionRoundTrips6650(t *testing.T) {
	ss := &SessionSync{}
	ss.SetLocalSnapshotProtocolVersion(8)
	if got := ss.localSnapshotProtocol.Load(); got != 8 {
		t.Fatalf("localSnapshotProtocol = %d, want 8", got)
	}
	// nil receiver must not panic: the daemon stamps every published instance
	// and a superseded epoch can hand over a nil.
	var nilSS *SessionSync
	nilSS.SetLocalSnapshotProtocolVersion(8)
}

// TestPeerCapabilityIsScopedToThePeerIncarnation6650 is the disconnect-clear.
//
// The capability belongs to the peer PROCESS that advertised it. A full
// disconnect ends that incarnation, and the peer that reconnects may be an
// OLDER process — which is precisely the rolling-upgrade case this gate exists
// for. A retained capability would authorise a push the new incarnation cannot
// represent, i.e. reintroduce the exact bug through the reconnect door.
func TestPeerCapabilityIsScopedToThePeerIncarnation6650(t *testing.T) {
	ss := &SessionSync{}
	ss.peerSnapshotProtocol.Store(8)
	if got := ss.PeerSnapshotProtocolVersion(); got != 8 {
		t.Fatalf("setup: peer version = %d, want 8", got)
	}

	// Mirror what handleDisconnect does on a FULL disconnect. Asserted against
	// the source below so this cannot drift from the real clear.
	ss.peerSnapshotProtocol.Store(0)
	if got := ss.PeerSnapshotProtocolVersion(); got != 0 {
		t.Fatalf("peer version = %d after the incarnation ended, want 0", got)
	}
}

// TestDisconnectClearsPeerCapability6650 binds the clear to the real
// handleDisconnect, beside the clockSynced clear it copies. The test above
// asserts the SEMANTICS on a hand-driven store; this asserts production
// actually performs it — without this, deleting the line from
// handleDisconnect leaves every test above green.
func TestDisconnectClearsPeerCapability6650(t *testing.T) {
	t.Parallel()
	src := readClusterSource(t, "sync_conn.go")
	if !sourceContainsFlat(src, "s.peerSnapshotProtocol.Store(0)") {
		t.Fatal("sync_conn.go's full-disconnect path does not clear peerSnapshotProtocol. " +
			"The peer capability would then outlive the incarnation that proved it, so a " +
			"reconnecting OLDER peer inherits the previous peer's capability and the gate " +
			"authorises a push it cannot represent (#6650).")
	}
	if !sourceContainsFlat(src, "s.clockSynced.Store(false)") {
		t.Fatal("the clockSynced clear this one is anchored beside has moved; re-verify " +
			"that the peerSnapshotProtocol clear is still on the FULL-disconnect path")
	}
}

// TestCapabilityAdvertisedOnConnectionInstall6650 binds the send wiring.
// Without the call, a fixed pair never exchanges versions, both sides read 0,
// and — because 0 fails closed — every multi-zone commit on a healthy upgraded
// cluster is refused. That is a loud failure rather than a silent one, but it
// is still a broken cluster, so the wiring gets its own assertion.
func TestCapabilityAdvertisedOnConnectionInstall6650(t *testing.T) {
	t.Parallel()
	src := readClusterSource(t, "sync_conn.go")
	if !sourceContainsFlat(src, "s.sendCapabilities(conn)") {
		t.Fatal("the connection-install path never calls sendCapabilities, so this node " +
			"advertises no config-snapshot protocol version. Its peer then reads 0 " +
			"(= incapable, fail-closed) and refuses every multi-zone scoped commit even " +
			"though both nodes are current (#6650).")
	}
	if !sourceContainsFlat(src, "s.sendClockSync(conn)") {
		t.Fatal("the sendClockSync call this one is anchored beside has moved; re-verify " +
			"sendCapabilities is still on the per-connection install path")
	}
}

// TestPeerCapabilitiesMessageTypeIsUnique6650 guards the additive-message
// contract. The whole no-version-bump argument rests on old peers hitting the
// receive switch's missing default arm and ignoring the frame; reusing a live
// type instead would have them MISPARSE it as real traffic.
func TestPeerCapabilitiesMessageTypeIsUnique6650(t *testing.T) {
	t.Parallel()
	live := liveSyncMessageTypesExcept(syncMsgPeerCapabilities)
	for _, m := range live {
		if m.v == syncMsgPeerCapabilities {
			t.Fatalf("syncMsgPeerCapabilities (%d) collides with %s. An old peer ignores an "+
				"UNKNOWN type via the receive switch's missing default arm — that is the "+
				"whole no-version-bump argument — but it MISPARSES a known one (#6650).",
				syncMsgPeerCapabilities, m.name)
		}
	}
	if len(live) < 35 {
		t.Fatalf("the live-type list holds only %d entries — it has fallen behind "+
			"sync.go and can no longer certify uniqueness", len(live))
	}
}

// TestPeerCapabilitiesPayloadIsLengthGated6650 pins the decode contract: a
// short frame must be ignored (leaving the 0 = incapable default) rather than
// partially decoded, and a longer one from a newer peer must still decode its
// leading field (#2170 trailing-field discipline).
func TestPeerCapabilitiesPayloadIsLengthGated6650(t *testing.T) {
	t.Parallel()
	long := make([]byte, 8)
	binary.LittleEndian.PutUint16(long[:2], 4)
	if got := binary.LittleEndian.Uint16(long[:2]); got != 4 {
		t.Fatalf("a longer payload must still decode its leading u16: got %d", got)
	}

	src := readClusterSource(t, "sync_conn_read.go")
	if !sourceContainsFlat(src, "if len(payload) < 2 {") {
		t.Error("the syncMsgPeerCapabilities arm has no length gate — a 1-byte frame " +
			"would slice out of range or decode garbage into the peer capability")
	}
	// Either spelling stores the decoded version; Swap additionally reports
	// whether the advertisement changed, which gates the capabilities-changed
	// callback so steady-state re-advertisements do not re-fire it (#10511).
	if !sourceContainsFlat(src, "s.peerSnapshotProtocol.Store(uint32(peerProto))") &&
		!sourceContainsFlat(src, "s.peerSnapshotProtocol.Swap(uint32(peerProto))") {
		t.Error("the syncMsgPeerCapabilities arm does not store the decoded version")
	}
}

// TestSendCapabilitiesAdvertisesUnconditionally6650_7147 SUPERSEDES the former
// TestSendCapabilitiesStaysSilentWhenUnset6650, which pinned the opposite
// source shape ("if v == 0 { return }") and is deliberately gone rather than
// deleted silently.
//
// WHY THE CONTRACT CHANGED. #6650's frame carried only the snapshot version,
// and for that payload silence was the more honest encoding of "not wired".
// #7147 added capability FLAGS to the same frame. Flags are a property of the
// BINARY, always true for this build, so suppressing the whole frame because an
// unrelated field was 0 would have made the fence-ack capability depend on
// userspace.ProtocolVersion staying nonzero — and had it ever been 0, the
// confirmed-fence gate would have stopped arming while looking exactly like a
// healthy pre-#7147 peer.
//
// WHAT SURVIVES. The invariant the old test actually protected is unchanged and
// is re-asserted below: a receiver cannot distinguish "frame absent" from
// "frame carrying version 0", because both leave peerSnapshotProtocol at 0 and
// #6650's contract already reads 0 as INCAPABLE rather than unknown. So the
// version SEMANTICS are identical; only the encoding moved.
func TestSendCapabilitiesAdvertisesUnconditionally6650_7147(t *testing.T) {
	t.Parallel()
	src := readClusterSource(t, "sync_conn_write.go")
	if !sourceContainsFlat(src, "v := s.localSnapshotProtocol.Load()") {
		t.Error("sendCapabilities no longer reads localSnapshotProtocol")
	}
	if sourceContainsFlat(src, "if v == 0 { return }") {
		t.Error("sendCapabilities still suppresses the advertisement when the local " +
			"version is unset. #7147 requires the frame unconditionally: the capability " +
			"FLAGS it now carries are a property of this binary and must not be gated on " +
			"an unrelated version field being nonzero, or the confirmed-fence gate " +
			"silently stops arming and looks identical to a healthy old peer.")
	}
	if !sourceContainsFlat(src, "buf[2] = localCapabilityFlags") {
		t.Error("sendCapabilities does not append the #7147 capability flags byte, so " +
			"no peer can ever learn this node acks fences and every confirmed-fence " +
			"takeover fails open without waiting")
	}

	// The surviving #6650 invariant, asserted behaviourally rather than by
	// source shape: version 0 on the wire and no frame at all must be
	// indistinguishable to the receiver.
	var ss SessionSync
	if got := ss.PeerSnapshotProtocolVersion(); got != 0 {
		t.Fatalf("a peer that never advertised reads %d, want 0", got)
	}
	ss.peerSnapshotProtocol.Store(uint32(uint16(0)))
	if got := ss.PeerSnapshotProtocolVersion(); got != 0 {
		t.Fatalf("a peer that advertised a literal 0 reads %d, want 0 — the two must "+
			"stay indistinguishable, which is what makes the encoding change safe", got)
	}
}

// readClusterSource reads a production file AND requires it to parse, so a
// guard below can never pass by matching text in a file that no longer
// compiles as Go.
func readClusterSource(t *testing.T, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return mustReadClusterFile(t, name)
}

// syncMessageType names one live syncMsg* constant for the uniqueness guards.
type syncMessageType struct {
	v    int
	name string
}

// liveSyncMessageTypesExcept enumerates every live syncMsg* constant except
// the one under test.
//
// A SLICE, not a map: syncMsgAuthHello and syncMsgConfigApplyNack both hold 27
// (phase-separated -- pre-install handshake vs post-install), and a map literal
// with duplicate constant keys does not compile. Enumerating pairs keeps every
// live name in the guard instead of silently dropping one.
//
// The exclusion is BY VALUE, so passing 27 would drop both AuthHello and
// ConfigApplyNack. No caller does; a future one that needs 27 must exclude by
// name instead.
//
// SINGLE-SOURCED across the #6650 and #6629 uniqueness guards deliberately: two
// copies of this census would drift, and a census that has fallen behind
// sync.go certifies nothing. Each caller excludes its own constant, so the same
// list serves both. The length floor in each caller catches the list falling
// behind.
func liveSyncMessageTypesExcept(under int) []syncMessageType {
	all := []syncMessageType{
		{syncMsgSessionV4, "SessionV4"}, {syncMsgSessionV6, "SessionV6"},
		{syncMsgDeleteV4, "DeleteV4"}, {syncMsgDeleteV6, "DeleteV6"},
		{syncMsgBulkStart, "BulkStart"}, {syncMsgBulkEnd, "BulkEnd"},
		{syncMsgHeartbeat, "Heartbeat"}, {syncMsgConfig, "Config"},
		{syncMsgIPsecSA, "IPsecSA"}, {syncMsgFailover, "Failover"},
		{syncMsgFence, "Fence"}, {syncMsgClockSync, "ClockSync"},
		{syncMsgBarrier, "Barrier"}, {syncMsgBarrierAck, "BarrierAck"},
		{syncMsgBulkAck, "BulkAck"}, {syncMsgFailoverAck, "FailoverAck"},
		{syncMsgFailoverCommit, "FailoverCommit"}, {syncMsgFailoverCommitAck, "FailoverCommitAck"},
		{syncMsgPrepareActivation, "PrepareActivation"}, {syncMsgFailoverBatch, "FailoverBatch"},
		{syncMsgFailoverBatchAck, "FailoverBatchAck"}, {syncMsgFailoverBatchCommit, "FailoverBatchCommit"},
		{syncMsgFailoverBatchCommitAck, "FailoverBatchCommitAck"}, {syncMsgHeartbeatAck, "HeartbeatAck"},
		{syncMsgDHCPLeaseV4, "DHCPLeaseV4"}, {syncMsgDHCPLeaseV6, "DHCPLeaseV6"},
		{syncMsgAuthHello, "AuthHello"}, {syncMsgAuthProof, "AuthProof"},
		{syncMsgConfigApplyNack, "ConfigApplyNack"},
		{syncMsgPeerCapabilities, "PeerCapabilities"},
		{syncMsgConfigKeyExchange, "ConfigKeyExchange"},
		{syncMsgConfigEncrypted, "ConfigEncrypted"},
		{syncMsgAuthUpgradeHello, "AuthUpgradeHello"},
		{syncMsgAuthUpgradeProof, "AuthUpgradeProof"},
		{syncMsgAuthUpgradeConfirm, "AuthUpgradeConfirm"},
		{syncMsgAuthUpgradeRequest, "AuthUpgradeRequest"},
		{syncMsgFenceAck, "FenceAck"},
		{syncMsgPersistentNatLease, "PersistentNatLease"},
		{syncMsgPersistentNatLeaseScoped, "PersistentNatLeaseScoped"},
	}
	out := make([]syncMessageType, 0, len(all))
	for _, m := range all {
		if m.v == under {
			continue
		}
		out = append(out, m)
	}
	return out
}

// TestLiveSyncMessageCensusIsComplete7163 makes every uniqueness guard in this
// package mean something.
//
// liveSyncMessageTypesExcept is a HAND-MAINTAINED list, and the uniqueness
// tests that consume it are only as good as it is. A constant added to sync.go
// and forgotten here does not fail anything — the census simply does not know
// about it, so a collision WITH it is invisible and the suite stays green. The
// length floors those tests carry are a partial guard at best: they catch a
// deletion from the census, not an omission from it.
//
// Collisions in this number space are not hypothetical. 27 is deliberately
// reused (syncMsgAuthHello is PRE-install, syncMsgConfigApplyNack is POST-),
// and #7147's issue proposed 30 for the fence ack when 30 was already
// syncMsgConfigKeyExchange.
//
// So this scans the package's own non-test sources for `syncMsgX = N`
// declarations and requires every one to appear in the census with a MATCHING
// value. Comment lines are stripped first, and that is not hygiene: without it
// the gate could be satisfied by a doc comment quoting the very declaration it
// is looking for. The floor on the scan count is there because a regex that
// matched nothing would sweep zero declarations and report a complete census —
// a check that fails to a value indistinguishable from healthy.
func TestLiveSyncMessageCensusIsComplete7163(t *testing.T) {
	t.Parallel()

	// -1 matches no live constant, so nothing is excluded.
	census := map[string]int{}
	for _, m := range liveSyncMessageTypesExcept(-1) {
		census["syncMsg"+m.name] = m.v
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	decl := regexp.MustCompile(`^\s*(syncMsg[A-Za-z0-9_]+)\s*=\s*(\d+)\s*$`)
	found := map[string]int{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if k := strings.Index(line, "//"); k >= 0 {
				line = line[:k]
			}
			m := decl.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			v, err := strconv.Atoi(m[2])
			if err != nil {
				t.Fatalf("%s: unparsable value in %q", f, line)
			}
			found[m[1]] = v
		}
	}

	if len(found) < 30 {
		t.Fatalf("the source scan found only %d syncMsg* declarations, which cannot be "+
			"right — the scan is broken, and a broken scan reports a complete census",
			len(found))
	}

	for name, v := range found {
		got, ok := census[name]
		if !ok {
			t.Errorf("%s = %d is declared in the package but MISSING from "+
				"liveSyncMessageTypesExcept. Every uniqueness test here is blind to a "+
				"collision with it.", name, v)
			continue
		}
		if got != v {
			t.Errorf("%s = %d in source but %d in the census; the uniqueness tests are "+
				"checking a value that is not on the wire", name, v, got)
		}
	}
}
