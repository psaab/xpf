package upgrade

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

// #14991 (D38-03): the pre-demote rolling/rollback compatibility gates
// evaluated HAProtocolCompatible / SessionSyncWireCompatible against the
// RUNNING local daemon and the CURRENT (running-binary) session-sync wire
// version, and parsePeerSessionSyncWire mapped a malformed peer wire value to
// (0, present) so SessionSyncWireCompatible(0) PERMITTED it. The pair that
// will actually have to interoperate after the cut is the TARGET binary
// (staged forward; versions/<rollback-target> on rollback) with the
// still-running peer. A target whose wire version differs from the peer
// must refuse BEFORE ForceSecondary, and a malformed peer wire value must
// fail closed instead of permitting.

func TestRollingTargetCompatRefusesSkewedTargetWire14991(t *testing.T) {
	peer := uint16(cluster.SessionSyncWireVersion + 7)
	target := &ImageVersions{
		HAProtocol:          9,
		HAProtocolMinCompat: 1,
		SessionSyncProtocol: int(cluster.SessionSyncWireVersion),
		present: map[string]bool{
			"ha-protocol-version":           true,
			"ha-protocol-min-compat":        true,
			"session-sync-protocol-version": true,
		},
	}
	// Peer HA inside the target window; only the wire mismatch can refuse.
	ok, reason, err := targetWireVerdict(target, peer, 5)
	if err != nil {
		t.Fatalf("verdict err = %v", err)
	}
	if ok {
		t.Fatalf("target wire %d vs peer wire %d permitted; want refusal (%s)",
			target.SessionSyncProtocol, peer, reason)
	}
	if !strings.Contains(reason, "session-sync") {
		t.Fatalf("reason = %q, want session-sync naming", reason)
	}
}

func TestRollingTargetCompatPermitsMatchingTarget14991(t *testing.T) {
	target := &ImageVersions{
		HAProtocol:          5,
		HAProtocolMinCompat: 1,
		SessionSyncProtocol: int(cluster.SessionSyncWireVersion),
		present: map[string]bool{
			"ha-protocol-version":           true,
			"ha-protocol-min-compat":        true,
			"session-sync-protocol-version": true,
		},
	}
	ok, reason, err := targetWireVerdict(target, cluster.SessionSyncWireVersion, 3)
	if err != nil || !ok {
		t.Fatalf("matching target/peer wire refused: ok=%v err=%v (%s)", ok, err, reason)
	}
	// HA window: peer below floor and peer newer than target both refuse.
	if ok, _, _ := targetWireVerdict(target, cluster.SessionSyncWireVersion, 0); ok {
		t.Fatal("peer HA 0 (unknown) permitted")
	}
	below := &ImageVersions{HAProtocol: 5, HAProtocolMinCompat: 4, SessionSyncProtocol: int(cluster.SessionSyncWireVersion),
		present: map[string]bool{"ha-protocol-version": true, "ha-protocol-min-compat": true, "session-sync-protocol-version": true}}
	if ok, _, _ := targetWireVerdict(below, cluster.SessionSyncWireVersion, 3); ok {
		t.Fatal("peer HA below target floor permitted")
	}
	if ok, _, _ := targetWireVerdict(target, cluster.SessionSyncWireVersion, 6); ok {
		t.Fatal("peer HA newer than target permitted")
	}
	// Unknown peer wire (0, pre-#7990) still permits: refusing would block
	// every roll from a pre-#7990 release.
	if ok, _, err := targetWireVerdict(target, 0, 3); err != nil || !ok {
		t.Fatalf("unknown peer wire refused: ok=%v err=%v", ok, err)
	}
	// Missing target fields fail closed (as an error: the check cannot run).
	bare := &ImageVersions{present: map[string]bool{}}
	if ok, _, err := targetWireVerdict(bare, cluster.SessionSyncWireVersion, 3); ok || err == nil {
		t.Fatalf("target with no protocol fields: ok=%v err=%v, want fail-closed error", ok, err)
	}
	if ok, _, err := targetWireVerdict(nil, cluster.SessionSyncWireVersion, 3); ok || err == nil {
		t.Fatalf("nil target: ok=%v err=%v, want fail-closed error", ok, err)
	}
}

func TestParsePeerHAProtocolMalformedFailsClosed14991(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"garbage peer HA", "HA protocol version: 1\nPeer HA protocol version: banana\n"},
		{"garbage local HA", "HA protocol version: banana\nPeer HA protocol version: 1\n"},
		{"negative peer HA", "HA protocol version: 1\nPeer HA protocol version: -1\n"},
		{"huge peer HA", "HA protocol version: 1\nPeer HA protocol version: 99999999999999999999\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := parseHAProtocolVersions(tc.in); ok {
				t.Fatalf("parseHAProtocolVersions(%q) ok=true, want fail-closed on malformed", tc.in)
			}
			if parseHAProtocolCompatible(tc.in) {
				t.Fatalf("parseHAProtocolCompatible(%q) = true, want false", tc.in)
			}
		})
	}
	okStatus := "HA protocol version: 2\nPeer HA protocol version: 3\n"
	local, peer, ok := parseHAProtocolVersions(okStatus)
	if !ok || local != 2 || peer != 3 {
		t.Fatalf("parseHAProtocolVersions(valid) = (%d,%d,%v), want (2,3,true)", local, peer, ok)
	}
	// The grpcCluster verdict layer must also fail closed (this is what
	// HAProtocolCompatible returns).
	for _, val := range []string{"banana", "-1"} {
		status := "HA protocol version: 1\nPeer HA protocol version: " + val + "\n"
		if compat, _, _ := haProtocolVerdictFromStatus(status); compat {
			t.Fatalf("malformed peer HA %q permitted at verdict layer", val)
		}
	}
	if compat, _, _ := haProtocolVerdictFromStatus("HA protocol version: 1\n"); compat {
		t.Fatal("absent peer HA line permitted at verdict layer")
	}
	if compat, local, peer := haProtocolVerdictFromStatus("HA protocol version: 2\nPeer HA protocol version: 2\n"); !compat || local != 2 || peer != 2 {
		t.Fatalf("matching HA verdict = (%v,%d,%d), want (true,2,2)", compat, local, peer)
	}
	if compat, _, _ := haProtocolVerdictFromStatus("HA protocol version: 2\nPeer HA protocol version: 3\n"); compat {
		t.Fatal("mismatched HA permitted at verdict layer")
	}
}

func TestMalformedPeerWireFailsClosed14991(t *testing.T) {
	for _, val := range []string{"banana", "-1", "70000", "2.5", ""} {
		status := "HA protocol version: 1\nPeer HA protocol version: 1\n" +
			"Peer session-sync wire version: " + val + "\n"
		ok, reason, err := sessionSyncWireVerdictFromStatus(status)
		if err == nil && ok {
			t.Fatalf("malformed peer wire %q permitted (reason %q); want fail closed", val, reason)
		}
		if err == nil {
			t.Fatalf("malformed peer wire %q: want an error (check cannot run), got refusal reason %q", val, reason)
		}
		_ = errors.Is // malformed must surface as an error, asserted above
	}
	// Controls: unknown permits, matching permits, differing refuses (no error).
	base := "HA protocol version: 1\nPeer HA protocol version: 1\n"
	if ok, _, err := sessionSyncWireVerdictFromStatus(base + "Peer session-sync wire version: unknown\n"); !ok || err != nil {
		t.Fatalf("unknown peer wire: ok=%v err=%v, want permit", ok, err)
	}
	good := base + "Peer session-sync wire version: 2\n"
	// Only meaningful when the local constant is 2; otherwise it is a skew.
	if cluster.SessionSyncWireVersion == 2 {
		if ok, _, err := sessionSyncWireVerdictFromStatus(good); !ok || err != nil {
			t.Fatalf("matching peer wire: ok=%v err=%v, want permit", ok, err)
		}
	}
	if ok, _, err := sessionSyncWireVerdictFromStatus(base + "Peer session-sync wire version: 4242\n"); ok || err != nil {
		t.Fatalf("differing peer wire: ok=%v err=%v, want refusal without error", ok, err)
	}
}

// End-to-end driver leg: runRollingWith must refuse BEFORE ForceSecondary
// when the staged target's wire version differs from the peer's, even
// though the RUNNING pair (fake cluster) is fully compatible.
func TestRunRollingWithRefusesSkewedStagedTarget14991(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	fs.protocolVersionsByDir = map[string]*ImageVersions{
		"staged": {
			HAProtocol:          1,
			HAProtocolMinCompat: 1,
			SessionSyncProtocol: int(cluster.SessionSyncWireVersion) + 9,
			present: map[string]bool{
				"ha-protocol-version":           true,
				"ha-protocol-min-compat":        true,
				"session-sync-protocol-version": true,
			},
		},
	}
	// Running pair is compatible on every legacy gate.
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1}
	// Peer wire/HA as the status topic would render them.
	cl.peerWire, cl.peerWirePresent, cl.peerHA, cl.localHA = cluster.SessionSyncWireVersion, true, 1, 1

	err := runRollingWith(r, cl, fastRC())
	if err == nil {
		t.Fatal("rolling proceeded to cut to a staged target whose session-sync wire differs from the peer")
	}
	if !strings.Contains(err.Error(), "staged target") {
		t.Fatalf("err = %v, want the staged-target refusal", err)
	}
	if cl.forced {
		t.Error("ForceSecondary called despite skewed staged target — demoted before refusing")
	}
	if fs.dropinContent != "" {
		t.Error("cut happened despite skewed staged target")
	}
}

// Paired control: a staged target compatible with the peer still rolls.
func TestRunRollingWithPermitsCompatibleStagedTarget14991(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	fs.protocolVersionsByDir = map[string]*ImageVersions{
		"staged": {
			HAProtocol:          1,
			HAProtocolMinCompat: 1,
			SessionSyncProtocol: int(cluster.SessionSyncWireVersion),
			present: map[string]bool{
				"ha-protocol-version":           true,
				"ha-protocol-min-compat":        true,
				"session-sync-protocol-version": true,
			},
		},
	}
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1}
	cl.peerWire, cl.peerWirePresent, cl.peerHA, cl.localHA = cluster.SessionSyncWireVersion, true, 1, 1
	if err := runRollingWith(r, cl, fastRC()); err != nil {
		t.Fatalf("rolling refused a compatible staged target: %v", err)
	}
	if !cl.forced {
		t.Error("ForceSecondary not called on the compatible path")
	}
}

// Rollback leg: a rollback TARGET binary whose wire differs from the peer
// must refuse before ForceSecondary, even though the running pair is
// compatible. The paired happy path is TestRollingRollback_HappyPath
// (default fake target = current constants).
func TestRunRollingRollbackRefusesSkewedTarget14991(t *testing.T) {
	fx := setupRollback(t, "2.0.0", "1.0.0", rollbackV1Snap)
	fx.fs.protocolVersionsByDir = map[string]*ImageVersions{
		"1.0.0": {
			HAProtocol:          1,
			HAProtocolMinCompat: 1,
			SessionSyncProtocol: int(cluster.SessionSyncWireVersion) + 9,
			present: map[string]bool{
				"ha-protocol-version":           true,
				"ha-protocol-min-compat":        true,
				"session-sync-protocol-version": true,
			},
		},
	}
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1}
	cl.peerWire, cl.peerWirePresent, cl.peerHA, cl.localHA = cluster.SessionSyncWireVersion, true, 1, 1
	err := runRollingRollbackWith(fx.r, cl, fastRC(), "")
	if err == nil {
		t.Fatal("rolling rollback proceeded to a target whose session-sync wire differs from the peer")
	}
	if !strings.Contains(err.Error(), "staged target") {
		t.Fatalf("err = %v, want the staged-target refusal", err)
	}
	if cl.forced {
		t.Error("ForceSecondary called despite skewed rollback target")
	}
	assertNoDestructiveCalls(t, fx.fs)
}

// A peer protocol read failure reaching the driver must fail closed before
// demotion.
func TestRunRollingWithFailsClosedOnPeerReadError14991(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 1}
	cl.peerProtoErr = errors.New("peer session-sync wire version \"banana\" is malformed")
	err := runRollingWith(r, cl, fastRC())
	if err == nil {
		t.Fatal("rolling proceeded when the peer protocol read failed")
	}
	if cl.forced {
		t.Error("ForceSecondary called despite an unreadable peer protocol version")
	}
}
