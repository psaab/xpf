package upgrade

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestParsePeerSessionSyncWire7990 pins the strict status parse: present,
// absent, unknown and malformed outcomes.
func TestParsePeerSessionSyncWire7990(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		in      string
		want    uint16
		present bool
		wantErr bool
	}{
		{"present", "Peer HA protocol version: 1\nPeer session-sync wire version: 2\n", 2, true, false},
		{"unknown renders as a word, not a number", "Peer session-sync wire version: unknown\n", 0, true, false},
		{"case insensitive", "peer session-sync WIRE version: 5\n", 5, true, false},
		{"indented", "   Peer session-sync wire version: 9   \n", 9, true, false},
		// The line is ABSENT: a pre-#7990 node, or a peer that is not alive.
		// Must be distinguishable from "unknown" at the parser, even though the
		// caller collapses them.
		{"absent", "HA protocol version: 1\nPeer HA protocol version: 1\n", 0, false, false},
		{"empty", "", 0, false, false},
		// A garbled present value must surface as an error (#14991), never
		// collapse to (0, present) where the permit-on-unknown path would
		// take it.
		{"garbage value", "Peer session-sync wire version: banana\n", 0, true, true},
		{"out of range", "Peer session-sync wire version: 70000\n", 0, true, true},
		// The LOCAL line must not be mistaken for the peer's — they differ only
		// by a prefix word, which is exactly the near-miss a substring match
		// would swallow.
		{"local line only", "Session-sync wire version: 4\n", 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, present, err := parsePeerSessionSyncWireStrict(tc.in)
			if tc.wantErr && err == nil {
				t.Errorf("parsePeerSessionSyncWireStrict(%q) err = nil, want malformed error", tc.in)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("parsePeerSessionSyncWireStrict(%q) err = %v, want nil", tc.in, err)
			}
			if got != tc.want || present != tc.present {
				t.Errorf("parsePeerSessionSyncWireStrict(%q) = (%d, %v), want (%d, %v)",
					tc.in, got, present, tc.want, tc.present)
			}
		})
	}
}

// TestDrainRefusesIncompatibleSessionSyncWire7990 binds the GATE, not the
// verdict. The verdict table lives in pkg/cluster; this asserts DrainAndConfirm
// actually consults it, which is the half that would stay green if the call site
// were dropped.
//
// Every other precheck is forced HEALTHY so the session-sync gate is the only
// thing that can refuse.
func TestDrainRefusesIncompatibleSessionSyncWire7990(t *testing.T) {
	t.Parallel()
	cl := &fakeCluster{
		peerAlive: true, compatible: true, peerReady: true,
		synced: true, drainAfter: 1,
		syncWireIncompat: true,
	}
	err := DrainAndConfirm(cl, time.Second, false)
	if err == nil {
		t.Fatal("DrainAndConfirm proceeded with an incompatible session-sync wire version — " +
			"the drain would hand the RGs to a peer that cannot decode this node's " +
			"session frames, dropping every established flow while the cluster still " +
			"looks healthy")
	}
	if !strings.Contains(err.Error(), "session-sync wire incompatible") {
		t.Fatalf("err = %v; want the session-sync refusal, not some other precheck — a "+
			"case that fails for a different reason proves nothing about this gate", err)
	}
	if cl.forced {
		t.Error("the node was force-demoted before the session-sync gate refused")
	}
}

// The paired cell: same fake, gate satisfied -> the drain proceeds. Without it,
// a gate that refused unconditionally would satisfy the case above.
func TestDrainProceedsOnCompatibleSessionSyncWire7990(t *testing.T) {
	t.Parallel()
	cl := &fakeCluster{
		peerAlive: true, compatible: true, peerReady: true,
		synced: true, drainAfter: 1,
	}
	if err := DrainAndConfirm(cl, 5*time.Second, false); err != nil {
		t.Fatalf("DrainAndConfirm refused a healthy pair: %v", err)
	}
	if cl.syncWireChecks == 0 {
		t.Error("DrainAndConfirm never consulted SessionSyncWireCompatible — the gate is " +
			"not wired, and every assertion about it is vacuous")
	}
}

// allowMixedHA must NOT disable this gate. That flag exists because the LANE-2
// mixed-base gate already validated the HA WINDOW and exact-equality would
// wrongly abort the second node; it says nothing about the session wire, which
// GateProtocolCompat checks for EXACT equality in both cases. Reusing it here
// would silently disable this gate on the path that most needs it.
func TestAllowMixedHADoesNotBypassSessionSyncGate7990(t *testing.T) {
	t.Parallel()
	cl := &fakeCluster{
		peerAlive: true, compatible: false, peerReady: true,
		synced: true, drainAfter: 1,
		syncWireIncompat: true,
	}
	err := DrainAndConfirm(cl, time.Second, true) // allowMixedHA = true
	if err == nil {
		t.Fatal("allowMixedHA bypassed the session-sync wire gate")
	}
	if !strings.Contains(err.Error(), "session-sync wire incompatible") {
		t.Fatalf("err = %v; want the session-sync refusal (allowMixedHA correctly skipped "+
			"the HA check, so this must be what refused)", err)
	}
}

// TestAbsentStatusLineFailsRatherThanPermits7990 is the cell for a defect I
// built into this change and had to remove.
//
// The first version collapsed "the status line is ABSENT" into "the peer
// advertises nothing" and PERMITTED both — a gate that cannot fire, silently,
// which is the exact failure shape this change exists to remove. The parser
// already distinguished the two; the only caller threw the distinction away.
//
// Absence is a statement about the INSTRUMENT, not about the peer. FormatStatus
// renders the peer line unconditionally when the peer is alive, and
// DrainAndConfirm's PeerAlive precheck runs FIRST — so by the time this runs the
// line must be present, and its absence means the status could not be rendered
// or parsed.
//
// The paired assertion is directly below: line PRESENT and "unknown" must
// PERMIT. Without it this cell would be satisfied by a gate that refuses
// everything, and the dual-accept property would be gone.
func TestAbsentStatusLineFailsRatherThanPermits7990(t *testing.T) {
	t.Parallel()
	statusNoLine := "HA protocol version: 1\nPeer HA protocol version: 1\n"
	if _, present, err := parsePeerSessionSyncWireStrict(statusNoLine); err != nil || present {
		t.Fatal("fixture is wrong: the status must NOT carry the peer line")
	}
	// Drive the DECISION layer, not the parser and the verdict it calls. An
	// earlier version of this cell drove those two directly and stayed GREEN
	// when the absent-line handling was reverted, because neither of them
	// changes — the collapse lives between them.
	ok, _, err := sessionSyncWireVerdictFromStatus(statusNoLine)
	if err == nil {
		t.Fatalf("an absent peer line produced no error (ok=%v) — the gate permits on an "+
			"instrument it could not read, which is a check that cannot fire", ok)
	}
	if ok {
		t.Error("an absent peer line PERMITTED the drain")
	}

	// The paired assertion: line PRESENT and "unknown" must PERMIT. Without it
	// this cell is satisfied by a gate that refuses everything, and the
	// dual-accept property that keeps pre-#7990 rolls working would be gone.
	statusUnknown := statusNoLine + "Peer session-sync wire version: unknown\n"
	okU, reason, errU := sessionSyncWireVerdictFromStatus(statusUnknown)
	if errU != nil || !okU {
		t.Errorf("an advertised-unknown peer was refused (ok=%v err=%v %s); every roll from "+
			"a pre-#7990 release would abort", okU, errU, reason)
	}

	// And a real mismatch must still refuse, so "permits unknown" has not been
	// implemented as "permits everything".
	statusSkew := statusNoLine + "Peer session-sync wire version: 4242\n"
	if okS, _, errS := sessionSyncWireVerdictFromStatus(statusSkew); okS || errS != nil {
		t.Errorf("a differing peer version was permitted (ok=%v err=%v)", okS, errS)
	}
}

// A transport failure reaching the peer's version must FAIL the drain, not be
// swallowed into "compatible". An unreadable status is not evidence of
// compatibility.
func TestDrainFailsWhenSessionSyncCheckErrors7990(t *testing.T) {
	t.Parallel()
	cl := &fakeCluster{
		peerAlive: true, compatible: true, peerReady: true,
		synced: true, drainAfter: 1,
		syncWireErr: errors.New("dial xpfd gRPC: connection refused"),
	}
	err := DrainAndConfirm(cl, time.Second, false)
	if err == nil || !strings.Contains(err.Error(), "session-sync wire check") {
		t.Fatalf("err = %v; want the check's transport error surfaced, not swallowed", err)
	}
}

// The HA refusal message must no longer claim to cover session-sync — it never
// did, and since #7925 the two are separate counters. A message that names a
// property it did not check sends the reader after the wrong thing.
func TestHARefusalDoesNotClaimSessionSync7990(t *testing.T) {
	t.Parallel()
	cl := &fakeCluster{
		peerAlive: true, compatible: false, peerReady: true,
		synced: true, drainAfter: 1,
	}
	err := DrainAndConfirm(cl, time.Second, false)
	if err == nil {
		t.Fatal("DrainAndConfirm proceeded with an incompatible HA protocol version")
	}
	if strings.Contains(strings.ToLower(err.Error()), "session-sync") {
		t.Errorf("the HA-protocol refusal still claims to cover session-sync: %v", err)
	}
}
