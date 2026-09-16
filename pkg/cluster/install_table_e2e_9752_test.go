package cluster

// #9752 round 4 item 4, chain link G2: the daemon link's converted (key, val)
// golden (produced by the real walk over the real producer delta) → sender
// QueueSession → wire bytes → decode → install (lossy mirror) → REAL sweep
// resend → wire bytes → decode → fresh-node install → installed-val golden
// for the builder link. Every hop consumes the prior hop's output; the only
// fixture is the golden file itself (verified output, not a hand literal).

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

func drainSessionV4(t *testing.T, ss *SessionSync) (dataplane.SessionKey, dataplane.SessionValue) {
	t.Helper()
	for len(ss.sendCh) > 0 {
		msg := <-ss.sendCh
		if len(msg) < syncHeaderSize || msg[4] != syncMsgSessionV4 {
			continue
		}
		key, val, ok := decodeSessionV4Payload(msg[syncHeaderSize:])
		if !ok {
			t.Fatal("undecodable queued v4 session frame")
		}
		return key, val
	}
	t.Fatal("no v4 session frame reached the queue")
	return dataplane.SessionKey{}, dataplane.SessionValue{}
}

func readSyncedValGolden9752(t *testing.T) (dataplane.SessionKey, dataplane.SessionValue) {
	t.Helper()
	raw, err := os.ReadFile("../dataplane/userspace/testdata/synced_val_9752.json")
	if err != nil {
		t.Fatalf("read val golden: %v", err)
	}
	var pair struct {
		Key dataplane.SessionKey
		Val dataplane.SessionValue
	}
	if err := json.Unmarshal(raw, &pair); err != nil {
		t.Fatalf("unmarshal val golden: %v", err)
	}
	if pair.Val.InstallTableDomain != 525590 || pair.Val.InstallTableCheck != 3318534811 {
		t.Fatalf("val golden lost the stamp: (%d,%d)",
			pair.Val.InstallTableDomain, pair.Val.InstallTableCheck)
	}
	if pair.Val.SessionID == 0 || pair.Val.RTFlowSessionID == 0 {
		t.Fatal("val golden lost session identity")
	}
	return pair.Key, pair.Val
}

func TestInstallTableProducerToResendEndToEnd9752(t *testing.T) {
	fwd, produced := readSyncedValGolden9752(t)

	// Sender: queue the converted pair (full struct, as the delta path
	// hands it over — full is the production shape HERE).
	senderDP := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}, sessionCounter: 1}
	ss1 := NewSessionSync(":0", "10.0.0.2:4785", senderDP)
	ss1.stats.Connected.Store(true)
	// Post-discovery steady state: both senders learned a capable peer
	// (the fence withholds stamped sends while undiscovered).
	capable := capabilityFrame9714(t, capFlagFenceAck|capFlagPeerDeleteOwnership|capFlagPurgeRetirementForwardOnly|capFlagInstallTableIdentity)
	ss1.handleMessage(nil, syncMsgPeerCapabilities, capable)
	ss1.QueueSessionV4(fwd, produced)
	key1, val1 := drainSessionV4(t, ss1)
	if key1 != fwd {
		t.Fatal("PRODUCER: decoded frame does not name the queued session")
	}
	if val1.InstallTableDomain != 525590 || val1.InstallTableCheck != 3318534811 {
		t.Fatalf("PRODUCER: wire lost the stamp: (%d,%d)", val1.InstallTableDomain, val1.InstallTableCheck)
	}

	// Receiver: real install apply over a lossy mirror.
	ss2, dp2 := lossyRecvSync9752(t)
	ss2.installClusterSyncedV4(key1, val1)
	// The FORWARD row (the install also writes the reverse companion,
	// which is unstamped by rule R1 — asserting lastSet would read it).
	var installedFwd dataplane.SessionValue
	foundFwd := false
	for _, w := range dp2.sets {
		if w.IsReverse == 0 {
			installedFwd, foundFwd = w, true
			break
		}
	}
	if !foundFwd {
		t.Fatal("INSTALL: no forward row reached the mirror")
	}
	if installedFwd.InstallTableDomain != 525590 || installedFwd.InstallTableCheck != 3318534811 {
		t.Fatalf("INSTALL: peer installed (%d,%d), want the announced stamp",
			installedFwd.InstallTableDomain, installedFwd.InstallTableCheck)
	}
	if mirror, _ := dp2.GetSessionV4(fwd); mirror.InstallTableDomain != 0 || mirror.InstallTableCheck != 0 {
		t.Fatal("FIXTURE: the mirror must read back (0,0) or the resend leg is not lossy")
	}

	// Resend leg: the receiver's REAL sweep re-announces from the lossy
	// mirror; the receive record supplies the stamp the mirror cannot.
	ss2.stats.Connected.Store(true)
	ss2.IsPrimaryFn = func() bool { return true }
	ss2.handleMessage(nil, syncMsgPeerCapabilities, capable)
	ss2.syncSweep()
	key2, val2 := drainSessionV4(t, ss2)
	if key2 != fwd {
		t.Fatal("RESEND: decoded frame does not name the swept session")
	}
	if val2.InstallTableDomain != 525590 || val2.InstallTableCheck != 3318534811 {
		t.Fatalf("RESEND: sweep re-announced (%d,%d); the receive record must feed the send path",
			val2.InstallTableDomain, val2.InstallTableCheck)
	}
	// Production loss, pinned: the mirror drops RTFlowSessionID and nothing
	// restores it (pre-existing #5212 sweep gap — the stable SessionID in
	// the fixed body is what memo keying uses). The helper import below
	// must therefore treat a missing session_id as unknown, never default.
	if val2.RTFlowSessionID != 0 {
		t.Fatalf("RESEND: sweep resend carries RTFlowSessionID=%d; the mirror must drop it (fixture not lossy?)",
			val2.RTFlowSessionID)
	}

	// Fresh third node (no memos either direction): the wire bytes alone
	// must carry the stamp to the install.
	ss3, dp3 := lossyRecvSync9752(t)
	ss3.installClusterSyncedV4(key2, val2)
	// The FORWARD row (the install also writes the reverse companion;
	// lastSet would hand the builder the companion).
	var installed dataplane.SessionValue
	found := false
	for _, w := range dp3.sets {
		if w.IsReverse == 0 {
			installed, found = w, true
			break
		}
	}
	if !found {
		t.Fatal("REINSTALL: no forward row reached the mirror")
	}
	if installed.InstallTableDomain != 525590 || installed.InstallTableCheck != 3318534811 {
		t.Fatalf("REINSTALL: fresh node installed (%d,%d); the resend bytes lost the stamp",
			installed.InstallTableDomain, installed.InstallTableCheck)
	}
	// #7097 scrub, pinned: the installed row carries no peer FIB (the
	// helper re-derives locally), so the builder omits egress_ifindex and
	// the Rust import re-resolves instead of taking the cached fast path.
	if installed.FibIfindex != 0 {
		t.Fatalf("REINSTALL: installed row carries FibIfindex=%d; scrub must clear it", installed.FibIfindex)
	}

	// Hand off to the builder link: the installed (key, value) pair. The
	// builder reads the installed row (via the helper mirror write, which
	// receives the full struct pre-BPF-drop — exactly what `installed`
	// records), so this is the production input shape.
	// Normalize per-boot nonces for golden stability (presence + ordering
	// are what the chain pins, not their values).
	installed.Generation, installed.ConfigEpoch = 10, 0
	installed.Created, installed.LastSeen = 0, 0
	pair := struct {
		Key dataplane.SessionKey
		Val dataplane.SessionValue
	}{key2, installed}
	wire, err := json.Marshal(pair)
	if err != nil {
		t.Fatalf("marshal installed pair: %v", err)
	}
	var rt struct {
		Key dataplane.SessionKey
		Val dataplane.SessionValue
	}
	if err := json.Unmarshal(wire, &rt); err != nil || rt != pair {
		t.Fatalf("installed golden would not round-trip: %v", err)
	}
	const path = "../dataplane/userspace/testdata/installed_val_9752.json"
	if os.Getenv("XPF_WRITE_INSTALLED_VAL_9752") != "" {
		if err := os.WriteFile(path, append(wire, '\n'), 0644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the shared installed golden: %v", err)
	}
	if string(golden) != string(wire)+"\n" {
		t.Fatalf("installed pair drifted vs the shared golden:\n got %s\nwant %s", wire, golden)
	}
}
