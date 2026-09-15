package cluster

// #9752 round 3 item 5 (Go half): ONE producer→transport→peer-install→
// resend chain on production shapes. A helper delta (full struct, as the
// daemon walk builds it) queues on the sender; real wire bytes cross to a
// receiver backed by a LOSSY mirror (reads drop the stamp, like BPF); the
// receiver installs (recv memo), then its REAL sweep resends (recv→send
// handoff); a fresh third node installs the resend. Every decode asserts
// the key — a resend to a garbage key proves nothing.

import (
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

func TestInstallTableProducerToResendEndToEnd9752(t *testing.T) {
	fwd := rtflowKeyV4(43001)

	// Sender: the delta path hands QueueSession a full struct (as the
	// daemon walk builds it — full is the production shape HERE).
	senderDP := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}, sessionCounter: 1}
	ss1 := NewSessionSync(":0", "10.0.0.2:4785", senderDP)
	ss1.stats.Connected.Store(true)
	ss1.QueueSessionV4(fwd, dataplane.SessionValue{SessionID: 77, RTFlowSessionID: 77,
		InstallTableDomain: 525590, InstallTableCheck: 3318534811})
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
	if got := lastSet9752(t, dp2); got.InstallTableDomain != 525590 || got.InstallTableCheck != 3318534811 {
		t.Fatalf("INSTALL: peer installed (%d,%d), want the announced stamp",
			got.InstallTableDomain, got.InstallTableCheck)
	}
	if mirror, _ := dp2.GetSessionV4(fwd); mirror.InstallTableDomain != 0 || mirror.InstallTableCheck != 0 {
		t.Fatal("FIXTURE: the mirror must read back (0,0) or the resend leg is not lossy")
	}

	// Resend leg: the receiver's REAL sweep re-announces from the lossy
	// mirror; the receive record supplies the stamp the mirror cannot.
	ss2.stats.Connected.Store(true)
	ss2.IsPrimaryFn = func() bool { return true }
	ss2.syncSweep()
	key2, val2 := drainSessionV4(t, ss2)
	if key2 != fwd {
		t.Fatal("RESEND: decoded frame does not name the swept session")
	}
	if val2.InstallTableDomain != 525590 || val2.InstallTableCheck != 3318534811 {
		t.Fatalf("RESEND: sweep re-announced (%d,%d); the receive record must feed the send path",
			val2.InstallTableDomain, val2.InstallTableCheck)
	}

	// Fresh third node (no memos either direction): the wire bytes alone
	// must carry the stamp to the install.
	ss3, dp3 := lossyRecvSync9752(t)
	ss3.installClusterSyncedV4(key2, val2)
	if got := lastSet9752(t, dp3); got.InstallTableDomain != 525590 || got.InstallTableCheck != 3318534811 {
		t.Fatalf("REINSTALL: fresh node installed (%d,%d); the resend bytes lost the stamp",
			got.InstallTableDomain, got.InstallTableCheck)
	}
}
