package cluster

import (
	"net"
	"testing"
	"time"
)

// #18032: the production capabilities frame is 38 bytes
// (5 + bootIncarnationLen + epoch + token + flags2), but the
// #16041 per-type cap was 37, so every frame was dropped
// pre-dispatch and the peer wire version was never learned.
func TestCapabilitiesFrameSurvivesPerTypeCap18032(t *testing.T) {
	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	ss.SetLocalSnapshotProtocolVersion(8)
	ss.LocalBootEpochFn = func() uint64 { return 7 }
	ss.LocalProcessTokenFn = func() uint64 { return 9 }
	h := newRecvHarness16041(t, ss)

	sender := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	sender.SetLocalSnapshotProtocolVersion(8)
	sender.LocalBootEpochFn = func() uint64 { return 7 }
	sender.LocalProcessTokenFn = func() uint64 { return 9 }
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	go sender.sendCapabilities(local)
	buf := make([]byte, 4096)
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := peer.Read(buf)
	if err != nil {
		t.Fatalf("read capabilities frame: %v", err)
	}
	_ = h.peer.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := h.peer.Write(buf[:n]); err != nil {
		t.Fatalf("forward capabilities frame: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ss.PeerSessionSyncWireVersion() == SessionSyncWireVersion {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := ss.stats.OversizeFramesRefused.Load(); got != 0 {
		t.Fatalf("OversizeFramesRefused = %d, want 0 (capabilities frame dropped by per-type cap)", got)
	}
	if got := ss.PeerSessionSyncWireVersion(); got != SessionSyncWireVersion {
		t.Fatalf("PeerSessionSyncWireVersion = %d, want %d", got, SessionSyncWireVersion)
	}
	if !ss.ConfigApplyAckCapable() {
		t.Fatal("ConfigApplyAckCapable = false after capabilities exchange")
	}
}
