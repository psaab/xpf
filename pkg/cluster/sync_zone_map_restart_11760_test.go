package cluster

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestZoneMapInstallCompletesBulkAndSendsAck11760(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 1 }
	rejoined := make(chan struct{}, 1)
	ss.OnBulkSyncReceived = func() { rejoined <- struct{}{} }

	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	conn := &frameCaptureConn{Conn: local}

	// Preserve #9655: without an installed map the first bulk must neither
	// complete nor emit BulkAck.
	ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(1, nil))
	ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(1, nil))
	if ss.BulkEverCompleted() {
		t.Fatal("a bulk with no zone snapshot completed before zone ownership was installed")
	}
	if len(conn.frames) != 0 {
		t.Fatalf("bulk without a zone snapshot emitted %d frames, want no BulkAck", len(conn.frames))
	}

	// This is the state published from active config after restart. Even an
	// empty ownership map is authoritative, unlike nil/unwired.
	ss.SetZoneOwnership(ZoneRGMap{}, nil, nil)
	ss.handleMessage(conn, syncMsgBulkStart, bulkStartPayload(2, nil))
	ss.handleMessage(conn, syncMsgBulkEnd, bulkEndPayload(2, nil))
	if !ss.BulkEverCompleted() {
		t.Fatal("bulk did not complete after zone ownership was installed")
	}
	select {
	case <-rejoined:
	case <-time.After(time.Second):
		t.Fatal("successful bulk did not release the HA sync hold")
	}
	if len(conn.frames) != 1 {
		t.Fatalf("completed bulk emitted %d frames, want one BulkAck", len(conn.frames))
	}
	ack := conn.frames[0]
	if len(ack) != syncHeaderSize+8 || ack[4] != syncMsgBulkAck {
		t.Fatalf("completion frame = type %d length %d, want BulkAck with 8-byte epoch", ack[4], len(ack))
	}
	if epoch := binary.LittleEndian.Uint64(ack[syncHeaderSize:]); epoch != 2 {
		t.Fatalf("BulkAck epoch = %d, want 2", epoch)
	}
}
