package daemon

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// The advertised capability arrives before the replacement's cold-prime
// BulkStart. The changed boot id must retain that connection's v4 proof and
// dispatch another reconcile after the switch invalidates an earlier pass.
func TestBootIDSwitchRelearnsSnapshotProtocolAndReconciles10782(t *testing.T) {
	d, store, _ := commitConfirmedSnapshotGateDaemon10782(t, 3, true)
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit multi-zone active config: %v", err)
	}
	configText := store.ShowActive()
	if configText == "" {
		t.Fatal("fixture has no active config text")
	}

	ss := d.getSessionSync()
	epoch := d.syncPeerConnEpoch.Add(1)
	d.reportPeerSnapshotConfigSyncDeferred(configText, epoch, "previous peer lacked snapshot v4")

	local, peer := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = peer.Close()
	})
	firstCallbackEntered := make(chan struct{})
	releaseFirstCallback := make(chan struct{})
	reconciled := make(chan struct{}, 1)
	var callbacks atomic.Int32
	ss.OnPeerCapabilitiesChanged = func() {
		if callbacks.Add(1) == 1 {
			close(firstCallbackEntered)
			<-releaseFirstCallback
			return
		}
		d.invalidateConfigSyncPushed()
		d.reconcileConfigSyncToPeer("peer capabilities re-learned after boot switch")
		reconciled <- struct{}{}
	}
	defer close(releaseFirstCallback)

	var priorBoot, newBoot [16]byte
	priorBoot[0], newBoot[0] = 0xa1, 0xb2
	ss.PrimePeerSnapshotIncarnationForTesting(
		local, userspace.MinProtocolMultiZoneScopedPolicy, priorBoot, newBoot,
		func() { <-firstCallbackEntered },
	)
	if got := ss.PeerSnapshotProtocolVersion(); got != userspace.MinProtocolMultiZoneScopedPolicy {
		t.Fatalf("boot-id switch left peer snapshot protocol at %d; want restored v4 from the priming connection", got)
	}

	payload := readQueuedConfigFrame10782(t, peer)
	if !bytes.Contains(payload, []byte(configText)) {
		t.Fatal("post-switch reconcile did not queue the current active configuration text")
	}
	select {
	case <-reconciled:
	case <-time.After(5 * time.Second):
		t.Fatal("post-switch capability reconciliation did not complete")
	}

	d.configSyncMu.Lock()
	marked := d.configSyncHasPushed &&
		d.configSyncPushedEpoch == epoch &&
		d.configSyncPushedGen == configGenerationHash(configText)
	d.configSyncMu.Unlock()
	if !marked {
		t.Fatal("successful post-switch config queue did not retain its epoch/generation marker")
	}
	if alarm := d.peerSnapshotProtocolDeferredAlarm(); alarm != "" {
		t.Fatalf("successful post-switch v4 queue did not clear the previous deferral alarm: %q", alarm)
	}
}

func readQueuedConfigFrame10782(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set config-frame read deadline: %v", err)
	}
	header := make([]byte, 12)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("read post-switch config frame: %v", err)
	}
	if header[4] != 8 { // syncMsgConfig
		t.Fatalf("post-switch frame type = %d, want config frame type 8", header[4])
	}
	n := binary.LittleEndian.Uint32(header[8:12])
	if n > 1<<20 {
		t.Fatalf("post-switch config payload length is implausible: %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read post-switch config payload: %v", err)
	}
	return payload
}
