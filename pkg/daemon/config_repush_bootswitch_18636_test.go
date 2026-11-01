package daemon

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #18636 (seat AE, #18646 review): after a standby OS reboot the BulkStart
// boot-id switch retires the peer incarnation, and with it the authority's
// per-incarnation sent mark. The authority must then push its config to the
// NEW incarnation, so the config-epoch guard has a generation the rebooted
// peer actually holds. The switch dispatches OnPeerCapabilitiesChanged
// (retired, not announced); the PRODUCTION handler that
// wireSessionSyncConfigCallbacks installs must clear the "already pushed for
// epoch/generation" marker and reconcile, or the switch leaves the marker
// satisfied and nothing is written to the new incarnation.
func TestBootSwitchCapabilityCallbackRepushesConfig18636(t *testing.T) {
	d, store, _ := commitConfirmedSnapshotGateDaemon10782(t, 3, true)
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit active config: %v", err)
	}
	configText := store.ShowActive()
	ss := d.getSessionSync()
	d.wireSessionSyncConfigCallbacks(ss) // production capability handler

	local, peer := net.Pipe()
	t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
	frames := make(chan []byte, 8)
	go func() {
		for {
			payload, ok := readConfigFrame18636(peer)
			if !ok {
				return
			}
			frames <- payload
		}
	}()
	waitFrame := func(what string) {
		t.Helper()
		select {
		case payload := <-frames:
			if !bytes.Contains(payload, []byte(configText)) {
				t.Fatalf("%s: queued frame does not carry the active config", what)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: no config frame was written", what)
		}
	}

	var priorBoot, newBoot [16]byte
	priorBoot[0], newBoot[0] = 0xc1, 0xd2
	ss.PrimePeerSnapshotIncarnationForTesting(
		local, userspace.MinProtocolMultiZoneScopedPolicy, priorBoot, newBoot,
		func() {
			// The capabilities frame's own callback pushed to this new
			// connection BEFORE its BulkStart (the #18521 ordering).
			waitFrame("push before BulkStart")
			// In production the BulkStart arrives seconds later, after that
			// reconcile has finished and kept its "already pushed" marker.
			// Wait for the same state, or a post-write revalidation racing
			// the switch would clear the marker and hide the re-arm.
			want := configGenerationHash(configText)
			deadline := time.Now().Add(5 * time.Second)
			for {
				d.configSyncMu.Lock()
				marked := d.configSyncHasPushed && d.configSyncPushedGen == want
				d.configSyncMu.Unlock()
				if marked {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("precondition: the pre-BulkStart push never left its already-pushed marker set")
				}
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(300 * time.Millisecond) // let the post-write revalidation finish
			d.configSyncMu.Lock()
			marked := d.configSyncHasPushed && d.configSyncPushedGen == want
			d.configSyncMu.Unlock()
			if !marked {
				t.Fatal("precondition: the pre-BulkStart push's marker was cleared before the BulkStart")
			}
		},
	)
	// The BulkStart switched the boot id and retired the incarnation; the
	// production callback must write the config to the new incarnation.
	waitFrame("re-push after the boot-id switch")
}

func readConfigFrame18636(conn net.Conn) ([]byte, bool) {
	header := make([]byte, 12)
	if _, err := ioReadFull18636(conn, header); err != nil {
		return nil, false
	}
	n := int(uint32(header[8]) | uint32(header[9])<<8 | uint32(header[10])<<16 | uint32(header[11])<<24)
	if n > 1<<20 {
		return nil, false
	}
	payload := make([]byte, n)
	if _, err := ioReadFull18636(conn, payload); err != nil {
		return nil, false
	}
	if header[4] != 8 { // not a config frame: skip it
		return readConfigFrame18636(conn)
	}
	return payload, true
}

func ioReadFull18636(conn net.Conn, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := conn.Read(buf[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}
