package cluster

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// FAIL-ON-REVERT: removing the final capability check makes the downgrade row
// emit config bytes after queue preparation.
func TestQueueConfigRevalidatesPeerSnapshotProtocolAtWrite10782(t *testing.T) {
	const text = "set system host-name guarded-snapshot\n"
	for _, tc := range []struct {
		name              string
		downgrade         bool
		incarnationSwitch bool
	}{
		{name: "stable v4 sends"},
		{name: "downgrade after preparation withholds", downgrade: true},
		{name: "boot-id incarnation switch withholds", incarnationSwitch: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &SessionSync{}
			local, peer := net.Pipe()
			t.Cleanup(func() {
				_ = local.Close()
				_ = peer.Close()
			})
			s.mu.Lock()
			s.conn0 = local
			s.mu.Unlock()
			s.stats.Connected.Store(true)
			s.SetPeerSnapshotProtocolVersionForTesting(userspace.MinProtocolMultiZoneScopedPolicy)
			expected := s.SnapshotPeerSnapshotProtocol()
			const peerEpoch = 4
			if tc.downgrade || tc.incarnationSwitch {
				s.testBeforePeerSnapshotConfigWrite = func() {
					if tc.downgrade {
						s.SetPeerSnapshotProtocolVersionForTesting(3)
					}
					if tc.incarnationSwitch {
						s.mu.Lock()
						s.applyPeerIncarnationSwitchLocked(0)
						s.mu.Unlock()
					}
				}
			}
			queued := make(chan bool, 1)
			go func() {
				queued <- s.QueueConfigWithPeerSnapshotProtocolAtGeneration(
					text, nil, 17, expected, userspace.MinProtocolMultiZoneScopedPolicy,
					peerEpoch, func() uint64 { return peerEpoch })
			}()
			if tc.downgrade || tc.incarnationSwitch {
				_ = peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				buf := make([]byte, 1)
				n, err := peer.Read(buf)
				if n != 0 {
					t.Fatalf("peer state change after queue preparation still wrote %d byte(s)", n)
				}
				if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
					t.Fatalf("expected no config bytes after peer state change, read err = %v", err)
				}
				if <-queued {
					t.Fatal("queue accepted a snapshot after the peer authorization changed")
				}
				return
			}
			msgType, payload, _ := readOneFrame(t, peer)
			if msgType != syncMsgConfig {
				t.Fatalf("stable v4 queue emitted frame type %d, want config", msgType)
			}
			gotText, gotGen := decodeConfigPayload(payload)
			if gotText != text || gotGen != 17 {
				t.Fatalf("stable v4 payload changed: text=%q gen=%d", gotText, gotGen)
			}
			if !<-queued {
				t.Fatal("stable v4 queue rejected a matching protocol authorization")
			}
		})
	}
}

// FAIL-ON-REVERT: a v4 capability on the surviving fabric must not authorize
// the new preferred connection installed into the empty alternate slot.
func TestSnapshotQueueRequiresSelectedFabricCapability10782(t *testing.T) {
	const text = "set system host-name selected-fabric\n"
	ss := NewSessionSync(":0", ":0", nil)
	fabric1, peer1 := net.Pipe()
	fabric0, peer0 := net.Pipe()
	t.Cleanup(func() {
		_ = fabric1.Close()
		_ = peer1.Close()
		_ = fabric0.Close()
		_ = peer0.Close()
	})
	old := &authConn{Conn: fabric1}
	ss.installConn(1, old)
	ss.mu.Lock()
	ss.configCrypto1.legacy = true
	ss.mu.Unlock()
	ss.handleMessage(old, syncMsgPeerCapabilities,
		[]byte{byte(userspace.MinProtocolMultiZoneScopedPolicy), 0})
	if got := ss.SnapshotPeerSnapshotProtocol().Version; got != userspace.MinProtocolMultiZoneScopedPolicy {
		t.Fatalf("surviving fabric capability = %d, want v4", got)
	}

	replacement := &authConn{Conn: fabric0}
	ss.installConn(0, replacement)
	ss.mu.Lock()
	ss.configCrypto0.legacy = true
	ss.mu.Unlock()
	if ss.getActiveConn() != replacement {
		t.Fatal("setup: new fabric 0 must become the preferred selected connection")
	}
	if got := ss.PeerSnapshotProtocolVersion(); got != userspace.MinProtocolMultiZoneScopedPolicy {
		t.Fatalf("setup: surviving fabric should leave global protocol at v4, got %d", got)
	}

	queue := func(name string, wantSend bool) {
		t.Helper()
		peer0.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		done := make(chan bool, 1)
		expected := ss.SnapshotPeerSnapshotProtocol()
		go func() {
			done <- ss.QueueConfigWithPeerSnapshotProtocolAtGeneration(
				text, nil, 17, expected, userspace.MinProtocolMultiZoneScopedPolicy,
				4, func() uint64 { return 4 })
		}()
		if !wantSend {
			buf := make([]byte, 1)
			n, err := peer0.Read(buf)
			if n != 0 {
				t.Fatalf("%s wrote %d config byte(s) before the selected fabric proved v4", name, n)
			}
			if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				t.Fatalf("%s expected no config bytes, read err = %v", name, err)
			}
			if <-done {
				t.Fatalf("%s queue accepted a snapshot without selected-fabric v4 proof", name)
			}
			return
		}
		msgType, payload, _ := readOneFrame(t, peer0)
		if msgType != syncMsgConfig {
			t.Fatalf("%s emitted frame type %d, want config", name, msgType)
		}
		gotText, gotGen := decodeConfigPayload(payload)
		if gotText != text || gotGen != 17 {
			t.Fatalf("%s payload = (%q, %d), want (%q, 17)", name, gotText, gotGen, text)
		}
		if !<-done {
			t.Fatalf("%s queue refused after selected fabric proved v4", name)
		}
	}

	queue("new fabric has not advertised", false)
	ss.handleMessage(replacement, syncMsgPeerCapabilities, []byte{3, 0})
	queue("new fabric advertises v3", false)
	ss.handleMessage(replacement, syncMsgPeerCapabilities,
		[]byte{byte(userspace.MinProtocolMultiZoneScopedPolicy), 0})
	queue("new fabric advertises v4", true)
}
