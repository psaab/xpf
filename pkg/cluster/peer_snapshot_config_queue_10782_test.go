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
