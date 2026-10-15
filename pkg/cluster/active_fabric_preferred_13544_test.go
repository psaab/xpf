package cluster

import (
	"strings"
	"testing"
)

// #13544: Stats().ActiveFabric, ActiveFabric() and FormatStats() reported raw
// slot occupancy (conn0 != nil → fabric 0) while outbound traffic actually
// rides preferredFabricLocked, which prefers the CURRENT-incarnation
// connection. When the peer rebooted and its replacement rides fabric 1 while
// the dead incarnation's socket still occupies fabric 0 (no FIN/RST on a hard
// reboot), the operators' view claimed fab0 while traffic rode fab1.
//
// FAIL-ON-REVERT: restoring the slot-occupancy checks in Stats/ActiveFabric
// makes the stale-fab0 cell report 0 instead of 1.
func TestActiveFabricReportsPreferredIncarnation13544(t *testing.T) {
	cases := []struct {
		name    string
		install func(t *testing.T, ss *SessionSync)
		want    int
		wantStr string
	}{
		{
			name: "stale fab0 current fab1 reports fab1",
			install: func(t *testing.T, ss *SessionSync) {
				ss.mu.Lock()
				ss.peerIncarnation = 2
				ss.conn0, ss.conn0Gen = pipeConn(t), 1 // dead incarnation
				ss.conn1, ss.conn1Gen = pipeConn(t), 2 // live replacement
				ss.mu.Unlock()
			},
			want: 1, wantStr: "fab1",
		},
		{
			name: "current fab0 stale fab1 reports fab0",
			install: func(t *testing.T, ss *SessionSync) {
				ss.mu.Lock()
				ss.peerIncarnation = 2
				ss.conn0, ss.conn0Gen = pipeConn(t), 2
				ss.conn1, ss.conn1Gen = pipeConn(t), 1
				ss.mu.Unlock()
			},
			want: 0, wantStr: "fab0",
		},
		{
			name: "both current prefers fab0",
			install: func(t *testing.T, ss *SessionSync) {
				ss.mu.Lock()
				ss.peerIncarnation = 2
				ss.conn0, ss.conn0Gen = pipeConn(t), 2
				ss.conn1, ss.conn1Gen = pipeConn(t), 2
				ss.mu.Unlock()
			},
			want: 0, wantStr: "fab0",
		},
		{
			name: "none current keeps slot-occupancy fallback fab0",
			install: func(t *testing.T, ss *SessionSync) {
				ss.mu.Lock()
				ss.peerIncarnation = 2
				ss.conn0, ss.conn0Gen = pipeConn(t), 1
				ss.conn1, ss.conn1Gen = pipeConn(t), 1
				ss.mu.Unlock()
			},
			want: 0, wantStr: "fab0",
		},
		{
			name: "only fab1 installed reports fab1",
			install: func(t *testing.T, ss *SessionSync) {
				ss.mu.Lock()
				ss.peerIncarnation = 2
				ss.conn1, ss.conn1Gen = pipeConn(t), 1
				ss.mu.Unlock()
			},
			want: 1, wantStr: "fab1",
		},
		{
			name:    "disconnected reports -1",
			install: func(t *testing.T, ss *SessionSync) {},
			want:    -1, wantStr: "none",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
			tc.install(t, ss)

			if got := ss.ActiveFabric(); got != tc.want {
				t.Errorf("ActiveFabric() = %d, want %d (preferred incarnation)", got, tc.want)
			}
			if got := ss.Stats().ActiveFabric; got != tc.want {
				t.Errorf("Stats().ActiveFabric = %d, want %d (preferred incarnation)", got, tc.want)
			}
			out := ss.FormatStats()
			if !strings.Contains(out, "Active fabric:      "+tc.wantStr) {
				t.Errorf("FormatStats() does not report %s:\n%s", tc.wantStr, out)
			}
		})
	}
}
