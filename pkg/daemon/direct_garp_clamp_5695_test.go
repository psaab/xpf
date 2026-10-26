package daemon

import (
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #5695 (codex-182 M16): the direct-mode (private-rg-election / no-reth-vrrp)
// failover path read the per-RG gratuitous-arp-count verbatim and fanned the
// full burst (1 immediate frame + (count-1) 50ms follow-ups) per VIP — an
// unbounded configured count was a self-inflicted CPU/socket-exhaustion vector.
// directSendGARPs now clamps the effective count to
// config.GratuitousARPBurstClamp.
//
// This test drives the full directSendGARPs path and captures the COUNT passed
// to the burst senders via the directGARPBurstFn / directNABurstFn seams.
//
// FAIL-ON-REVERT: delete the `if clamped, was := config.ClampGratuitousARPCount`
// block in directSendGARPs and the clamp assertion observes the raw 100000 →
// RED.

// directClampTestDaemon builds a cluster-mode Daemon that owns RG 1 with an
// IPv4 + IPv6 VIP on reth0 and the given gratuitous-arp-count.
func directClampTestDaemon(t *testing.T, garpCount int) *Daemon {
	t.Helper()
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	sets := "set chassis cluster cluster-id 1\n" +
		"set chassis cluster redundancy-group 1 node 0 priority 200\n" +
		"set chassis cluster authentication-key test-cluster-psk-6611\n" +
		"set chassis cluster control-interface em0\n" +
		"set chassis cluster peer-address 10.99.0.2\n" +
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24\n" +
		"set chassis cluster redundancy-group 1 node 1 priority 100\n" +
		"set interfaces reth0 redundant-ether-options redundancy-group 1\n" +
		"set interfaces reth0 unit 0 family inet address 10.0.5.10/24\n" +
		"set interfaces reth0 unit 0 family inet6 address fd00::10/64\n"
	if garpCount > 0 {
		sets += "set chassis cluster redundancy-group 1 gratuitous-arp-count " +
			strconv.Itoa(garpCount) + "\n"
	}
	if _, err := s.LoadSet(sets); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &Daemon{
		store:             s,
		rgStates:          make(map[int]*rgStateMachine),
		directVIPOwned:    map[int]bool{1: true},
		directAnnounceSeq: map[int]uint64{1: 1},
	}
}

func TestDirectSendGARPs_ClampsBurstCount_5695(t *testing.T) {
	cases := []struct {
		name      string
		garpCount int
		want      int
	}{
		{"unset defaults to 3", 0, 3},
		{"deployed value unclamped", 8, 8},
		{"junos max unclamped", 16, 16},
		{"pathological clamped", 100000, config.GratuitousARPBurstClamp},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var v4counts, v6counts []int
			capture := func(_ string, _ net.IP, count int, _ cluster.BurstStillValid) error {
				mu.Lock()
				v4counts = append(v4counts, count)
				mu.Unlock()
				return nil
			}
			captureNA := func(_ string, _ net.IP, count int, _ cluster.BurstStillValid) error {
				mu.Lock()
				v6counts = append(v6counts, count)
				mu.Unlock()
				return nil
			}
			installBurstSeams(t, capture, captureNA)
			prevProbe := directARPProbeFn
			directARPProbeFn = func(string, net.IP, net.IP) error { return nil }
			t.Cleanup(func() { directARPProbeFn = prevProbe })

			d := directClampTestDaemon(t, tc.garpCount)
			d.directSendGARPs(1)

			mu.Lock()
			defer mu.Unlock()
			if len(v4counts) == 0 {
				t.Fatalf("no IPv4 GARP burst fired")
			}
			for _, c := range v4counts {
				if c != tc.want {
					t.Errorf("IPv4 GARP burst count = %d, want %d (configured=%d, clamp=%d)",
						c, tc.want, tc.garpCount, config.GratuitousARPBurstClamp)
				}
			}
			for _, c := range v6counts {
				if c != tc.want {
					t.Errorf("IPv6 NA burst count = %d, want %d (configured=%d, clamp=%d)",
						c, tc.want, tc.garpCount, config.GratuitousARPBurstClamp)
				}
			}
		})
	}
}
