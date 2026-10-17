package daemon

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// linkAttrsFor14614 builds a link carrying exactly the attrs the SNMP
// trap path and the ifTable path classify (index, name, oper state,
// admin flags).
func linkAttrsFor14614(index int, name string, oper netlink.LinkOperState, flags net.Flags) netlink.Link {
	return &netlink.Device{LinkAttrs: netlink.LinkAttrs{
		Index:     index,
		Name:      name,
		OperState: oper,
		Flags:     flags,
	}}
}

// TestSNMPOperClassificationAgrees14614 is the #14614 consistency guard:
// for identical LinkAttrs, the link-trap path (resyncLinkState ->
// applyLinkState) and buildSNMPIfData (ifTable ifOperStatus) MUST agree
// on whether the interface is operationally up.
//
// Pre-fix the trap path used OperState == OperUp only while ifTable used
// OperUp || OperUnknown, so an OperUnknown+IFF_UP tunnel (xfrm/gre/wg/
// ip6tnl report UNKNOWN when up) read as up in ifTable yet was classified
// down for traps — a seeded such tunnel never emitted linkDown/linkUp
// and a post-boot-created one emitted a false linkDown never cleared.
func TestSNMPOperClassificationAgrees14614(t *testing.T) {
	cases := []struct {
		name  string
		oper  netlink.LinkOperState
		flags net.Flags
		want  bool // operationally up
	}{
		{"operup admin-up", netlink.OperUp, net.FlagUp, true},
		{"operup admin-down flags clear", netlink.OperUp, 0, true},
		{"operunknown admin-up (tunnel up)", netlink.OperUnknown, net.FlagUp, true},
		{"operunknown admin-down (tunnel down)", netlink.OperUnknown, 0, false},
		{"operdown admin-up (carrier down)", netlink.OperDown, net.FlagUp, false},
		{"operdown admin-down", netlink.OperDown, 0, false},
		{"lowerlayerdown admin-up", netlink.OperLowerLayerDown, net.FlagUp, false},
	}

	prevLister := snmpLinkLister
	prevSpeed := snmpLinkSpeedReader
	t.Cleanup(func() {
		snmpLinkLister = prevLister
		snmpLinkSpeedReader = prevSpeed
	})
	snmpLinkSpeedReader = func([]netlink.Link) map[int]uint32 { return nil }

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			link := linkAttrsFor14614(9, "gr-0-0-0", tc.oper, tc.flags)
			attrs := link.Attrs()

			// ifTable classification for these exact attrs.
			snmpLinkLister = func() ([]netlink.Link, error) {
				return []netlink.Link{&testLink{attrs: *attrs}}, nil
			}
			got := buildSNMPIfData()
			if len(got) != 1 {
				t.Fatalf("buildSNMPIfData returned %d rows, want 1", len(got))
			}
			ifTableUp := got[0].OperStatus == 1
			if ifTableUp != tc.want {
				t.Fatalf("ifTable OperStatus=%d for oper=%v flags=%v, want up=%v",
					got[0].OperStatus, tc.oper, tc.flags, tc.want)
			}

			// Trap-path classification for the same attrs, via the
			// resync path (a fresh index with emit=true records and
			// emits its classified state).
			rec := &linkStateEmitRecorder{}
			d := &Daemon{
				linkStateList: func() ([]netlink.Link, error) {
					return []netlink.Link{link}, nil
				},
				linkStateEmit: rec.emit,
			}
			d.resyncLinkState(make(map[int]bool), true)
			events := rec.snapshot()
			if len(events) != 1 {
				t.Fatalf("trap path emitted %d events for a fresh index, want 1: %+v", len(events), events)
			}
			if events[0].up != tc.want {
				t.Fatalf("trap path classified oper=%v flags=%v as up=%v, want %v",
					tc.oper, tc.flags, events[0].up, tc.want)
			}
			if events[0].up != ifTableUp {
				t.Fatalf("trap path (up=%v) and ifTable (up=%v) disagree for oper=%v flags=%v",
					events[0].up, ifTableUp, tc.oper, tc.flags)
			}
		})
	}
}

// TestMonitorLinkStateOperUnknownTunnel14614 is the #14614 decisive
// regression: an OperUnknown+IFF_UP tunnel seeded at boot must emit
// exactly one linkDown when it goes DOWN and exactly one linkUp when it
// returns to OperUnknown+IFF_UP, and a new OperUnknown+IFF_UP tunnel
// appearing after boot must never emit linkDown.
//
// Pre-fix the seed recorded the UNKNOWN tunnel as down (false), so the
// DOWN transition was a no-change (no linkDown), the return to UNKNOWN
// was also a no-change (no linkUp), and the new tunnel emitted a false
// linkDown — this test times out / sees the wrong sequence pre-fix.
func TestMonitorLinkStateOperUnknownTunnel14614(t *testing.T) {
	rec := &linkStateEmitRecorder{}

	linkList := func() ([]netlink.Link, error) {
		// Boot seed: idx 9 is an UNKNOWN+IFF_UP tunnel already up.
		return []netlink.Link{linkAttrsFor14614(9, "gr-0-0-0", netlink.OperUnknown, net.FlagUp)}, nil
	}
	subscribe := func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
		go func() {
			defer close(ch)
			// A new UNKNOWN+IFF_UP tunnel appears after boot.
			ch <- netlink.LinkUpdate{Link: linkAttrsFor14614(10, "gr-0-0-1", netlink.OperUnknown, net.FlagUp)}
			// The seeded tunnel goes down, then returns to UNKNOWN up.
			ch <- netlink.LinkUpdate{Link: linkAttrsFor14614(9, "gr-0-0-0", netlink.OperDown, 0)}
			ch <- netlink.LinkUpdate{Link: linkAttrsFor14614(9, "gr-0-0-0", netlink.OperUnknown, net.FlagUp)}
			<-done
		}()
		return nil
	}

	d := &Daemon{
		linkStateList:         linkList,
		linkStateSubscribe:    subscribe,
		linkStateEmit:         rec.emit,
		linkStateResubBackoff: time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	doneCh := make(chan struct{})
	go func() {
		d.monitorLinkState(ctx)
		close(doneCh)
	}()

	want := []linkStateEvent{
		{index: 10, name: "gr-0-0-1", up: true}, // new tunnel: linkUp, never linkDown
		{index: 9, name: "gr-0-0-0", up: false}, // seeded tunnel down: exactly one linkDown
		{index: 9, name: "gr-0-0-0", up: true},  // seeded tunnel back: exactly one linkUp
	}
	ok := waitUntil(t, 2*time.Second, func() bool {
		return len(rec.snapshot()) >= len(want)
	})
	if !ok {
		t.Fatalf("OperUnknown tunnel transitions not emitted; got %+v, want %+v", rec.snapshot(), want)
	}
	// Give any duplicate/extra trap a chance to appear, then assert exact.
	time.Sleep(20 * time.Millisecond)
	got := rec.snapshot()
	if len(got) != len(want) {
		t.Fatalf("emitted %d traps, want exactly %d: got %+v want %+v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("trap %d = %+v, want %+v (full sequence got %+v)", i, got[i], want[i], got)
		}
	}

	cancel()
	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("monitorLinkState did not exit after context cancel")
	}
}
