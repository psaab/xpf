package routing

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// monitorFakeLink is a minimal netlink.Link carrying caller-chosen attrs.
type monitorFakeLink struct {
	attrs netlink.LinkAttrs
}

func (l *monitorFakeLink) Attrs() *netlink.LinkAttrs { return &l.attrs }
func (l *monitorFakeLink) Type() string              { return "monitor-fake" }

// monitorFakeOps satisfies linkOps but only LinkByName is meaningful; the
// interface-monitor path touches nothing else. Unused methods return nil so
// the type still implements the full surface.
type monitorFakeOps struct {
	links map[string]netlink.Link

	// #8073: hardErr[name] makes LinkByName return a NON-not-found
	// (transient) error — ENOBUFS under load, EINTR, a truncated netlink
	// socket. isLinkNotFound must be FALSE for it, which is the whole
	// distinction the monitor lookup now draws.
	hardErr map[string]error
}

func (o *monitorFakeOps) LinkByName(name string) (netlink.Link, error) {
	if err, ok := o.hardErr[name]; ok {
		return nil, err
	}
	if l, ok := o.links[name]; ok {
		return l, nil
	}
	// #8073: an absent link must produce an error that isLinkNotFound
	// RECOGNISES. This previously returned net.UnknownNetworkError, which
	// isLinkNotFound reports false for — so the fake's "absent" case was
	// indistinguishable from a transient failure. That was invisible while
	// every caller treated the two identically, and it would have made the
	// carry-forward test below pass for the wrong reason.
	return nil, errLinkNotFound{fmt.Errorf("not found: %s", name)}
}

func (o *monitorFakeOps) LinkAdd(netlink.Link) error                     { return nil }
func (o *monitorFakeOps) LinkDel(netlink.Link) error                     { return nil }
func (o *monitorFakeOps) LinkSetUp(netlink.Link) error                   { return nil }
func (o *monitorFakeOps) LinkSetDown(netlink.Link) error                 { return nil }
func (o *monitorFakeOps) LinkSetMaster(netlink.Link, netlink.Link) error { return nil }
func (o *monitorFakeOps) LinkSetNoMaster(netlink.Link) error             { return nil }
func (o *monitorFakeOps) LinkSetMTU(netlink.Link, int) error             { return nil }
func (o *monitorFakeOps) LinkList() ([]netlink.Link, error)              { return nil, nil }
func (o *monitorFakeOps) AddrAdd(netlink.Link, *netlink.Addr) error      { return nil }
func (o *monitorFakeOps) AddrDel(netlink.Link, *netlink.Addr) error      { return nil }
func (o *monitorFakeOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	return nil, nil
}

// TestInterfaceMonitor_CarrierState is the #2070 regression: a monitored
// interface that is administratively up but has lost carrier (cable pulled /
// peer link down) MUST report DOWN so the redundancy-group weight is demoted
// and HA failover fires. The pre-fix code OR'd in net.FlagUp (IFF_UP, the
// admin flag), which stays set on carrier loss, so a carrier-down link was
// reported UP and failover was suppressed.
func TestInterfaceMonitor_CarrierState(t *testing.T) {
	const ifName = "ge-0/0/0"
	linuxName := config.LinuxIfName(ifName)

	tests := []struct {
		name      string
		operState netlink.LinkOperState
		flags     net.Flags
		wantUp    bool
	}{
		{
			// Cable pulled: admin-up but no carrier. The bug reported UP here.
			name:      "admin-up carrier-down reports down",
			operState: netlink.OperDown,
			flags:     net.FlagUp,
			wantUp:    false,
		},
		{
			// Peer link down: kernel reports lower-layer-down, IFF_UP still set.
			name:      "admin-up lower-layer-down reports down",
			operState: netlink.OperLowerLayerDown,
			flags:     net.FlagUp,
			wantUp:    false,
		},
		{
			name:      "admin-up carrier-up reports up",
			operState: netlink.OperUp,
			flags:     net.FlagUp,
			wantUp:    true,
		},
		{
			// Admin-down: IFF_UP clear, must report down.
			name:      "admin-down reports down",
			operState: netlink.OperDown,
			flags:     0,
			wantUp:    false,
		},
		{
			// Virtual device with no carrier reporting: OperUnknown falls back
			// to the admin flag (matches pkg/vrrp.linkAttrsUp).
			name:      "operunknown admin-up reports up",
			operState: netlink.OperUnknown,
			flags:     net.FlagUp,
			wantUp:    true,
		},
		{
			name:      "operunknown admin-down reports down",
			operState: netlink.OperUnknown,
			flags:     0,
			wantUp:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ops := &monitorFakeOps{links: map[string]netlink.Link{
				linuxName: &monitorFakeLink{attrs: netlink.LinkAttrs{
					Name:      linuxName,
					OperState: tc.operState,
					Flags:     tc.flags,
				}},
			}}
			mm := &monitorManager{
				ops:           ops,
				monitorStatus: make(map[int][]InterfaceMonitorStatus),
			}

			groups := []*config.RedundancyGroup{{
				ID: 1,
				InterfaceMonitors: []*config.InterfaceMonitor{
					{Interface: ifName, Weight: 100},
				},
			}}
			mm.Apply(groups)

			statuses := mm.monitorStatus[1]
			if len(statuses) != 1 {
				t.Fatalf("expected 1 monitor status, got %d", len(statuses))
			}
			if statuses[0].Up != tc.wantUp {
				t.Errorf("Up = %v, want %v (operstate=%v flags=%v)",
					statuses[0].Up, tc.wantUp, tc.operState, tc.flags)
			}
		})
	}
}

// #8073: a transient LinkByName failure must not silently drop a monitored
// interface from cluster status.
//
// (#17132: display only — the election reads the dampened pkg/cluster
// Monitor. A dropped row is a missing `show` entry, not stale debt.)
//
// The three passes are the test. Pass 2 alone would pass with the fix deleted
// if the fake's absent-case error were unrecognised by isLinkNotFound (it was,
// until this change), and pass 3 is the over-reach control: without it, a fix
// that carried EVERY failed lookup forward would look correct while breaking
// the peer-owned case this branch exists to serve.
func TestTransientLookupCarriesForwardMonitorStatus_8073(t *testing.T) {
	const ifName = "ge-0/0/5"
	linuxName := config.LinuxIfName(ifName)

	ops := &monitorFakeOps{links: map[string]netlink.Link{
		linuxName: &monitorFakeLink{attrs: netlink.LinkAttrs{
			Name:      linuxName,
			OperState: netlink.OperUp,
			Flags:     net.FlagUp,
		}},
	}}
	mm := &monitorManager{
		ops:           ops,
		monitorStatus: make(map[int][]InterfaceMonitorStatus),
	}
	groups := []*config.RedundancyGroup{{
		ID: 1,
		InterfaceMonitors: []*config.InterfaceMonitor{
			{Interface: ifName, Weight: 100},
		},
	}}

	// Pass 1 — link present and up. Establishes the state to carry.
	mm.Apply(groups)
	if got := mm.monitorStatus[1]; len(got) != 1 || !got[0].Up {
		t.Fatalf("pass 1: want one Up status, got %+v", got)
	}

	// Pass 2 — transient failure. The interface must SURVIVE with its last
	// observed state, so SetMonitorWeight keeps being called for it.
	ops.hardErr = map[string]error{linuxName: errors.New("ENOBUFS: netlink receive buffer overrun")}
	mm.Apply(groups)
	got := mm.monitorStatus[1]
	if len(got) != 1 {
		t.Fatalf("pass 2: a transient lookup failure dropped the monitored "+
			"interface — its weight is now stranded, not recomputed; got %+v", got)
	}
	if !got[0].Up {
		t.Errorf("pass 2: carried status must preserve the last OBSERVED state (Up=true); "+
			"synthesizing Up=false would demote the RG on a netlink hiccup, got %+v", got[0])
	}
	if got[0].Interface != ifName {
		t.Errorf("pass 2: carried the wrong interface: %q", got[0].Interface)
	}

	// Pass 2b — a weight change in the same commit must still be honored,
	// since the weight comes from config and only the LINK STATE is stale.
	groups[0].InterfaceMonitors[0].Weight = 40
	mm.Apply(groups)
	if got := mm.monitorStatus[1]; len(got) != 1 || got[0].Weight != 40 {
		t.Errorf("pass 2b: carried status must take the CURRENT configured weight, got %+v", got)
	}

	// Pass 3 — OVER-REACH CONTROL. A genuine not-found means the interface
	// belongs to the peer node, and dropping it is correct. A fix that
	// carried every failed lookup forward would keep reporting an interface
	// this node does not have.
	ops.hardErr = nil
	delete(ops.links, linuxName)
	mm.Apply(groups)
	if got := mm.monitorStatus[1]; len(got) != 0 {
		t.Errorf("pass 3: a genuinely absent (peer-owned) interface must still be "+
			"dropped, not carried forward; got %+v", got)
	}
}
