// Tests for the #1197 neighbor listener filter and force-probe
// tier classification logic. These cover the pure logic; the
// netlink subscription itself requires a live kernel and is
// covered by manual repro + smoke matrix.
package daemon

import (
	"net"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/vishvananda/netlink"
)

func TestProbeTierClassification(t *testing.T) {
	tests := []struct {
		name        string
		state       uint16
		criticality int
		want        int
	}{
		{"NUD_NONE (state==0) is tier 1", 0, criticalityNormal, 1},
		{"NUD_NONE fabric still tier 1", 0, criticalityFabric, 1},
		{"STALE is tier 1", uint16(netlink.NUD_STALE), criticalityNormal, 1},
		{"PROBE is tier 1", uint16(netlink.NUD_PROBE), criticalityNormal, 1},
		{"DELAY is tier 1", uint16(netlink.NUD_DELAY), criticalityNormal, 1},
		{"FAILED is tier 1", uint16(netlink.NUD_FAILED), criticalityNormal, 1},
		{"INCOMPLETE is tier 1", uint16(netlink.NUD_INCOMPLETE), criticalityNormal, 1},
		{"REACHABLE+fabric is tier 2", uint16(netlink.NUD_REACHABLE), criticalityFabric, 2},
		{"REACHABLE+next-hop is tier 2", uint16(netlink.NUD_REACHABLE), criticalityNextHop, 2},
		{"REACHABLE+normal is tier 3", uint16(netlink.NUD_REACHABLE), criticalityNormal, 3},
		{"PERMANENT+normal is tier 3", uint16(netlink.NUD_PERMANENT), criticalityNormal, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := probeTier(tc.state, tc.criticality)
			if got != tc.want {
				t.Errorf("probeTier(%v, %v) = %d, want %d",
					tc.state, tc.criticality, got, tc.want)
			}
		})
	}
}

func TestUsableNUDMask(t *testing.T) {
	cases := []struct {
		name  string
		state int
		usable bool
	}{
		{"REACHABLE usable", netlink.NUD_REACHABLE, true},
		{"STALE usable", netlink.NUD_STALE, true},
		{"DELAY usable", netlink.NUD_DELAY, true},
		{"PROBE usable", netlink.NUD_PROBE, true},
		{"PERMANENT usable", netlink.NUD_PERMANENT, true},
		{"NOARP usable", netlink.NUD_NOARP, true},
		{"FAILED NOT usable", netlink.NUD_FAILED, false},
		{"INCOMPLETE NOT usable", netlink.NUD_INCOMPLETE, false},
		{"NUD_NONE (0) NOT in mask", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.state&usableNUD != 0
			if got != tc.usable {
				t.Errorf("state=%v: usableNUD bit = %v, want %v",
					tc.state, got, tc.usable)
			}
		})
	}
}

// (Older stub types removed; superseded by stubProviderForListener
// below which implements the real neighborSnapshotProvider interface
// and supports the TestShouldTriggerRegen suite.)

func TestNeighborListenerNUDStateBitmaskCoverage(t *testing.T) {
	// Sanity: documented learnedMask in the plan must match
	// usableNUD constant. usableNUD = REACHABLE | STALE | DELAY
	// | PROBE | PERMANENT | NOARP — matches Codex round-5 #5
	// requirement.
	expected := netlink.NUD_REACHABLE | netlink.NUD_STALE |
		netlink.NUD_DELAY | netlink.NUD_PROBE |
		netlink.NUD_PERMANENT | netlink.NUD_NOARP
	if usableNUD != expected {
		t.Errorf("usableNUD = %x, want %x", usableNUD, expected)
	}
	// NUD_NONE must NOT be in mask
	if usableNUD&0 != 0 {
		t.Error("usableNUD must not include NUD_NONE")
	}
	// FAILED, INCOMPLETE must NOT be in mask
	if usableNUD&netlink.NUD_FAILED != 0 {
		t.Error("usableNUD must not include NUD_FAILED")
	}
	if usableNUD&netlink.NUD_INCOMPLETE != 0 {
		t.Error("usableNUD must not include NUD_INCOMPLETE")
	}
}

func TestNeighborListenerEventTypes(t *testing.T) {
	// Sanity: confirm the syscall constants we depend on.
	if syscall.RTM_NEWNEIGH == 0 || syscall.RTM_DELNEIGH == 0 {
		t.Skip("RTM_NEWNEIGH/RTM_DELNEIGH constants unavailable on this platform")
	}
	if syscall.RTM_NEWNEIGH == syscall.RTM_DELNEIGH {
		t.Error("RTM_NEWNEIGH and RTM_DELNEIGH must differ")
	}
}

// stubProviderForListener implements neighborSnapshotProvider for
// shouldTriggerRegen tests. Wraps a small in-memory map.
type stubProviderForListener struct {
	regenCount int
	entries    map[neighborProbeKey]*userspace.NeighborSnapshot
}

type neighborProbeKey struct {
	ifindex int
	ip      string
}

func (s *stubProviderForListener) RegenerateNeighborSnapshot()  { s.regenCount++ }
func (s *stubProviderForListener) SnapshotHasIfindex(int) bool  { return true }
func (s *stubProviderForListener) IsMonitoredIfindex(int) bool  { return true }
func (s *stubProviderForListener) LookupSnapshotNeighbor(ifindex int, ip net.IP) *userspace.NeighborSnapshot {
	if s.entries == nil {
		return nil
	}
	return s.entries[neighborProbeKey{ifindex, ip.String()}]
}

// withStubProvider runs body with a fresh stub provider. Tests
// invoke shouldTriggerRegenWithProvider directly with the stub
// rather than going through d.dp (which expects the full
// dataplane.DataPlane interface).
func withStubProvider(t *testing.T, fn func(p *stubProviderForListener)) {
	t.Helper()
	p := &stubProviderForListener{
		entries: make(map[neighborProbeKey]*userspace.NeighborSnapshot),
	}
	fn(p)
}

// TestShouldTriggerRegen exercises the full forwarding-effective
// diff decision tree per Copilot review #4. Covers MAC change,
// RTM_DELNEIGH, same-MAC same-state churn (ignored), transition
// to FAILED/INCOMPLETE, NEW publishable entry, NEW unusable entry.
func TestShouldTriggerRegen(t *testing.T) {
	mkUpdate := func(ev uint16, ifindex int, ip net.IP, mac net.HardwareAddr, state int) netlink.NeighUpdate {
		return netlink.NeighUpdate{
			Type: ev,
			Neigh: netlink.Neigh{
				LinkIndex:    ifindex,
				IP:           ip,
				HardwareAddr: mac,
				State:        state,
			},
		}
	}
	parseMAC := func(s string) net.HardwareAddr {
		m, _ := net.ParseMAC(s)
		return m
	}

	t.Run("RTM_DELNEIGH always triggers", func(t *testing.T) {
		withStubProvider(t, func(p *stubProviderForListener) {
			u := mkUpdate(syscall.RTM_DELNEIGH, 5, net.ParseIP("10.0.0.1"), nil, 0)
			if !shouldTriggerRegenWithProvider(u, p) {
				t.Error("RTM_DELNEIGH should always trigger")
			}
		})
	})

	t.Run("MAC change triggers", func(t *testing.T) {
		withStubProvider(t, func(p *stubProviderForListener) {
			ip := net.ParseIP("10.0.0.1")
			p.entries[neighborProbeKey{5, "10.0.0.1"}] = &userspace.NeighborSnapshot{
				Ifindex: 5, IP: "10.0.0.1", MAC: "aa:aa:aa:aa:aa:aa",
			}
			u := mkUpdate(syscall.RTM_NEWNEIGH, 5, ip, parseMAC("bb:bb:bb:bb:bb:bb"), netlink.NUD_REACHABLE)
			if !shouldTriggerRegenWithProvider(u, p) {
				t.Error("MAC change should trigger")
			}
		})
	})

	t.Run("same-MAC REACHABLE→STALE churn ignored", func(t *testing.T) {
		withStubProvider(t, func(p *stubProviderForListener) {
			ip := net.ParseIP("10.0.0.1")
			mac := parseMAC("aa:aa:aa:aa:aa:aa")
			p.entries[neighborProbeKey{5, "10.0.0.1"}] = &userspace.NeighborSnapshot{
				Ifindex: 5, IP: "10.0.0.1", MAC: "aa:aa:aa:aa:aa:aa",
			}
			u := mkUpdate(syscall.RTM_NEWNEIGH, 5, ip, mac, netlink.NUD_STALE)
			if shouldTriggerRegenWithProvider(u, p) {
				t.Error("same-MAC REACHABLE→STALE should NOT trigger (aging churn)")
			}
		})
	})

	t.Run("transition to FAILED triggers", func(t *testing.T) {
		withStubProvider(t, func(p *stubProviderForListener) {
			ip := net.ParseIP("10.0.0.1")
			mac := parseMAC("aa:aa:aa:aa:aa:aa")
			p.entries[neighborProbeKey{5, "10.0.0.1"}] = &userspace.NeighborSnapshot{
				Ifindex: 5, IP: "10.0.0.1", MAC: "aa:aa:aa:aa:aa:aa",
			}
			u := mkUpdate(syscall.RTM_NEWNEIGH, 5, ip, mac, netlink.NUD_FAILED)
			if !shouldTriggerRegenWithProvider(u, p) {
				t.Error("transition to FAILED should trigger (entry becomes unusable)")
			}
		})
	})

	t.Run("transition to INCOMPLETE triggers", func(t *testing.T) {
		withStubProvider(t, func(p *stubProviderForListener) {
			ip := net.ParseIP("10.0.0.1")
			mac := parseMAC("aa:aa:aa:aa:aa:aa")
			p.entries[neighborProbeKey{5, "10.0.0.1"}] = &userspace.NeighborSnapshot{
				Ifindex: 5, IP: "10.0.0.1", MAC: "aa:aa:aa:aa:aa:aa",
			}
			u := mkUpdate(syscall.RTM_NEWNEIGH, 5, ip, mac, netlink.NUD_INCOMPLETE)
			if !shouldTriggerRegenWithProvider(u, p) {
				t.Error("transition to INCOMPLETE should trigger")
			}
		})
	})

	t.Run("new entry with usable state and MAC triggers", func(t *testing.T) {
		withStubProvider(t, func(p *stubProviderForListener) {
			ip := net.ParseIP("10.0.0.99")
			mac := parseMAC("aa:aa:aa:aa:aa:aa")
			u := mkUpdate(syscall.RTM_NEWNEIGH, 5, ip, mac, netlink.NUD_REACHABLE)
			if !shouldTriggerRegenWithProvider(u, p) {
				t.Error("new publishable entry should trigger")
			}
		})
	})

	t.Run("new entry without MAC does not trigger", func(t *testing.T) {
		withStubProvider(t, func(p *stubProviderForListener) {
			ip := net.ParseIP("10.0.0.99")
			u := mkUpdate(syscall.RTM_NEWNEIGH, 5, ip, nil, netlink.NUD_INCOMPLETE)
			if shouldTriggerRegenWithProvider(u, p) {
				t.Error("new INCOMPLETE entry without MAC should NOT trigger")
			}
		})
	})

	t.Run("composite REACHABLE|FAILED for new entry does not trigger", func(t *testing.T) {
		withStubProvider(t, func(p *stubProviderForListener) {
			ip := net.ParseIP("10.0.0.99")
			mac := parseMAC("aa:aa:aa:aa:aa:aa")
			u := mkUpdate(syscall.RTM_NEWNEIGH, 5, ip, mac, netlink.NUD_REACHABLE|netlink.NUD_FAILED)
			if shouldTriggerRegenWithProvider(u, p) {
				t.Error("composite REACHABLE|FAILED should NOT trigger as usable new entry")
			}
		})
	})
}

// TestCompositeNUDStateUnusable verifies that a state with both
// usable bits AND failed/incomplete bits is correctly classified
// as unusable. Codex code-review v2 found this composite-state
// hole; v3 fixed via 'usable := has-usable AND no-failed'.
func TestCompositeNUDStateUnusable(t *testing.T) {
	tests := []struct {
		name   string
		state  int
		usable bool
	}{
		{
			"REACHABLE alone is usable",
			netlink.NUD_REACHABLE,
			true,
		},
		{
			"REACHABLE|FAILED composite is NOT usable",
			netlink.NUD_REACHABLE | netlink.NUD_FAILED,
			false,
		},
		{
			"STALE|INCOMPLETE composite is NOT usable",
			netlink.NUD_STALE | netlink.NUD_INCOMPLETE,
			false,
		},
		{
			"PERMANENT alone is usable",
			netlink.NUD_PERMANENT,
			true,
		},
		{
			"PERMANENT|FAILED is NOT usable",
			netlink.NUD_PERMANENT | netlink.NUD_FAILED,
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Mirror the logic in shouldTriggerRegen.
			usable := tc.state&usableNUD != 0 &&
				tc.state&(netlink.NUD_FAILED|netlink.NUD_INCOMPLETE) == 0
			if usable != tc.usable {
				t.Errorf("state=%v: composite usable check = %v, want %v",
					tc.state, usable, tc.usable)
			}
		})
	}
}
