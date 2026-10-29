package cluster

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #16734 (R3-A21-01, #15038 residual): #15038 made a probe that cannot be
// sent from a non-primary NOT completed and left the dampening state
// untouched. That is neutral only for a node that never measured. A node
// that measured DOWN while primary, then demoted (weight 0 -> secondary),
// afterwards cannot measure the target at all (no VIP, no installed
// secondary address): every probe is not-completed, so its dampened DOWN
// state and the installed ip debt stayed frozen for the life of the
// process. After the upstream recovered the demoted node stayed at
// weight 0; losing the new primary then left the RG ownerless, and an
// outage long enough to demote both nodes left zero owners at once.
//
// The fix: probeSourceFor reports canMeasure=false for a bound
// target on a non-primary only when netlink confirms no usable secondary
// source exists on the resolved interface. A clean address list without
// the configured address or a typed LinkNotFoundError followed by a clean
// LinkList confirms absence; the latter is required because LinkByName's
// legacy dump fallback can hide ErrDumpInterrupted. Other lookup errors,
// including interrupted partial dumps, preserve neutral handling. On a
// not-completed probe after confirmed absence, pollCycle releases the
// dampened state (releaseIPTargetState) so reconcileRGIPDebts removes the
// debt and the node becomes promotable again. A present secondary address
// (and primaries or unbound targets) keeps the #15038/#5301 neutral
// treatment, so transient bind/send failures never clear a real DOWN state.

// boundNoSecondaryRG is the issue's production shape: global-weight /
// global-threshold 255, one bound target of weight 255, and NO
// secondary-ip-address (the common configuration; xpf installs no
// secondary address, so the secondary holds no on-subnet source).
func boundNoSecondaryRG() *config.RedundancyGroup {
	return &config.RedundancyGroup{
		ID:             1,
		Preempt:        true,
		NodePriorities: map[int]int{0: 200, 1: 100},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight:    255,
			GlobalThreshold: 255,
			Targets: []*config.IPMonitorTarget{
				{Address: "10.0.0.1", Weight: 255, Interface: "reth0.0"},
			},
		},
	}
}

type sourceAddressNlHandle17759 struct {
	*mockNlHandle
	addresses      map[string][]netlink.Addr
	addressListErr error
	linkByNameErr  error
	linkListErr    error
}

func (h *sourceAddressNlHandle17759) LinkByName(name string) (netlink.Link, error) {
	if h.linkByNameErr != nil {
		return nil, h.linkByNameErr
	}
	return h.mockNlHandle.LinkByName(name)
}

func (h *sourceAddressNlHandle17759) LinkList() ([]netlink.Link, error) {
	links := make([]netlink.Link, 0, len(h.mockNlHandle.links))
	for _, link := range h.mockNlHandle.links {
		links = append(links, link)
	}
	return links, h.linkListErr
}

func (h *sourceAddressNlHandle17759) AddrList(link netlink.Link, _ int) ([]netlink.Addr, error) {
	return h.addresses[link.Attrs().Name], h.addressListErr
}
func newSourceAddressNlHandle17759(present bool) *sourceAddressNlHandle17759 {
	links := newMockNlHandle()
	links.setLink("reth0", true)
	h := &sourceAddressNlHandle17759{
		mockNlHandle: links,
		addresses:    make(map[string][]netlink.Addr),
	}
	if present {
		h.addresses["reth0"] = []netlink.Addr{sourceAddress17759()}
	}
	return h
}

func sourceAddress17759() netlink.Addr {
	return netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.ParseIP("10.0.0.3"),
			Mask: net.CIDRMask(32, 32),
		},
	}
}

func newDemotionNode(t *testing.T, nodeID int, rg *config.RedundancyGroup, probeFn func(context.Context, *config.IPMonitorTarget, string, string) (bool, bool)) (*Manager, *Monitor) {
	t.Helper()
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(nodeID, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = probeFn
	return m, mon
}

// TestIPMonitorDemotedNodeReleasesFrozenDebt16734 is the va21 survivor
// twin in independent form: node0 measures DOWN while primary (weight
// 0, demoted), the upstream recovers but node0 — now secondary with no
// secondary source — cannot measure, and the frozen debt must release
// so that after the peer is lost node0 promotes. Without the fix node0
// stays secondary at weight 0 forever (no owner).
func TestIPMonitorDemotedNodeReleasesFrozenDebt16734(t *testing.T) {
	reachable := true
	measurable := map[int]bool{0: true, 1: true}
	mkProbe := func(node int) func(context.Context, *config.IPMonitorTarget, string, string) (bool, bool) {
		return func(context.Context, *config.IPMonitorTarget, string, string) (bool, bool) {
			if !measurable[node] {
				return false, false // cannot send from this node: not a measurement
			}
			return reachable, true
		}
	}

	n0, mon0 := newDemotionNode(t, 0, boundNoSecondaryRG(), mkProbe(0))
	n1, mon1 := newDemotionNode(t, 1, boundNoSecondaryRG(), mkProbe(1))
	n0.SetGroupStateForTesting(1, StatePrimary)
	n1.SetGroupStateForTesting(1, StateSecondary)

	// Healthy start: node0 primary at full weight, node1 secondary.
	for range 3 {
		mon0.poll()
		mon1.poll()
	}
	if w := n0.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("healthy primary weight = %d, want 255", w)
	}

	// Upstream outage: node0's probes fail while primary. After the
	// fail threshold it must demote itself (weight 0) — the #15038
	// primary control must keep working.
	reachable = false
	for range 5 {
		mon0.poll()
	}
	if w := n0.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("demoted primary weight = %d, want 0 after measured DOWN", w)
	}
	if st := n0.GroupStates()[0]; len(st.MonitorFails) == 0 {
		t.Fatalf("demoted primary MonitorFails empty, want the ip debt installed")
	}
	// Election demotes it; reflect that role change as a cluster would.
	n0.SetGroupStateForTesting(1, StateSecondary)
	measurable[0] = false // secondary holds no VIP and no secondary address

	// Peer takes over as primary and can measure the (still down) target.
	n1.SetGroupStateForTesting(1, StatePrimary)
	measurable[1] = true
	for range 3 {
		mon1.poll()
	}

	// Upstream recovers. node1 (primary) measures reachable and clears
	// any debt. node0 still cannot measure: its frozen DOWN state must
	// be RELEASED, not left untouched.
	reachable = true
	for range 5 {
		mon0.poll()
		mon1.poll()
	}
	if w := n0.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("recovered demoted node weight = %d, want 255: unmeasurable DOWN state must be released (#16734)", w)
	}
	if st := n0.GroupStates()[0]; len(st.MonitorFails) != 0 {
		t.Fatalf("recovered demoted node MonitorFails = %v, want none (#16734)", st.MonitorFails)
	}

	// Peer loss: the survivor must promote (exactly one owner).
	n0.mu.Lock()
	n0.peerAlive = false
	n0.peerEverSeen = true
	n0.groups[1].State = StateSecondary
	n0.electSingleNode()
	n0.mu.Unlock()
	if !n0.IsLocalPrimary(1) {
		t.Fatalf("survivor did not promote after peer loss: state=%s weight=%d (#16734)",
			n0.GroupStates()[0].State, n0.GroupStates()[0].Weight)
	}
}

// TestIPMonitorDemotedGlobalThresholdReleases16734 covers the exact
// config in the issue (global-threshold aggregate mode): frozen debt
// releases for configured-but-uninstalled sources, cleanly confirmed
// missing interfaces, and addresses present only on another interface.
// Link/address lookup errors, including interrupted partial dumps, retain
// the existing debt; no configured secondary source retains #16734 behavior.
func TestIPMonitorDemotedGlobalThresholdReleases16734(t *testing.T) {
	run := func(t *testing.T, withSecondary bool, configureNl func(*sourceAddressNlHandle17759), wantWeight int, wantDebt bool) {
		t.Helper()
		rg := boundNoSecondaryRG()
		if withSecondary {
			rg.IPMonitoring.Targets[0].SecondaryIPAddress = "10.0.0.3"
		}
		cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
		m := NewManager(0, 1)
		m.UpdateConfig(cfg)
		drainEvents(m, 1)
		m.SetGroupStateForTesting(1, StatePrimary)
		mon := NewMonitor(m, cfg.RedundancyGroups)
		nlh := newSourceAddressNlHandle17759(false)
		if configureNl != nil {
			configureNl(nlh)
		}
		mon.nlHandle = nlh
		setNoDampening(mon)

		primary := true
		mon.probeFn = func(context.Context, *config.IPMonitorTarget, string, string) (bool, bool) {
			if primary {
				return false, true // primary measures the outage
			}
			return false, false // secondary cannot send: not completed
		}
		for range 5 {
			mon.poll()
		}
		if w := m.GroupStates()[0].Weight; w != 0 {
			t.Fatalf("withSecondary=%v: weight after measured DOWN = %d, want 0", withSecondary, w)
		}
		if fails := m.GroupStates()[0].MonitorFails; len(fails) == 0 {
			t.Fatalf("withSecondary=%v: measured DOWN installed no debt", withSecondary)
		}

		// Demotion: query behavior now controls whether the existing DOWN
		// debt is released or kept neutral.
		m.SetGroupStateForTesting(1, StateSecondary)
		primary = false
		for range 5 {
			mon.poll()
		}
		if w := m.GroupStates()[0].Weight; w != wantWeight {
			t.Fatalf("withSecondary=%v: weight after unmeasurable probe = %d, want %d", withSecondary, w, wantWeight)
		}
		fails := m.GroupStates()[0].MonitorFails
		if wantDebt && len(fails) == 0 {
			t.Fatalf("withSecondary=%v: DOWN debt was not retained after inconclusive lookup", withSecondary)
		}
		if !wantDebt && len(fails) != 0 {
			t.Fatalf("withSecondary=%v: MonitorFails = %v, want none after confirmed absence", withSecondary, fails)
		}
	}

	t.Run("no-secondary-ip", func(t *testing.T) { run(t, false, nil, 255, false) })
	t.Run("with-secondary-ip-uninstalled", func(t *testing.T) { run(t, true, nil, 255, false) })
	t.Run("with-secondary-ip-interface-missing-clean-link-list", func(t *testing.T) {
		run(t, true, func(nlh *sourceAddressNlHandle17759) {
			nlh.linkByNameErr = netlink.LinkNotFoundError{}
			delete(nlh.mockNlHandle.links, "reth0")
		}, 255, false)
	})
	t.Run("with-secondary-ip-on-different-interface", func(t *testing.T) {
		run(t, true, func(nlh *sourceAddressNlHandle17759) {
			nlh.mockNlHandle.setLink("reth1", true)
			nlh.addresses["reth1"] = []netlink.Addr{sourceAddress17759()}
		}, 255, false)
	})
	t.Run("with-secondary-ip-link-query-fails", func(t *testing.T) {
		run(t, true, func(nlh *sourceAddressNlHandle17759) {
			nlh.linkByNameErr = errors.New("temporary link lookup failure")
		}, 0, true)
	})
	t.Run("with-secondary-ip-link-list-fails", func(t *testing.T) {
		run(t, true, func(nlh *sourceAddressNlHandle17759) {
			nlh.linkByNameErr = netlink.LinkNotFoundError{}
			delete(nlh.mockNlHandle.links, "reth0")
			nlh.linkListErr = errors.New("temporary link dump failure")
		}, 0, true)
	})
	t.Run("with-secondary-ip-interrupted-link-dump", func(t *testing.T) {
		run(t, true, func(nlh *sourceAddressNlHandle17759) {
			nlh.linkByNameErr = netlink.LinkNotFoundError{}
			nlh.mockNlHandle.setLink("reth1", true)
			delete(nlh.mockNlHandle.links, "reth0")
			nlh.linkListErr = netlink.ErrDumpInterrupted
		}, 0, true)
	})
	t.Run("with-secondary-ip-address-query-fails", func(t *testing.T) {
		run(t, true, func(nlh *sourceAddressNlHandle17759) {
			nlh.addressListErr = errors.New("temporary address dump failure")
		}, 0, true)
	})
	t.Run("with-secondary-ip-interrupted-partial-address-dump", func(t *testing.T) {
		run(t, true, func(nlh *sourceAddressNlHandle17759) {
			// The partial dump omits configured 10.0.0.3 but returns
			// another address before reporting interruption.
			nlh.addresses["reth0"] = []netlink.Addr{{
				IPNet: &net.IPNet{
					IP:   net.ParseIP("10.0.0.4"),
					Mask: net.CIDRMask(32, 32),
				},
			}}
			nlh.addressListErr = netlink.ErrDumpInterrupted
		}, 0, true)
	})
}

// TestIPMonitorWrongFamilySecondaryReleasesFrozenDebt18413 covers a tolerant
// v4 target whose configured secondary is installed only as IPv6. That source
// cannot bind probeICMP's udp4 socket and is unmeasurable even when netlink's
// address query fails. The matched-family control remains measurable and keeps
// the #16734 neutral treatment when its probe does not complete.
func TestIPMonitorWrongFamilySecondaryReleasesFrozenDebt18413(t *testing.T) {
	for _, tc := range []struct {
		name           string
		source         string
		addressListErr error
		wantMeasure    bool
		wantWeight     int
		wantDebt       bool
	}{
		{
			name:       "installed IPv6 source for IPv4 target is unmeasurable",
			source:     "2001:db8::3",
			wantWeight: 255,
		},
		{
			name:           "wrong-family source is unmeasurable despite netlink error",
			source:         "2001:db8::3",
			addressListErr: errors.New("temporary address dump failure"),
			wantWeight:     255,
		},
		{
			name:        "installed IPv4 source for IPv4 target remains measurable",
			source:      "10.0.0.3",
			wantMeasure: true,
			wantWeight:  0,
			wantDebt:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rg := boundNoSecondaryRG()
			rg.IPMonitoring.Targets[0].SecondaryIPAddress = tc.source
			cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
			m := NewManager(0, 1)
			m.UpdateConfig(cfg)
			drainEvents(m, 1)
			m.SetGroupStateForTesting(1, StatePrimary)
			mon := NewMonitor(m, cfg.RedundancyGroups)
			nlh := newSourceAddressNlHandle17759(false)
			bits := 128
			if net.ParseIP(tc.source).To4() != nil {
				bits = 32
			}
			nlh.addresses["reth0"] = []netlink.Addr{{
				IPNet: &net.IPNet{
					IP:   net.ParseIP(tc.source),
					Mask: net.CIDRMask(bits, bits),
				},
			}}
			nlh.addressListErr = tc.addressListErr
			mon.nlHandle = nlh
			setNoDampening(mon)

			primary := true
			mon.probeFn = func(context.Context, *config.IPMonitorTarget, string, string) (bool, bool) {
				if primary {
					return false, true // primary measures the outage
				}
				return false, false // secondary probe cannot bind/send
			}
			for range 5 {
				mon.poll()
			}
			if w := m.GroupStates()[0].Weight; w != 0 {
				t.Fatalf("weight after measured DOWN = %d, want 0", w)
			}
			if len(m.GroupStates()[0].MonitorFails) == 0 {
				t.Fatal("measured DOWN installed no election debt")
			}

			m.SetGroupStateForTesting(1, StateSecondary)
			primary = false
			_, _, canMeasure := mon.probeSourceFor(rg, rg.IPMonitoring.Targets[0])
			if canMeasure != tc.wantMeasure {
				t.Fatalf("canMeasure = %v, want %v", canMeasure, tc.wantMeasure)
			}
			for range 5 {
				mon.poll()
			}
			if w := m.GroupStates()[0].Weight; w != tc.wantWeight {
				t.Fatalf("weight after uncompleted probe = %d, want %d", w, tc.wantWeight)
			}
			if gotDebt := len(m.GroupStates()[0].MonitorFails) != 0; gotDebt != tc.wantDebt {
				t.Fatalf("DOWN debt present = %v, want %v", gotDebt, tc.wantDebt)
			}
		})
	}
}

// TestIPMonitorMeasurableAbortStaysNeutral16734 is the guard against
// over-clearing: on a node that CAN measure (primary seeing deadline
// aborts, or a secondary holding a secondary address seeing transient
// not-completed probes), a dampened DOWN state must survive — only the
// genuinely unmeasurable shape releases it. Without the canMeasure
// gate, a flapping cycle deadline would clear real debt and fail open.
func TestIPMonitorMeasurableAbortStaysNeutral16734(t *testing.T) {
	// Primary, measurable, then probes stop completing (deadline/Stop).
	rg := vipBoundRG()
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)
	m.SetGroupStateForTesting(1, StatePrimary)
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	completed := true
	mon.probeFn = func(context.Context, *config.IPMonitorTarget, string, string) (bool, bool) {
		if !completed {
			return false, false
		}
		return false, true // measured DOWN
	}
	for range 5 {
		mon.poll()
	}
	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("primary measured-DOWN weight = %d, want 0", w)
	}
	completed = false
	for range 5 {
		mon.poll()
	}
	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("primary abort weight = %d, want 0: measurable aborts must stay neutral (#16734 guard)", w)
	}

	// Secondary WITH a secondary address, measurable, measures DOWN,
	// then probes stop completing: DOWN must also survive.
	m2 := NewManager(1, 1)
	m2.UpdateConfig(cfg)
	drainEvents(m2, 1)
	m2.SetGroupStateForTesting(1, StateSecondary)
	mon2 := NewMonitor(m2, cfg.RedundancyGroups)
	mon2.nlHandle = newSourceAddressNlHandle17759(true)
	setNoDampening(mon2)
	completed2 := true
	mon2.probeFn = func(context.Context, *config.IPMonitorTarget, string, string) (bool, bool) {
		if !completed2 {
			return false, false
		}
		return false, true
	}
	for range 5 {
		mon2.poll()
	}
	if w := m2.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("secondary-with-address measured-DOWN weight = %d, want 0", w)
	}
	completed2 = false
	for range 5 {
		mon2.poll()
	}
	if w := m2.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("secondary-with-address abort weight = %d, want 0: measurable aborts must stay neutral (#16734 guard)", w)
	}

	// An inconclusive address query still makes the secondary measurable.
	// Turning `present || !verified` into `present` would release this
	// DOWN debt when the later probe aborts.
	m3 := NewManager(1, 1)
	m3.UpdateConfig(cfg)
	drainEvents(m3, 1)
	m3.SetGroupStateForTesting(1, StateSecondary)
	mon3 := NewMonitor(m3, cfg.RedundancyGroups)
	nlh3 := newSourceAddressNlHandle17759(false)
	nlh3.addressListErr = errors.New("temporary address dump failure")
	mon3.nlHandle = nlh3
	setNoDampening(mon3)
	completed3 := true
	mon3.probeFn = func(context.Context, *config.IPMonitorTarget, string, string) (bool, bool) {
		if !completed3 {
			return false, false
		}
		return false, true
	}
	for range 5 {
		mon3.poll()
	}
	if w := m3.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("secondary-with-inconclusive-lookup measured-DOWN weight = %d, want 0", w)
	}
	if len(m3.GroupStates()[0].MonitorFails) == 0 {
		t.Fatalf("secondary-with-inconclusive-lookup measured DOWN installed no debt")
	}
	completed3 = false
	for range 5 {
		mon3.poll()
	}
	if w := m3.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("secondary-with-inconclusive-lookup abort weight = %d, want 0: inconclusive lookup must stay neutral (#16734 guard)", w)
	}
	if len(m3.GroupStates()[0].MonitorFails) == 0 {
		t.Fatalf("secondary-with-inconclusive-lookup abort cleared DOWN debt")
	}
}

// TestIPMonitorBothDemotedRecoverOneOwner16734 covers the second
// production consequence: an outage long enough to demote both nodes.
// Node0 demotes first and becomes unmeasurable (releases its debt);
// node1, now primary, measures DOWN and demotes too. When the upstream
// recovers, node1 re-measures reachable and node0 stays released, so
// the RG ends with weight available to elect exactly one owner instead
// of both nodes pinned at weight 0.
func TestIPMonitorBothDemotedRecoverOneOwner16734(t *testing.T) {
	reachable := false
	measurable := map[int]bool{0: true, 1: false}
	mkProbe := func(node int) func(context.Context, *config.IPMonitorTarget, string, string) (bool, bool) {
		return func(context.Context, *config.IPMonitorTarget, string, string) (bool, bool) {
			if !measurable[node] {
				return false, false
			}
			return reachable, true
		}
	}
	n0, mon0 := newDemotionNode(t, 0, boundNoSecondaryRG(), mkProbe(0))
	n1, mon1 := newDemotionNode(t, 1, boundNoSecondaryRG(), mkProbe(1))
	n0.SetGroupStateForTesting(1, StatePrimary)
	n1.SetGroupStateForTesting(1, StateSecondary)

	// Outage: node0 (primary) measures DOWN and demotes.
	for range 5 {
		mon0.poll()
	}
	if w := n0.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("node0 weight after DOWN = %d, want 0", w)
	}
	n0.SetGroupStateForTesting(1, StateSecondary)
	measurable[0] = false
	// node0 releases while unmeasurable.
	for range 3 {
		mon0.poll()
	}
	if w := n0.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("node0 released weight = %d, want 255 (#16734)", w)
	}

	// Node1 takes over, measures the still-down target, demotes too.
	n1.SetGroupStateForTesting(1, StatePrimary)
	measurable[1] = true
	for range 5 {
		mon1.poll()
	}
	if w := n1.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("node1 weight after DOWN = %d, want 0", w)
	}
	n1.SetGroupStateForTesting(1, StateSecondary)
	measurable[1] = false
	for range 3 {
		mon1.poll()
	}
	if w := n1.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("node1 released weight = %d, want 255 (#16734)", w)
	}

	// Recovery: at least one node must be promotable. Promote node0 as
	// the election winner would and assert exactly one owner results.
	reachable = true
	n0.mu.Lock()
	n0.peerAlive = false
	n0.peerEverSeen = true
	n0.groups[1].State = StateSecondary
	n0.electSingleNode()
	n0.mu.Unlock()
	// n1 was pinned secondary by the test and never re-elected (no peer
	// heartbeat models the inter-node election here); what #16734
	// requires is that BOTH nodes recovered promotable weight (neither
	// pinned at 0) and the node that runs single-node election after
	// peer loss actually promotes. The inter-node election that picks
	// exactly one owner from two weight-255 secondaries is the existing
	// election's job (preempt/priority), already covered by the
	// #15038 two-manager test.
	if w := n0.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("node0 weight after both-demoted recovery = %d, want 255 (promotable)", w)
	}
	if w := n1.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("node1 weight after both-demoted recovery = %d, want 255 (promotable)", w)
	}
	if !n0.IsLocalPrimary(1) {
		t.Fatalf("node0 did not promote after peer loss: state=%s weight=%d (#16734)",
			n0.GroupStates()[0].State, n0.GroupStates()[0].Weight)
	}
}
