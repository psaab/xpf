package cluster

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #15038 (A21-01): ip-monitoring runs on BOTH nodes, but the RETH addresses
// it probes through exist only as VIPs on the primary. On the secondary the
// probe cannot be sent from an address the node does not hold, so the send
// fails — and the pre-fix probeICMP reported that send failure as a
// COMPLETED failure (reachable=false, completed=true). The dampener then
// marked the target down, installed the full ip-monitoring debt, and held
// the secondary at weight 0. On primary loss (or at cold boot, where both
// nodes do this) no node could ever own the RG.
//
// The fix: a probe that cannot be sent from the source this node should use
// (WriteTo fails on a non-primary, or the dial cannot bind the required
// source) is NOT completed — the dampening state is left untouched, exactly
// like a probe aborted by the cycle deadline. The primary, which holds the
// VIP and CAN send, keeps full failover semantics.

// vipBoundRG builds the A21-01 scenario: one RG whose ip-monitoring target
// (10.0.0.1, on the RETH subnet) is probed via reth0.0. On node0 (primary)
// the node holds the VIP 10.0.0.2; the probe can be sent and the target is
// reachable. On the secondary the node holds only the secondary address.
func vipBoundRG() *config.RedundancyGroup {
	return &config.RedundancyGroup{
		ID:             1,
		Preempt:        true,
		NodePriorities: map[int]int{0: 200, 1: 100},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight: 255,
			Targets: []*config.IPMonitorTarget{
				{Address: "10.0.0.1", Weight: 255, Interface: "reth0.0", SecondaryIPAddress: "10.0.0.3"},
			},
		},
	}
}

// TestIPMonitorSecondaryUnsendableProbeNotCompleted_15038 is the core
// regression: with reachability equal to "node holds the VIP" (the
// secondary's probe cannot be sent), the secondary must NOT accrue the
// ip-monitoring debt. Pre-fix the secondary's weight drops to 0 and stays
// there; post-fix it remains 255 so the survivor can be promoted when the
// primary is lost.
//
// RED on master: probeICMP reports a WriteTo error as (false, true), the
// dampener marks the target down after the fail threshold, and
// reconcileRGIPDebts installs the 255 debt → weight 0.
func TestIPMonitorSecondaryUnsendableProbeNotCompleted_15038(t *testing.T) {
	rg := vipBoundRG()
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}

	// Secondary node (node 1): does not hold the VIP, so its probe cannot
	// be sent. Model the real probeICMP path with a socket whose WriteTo
	// fails the way an unbound-source send to a RETH-subnet target does.
	m := NewManager(1, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)
	// A lone node's UpdateConfig elects it primary (single-node mode);
	// pin it secondary — in a real cluster the heartbeat keeps the
	// non-owner secondary, which is the state the defect held at 0.
	m.SetGroupStateForTesting(1, StateSecondary)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	// Use the REAL probeICMP (no probeFn seam) with a failing-write socket:
	// this exercises the exact completed-failure classification at fault.
	mon.icmpDialer = func(network, src string) (icmpConn, error) {
		return &writeFailICMPConn{err: errors.New("sendto: network is unreachable")}, nil
	}

	for range 5 {
		mon.poll()
	}
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("secondary weight = %d, want 255: an unsendable probe on a non-primary "+
			"must not install ip-monitoring debt (#15038)", w)
	}
	if st := m.GroupStates()[0]; len(st.MonitorFails) != 0 {
		t.Fatalf("secondary MonitorFails = %v, want none (probe never completed)", st.MonitorFails)
	}
}

// TestProbeICMPWriteFailureRoleClassification_15038 pins the classification
// directly: the same WriteTo failure is not-completed on a non-primary and
// completed on the primary.
func TestProbeICMPWriteFailureRoleClassification_15038(t *testing.T) {
	task := ipProbeTask{target: &config.IPMonitorTarget{Address: "10.0.0.1"}, rgID: 1}
	mk := func(primary bool) *Monitor {
		m := NewManager(0, 1)
		cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{vipBoundRG()}}
		m.UpdateConfig(cfg)
		drainEvents(m, 1)
		if primary {
			m.SetGroupStateForTesting(1, StatePrimary)
		} else {
			m.SetGroupStateForTesting(1, StateSecondary)
		}
		mon := NewMonitor(m, cfg.RedundancyGroups)
		mon.icmpDialer = func(network, src string) (icmpConn, error) {
			return &writeFailICMPConn{err: errors.New("sendto: network is unreachable")}, nil
		}
		return mon
	}
	if _, completed := mk(false).probeICMP(t.Context(), task); completed {
		t.Fatal("non-primary WriteTo failure: completed=true, want false (#15038)")
	}
	if _, completed := mk(true).probeICMP(t.Context(), task); !completed {
		t.Fatal("primary WriteTo failure: completed=false, want true (#15038 control)")
	}
}

// TestIPMonitorPrimarySendFailureStillFails_15038 is the control: on the
// PRIMARY (which holds the VIP and can choose the source), a genuine send
// failure / unreachable target is a real path failure and must still
// demote. The not-completed treatment is scoped to the node that cannot
// send because it does not hold the address — never to the owner.
func TestIPMonitorPrimarySendFailureStillFails_15038(t *testing.T) {
	rg := vipBoundRG()
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}

	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)
	// Node 0 is primary for RG 1.
	m.SetGroupStateForTesting(1, StatePrimary)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.icmpDialer = func(network, src string) (icmpConn, error) {
		return &writeFailICMPConn{err: errors.New("sendto: network is unreachable")}, nil
	}

	for range 5 {
		mon.poll()
	}
	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("primary weight = %d, want 0: a send failure on the VIP owner is a "+
			"completed failure and must demote (#15038 control)", w)
	}
}

// TestIPMonitorTwoManagerColdBootAndSurvivor_15038 is the issue's
// acceptance shape: two managers, reachability equal to "node holds the
// VIP". At cold boot exactly one node (the VIP holder that can probe) may
// be primary; after the primary is lost the survivor — whose probes were
// previously unsendable — must be promotable (weight > 0) and promote.
func TestIPMonitorTwoManagerColdBootAndSurvivor_15038(t *testing.T) {
	mkNode := func(nodeID int, holdsVIP bool) (*Manager, *Monitor) {
		rg := vipBoundRG()
		cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}
		m := NewManager(nodeID, 1)
		m.UpdateConfig(cfg)
		drainEvents(m, 1)
		mon := NewMonitor(m, cfg.RedundancyGroups)
		injectFakeNl(mon)
		setNoDampening(mon)
		if holdsVIP {
			// Can send from the VIP; target reachable.
			mon.probeFn = func(_ context.Context, _ *config.IPMonitorTarget, _ string, _ string) (bool, bool) { return true, true }
		} else {
			// Cannot send: real probe path with a failing write.
			mon.icmpDialer = func(network, src string) (icmpConn, error) {
				return &writeFailICMPConn{err: errors.New("sendto: network is unreachable")}, nil
			}
		}
		return m, mon
	}

	primary, monP := mkNode(0, true)
	secondary, monS := mkNode(1, false)
	primary.SetGroupStateForTesting(1, StatePrimary)
	secondary.SetGroupStateForTesting(1, StateSecondary)

	for range 5 {
		monP.poll()
		monS.poll()
	}

	if w := primary.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("primary weight = %d, want 255 (reachable via VIP)", w)
	}
	if w := secondary.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("secondary weight = %d, want 255: unsendable probes must not "+
			"pin the survivor at weight 0 (#15038)", w)
	}

	// Cold-boot invariant: exactly one primary.
	primaries := 0
	if primary.IsLocalPrimary(1) {
		primaries++
	}
	if secondary.IsLocalPrimary(1) {
		primaries++
	}
	if primaries != 1 {
		t.Fatalf("cold boot primaries = %d, want exactly 1", primaries)
	}

	// Primary loss: the peer is gone. The survivor must promote — with the
	// pre-fix debt it is stuck at weight 0 and electSingleNode leaves it
	// secondary forever (no owner).
	secondary.mu.Lock()
	secondary.peerAlive = false
	secondary.peerEverSeen = true
	secondary.groups[1].State = StateSecondary
	secondary.mu.Unlock()
	secondary.mu.Lock()
	secondary.electSingleNode()
	secondary.mu.Unlock()
	if !secondary.IsLocalPrimary(1) {
		t.Fatalf("survivor did not promote after primary loss: state=%s weight=%d (#15038)",
			secondary.GroupStates()[0].State, secondary.GroupStates()[0].Weight)
	}
}

// writeFailICMPConn models a socket opened on a node that does not hold the
// probe's source address: the write fails before anything reaches the wire.
type writeFailICMPConn struct {
	err error
}

func (c *writeFailICMPConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	return 0, c.err
}

func (c *writeFailICMPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return 0, nil, c.err
}
func (c *writeFailICMPConn) SetReadDeadline(t time.Time) error { return nil }
func (c *writeFailICMPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("0.0.0.0")}
}
func (c *writeFailICMPConn) Close() error { return nil }
