package cluster

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// mockLink implements netlink.Link for testing.
type mockLink struct {
	attrs netlink.LinkAttrs
}

func (m *mockLink) Attrs() *netlink.LinkAttrs { return &m.attrs }
func (m *mockLink) Type() string              { return "mock" }

// mockNlHandle implements nlLinkGetter for testing.
type mockNlHandle struct {
	links map[string]*mockLink
}

func (h *mockNlHandle) LinkByName(name string) (netlink.Link, error) {
	if link, ok := h.links[name]; ok {
		return link, nil
	}
	return nil, net.UnknownNetworkError("not found: " + name)
}

func newMockNlHandle() *mockNlHandle {
	return &mockNlHandle{links: make(map[string]*mockLink)}
}

func (h *mockNlHandle) setLink(name string, up bool) {
	var state netlink.LinkOperState = netlink.OperDown
	if up {
		state = netlink.OperUp
	}
	h.links[name] = &mockLink{
		attrs: netlink.LinkAttrs{Name: name, OperState: state},
	}
}

// setLinkCarrierDown models a cable-pulled / peer-down interface: it is
// administratively up (IFF_UP set) but has lost carrier, so OperState is
// OperDown. This is the #2070 case — the monitor must report it DOWN and
// demote the redundancy group. Pre-fix the OR with net.FlagUp reported UP.
func (h *mockNlHandle) setLinkCarrierDown(name string) {
	h.links[name] = &mockLink{
		attrs: netlink.LinkAttrs{
			Name:      name,
			OperState: netlink.OperDown,
			Flags:     net.FlagUp,
		},
	}
}

// setNoDampening configures the monitor for immediate state changes (no dampening).
func setNoDampening(mon *Monitor) {
	mon.FailThreshold = 1
	mon.PassThreshold = 1
	mon.HoldDown = 1 * time.Nanosecond
}

func TestMonitor_InterfaceStateChange(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
			&config.InterfaceMonitor{Interface: "untrust0", Weight: 150},
		),
	)
	m.UpdateConfig(cfg)
	// Drain election events.
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)
	nlh.setLink("untrust0", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	// Initial poll: all up, no weight change.
	mon.poll()

	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("initial weight = %d, want 255", states[0].Weight)
	}

	// Bring trust0 down.
	nlh.setLink("trust0", false)
	mon.poll()

	states = m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight after trust0 down = %d, want 155", states[0].Weight)
	}

	// Recover trust0.
	nlh.setLink("trust0", true)
	mon.poll()

	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after recovery = %d, want 255", states[0].Weight)
	}
}

func TestMonitor_AllInterfacesDown(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 200},
			&config.InterfaceMonitor{Interface: "untrust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", false)
	nlh.setLink("untrust0", false)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	mon.poll()

	states := m.GroupStates()
	if states[0].Weight != 0 {
		t.Errorf("weight = %d, want 0 (all down, clamped)", states[0].Weight)
	}
	if m.IsLocalPrimary(0) {
		t.Error("should not be primary with weight 0")
	}
}

func TestMonitor_NoChangeNoCall(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	// Poll twice with same state — weight should remain 255.
	mon.poll()
	mon.poll()

	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight = %d, want 255 (no change)", states[0].Weight)
	}
}

func TestMonitor_StartStop(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", false)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	ctx, cancel := context.WithCancel(context.Background())
	mon.Start(ctx)

	// Wait for at least one poll.
	time.Sleep(1200 * time.Millisecond)

	states := m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight after monitor start = %d, want 155", states[0].Weight)
	}

	cancel()
	mon.Stop()

	// Verify stop completes without panic.
}

func TestMonitor_UpdateGroups(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)
	nlh.setLink("dmz0", false)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)
	mon.poll()

	// Now add a second RG with dmz0 monitor.
	cfg2 := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
		makeRG(1, false, map[int]int{0: 150},
			&config.InterfaceMonitor{Interface: "dmz0", Weight: 255},
		),
	)
	m.UpdateConfig(cfg2)
	drainEvents(m, 1) // RG 1 election
	mon.UpdateGroups(cfg2.RedundancyGroups)
	mon.poll()

	states := m.GroupStates()
	// RG 0: trust0 up -> weight 255
	for _, st := range states {
		if st.GroupID == 0 && st.Weight != 255 {
			t.Errorf("RG 0 weight = %d, want 255", st.Weight)
		}
		if st.GroupID == 1 && st.Weight != 0 {
			t.Errorf("RG 1 weight = %d, want 0 (dmz0 down)", st.Weight)
		}
	}
}

func TestMonitor_IPMonitoring(t *testing.T) {
	m := NewManager(0, 1)
	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight: 100,
			// No global-threshold: independent per-target debt mode. A single
			// weight-50 target failing deducts exactly 50 (255->205). The
			// cumulative global-threshold gate is covered separately in
			// monitor_globalthreshold_5271_test.go (#5271).
			Targets: []*config.IPMonitorTarget{
				{Address: "10.0.1.1", Weight: 50},
			},
		},
	}
	cfg := &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{rg},
	}
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reachable := true
	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.icmpDialer = func(network, src string) (icmpConn, error) {
		return &mockICMPConn{reachable: reachable}, nil
	}
	setNoDampening(mon)

	// Initial: reachable.
	mon.poll()
	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight = %d, want 255 (IP reachable)", states[0].Weight)
	}

	// Make IP unreachable.
	reachable = false
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 205 {
		t.Errorf("weight = %d, want 205 (255-50)", states[0].Weight)
	}

	// Recover.
	reachable = true
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after recovery = %d, want 255", states[0].Weight)
	}
}

func TestMonitor_Dampening(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	// Use default thresholds (3/3), disable hold-down for this test.
	mon.HoldDown = 1 * time.Nanosecond

	// Initial poll: up.
	mon.poll()
	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Fatalf("initial weight = %d, want 255", states[0].Weight)
	}

	// Bring down. First 2 polls should NOT trigger (threshold=3).
	nlh.setLink("trust0", false)
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after 1 failure = %d, want 255 (dampened)", states[0].Weight)
	}

	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after 2 failures = %d, want 255 (dampened)", states[0].Weight)
	}

	// 3rd poll triggers the state change.
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight after 3 failures = %d, want 155", states[0].Weight)
	}

	// Recovery: first 2 passes should NOT trigger.
	nlh.setLink("trust0", true)
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight after 1 pass = %d, want 155 (dampened)", states[0].Weight)
	}

	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight after 2 passes = %d, want 155 (dampened)", states[0].Weight)
	}

	// 3rd pass triggers recovery.
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after 3 passes = %d, want 255", states[0].Weight)
	}
}

func TestMonitor_HoldDown(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)

	now := time.Now()
	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	mon.FailThreshold = 1
	mon.PassThreshold = 1
	mon.HoldDown = 5 * time.Second
	mon.nowFunc = func() time.Time { return now }

	// Initial poll.
	mon.poll()

	// Bring down — immediate (threshold=1).
	nlh.setLink("trust0", false)
	mon.poll()
	states := m.GroupStates()
	if states[0].Weight != 155 {
		t.Fatalf("weight after down = %d, want 155", states[0].Weight)
	}

	// Bring up immediately — should be blocked by hold-down.
	nlh.setLink("trust0", true)
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight during hold-down = %d, want 155 (held)", states[0].Weight)
	}

	// Advance time but not past hold-down.
	now = now.Add(3 * time.Second)
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 155 {
		t.Errorf("weight during hold-down (3s) = %d, want 155 (held)", states[0].Weight)
	}

	// Advance past hold-down.
	now = now.Add(3 * time.Second)
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after hold-down = %d, want 255", states[0].Weight)
	}
}

func TestMonitor_Flapping(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	// Use default thresholds (3/3), disable hold-down.
	mon.HoldDown = 1 * time.Nanosecond

	mon.poll() // initial: up

	// Alternate up/down rapidly — consecutive count resets each flip,
	// so threshold is never reached.
	for i := 0; i < 20; i++ {
		nlh.setLink("trust0", false)
		mon.poll()
		nlh.setLink("trust0", true)
		mon.poll()
	}

	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after flapping = %d, want 255 (dampened)", states[0].Weight)
	}
}

func TestMonitor_IPDampening(t *testing.T) {
	m := NewManager(0, 1)
	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight: 100,
			Targets: []*config.IPMonitorTarget{
				{Address: "10.0.1.1", Weight: 80},
			},
		},
	}
	cfg := &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{rg},
	}
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reachable := true
	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.icmpDialer = func(network, src string) (icmpConn, error) {
		return &mockICMPConn{reachable: reachable}, nil
	}
	// Default thresholds (3/3), disable hold-down.
	mon.HoldDown = 1 * time.Nanosecond

	// Initial polls: reachable.
	mon.poll()
	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Fatalf("initial weight = %d, want 255", states[0].Weight)
	}

	// First two unreachable polls — dampened.
	reachable = false
	mon.poll()
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after 2 failures = %d, want 255 (dampened)", states[0].Weight)
	}

	// Third unreachable poll — triggers.
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 175 {
		t.Errorf("weight after 3 failures = %d, want 175 (255-80)", states[0].Weight)
	}
}

func TestMonitor_IPv6IPMonitoring(t *testing.T) {
	m := NewManager(0, 1)
	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight: 100,
			Targets: []*config.IPMonitorTarget{
				{Address: "2001:db8::1", Weight: 60},
			},
		},
	}
	cfg := &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{rg},
	}
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	reachable := true
	var gotNetwork string
	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.icmpDialer = func(network, src string) (icmpConn, error) {
		gotNetwork = network
		return &mockICMPConn{reachable: reachable, v6: true}, nil
	}
	setNoDampening(mon)

	// IPv6 target reachable.
	mon.poll()
	if gotNetwork != "udp6" {
		t.Errorf("network = %q, want \"udp6\"", gotNetwork)
	}
	states := m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight = %d, want 255 (IPv6 reachable)", states[0].Weight)
	}

	// IPv6 target unreachable.
	reachable = false
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 195 {
		t.Errorf("weight = %d, want 195 (255-60)", states[0].Weight)
	}

	// Recover.
	reachable = true
	mon.poll()
	states = m.GroupStates()
	if states[0].Weight != 255 {
		t.Errorf("weight after recovery = %d, want 255", states[0].Weight)
	}
}

func TestMonitor_IPv4ProbeUsesUDP4(t *testing.T) {
	m := NewManager(0, 1)
	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight: 100,
			Targets: []*config.IPMonitorTarget{
				{Address: "10.0.1.1", Weight: 50},
			},
		},
	}
	cfg := &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{rg},
	}
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	var gotNetwork string
	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.icmpDialer = func(network, src string) (icmpConn, error) {
		gotNetwork = network
		return &mockICMPConn{reachable: true}, nil
	}
	setNoDampening(mon)

	mon.poll()
	if gotNetwork != "udp4" {
		t.Errorf("network = %q, want \"udp4\"", gotNetwork)
	}
}

func TestMonitor_InvalidAddress(t *testing.T) {
	m := NewManager(0, 1)
	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight: 100,
			Targets: []*config.IPMonitorTarget{
				{Address: "not-an-ip", Weight: 50},
			},
		},
	}
	cfg := &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{rg},
	}
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	dialerCalled := false
	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.icmpDialer = func(network, src string) (icmpConn, error) {
		dialerCalled = true
		return &mockICMPConn{reachable: true}, nil
	}
	setNoDampening(mon)

	// Invalid address should not crash and should be treated as unreachable.
	mon.poll()
	if dialerCalled {
		t.Error("dialer should not be called for invalid address")
	}
}

// mockICMPConn simulates a Linux datagram ICMP socket. On WriteTo it records
// the request's target and sequence; on ReadFrom it synthesizes a matching
// echo reply — source == target, identifier == the simulated kernel-assigned
// socket port, sequence == the request's sequence — modeling the real
// SOCK_DGRAM behavior where the kernel overwrites the identifier with the
// socket port and preserves the sequence. Adversarial overrides let a test
// model a spoofed / stale reply (wrong source, identifier, or sequence).
type mockICMPConn struct {
	reachable bool
	v6        bool // if true, return ICMPv6 echo reply

	// localPort is the simulated kernel-assigned identifier reported by
	// LocalAddr and echoed as the reply identifier. 0 means use 0xbf.
	localPort int

	// Adversarial overrides. When set, the reply deviates from a faithful
	// echo of the request so validation can be exercised.
	badSource net.IP // reply source instead of the probed target
	badID     *int   // reply identifier instead of localPort
	badSeq    *int   // reply sequence instead of the request's sequence

	// Captured from the most recent WriteTo.
	lastTarget net.IP
	lastSeq    int

	// readCount models a socket that delivers at most one reply before the
	// read deadline expires, so the validation loop terminates.
	readCount int
}

func (c *mockICMPConn) proto() int {
	if c.v6 {
		return 58
	}
	return 1
}

func (c *mockICMPConn) port() int {
	if c.localPort != 0 {
		return c.localPort
	}
	return 0xbf
}

func (c *mockICMPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{Port: c.port()}
}

func (c *mockICMPConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	if ua, ok := dst.(*net.UDPAddr); ok {
		c.lastTarget = ua.IP
	}
	if m, err := icmp.ParseMessage(c.proto(), b); err == nil {
		if e, ok := m.Body.(*icmp.Echo); ok {
			c.lastSeq = e.Seq
		}
	}
	return len(b), nil
}

func (c *mockICMPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if !c.reachable {
		return 0, nil, net.UnknownNetworkError("timeout")
	}
	c.readCount++
	if c.readCount > 1 {
		// Model the read deadline expiring with no further replies, so a
		// probe that rejected the first (non-matching) reply gives up.
		return 0, nil, net.UnknownNetworkError("timeout")
	}

	id := c.port()
	if c.badID != nil {
		id = *c.badID
	}
	seq := c.lastSeq
	if c.badSeq != nil {
		seq = *c.badSeq
	}

	var replyType icmp.Type
	if c.v6 {
		replyType = ipv6.ICMPTypeEchoReply
	} else {
		replyType = ipv4.ICMPTypeEchoReply
	}
	reply, err := (&icmp.Message{
		Type: replyType,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("xpf")},
	}).Marshal(nil)
	if err != nil {
		return 0, nil, err
	}
	n := copy(b, reply)

	src := c.lastTarget
	if c.badSource != nil {
		src = c.badSource
	}
	return n, &net.UDPAddr{IP: src}, nil
}

func (c *mockICMPConn) SetReadDeadline(t time.Time) error { return nil }
func (c *mockICMPConn) Close() error                      { return nil }

// TestProbeICMP_ReplyValidation verifies that probeICMP only counts an echo
// reply as a successful probe when the responder source address, the ICMP
// identifier (the datagram socket's local port), and the sequence number all
// match the request. A reply failing any check must be ignored — otherwise a
// stray or spoofed reply falsely reports a down path as up and suppresses the
// intended failover (the L-3 finding).
func TestProbeICMP_ReplyValidation(t *testing.T) {
	intp := func(v int) *int { return &v }

	cases := []struct {
		name   string
		v6     bool
		target string
		mutate func(c *mockICMPConn)
		want   bool
	}{
		{
			name:   "v4 correct reply accepted",
			target: "10.0.1.1",
			want:   true,
		},
		{
			name:   "v4 wrong source rejected",
			target: "10.0.1.1",
			mutate: func(c *mockICMPConn) { c.badSource = net.ParseIP("10.0.1.99") },
			want:   false,
		},
		{
			name:   "v4 wrong identifier rejected",
			target: "10.0.1.1",
			// 0xbf is the constant the request marshals; the kernel would
			// have rewritten it to the socket port, so a reply still bearing
			// 0xbf is a foreign/spoofed reply.
			mutate: func(c *mockICMPConn) { c.badID = intp(0xbf) },
			want:   false,
		},
		{
			name:   "v4 stale sequence rejected",
			target: "10.0.1.1",
			mutate: func(c *mockICMPConn) { c.badSeq = intp(1) },
			want:   false,
		},
		{
			name:   "v6 correct reply accepted",
			v6:     true,
			target: "2001:db8::1",
			want:   true,
		},
		{
			name:   "v6 wrong source rejected",
			v6:     true,
			target: "2001:db8::1",
			mutate: func(c *mockICMPConn) { c.badSource = net.ParseIP("2001:db8::99") },
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc := &mockICMPConn{reachable: true, v6: tc.v6, localPort: 45502}
			if tc.mutate != nil {
				tc.mutate(mc)
			}
			mon := &Monitor{
				icmpDialer: func(network, src string) (icmpConn, error) { return mc, nil },
			}
			if got, _ := mon.probeICMP(context.Background(), ipProbeTask{target: &config.IPMonitorTarget{Address: tc.target}, rgID: -1}); got != tc.want {
				t.Errorf("probeICMP(%s) = %v, want %v", tc.target, got, tc.want)
			}
		})
	}
}

// TestProbeICMP_StaleSequenceAcrossProbes verifies that a reply carrying the
// sequence from a PREVIOUS probe (a delayed/duplicated reply) is not accepted
// by a later probe, since each probe stamps a fresh sequence.
func TestProbeICMP_StaleSequenceAcrossProbes(t *testing.T) {
	first := &mockICMPConn{reachable: true, localPort: 45502}
	mon := &Monitor{
		icmpDialer: func(network, src string) (icmpConn, error) { return first, nil },
	}
	if r, _ := mon.probeICMP(context.Background(), ipProbeTask{target: &config.IPMonitorTarget{Address: "10.0.1.1"}, rgID: -1}); !r {
		t.Fatal("first probe should succeed")
	}

	// Second probe: a reply that replays the FIRST probe's exact sequence
	// (captured in first.lastSeq) must be rejected because the second probe
	// stamped a fresh sequence.
	replay := &mockICMPConn{reachable: true, localPort: 45502, badSeq: &first.lastSeq}
	mon.icmpDialer = func(network, src string) (icmpConn, error) { return replay, nil }
	if r, _ := mon.probeICMP(context.Background(), ipProbeTask{target: &config.IPMonitorTarget{Address: "10.0.1.1"}, rgID: -1}); r {
		t.Error("probe accepted a reply carrying the previous probe's sequence")
	}
}

func TestMonitor_LocalStatusesConcurrent(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	ctx, cancel := context.WithCancel(context.Background())
	mon.Start(ctx)
	defer func() {
		cancel()
		mon.Stop()
	}()

	// Hammer LocalInterfaceStatuses concurrently with poll() to trigger
	// the race detector if the lock is not held properly.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			_ = mon.LocalInterfaceStatuses()
		}
	}()

	<-done
}

// TestMonitor_CarrierDownDemotesRG is the #2070 regression for the live
// cluster carrier-detection loop. An admin-up interface that loses carrier
// (cable pulled / peer down) must be reported DOWN so the redundancy group
// is demoted and HA failover fires. Pre-fix, poll() OR'd in net.FlagUp
// (IFF_UP, the admin flag, which stays set on carrier loss), so the link
// was reported UP, the weight was never subtracted, and failover was
// suppressed — the bug this test would catch.
func TestMonitor_CarrierDownDemotesRG(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	// Initial poll: carrier up, full weight.
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("initial weight = %d, want 255", w)
	}

	// Pull the cable: admin-up but carrier-down. This MUST demote the RG.
	nlh.setLinkCarrierDown("trust0")
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 155 {
		t.Errorf("weight after carrier-down = %d, want 155 "+
			"(carrier-down link reported UP — #2070)", w)
	}

	// Restore carrier: RG recovers.
	nlh.setLink("trust0", true)
	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Errorf("weight after carrier recovery = %d, want 255", w)
	}
}

// countingNlHandle is a fake nlHandleCloser that records how many times it is
// closed. Paired with a counting factory, it lets the getNlHandle tests assert
// that exactly one production handle is created under concurrency (no FD leak)
// and that Stop closes it exactly once.
type countingNlHandle struct {
	closes *int32
}

func (h *countingNlHandle) LinkByName(name string) (netlink.Link, error) {
	return nil, net.UnknownNetworkError("counting fake: " + name)
}

func (h *countingNlHandle) Close() { atomic.AddInt32(h.closes, 1) }

// TestGetNlHandleConcurrentSingleCreation hammers getNlHandle from many
// goroutines and asserts exactly one netlink handle is created — the #4715
// FD-leak + data-race fix. Pre-fix, getNlHandle read/wrote mon.cachedNlHandle
// lock-free, so concurrent callers each ran the factory (leaking every handle
// but the last) and the write raced Stop()'s cachedNlHandle=nil. With the fix
// the check-create-cache runs under mon.mu, so creations==1 and `go test
// -race` is clean. Reverting the locking (keeping the factory seam) makes this
// test RED: `-race` reports a data race on cachedNlHandle AND the 1ms factory
// delay lets several goroutines observe cachedNlHandle==nil, so creations>1.
func TestGetNlHandleConcurrentSingleCreation(t *testing.T) {
	mon := NewMonitor(nil, nil)

	var creations, closes int32
	mon.newNlHandle = func() (nlHandleCloser, error) {
		atomic.AddInt32(&creations, 1)
		// Widen the race window: two lock-free callers would both observe
		// cachedNlHandle==nil during this delay and each create a handle.
		time.Sleep(time.Millisecond)
		return &countingNlHandle{closes: &closes}, nil
	}

	const goroutines = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if got := mon.getNlHandle(); got == nil {
				t.Error("getNlHandle returned nil")
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&creations); got != 1 {
		t.Fatalf("expected exactly 1 handle creation under concurrency, got %d "+
			"(each extra creation leaks a netlink socket FD)", got)
	}

	// Stop closes the single cached handle exactly once — no leak.
	mon.Stop()
	if got := atomic.LoadInt32(&closes); got != 1 {
		t.Fatalf("expected exactly 1 Close on Stop, got %d", got)
	}

	// After Stop nils cachedNlHandle, getNlHandle recreates on demand,
	// preserving the prior lazy-recreate contract.
	if got := mon.getNlHandle(); got == nil {
		t.Error("getNlHandle after Stop returned nil")
	}
	if got := atomic.LoadInt32(&creations); got != 2 {
		t.Fatalf("expected the handle recreated after Stop (2 total creations), got %d", got)
	}
	mon.Stop()
	if got := atomic.LoadInt32(&closes); got != 2 {
		t.Fatalf("expected the recreated handle closed on the second Stop (2 total), got %d", got)
	}
}

// TestGetNlHandleSingleThreadedCachesAndCloses is the behavioral guard: a
// single caller still gets a working, cached handle, repeat calls return the
// same handle (one creation), and Stop closes it.
func TestGetNlHandleSingleThreadedCachesAndCloses(t *testing.T) {
	mon := NewMonitor(nil, nil)

	var creations, closes int32
	mon.newNlHandle = func() (nlHandleCloser, error) {
		atomic.AddInt32(&creations, 1)
		return &countingNlHandle{closes: &closes}, nil
	}

	h1 := mon.getNlHandle()
	if h1 == nil {
		t.Fatal("getNlHandle returned nil")
	}
	h2 := mon.getNlHandle()
	if h1 != h2 {
		t.Fatal("getNlHandle returned a different handle on repeat call — not cached")
	}
	if got := atomic.LoadInt32(&creations); got != 1 {
		t.Fatalf("expected 1 creation for repeated single-threaded calls, got %d", got)
	}

	mon.Stop()
	if got := atomic.LoadInt32(&closes); got != 1 {
		t.Fatalf("expected 1 Close on Stop, got %d", got)
	}
}

// drainEvents is defined in election_test.go
