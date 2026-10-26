package dhcprelay

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
)

func TestAddOption82(t *testing.T) {
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatal(err)
	}

	addOption82(pkt, "trust0")

	opt := pkt.Options.Get(option82)
	if opt == nil {
		t.Fatal("Option 82 not found")
	}

	// Parse sub-option: type(1) + length + value
	if len(opt) < 2 {
		t.Fatalf("Option 82 too short: %d bytes", len(opt))
	}
	if opt[0] != suboption1CircuitID {
		t.Errorf("sub-option type: got %d, want %d", opt[0], suboption1CircuitID)
	}
	if opt[1] != byte(len("trust0")) {
		t.Errorf("sub-option length: got %d, want %d", opt[1], len("trust0"))
	}
	circuitID := string(opt[2:])
	if circuitID != "trust0" {
		t.Errorf("circuit-id: got %q, want %q", circuitID, "trust0")
	}
}

func TestStripOption82(t *testing.T) {
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatal(err)
	}

	addOption82(pkt, "trust0")
	if pkt.Options.Get(option82) == nil {
		t.Fatal("Option 82 should be present before strip")
	}

	stripOption82(pkt)
	if pkt.Options.Get(option82) != nil {
		t.Error("Option 82 should be removed after strip")
	}
}

func TestAddOption82_Replaces(t *testing.T) {
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatal(err)
	}

	addOption82(pkt, "trust0")
	addOption82(pkt, "dmz0")

	opt := pkt.Options.Get(option82)
	if opt == nil {
		t.Fatal("Option 82 not found")
	}
	circuitID := string(opt[2:])
	if circuitID != "dmz0" {
		t.Errorf("circuit-id should be replaced: got %q, want %q", circuitID, "dmz0")
	}
}

func TestDefaultIfaceResolverLoopback(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no loopback interface")
	}
	ip, err := defaultIfaceResolver(lo.Name)
	if err == nil {
		t.Errorf("expected error for loopback, got IP %s", ip)
	}
}

// TestClientRequestRelayable asserts the client->server forwarding gate
// (#2153/#2789): a relay must forward DISCOVER, REQUEST, INFORM, and DECLINE,
// but not server reply types or the client-to-server-direct RELEASE. INFORM is
// the #2153 regression target and DECLINE the #2789 target — before each fix
// the gate returned false for that type. Pre-#2153 the dropped INFORM left a
// domain-joined client that holds its own address without DNS/domain/NTP
// options from the central server; pre-#2789 the dropped DECLINE meant a
// client-detected address conflict never reached the server, which kept
// re-offering the in-use address.
func TestClientRequestRelayable(t *testing.T) {
	cases := []struct {
		msgType dhcpv4.MessageType
		want    bool
	}{
		{dhcpv4.MessageTypeDiscover, true},
		{dhcpv4.MessageTypeRequest, true},
		{dhcpv4.MessageTypeInform, true},  // #2153 regression target
		{dhcpv4.MessageTypeDecline, true}, // #2789 regression target
		{dhcpv4.MessageTypeRelease, false},
		{dhcpv4.MessageTypeOffer, false},
		{dhcpv4.MessageTypeAck, false},
		{dhcpv4.MessageTypeNak, false},
		{dhcpv4.MessageType(0), false}, // missing/zero message type
	}
	for _, tc := range cases {
		if got := clientRequestRelayable(tc.msgType); got != tc.want {
			t.Errorf("clientRequestRelayable(%v) = %v, want %v",
				tc.msgType, got, tc.want)
		}
	}
}

// TestRunRelay_RelaysInform is the end-to-end gate proof for #2153: a real
// BOOTREQUEST/INFORM datagram pushed through the live runRelay loop must be
// forwarded to the server conn (not silently dropped). It drives the production
// path via Apply + the recording factory; the client conn delivers one INFORM
// then blocks. The assertion FAILS against the pre-#2153 gate, which `continue`d
// on INFORM and never wrote to the server conn.
func TestRunRelay_RelaysInform(t *testing.T) {
	// Build a client INFORM: BOOTREQUEST with ciaddr set (client owns its
	// address) and no yiaddr — the canonical DHCPINFORM shape (RFC 2131 §3.4).
	inform, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	inform.OpCode = dhcpv4.OpcodeBootRequest
	inform.ClientHWAddr = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	inform.ClientIPAddr = net.IPv4(192, 0, 2, 50)
	inform.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeInform))

	// The factory hands out the client conn first (runRelay's first newConn
	// call) then the server conn. Seed the client conn with the INFORM; after
	// it is consumed ReadFrom blocks until Stop.
	client := newFakeConn()
	client.pending = [][]byte{inform.ToBytes()}
	server := newFakeConn()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)

	m.Apply(context.Background(), singleInterfaceConfig())
	defer m.Stop()

	// Wait for the INFORM to be relayed onto the server conn.
	deadline := time.Now().Add(2 * time.Second)
	for server.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.writeCount() == 0 {
		t.Fatal("INFORM was not relayed to the server within 2s " +
			"(pre-#2153 gate dropped it)")
	}

	// The relayed datagram must parse, be a BOOTREQUEST/INFORM, and carry the
	// relay-set giaddr (10.0.0.254, from testManager's resolver).
	relayed, err := dhcpv4.FromBytes(server.firstWrite(t))
	if err != nil {
		t.Fatalf("relayed datagram does not parse: %v", err)
	}
	if relayed.OpCode != dhcpv4.OpcodeBootRequest {
		t.Errorf("relayed opcode = %v, want BOOTREQUEST", relayed.OpCode)
	}
	if relayed.MessageType() != dhcpv4.MessageTypeInform {
		t.Errorf("relayed message type = %v, want INFORM", relayed.MessageType())
	}
	if !relayed.GatewayIPAddr.Equal(net.IPv4(10, 0, 0, 254)) {
		t.Errorf("relayed giaddr = %v, want 10.0.0.254", relayed.GatewayIPAddr)
	}
}

// TestRunRelay_RelaysOversizeDatagram is the fail-on-revert proof for #3012:
// a DHCP BOOTREQUEST whose serialized form exceeds 1500 bytes (large option
// set / jumbo-MTU link) must be read intact and relayed — NOT truncated by the
// read buffer and silently dropped.
//
// fakeConn.ReadFrom copies only len(buf) bytes (copy(p, d)), exactly mirroring
// the kernel's MSG_TRUNC behavior on a real UDP socket: if the read buffer is
// smaller than the datagram the tail (the option block) is lost and
// dhcpv4.FromBytes fails -> the relay drops the packet. With the buffer sized
// to readBufSize (#3012) the whole datagram is read and relayed. Reverting
// readBufSize to 1500 (or any value below the datagram length) makes this test
// RED: the truncated datagram fails to parse and is never written to the
// server conn.
func TestRunRelay_RelaysOversizeDatagram(t *testing.T) {
	req, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	req.OpCode = dhcpv4.OpcodeBootRequest
	req.ClientHWAddr = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x03}
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))
	// Append a large option (vendor-specific information) to push the
	// serialized datagram well past 1500 bytes. DHCP options carry no
	// 1500-byte limit; this models a real large-option-set client.
	bigVal := make([]byte, 1600)
	for i := range bigVal {
		bigVal[i] = byte(i)
	}
	req.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionVendorSpecificInformation, bigVal))

	wire := req.ToBytes()
	if len(wire) <= 1500 {
		t.Fatalf("test datagram is %d bytes, want > 1500 to exercise the "+
			"oversize read path", len(wire))
	}

	client := newFakeConn()
	client.pending = [][]byte{wire}
	server := newFakeConn()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)

	m.Apply(context.Background(), singleInterfaceConfig())
	defer m.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for server.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.writeCount() == 0 {
		t.Fatalf("oversize (%d-byte) BOOTREQUEST was not relayed within 2s "+
			"(read buffer truncated it — readBufSize regressed below the "+
			"datagram length)", len(wire))
	}

	relayed, err := dhcpv4.FromBytes(server.firstWrite(t))
	if err != nil {
		t.Fatalf("relayed oversize datagram does not parse "+
			"(truncated read): %v", err)
	}
	if relayed.OpCode != dhcpv4.OpcodeBootRequest {
		t.Errorf("relayed opcode = %v, want BOOTREQUEST", relayed.OpCode)
	}
	// The large option must survive intact end-to-end — proof the tail was
	// not truncated by the read.
	got := relayed.Options.Get(dhcpv4.OptionVendorSpecificInformation)
	if len(got) != len(bigVal) {
		t.Fatalf("relayed vendor option = %d bytes, want %d "+
			"(option block truncated by the read buffer)", len(got), len(bigVal))
	}
}

// TestRunRelay_RelaysDecline is the end-to-end gate proof for #2789: a real
// BOOTREQUEST/DECLINE datagram pushed through the live runRelay loop must be
// forwarded to the server conn (so the server marks the conflicting address
// unavailable per RFC 2131 §4.4.1), and must carry the relay-set giaddr so the
// server can attribute the decline to this relayed segment. The assertion
// FAILS against the pre-#2789 gate, which `continue`d on DECLINE and never
// wrote to the server conn.
func TestRunRelay_RelaysDecline(t *testing.T) {
	// Build a client DECLINE: BOOTREQUEST whose Requested-IP option names the
	// address the client found in use (RFC 2131 §4.4.1 — the declined address
	// is carried in option 50, ciaddr stays zero).
	decline, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	decline.OpCode = dhcpv4.OpcodeBootRequest
	decline.ClientHWAddr = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	decline.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDecline))
	decline.UpdateOption(dhcpv4.OptRequestedIPAddress(net.IPv4(192, 0, 2, 77)))

	client := newFakeConn()
	client.pending = [][]byte{decline.ToBytes()}
	server := newFakeConn()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)

	m.Apply(context.Background(), singleInterfaceConfig())
	defer m.Stop()

	// Wait for the DECLINE to be relayed onto the server conn.
	deadline := time.Now().Add(2 * time.Second)
	for server.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.writeCount() == 0 {
		t.Fatal("DECLINE was not relayed to the server within 2s " +
			"(pre-#2789 gate dropped it)")
	}

	// The relayed datagram must parse, be a BOOTREQUEST/DECLINE, carry the
	// relay-set giaddr (10.0.0.254, from testManager's resolver), and preserve
	// the declined address so the server knows which binding to mark in-use.
	relayed, err := dhcpv4.FromBytes(server.firstWrite(t))
	if err != nil {
		t.Fatalf("relayed datagram does not parse: %v", err)
	}
	if relayed.OpCode != dhcpv4.OpcodeBootRequest {
		t.Errorf("relayed opcode = %v, want BOOTREQUEST", relayed.OpCode)
	}
	if relayed.MessageType() != dhcpv4.MessageTypeDecline {
		t.Errorf("relayed message type = %v, want DECLINE", relayed.MessageType())
	}
	if !relayed.GatewayIPAddr.Equal(net.IPv4(10, 0, 0, 254)) {
		t.Errorf("relayed giaddr = %v, want 10.0.0.254", relayed.GatewayIPAddr)
	}
	if got := relayed.RequestedIPAddress(); !got.Equal(net.IPv4(192, 0, 2, 77)) {
		t.Errorf("relayed requested-IP = %v, want 192.0.2.77", got)
	}
}

// TestRunRelay_HopCountLimit asserts the RFC 1542 §4.1.1 hop limit is enforced
// before the uint8 increment, so a request whose HopCount has already reached
// (or maxed out) the limit is dropped rather than wrapped past the check.
// HopCount==255 is the regression case: a post-increment "> 16" test wraps it
// to 0 and relays it, defeating loop protection.
func TestRunRelay_HopCountLimit(t *testing.T) {
	cases := []struct {
		name        string
		hops        uint8
		wantRelayed bool
		wantHops    uint8 // relayed hop count (only checked when wantRelayed)
	}{
		{"below_limit", 15, true, 16},
		{"at_limit", 16, false, 0},
		{"wrap_boundary_255", 255, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := dhcpv4.New()
			if err != nil {
				t.Fatalf("dhcpv4.New: %v", err)
			}
			req.OpCode = dhcpv4.OpcodeBootRequest
			req.ClientHWAddr = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
			req.HopCount = tc.hops
			req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))

			client := newFakeConn()
			client.pending = [][]byte{req.ToBytes()}
			server := newFakeConn()
			factory, _ := recordingFactory(client, server)
			m := testManager(factory)
			m.Apply(context.Background(), singleInterfaceConfig())
			defer m.Stop()

			// Give the loop time to consume the datagram and act on it.
			deadline := time.Now().Add(1 * time.Second)
			for client.readCalls.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}

			got := server.writeCount()
			if tc.wantRelayed && got == 0 {
				t.Fatalf("hops=%d: expected relay, got none", tc.hops)
			}
			if !tc.wantRelayed && got != 0 {
				t.Fatalf("hops=%d: expected drop, but %d datagram(s) relayed", tc.hops, got)
			}
			if tc.wantRelayed {
				relayed, err := dhcpv4.FromBytes(server.firstWrite(t))
				if err != nil {
					t.Fatalf("relayed datagram does not parse: %v", err)
				}
				if relayed.HopCount != tc.wantHops {
					t.Errorf("relayed HopCount = %d, want %d", relayed.HopCount, tc.wantHops)
				}
			}
		})
	}
}

// TestRunRelay_ConfiguredMaxHopCount asserts the #4309 configurable hop limit:
// `overrides maximum-hop-count <n>` lowers the drop threshold from the default
// 16, a request AT the configured limit is dropped, one below it is relayed,
// and the drop increments RequestsDroppedMaxHops. RED-on-revert: with the hop
// check pinned to the hardcoded 16 (or ir.maxHopCount unwired), the hops=4
// request would relay instead of drop.
func TestRunRelay_ConfiguredMaxHopCount(t *testing.T) {
	cfg := singleInterfaceConfig()
	cfg.Groups["g"].MaximumHopCount = 4

	cases := []struct {
		name        string
		hops        uint8
		wantRelayed bool
	}{
		{"below_configured_limit", 3, true},
		{"at_configured_limit", 4, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := dhcpv4.New()
			if err != nil {
				t.Fatalf("dhcpv4.New: %v", err)
			}
			req.OpCode = dhcpv4.OpcodeBootRequest
			req.ClientHWAddr = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
			req.HopCount = tc.hops
			req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))

			client := newFakeConn()
			client.pending = [][]byte{req.ToBytes()}
			server := newFakeConn()
			factory, _ := recordingFactory(client, server)
			m := testManager(factory)
			m.Apply(context.Background(), cfg)
			defer m.Stop()

			deadline := time.Now().Add(1 * time.Second)
			for client.readCalls.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}

			got := server.writeCount()
			if tc.wantRelayed && got == 0 {
				t.Fatalf("hops=%d limit=4: expected relay, got none", tc.hops)
			}
			if !tc.wantRelayed {
				if got != 0 {
					t.Fatalf("hops=%d limit=4: expected drop, but %d datagram(s) relayed", tc.hops, got)
				}
				// The drop must be counted.
				var dropped uint64
				for _, s := range m.Stats() {
					dropped += s.RequestsDroppedMaxHops
				}
				if dropped == 0 {
					t.Errorf("hops=%d limit=4: dropped but RequestsDroppedMaxHops stayed 0", tc.hops)
				}
			}
		})
	}
}

// --- Lifecycle test scaffolding (#1915) ---

// fakeConn is a fake net.PacketConn whose ReadFrom blocks until Close (unless
// readErr or pending datagrams are set). It records writes and the close call
// so lifecycle tests assert bounded teardown and goroutine joins with no real
// sockets and no root.
type fakeConn struct {
	mu        sync.Mutex
	closed    bool
	closeCh   chan struct{}
	readCalls atomic.Int64
	pending   [][]byte // datagrams ReadFrom returns before blocking
	writes    []fakeWrite
	// readErr, if set, is returned by ReadFrom (instead of blocking) once
	// pending is exhausted — used to simulate an early one-sided close.
	readErr error
	// srcAddr, when non-nil, is the source address ReadFrom reports for each
	// pending datagram. nil falls back to the default 10.0.0.1:68 — this lets
	// the #4163 source-validation tests drive a reply from a non-configured
	// source without disturbing the existing reply-path tests.
	srcAddr net.Addr
	// wake signals a blocked ReadFrom that push() queued a new datagram.
	// Buffered depth 1; see push.
	wake chan struct{}
}

type fakeWrite struct {
	data []byte
	addr net.Addr
}

func newFakeConn() *fakeConn {
	return &fakeConn{closeCh: make(chan struct{}), wake: make(chan struct{}, 1)}
}

func (f *fakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	f.readCalls.Add(1)
	// Loop rather than recurse after a wake: a push that is consumed by a
	// racing reader leaves this reader to block again, and iteration keeps
	// that bounded by the stack the caller already has.
	for {
		f.mu.Lock()
		if len(f.pending) > 0 {
			d := f.pending[0]
			f.pending = f.pending[1:]
			src := f.srcAddr
			f.mu.Unlock()
			n := copy(p, d)
			if src == nil {
				src = &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 68}
			}
			return n, src, nil
		}
		rerr := f.readErr
		f.mu.Unlock()
		if rerr != nil {
			return 0, nil, rerr
		}
		// Nothing queued: block until Close (the pre-existing behavior every
		// pre-seeding test relies on) OR until push() queues a datagram
		// mid-flight. The wake path exists for the #6562 end-to-end exchange
		// test, which must inject a server reply only AFTER the request it
		// answers has been relayed — a reply pre-seeded before the session
		// starts would race the binding.
		select {
		case <-f.closeCh:
			return 0, nil, net.ErrClosed
		case <-f.wake:
		}
	}
}

// push queues a datagram for a subsequent ReadFrom and wakes a reader that is
// already blocked. The wake channel is buffered depth 1 and the send is
// non-blocking, so a push that races a reader already draining pending cannot
// deadlock: the queued datagram is picked up by the next read either way.
func (f *fakeConn) push(d []byte) {
	f.mu.Lock()
	f.pending = append(f.pending, d)
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *fakeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, net.ErrClosed
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	f.writes = append(f.writes, fakeWrite{data: cp, addr: addr})
	return len(p), nil
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return net.ErrClosed
	}
	f.closed = true
	close(f.closeCh)
	f.mu.Unlock()
	return nil
}

func (f *fakeConn) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// writeCount returns the number of datagrams written to this conn.
func (f *fakeConn) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

// firstWrite returns a copy of the first datagram written to this conn.
func (f *fakeConn) firstWrite(t *testing.T) []byte {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.writes) == 0 {
		t.Fatal("no datagram was written to the conn")
	}
	return append([]byte(nil), f.writes[0].data...)
}

func (f *fakeConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

// factoryCall records one packetConnFactory invocation.
type factoryCall struct {
	ifaceName string
	reusePort bool
	broadcast bool
	bindAddr  *net.UDPAddr
}

// recordingFactory returns a packetConnFactory that records each call and
// hands back the next conn from the supplied list (sequential); calls beyond
// the supplied conns get a fresh fakeConn. The getter returns a snapshot.
func recordingFactory(conns ...*fakeConn) (packetConnFactory, func() []factoryCall) {
	var mu sync.Mutex
	var calls []factoryCall
	idx := 0
	f := func(ctx context.Context, ifaceName string, reusePort, broadcast bool,
		bindAddr *net.UDPAddr) (net.PacketConn, error) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, factoryCall{
			ifaceName: ifaceName,
			reusePort: reusePort,
			broadcast: broadcast,
			bindAddr:  bindAddr,
		})
		var c *fakeConn
		if idx < len(conns) {
			c = conns[idx]
		} else {
			c = newFakeConn()
		}
		idx++
		return c, nil
	}
	getter := func() []factoryCall {
		mu.Lock()
		defer mu.Unlock()
		out := make([]factoryCall, len(calls))
		copy(out, calls)
		return out
	}
	return f, getter
}

// testManager builds a Manager with mocked seams: an immediately-succeeding
// giaddr resolver, the supplied factory, and a tiny retry interval.
func testManager(factory packetConnFactory) *Manager {
	m := NewManager()
	m.newConn = factory
	m.resolveGIAddr = func(ifaceName string) (net.IP, error) {
		return net.IPv4(10, 0, 0, 254), nil
	}
	m.retryInterval = time.Millisecond
	// Default to a stable ifindex with the #2347 drift watcher effectively off
	// (a long interval) so pre-existing lifecycle tests see no extra churn.
	// Drift tests override resolveIfindex + ifindexCheck.
	m.resolveIfindex = func(ifaceName string) (int, error) { return 100, nil }
	m.ifindexCheck = time.Hour
	// Default to a no-op fake L2 sender so lifecycle tests do not depend on
	// CAP_NET_RAW or a real NIC (#2076). Individual tests override m.newL2.
	m.newL2 = func(ifaceName string) (l2Replier, error) {
		return &fakeL2{}, nil
	}
	return m
}

func singleInterfaceConfig() *config.DHCPRelayConfig {
	return &config.DHCPRelayConfig{
		ServerGroups: map[string]*config.DHCPRelayServerGroup{
			"sg": {Name: "sg", Servers: []string{"192.0.2.1"}},
		},
		Groups: map[string]*config.DHCPRelayGroup{
			"g": {Name: "g", Interfaces: []string{"ge-0-0-0"}, ActiveServerGroup: "sg"},
		},
	}
}

func twoInterfaceConfig() *config.DHCPRelayConfig {
	return &config.DHCPRelayConfig{
		ServerGroups: map[string]*config.DHCPRelayServerGroup{
			"sg": {Name: "sg", Servers: []string{"192.0.2.1"}},
		},
		Groups: map[string]*config.DHCPRelayGroup{
			"g": {
				Name:              "g",
				Interfaces:        []string{"ge-0-0-0", "ge-0-0-1"},
				ActiveServerGroup: "sg",
			},
		},
	}
}

// relayConfig builds a single-group relay config from explicit interfaces,
// server IPs, and the always-broadcast flag — the inputs the #2348 reconcile
// keys on (interface set + spec). It lets the reconcile tests express
// add/remove/change directly.
func relayConfig(servers []string, alwaysBroadcast bool, ifaces ...string) *config.DHCPRelayConfig {
	return &config.DHCPRelayConfig{
		ServerGroups: map[string]*config.DHCPRelayServerGroup{
			"sg": {Name: "sg", Servers: servers},
		},
		Groups: map[string]*config.DHCPRelayGroup{
			"g": {
				Name:              "g",
				Interfaces:        ifaces,
				ActiveServerGroup: "sg",
				AlwaysBroadcast:   alwaysBroadcast,
			},
		},
	}
}

// statsIfaces returns the set of interface names with a running relay.
func statsIfaces(m *Manager) map[string]bool {
	out := map[string]bool{}
	for _, s := range m.Stats() {
		out[s.Interface] = true
	}
	return out
}

// waitRelays blocks until the manager reports n relays or the deadline passes.
func waitRelays(t *testing.T, m *Manager, n int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if len(m.Stats()) >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("expected >= %d relays, got %d", n, len(m.Stats()))
}

// waitCalls blocks until the factory has been called n times or deadline.
func waitCalls(t *testing.T, getCalls func() []factoryCall, n int, d time.Duration) []factoryCall {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if c := getCalls(); len(c) >= n {
			return c
		}
		time.Sleep(time.Millisecond)
	}
	c := getCalls()
	t.Fatalf("expected >= %d factory calls, got %d: %+v", n, len(c), c)
	return c
}

// TestApply_MultiInterface_NoCollision proves the EADDRINUSE fix by
// construction: two interfaces each get a 0.0.0.0:67 client listener with
// reusePort=true AND a distinct non-empty ifaceName (the BINDTODEVICE
// invariant), plus a server conn each — four factory calls, no error.
func TestApply_MultiInterface_NoCollision(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)
	defer m.Stop()

	m.Apply(context.Background(), twoInterfaceConfig())
	waitRelays(t, m, 2, 2*time.Second)
	calls := waitCalls(t, getCalls, 4, 2*time.Second)
	if len(calls) != 4 {
		t.Fatalf("expected exactly 4 factory calls, got %d: %+v", len(calls), calls)
	}

	clientIfaces := map[string]bool{}
	clientListeners, serverListeners := 0, 0
	for _, c := range calls {
		// Both conns now bind port 67 (#2888): classify by bind IP — the client
		// listener binds the 0.0.0.0 wildcard, the server conn binds the
		// specific giaddr.
		if c.bindAddr.IP.Equal(net.IPv4zero) {
			clientListeners++
			if c.bindAddr.Port != relayPort {
				t.Errorf("client listener must bind :67: %+v", c)
			}
			if !c.reusePort {
				t.Errorf("client listener on :67 must set reusePort: %+v", c)
			}
			if !c.broadcast {
				t.Errorf("client listener must set broadcast (SO_BROADCAST): %+v", c)
			}
			if c.ifaceName == "" {
				t.Errorf("client listener MUST have non-empty BINDTODEVICE ifaceName: %+v", c)
			}
			clientIfaces[c.ifaceName] = true
		} else {
			serverListeners++
			// #2888: the server conn must bind giaddr:67 (BOOTPS) so a strict
			// server's reply to giaddr:67 is received, and must set reusePort so
			// the :67 bind coexists with the client listener's 0.0.0.0:67.
			if c.bindAddr.Port != relayPort {
				t.Errorf("server conn must bind :67 (BOOTPS), got %+v", c)
			}
			if !c.reusePort {
				t.Errorf("server conn must set reusePort to coexist on :67: %+v", c)
			}
			if c.ifaceName != "" {
				t.Errorf("server conn must NOT set BINDTODEVICE: %+v", c)
			}
		}
	}
	if clientListeners != 2 {
		t.Errorf("expected 2 client listeners, got %d", clientListeners)
	}
	if serverListeners != 2 {
		t.Errorf("expected 2 server conns, got %d", serverListeners)
	}
	if len(clientIfaces) != 2 {
		t.Errorf("expected 2 distinct client ifaceNames, got %v", clientIfaces)
	}
}

// TestServerConn_BindsGiaddrBOOTPS is the #2888 fail-on-revert guard. RFC 2131
// §4.1 specifies a server unicasts its reply back to the relay agent at
// giaddr:67 (BOOTPS), NOT the relay's source port. If the server-facing socket
// binds an ephemeral port (giaddr:0) — the pre-#2888 behavior — a strict
// server's reply to giaddr:67 has no listener and is dropped, so a relayed
// lease never completes.
//
// This test asserts, by construction, that the server conn binds to the resolved
// giaddr on PORT 67. Reverting the bind to Port:0 (ephemeral) makes the
// `Port != relayPort` assertion fail RED. It also pins the reusePort=true
// requirement, since giaddr:67 must coexist with the client listener's
// 0.0.0.0:67 (without SO_REUSEADDR/SO_REUSEPORT the second :67 bind would
// EADDRINUSE in production).
func TestServerConn_BindsGiaddrBOOTPS(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)
	defer m.Stop()

	// testManager's resolver returns 10.0.0.254 as the giaddr.
	wantGIAddr := net.IPv4(10, 0, 0, 254)

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	calls := waitCalls(t, getCalls, 2, 2*time.Second) // client + server conn

	var serverCalls int
	for _, c := range calls {
		// The server conn binds the specific giaddr; the client listener binds
		// the 0.0.0.0 wildcard.
		if c.bindAddr.IP.Equal(net.IPv4zero) {
			continue
		}
		serverCalls++
		if !c.bindAddr.IP.Equal(wantGIAddr) {
			t.Errorf("server conn must bind the resolved giaddr %v, got %v",
				wantGIAddr, c.bindAddr.IP)
		}
		// FAIL-ON-REVERT: the server-facing socket MUST bind BOOTPS (67), not an
		// ephemeral port (0). Reverting to Port:0 turns this RED.
		if c.bindAddr.Port != relayPort {
			t.Errorf("server conn must bind giaddr:%d (BOOTPS) so a strict "+
				"server's reply to giaddr:67 is received (#2888), got port %d: %+v",
				relayPort, c.bindAddr.Port, c)
		}
		// giaddr:67 must coexist with the client listener's 0.0.0.0:67.
		if !c.reusePort {
			t.Errorf("server conn must set SO_REUSEADDR/SO_REUSEPORT to coexist "+
				"with the client listener on :67 (#2888): %+v", c)
		}
		if c.broadcast {
			t.Errorf("server conn must not set SO_BROADCAST (server replies are unicast): %+v", c)
		}
		if c.ifaceName != "" {
			t.Errorf("server conn must NOT set BINDTODEVICE: %+v", c)
		}
	}
	if serverCalls != 1 {
		t.Fatalf("expected exactly 1 server conn (non-wildcard bind), got %d: %+v",
			serverCalls, calls)
	}
}

// TestStop_BoundedNoPackets starts a relay whose fake conns block in ReadFrom
// and asserts Stop() returns promptly (close-on-cancel unblocks the reads).
func TestStop_BoundedNoPackets(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second) // both conns created

	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return within 2s — blocking ReadFrom not unblocked")
	}
	if !client.isClosed() || !server.isClosed() {
		t.Error("both conns must be closed after Stop()")
	}
}

// TestApply_Reapply_DoesNotHang calls Apply twice; the second Stops gen-1 and
// must return bounded with gen-1 conns closed.
// TestApply_Reapply_Idempotent proves that re-applying the SAME config does
// NOT churn a healthy relay (#2348): Apply now diffs desired-vs-running per
// interface, so an unchanged interface keeps its existing session — the gen-1
// conns stay OPEN and the factory is not called a second time. (Pre-#2348 Apply
// tore everything down and rebuilt on every call, dropping every relay even
// when nothing changed.) The re-Apply must also return promptly (no hang).
func TestApply_Reapply_Idempotent(t *testing.T) {
	gen1Client := newFakeConn()
	gen1Server := newFakeConn()
	factory, getCalls := recordingFactory(gen1Client, gen1Server)
	m := testManager(factory)
	defer m.Stop()

	cfg := singleInterfaceConfig()
	m.Apply(context.Background(), cfg)
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	done := make(chan struct{})
	go func() { m.Apply(context.Background(), cfg); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("second Apply() hung")
	}

	// No churn: the unchanged relay keeps its gen-1 conns and the factory is
	// not re-invoked. Give any (erroneous) restart a brief window to manifest.
	time.Sleep(50 * time.Millisecond)
	if gen1Client.isClosed() || gen1Server.isClosed() {
		t.Error("idempotent re-apply must NOT close gen-1 conns (no churn)")
	}
	if got := len(getCalls()); got != 2 {
		t.Errorf("idempotent re-apply must not reopen sockets: factory calls = %d, want 2", got)
	}
	if n := len(m.Stats()); n != 1 {
		t.Errorf("relay count after idempotent re-apply = %d, want 1", n)
	}
}

// TestApply_AddInterface_DayTwo proves a relay group added on a day-2 commit
// starts its listener (#2348): a first Apply with one interface, then a second
// Apply with two interfaces, must leave the original relay running AND start a
// listener for the newly added interface. Fails (only one relay) if Apply does
// not start the added interface.
func TestApply_AddInterface_DayTwo(t *testing.T) {
	factory, _ := recordingFactory()
	m := testManager(factory)
	defer m.Stop()

	m.Apply(context.Background(), relayConfig([]string{"192.0.2.1"}, false, "ge-0-0-0"))
	waitRelays(t, m, 1, 2*time.Second)

	m.Apply(context.Background(), relayConfig([]string{"192.0.2.1"}, false, "ge-0-0-0", "ge-0-0-1"))
	waitRelays(t, m, 2, 2*time.Second)

	ifaces := statsIfaces(m)
	if !ifaces["ge-0-0-0"] || !ifaces["ge-0-0-1"] {
		t.Errorf("day-2 add must run both interfaces, got %v", ifaces)
	}
}

// TestApply_RemoveInterface_StopsRelay proves a relay whose interface is no
// longer in the config is stopped on the next Apply (#2348), and that the stop
// is BOUNDED (reuses the ir.cancel()+<-ir.done teardown — Apply returns
// promptly even though the removed relay's conns block in ReadFrom). The
// remaining interface's relay stays up and its conns stay open (no collateral
// churn).
func TestApply_RemoveInterface_StopsRelay(t *testing.T) {
	// Conns are handed out sequentially: iface order in the desired map is
	// non-deterministic, so use blocking fakes for all four and assert via
	// Stats() + total-closed accounting rather than a specific conn.
	factory, _ := recordingFactory()
	m := testManager(factory)
	defer m.Stop()

	m.Apply(context.Background(), relayConfig([]string{"192.0.2.1"}, false, "ge-0-0-0", "ge-0-0-1"))
	waitRelays(t, m, 2, 2*time.Second)

	done := make(chan struct{})
	go func() {
		m.Apply(context.Background(), relayConfig([]string{"192.0.2.1"}, false, "ge-0-0-0"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Apply removing an interface hung — bounded Stop teardown not reused")
	}

	// Give the removed relay's teardown a beat, then assert exactly the kept
	// interface remains.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(m.Stats()) == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	ifaces := statsIfaces(m)
	if len(ifaces) != 1 || !ifaces["ge-0-0-0"] {
		t.Errorf("after removing ge-0-0-1, expected only ge-0-0-0, got %v", ifaces)
	}
}

// TestApply_NilConfig_StopsAll proves that applying a nil relay config (the
// `forwarding-options dhcp-relay` block deleted on a day-2 commit) stops every
// running relay (#2348). Bounded (the blocking fake conns must not hang Apply).
func TestApply_NilConfig_StopsAll(t *testing.T) {
	factory, _ := recordingFactory()
	m := testManager(factory)
	defer m.Stop()

	m.Apply(context.Background(), twoInterfaceConfig())
	waitRelays(t, m, 2, 2*time.Second)

	done := make(chan struct{})
	go func() { m.Apply(context.Background(), nil); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Apply(nil) hung")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(m.Stats()) == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if n := len(m.Stats()); n != 0 {
		t.Errorf("Apply(nil) must stop all relays, %d still running", n)
	}
}

// TestApply_ChangedServers_Restarts proves a group whose server set changed on
// a day-2 commit is RESTARTED (#2348): the old session is torn down (its conns
// closed) and a fresh listener is opened. The interface count is unchanged, but
// the gen-1 conns must be closed (restart) — distinguishing a restart from the
// idempotent no-churn path.
func TestApply_ChangedServers_Restarts(t *testing.T) {
	gen1Client := newFakeConn()
	gen1Server := newFakeConn()
	factory, getCalls := recordingFactory(gen1Client, gen1Server)
	m := testManager(factory)
	defer m.Stop()

	m.Apply(context.Background(), relayConfig([]string{"192.0.2.1"}, false, "ge-0-0-0"))
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	// Change the server set: must restart the relay.
	m.Apply(context.Background(), relayConfig([]string{"192.0.2.99"}, false, "ge-0-0-0"))

	// The gen-1 conns must close (old session torn down).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if gen1Client.isClosed() && gen1Server.isClosed() {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !gen1Client.isClosed() || !gen1Server.isClosed() {
		t.Error("server-set change must tear down the old session (gen-1 conns closed)")
	}
	// A fresh listener (2 more factory calls) opens for the new spec, and the
	// relay stays present.
	waitCalls(t, getCalls, 4, 2*time.Second)
	if n := len(m.Stats()); n != 1 {
		t.Errorf("relay count after server change = %d, want 1", n)
	}
}

// TestApply_ChangedBroadcast_Restarts proves a group whose always-broadcast
// flag flipped is restarted (#2348) — the spec equality must include
// alwaysBroadcast, not just the server set.
func TestApply_ChangedBroadcast_Restarts(t *testing.T) {
	gen1Client := newFakeConn()
	gen1Server := newFakeConn()
	factory, getCalls := recordingFactory(gen1Client, gen1Server)
	m := testManager(factory)
	defer m.Stop()

	m.Apply(context.Background(), relayConfig([]string{"192.0.2.1"}, false, "ge-0-0-0"))
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	m.Apply(context.Background(), relayConfig([]string{"192.0.2.1"}, true, "ge-0-0-0"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if gen1Client.isClosed() && gen1Server.isClosed() {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !gen1Client.isClosed() || !gen1Server.isClosed() {
		t.Error("always-broadcast flip must restart the relay (gen-1 conns closed)")
	}
	waitCalls(t, getCalls, 4, 2*time.Second)
	if n := len(m.Stats()); n != 1 {
		t.Errorf("relay count after broadcast flip = %d, want 1", n)
	}
}

// TestServerGoroutine_Joined asserts the response goroutine's serverConn is
// closed (and thus the goroutine returned) after Stop — proving the WaitGroup
// join completes (Stop would hang if the join did not).
func TestServerGoroutine_Joined(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	m.Stop() // would hang here if the join did not complete
	if !server.isClosed() {
		t.Error("server conn must be closed (response goroutine joined)")
	}
}

// TestRunRelay_StartupRetry injects a resolver that fails the first K calls
// (covering BOTH the interface-missing and address-missing cases) and asserts
// the relay does not die: it eventually creates sockets. Stop then returns.
func TestRunRelay_StartupRetry(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)

	const k = 3
	var attempts atomic.Int64
	m.resolveGIAddr = func(ifaceName string) (net.IP, error) {
		n := attempts.Add(1)
		if n <= k {
			if n == 1 {
				return nil, errors.New("interface lookup: not found") // interface missing
			}
			return nil, errors.New("no IPv4 address") // address missing
		}
		return net.IPv4(10, 0, 0, 254), nil
	}

	m.Apply(context.Background(), singleInterfaceConfig())

	calls := waitCalls(t, getCalls, 2, 2*time.Second)
	if len(calls) < 2 {
		t.Fatalf("relay died during retry: only %d factory calls (attempts=%d)", len(calls), attempts.Load())
	}
	if attempts.Load() <= k {
		t.Errorf("expected resolver retried past %d attempts, got %d", k, attempts.Load())
	}

	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return")
	}
}

// TestRunRelay_StopDuringRetry cancels while the resolver is still failing;
// Stop must return promptly (the retry select is ctx-cancelable) and no
// sockets are created.
func TestRunRelay_StopDuringRetry(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)
	m.retryInterval = 50 * time.Millisecond
	m.resolveGIAddr = func(ifaceName string) (net.IP, error) {
		return nil, errors.New("never ready")
	}

	m.Apply(context.Background(), singleInterfaceConfig())
	time.Sleep(20 * time.Millisecond)

	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() during retry did not return promptly")
	}
	if got := len(getCalls()); got != 0 {
		t.Errorf("no sockets should be created during failing retry, got %d calls", got)
	}
}

// TestRunRelay_BindFailureRetries injects a packetConnFactory that fails the
// first K bind attempts with a transient error, then succeeds. It proves the
// per-interface supervisor does NOT die on a transient bind/listen failure
// (#2787): it keeps retrying and eventually binds. This is a fail-on-revert
// test — reverting runRelaySession to `return false`/`return sessionStop` on a
// listen error makes the supervisor exit on the first failure, so the client
// conn is never created and waitCalls below times out (RED).
func TestRunRelay_BindFailureRetries(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()

	const k = 3
	var mu sync.Mutex
	var calls []factoryCall
	attempts := 0
	factory := func(ctx context.Context, ifaceName string, reusePort, broadcast bool,
		bindAddr *net.UDPAddr) (net.PacketConn, error) {
		mu.Lock()
		defer mu.Unlock()
		// Only the client-facing listener (reusePort+broadcast on the iface)
		// is failed; once it binds, hand out the recorded conns in order.
		if reusePort && broadcast {
			attempts++
			if attempts <= k {
				return nil, errors.New("listen udp 0.0.0.0:67: bind: cannot assign requested address")
			}
			calls = append(calls, factoryCall{ifaceName, reusePort, broadcast, bindAddr})
			return client, nil
		}
		calls = append(calls, factoryCall{ifaceName, reusePort, broadcast, bindAddr})
		return server, nil
	}
	getCalls := func() []factoryCall {
		mu.Lock()
		defer mu.Unlock()
		out := make([]factoryCall, len(calls))
		copy(out, calls)
		return out
	}

	m := testManager(factory)
	m.retryInterval = 5 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())

	// The supervisor must survive the K failures and bind both conns. With a
	// terminal `return sessionStop` on listen failure this never reaches 2
	// (the supervisor dies after the first failed bind) and times out.
	calls2 := waitCalls(t, getCalls, 2, 2*time.Second)
	if len(calls2) < 2 {
		t.Fatalf("supervisor died on transient bind failure: only %d successful "+
			"factory calls (attempts=%d) — relay never recovered", len(calls2), attempts)
	}
	mu.Lock()
	gotAttempts := attempts
	mu.Unlock()
	if gotAttempts <= k {
		t.Errorf("expected listener bind retried past %d failures, got %d attempts", k, gotAttempts)
	}

	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return after bind-retry recovery")
	}
}

// TestRunRelay_StopDuringBindRetry cancels while the bind is still failing;
// Stop must return promptly (the supervisor's retry select is ctx-cancelable,
// #2787) and the relay never binds a client conn.
func TestRunRelay_StopDuringBindRetry(t *testing.T) {
	var mu sync.Mutex
	clientBinds := 0
	factory := func(ctx context.Context, ifaceName string, reusePort, broadcast bool,
		bindAddr *net.UDPAddr) (net.PacketConn, error) {
		mu.Lock()
		defer mu.Unlock()
		if reusePort && broadcast {
			clientBinds++
		}
		return nil, errors.New("bind: cannot assign requested address")
	}
	m := testManager(factory)
	m.retryInterval = 50 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())
	time.Sleep(20 * time.Millisecond)

	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() during bind retry did not return promptly")
	}
	mu.Lock()
	got := clientBinds
	mu.Unlock()
	if got == 0 {
		t.Error("expected at least one client bind attempt during the failing retry window")
	}
}

// TestRunRelay_OneSidedExitNoHang makes the response goroutine's serverConn
// return ErrClosed while ctx is NOT cancelled. Per the cross-cancellation
// design the response loop returns -> defer cancel() fires -> watcher closes
// both conns -> the main loop returns -> runRelay completes.
func TestRunRelay_OneSidedExitNoHang(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	server.mu.Lock()
	server.readErr = net.ErrClosed // one-sided exit, no ctx cancel
	server.mu.Unlock()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)

	m.Apply(context.Background(), singleInterfaceConfig())

	// The relay self-terminates via cross-cancellation: the response loop's
	// cancel drives the watcher to close the client conn, which unblocks the
	// main loop. Wait for the client conn to be closed.
	deadline := time.Now().Add(2 * time.Second)
	for !client.isClosed() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !client.isClosed() {
		t.Fatal("one-sided response-loop exit did not cross-cancel + close the client conn")
	}

	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() hung after one-sided exit")
	}
}

// TestRunRelay_ClosedNoSpin closes the client conn while ctx is not cancelled;
// the main loop must return (not hot-spin on ErrClosed). Bound the ReadFrom
// call count after the close.
func TestRunRelay_ClosedNoSpin(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	client.Close() // external close, ctx still alive
	time.Sleep(100 * time.Millisecond)
	before := client.readCalls.Load()
	time.Sleep(200 * time.Millisecond)
	after := client.readCalls.Load()
	if after-before > 1 {
		t.Errorf("main loop hot-spun on ErrClosed: %d extra ReadFrom calls", after-before)
	}

	m.Stop()
}

// --- #2076 lifecycle / fail-soft tests ---

// countingL2Factory returns an l2SenderFactory that records open attempts and
// returns the supplied sender (or error).
func countingL2Factory(s l2Replier, err error) (l2SenderFactory, func() int) {
	var mu sync.Mutex
	var opens int
	f := func(ifaceName string) (l2Replier, error) {
		mu.Lock()
		opens++
		mu.Unlock()
		if err != nil {
			return nil, err
		}
		return s, nil
	}
	getter := func() int {
		mu.Lock()
		defer mu.Unlock()
		return opens
	}
	return f, getter
}

// TestRunRelay_L2OpenFailure_RelayStaysUp proves that an L2 open failure (e.g.
// no CAP_NET_RAW) is fail-soft: the relay still creates its UDP sockets and
// Stop returns. runRelay must NOT return early on L2 open error (#2076 §7.3).
func TestRunRelay_L2OpenFailure_RelayStaysUp(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)
	l2f, getOpens := countingL2Factory(nil, errors.New("EPERM: no CAP_NET_RAW"))
	m.newL2 = l2f

	m.Apply(context.Background(), singleInterfaceConfig())
	calls := waitCalls(t, getCalls, 2, 2*time.Second)
	if len(calls) < 2 {
		t.Fatalf("relay died on L2 open failure: only %d UDP conns", len(calls))
	}
	if getOpens() == 0 {
		t.Errorf("expected at least one L2 open attempt")
	}

	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return after L2 open failure")
	}
}

// TestRunRelay_AlwaysBroadcast_SkipsL2Open proves that when overrides
// always-broadcast is set, the relay never opens the L2 socket (#2076 §7.1:
// override wins before the L2 path is even considered).
func TestRunRelay_AlwaysBroadcast_SkipsL2Open(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)
	l2f, getOpens := countingL2Factory(&fakeL2{}, nil)
	m.newL2 = l2f

	cfg := singleInterfaceConfig()
	cfg.Groups["g"].AlwaysBroadcast = true
	m.Apply(context.Background(), cfg)
	waitCalls(t, getCalls, 2, 2*time.Second)

	// Give runRelay a beat to reach (and skip) the L2 open.
	time.Sleep(50 * time.Millisecond)
	if getOpens() != 0 {
		t.Errorf("always-broadcast must NOT open the L2 socket, got %d opens", getOpens())
	}
	m.Stop()
}

// TestRunRelay_L2Closed_AfterStop proves the L2 sender is closed (exactly once)
// when the relay stops — closure happens after wg.Wait() (#2076 §7.3).
func TestRunRelay_L2Closed_AfterStop(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)
	fl2 := &fakeL2{}
	l2f, _ := countingL2Factory(fl2, nil)
	m.newL2 = l2f

	m.Apply(context.Background(), singleInterfaceConfig())
	waitCalls(t, getCalls, 2, 2*time.Second)
	m.Stop()

	fl2.mu.Lock()
	cc := fl2.closeCount
	fl2.mu.Unlock()
	if cc != 1 {
		t.Errorf("L2 sender Close count = %d, want exactly 1", cc)
	}
}

// TestL2Sender_CloseIdempotent proves the real *l2Sender Close is idempotent
// (sync.Once). It uses a sentinel fd; the second Close must be a no-op even
// though the fd was already closed.
func TestL2Sender_CloseIdempotent(t *testing.T) {
	// A nil *l2Sender Close must be safe.
	var nilSender *l2Sender
	if err := nilSender.Close(); err != nil {
		t.Errorf("nil l2Sender.Close() = %v, want nil", err)
	}

	// Use a real, closeable fd (a pipe read end) to prove Close idempotency
	// without a NIC. The first Close closes it; the second must be a no-op
	// (sync.Once), NOT a double-close EBADF.
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		t.Skipf("pipe unavailable: %v", err)
	}
	_ = unix.Close(p[1]) // close the unused write end
	s := &l2Sender{fd: p[0], ifaceName: "test"}
	if err := s.Close(); err != nil {
		t.Errorf("first Close = %v, want nil", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close = %v, want nil (idempotent)", err)
	}
}

// --- #2347 ifindex-drift detection ---

// driftResolver returns an ifindexResolver backed by an atomic value (so a test
// can flip the live ifindex mid-flight) plus an atomic error toggle (so a test
// can simulate a transient resolve failure). It also counts calls.
func driftResolver(initial int) (ifindexResolver, *atomic.Int64, *atomic.Bool, *atomic.Int64) {
	idx := &atomic.Int64{}
	idx.Store(int64(initial))
	failing := &atomic.Bool{}
	calls := &atomic.Int64{}
	r := func(ifaceName string) (int, error) {
		calls.Add(1)
		if failing.Load() {
			return 0, errors.New("transient resolve failure")
		}
		return int(idx.Load()), nil
	}
	return r, idx, failing, calls
}

// TestRunRelay_IfindexDrift_RebindsListener proves the #2347 fix: when the
// interface's live ifindex changes under unchanged config, the relay tears down
// the stale-bound session and rebinds a fresh client listener to the new
// ifindex. Asserted by construction via the factory call count: the first
// session opens 2 conns (client+server); after drift the supervisor rebuilds,
// opening 2 more — 4 total — and the rebuilt client listener still carries the
// SO_BINDTODEVICE ifaceName invariant.
func TestRunRelay_IfindexDrift_RebindsListener(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)
	defer m.Stop()

	resolve, liveIdx, _, _ := driftResolver(100)
	m.resolveIfindex = resolve
	m.ifindexCheck = 5 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second) // gen-1 client + server

	// Interface deleted+recreated -> new kernel ifindex.
	liveIdx.Store(200)

	// The drift watcher must cancel the session and the supervisor must rebuild,
	// producing 2 more factory calls (gen-2 client + server).
	calls := waitCalls(t, getCalls, 4, 2*time.Second)

	// The rebound client listener (a 0.0.0.0:67 call after the first two) must
	// keep the per-interface SO_BINDTODEVICE ifaceName. Both conns now bind :67
	// (#2888), so classify the client listener by its 0.0.0.0 wildcard bind.
	clientListeners := 0
	for _, c := range calls {
		if c.bindAddr.IP.Equal(net.IPv4zero) {
			clientListeners++
			if c.ifaceName != "ge-0-0-0" {
				t.Errorf("rebound client listener lost BINDTODEVICE ifaceName: %+v", c)
			}
		}
	}
	if clientListeners < 2 {
		t.Errorf("expected >=2 client listeners (original + rebind), got %d", clientListeners)
	}
}

// TestRunRelay_IfindexStable_NoRebind proves idempotency: with the live ifindex
// never changing, the drift watcher fires repeatedly but never restarts the
// session. The factory is called exactly twice (one session) for the lifetime.
func TestRunRelay_IfindexStable_NoRebind(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)
	defer m.Stop()

	resolve, _, _, calls := driftResolver(100)
	m.resolveIfindex = resolve
	m.ifindexCheck = 2 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	// Let the watcher tick many times against a stable ifindex.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && calls.Load() < 10 {
		time.Sleep(2 * time.Millisecond)
	}
	if calls.Load() < 5 {
		t.Fatalf("drift watcher did not run enough to be meaningful (%d resolves)", calls.Load())
	}

	// No rebind: still exactly the original 2 factory calls.
	if got := len(getCalls()); got != 2 {
		t.Errorf("stable ifindex must NOT rebind: got %d factory calls, want 2", got)
	}
}

// TestRunRelay_IfindexResolveFailure_KeepsListener proves the tolerant-resolve
// invariant: a transient ifindex resolve failure must NOT tear down a working
// listener (no rebind, no socket close), mirroring #2294's tolerant probe.
func TestRunRelay_IfindexResolveFailure_KeepsListener(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)
	defer m.Stop()

	resolve, _, failing, calls := driftResolver(100)
	m.resolveIfindex = resolve
	m.ifindexCheck = 2 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	// Resolver now fails on every tick.
	failing.Store(true)

	// Let it fail many times.
	deadline := time.Now().Add(200 * time.Millisecond)
	base := calls.Load()
	for time.Now().Before(deadline) && calls.Load() < base+10 {
		time.Sleep(2 * time.Millisecond)
	}

	// The working session must be intact: no rebind (still 2 factory calls) and
	// the gen-1 conns must NOT be closed.
	if got := len(getCalls()); got != 2 {
		t.Errorf("resolve failure must NOT rebind: got %d factory calls, want 2", got)
	}
	if client.isClosed() || server.isClosed() {
		t.Error("resolve failure must NOT tear down the working listener")
	}
}

// TestRunRelay_IfindexDrift_StopStillBounded proves a #1915 non-regression: even
// after a drift rebind, Stop() returns under a bounded timeout (the supervisor
// observes ctx cancellation and the close-on-cancel + WaitGroup join still
// unblock the rebuilt session's blocking ReadFrom).
func TestRunRelay_IfindexDrift_StopStillBounded(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)
	// Clean up on an early t.Fatal (waitRelays/waitCalls timeout) before the
	// explicit timed Stop below. Stop() is idempotent (it empties m.relays
	// under lock), so the later explicit Stop is unaffected and this defer is
	// a no-op on the happy path — it just prevents leaked relay goroutines
	// from interfering with subsequent tests on an early failure.
	defer m.Stop()

	resolve, liveIdx, _, _ := driftResolver(100)
	m.resolveIfindex = resolve
	m.ifindexCheck = 5 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	liveIdx.Store(200) // force a rebind
	waitCalls(t, getCalls, 4, 2*time.Second)

	done := make(chan struct{})
	go func() { m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() after ifindex-drift rebind did not return within 2s (#1915 regression)")
	}
}

// TestRunRelay_DegradedBaseline_AdoptsFirstRealIfindex proves that a failed
// baseline capture at bind (boundIfindex==0) does NOT cause a spurious rebind:
// the first real resolve is adopted as the baseline, and only a subsequent
// change triggers a rebind.
func TestRunRelay_DegradedBaseline_AdoptsFirstRealIfindex(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)
	defer m.Stop()

	// First resolve (the bind-time baseline capture) fails; later resolves
	// return a stable real index.
	var first atomic.Bool
	first.Store(true)
	m.resolveIfindex = func(ifaceName string) (int, error) {
		if first.Swap(false) {
			return 0, errors.New("baseline capture failed")
		}
		return 300, nil
	}
	m.ifindexCheck = 2 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	// Watcher adopts 300 as baseline then sees 300 forever -> no rebind.
	time.Sleep(150 * time.Millisecond)
	if got := len(getCalls()); got != 2 {
		t.Errorf("degraded baseline must adopt first real ifindex, not rebind: got %d calls, want 2", got)
	}
}

// --- #3960 primary-IPv4 (giaddr) re-resolution ---

// giaddrResolver returns an ifaceResolver backed by an atomic address (so a test
// can readdress the interface mid-flight) plus an atomic error toggle (so a test
// can simulate the interface losing its address). It also counts calls. The
// stored value is always a net.IP, so atomic.Value's same-type rule holds.
func giaddrResolver(initial net.IP) (ifaceResolver, *atomic.Value, *atomic.Bool, *atomic.Int64) {
	addr := &atomic.Value{}
	addr.Store(initial)
	failing := &atomic.Bool{}
	calls := &atomic.Int64{}
	r := func(ifaceName string) (net.IP, error) {
		calls.Add(1)
		if failing.Load() {
			return nil, errors.New("no IPv4 address")
		}
		return addr.Load().(net.IP), nil
	}
	return r, addr, failing, calls
}

// serverConnBinds returns, in factory-call order, the bind IPs of the server
// conns (the non-wildcard binds; the client listener binds 0.0.0.0).
func serverConnBinds(calls []factoryCall) []net.IP {
	var out []net.IP
	for _, c := range calls {
		if !c.bindAddr.IP.Equal(net.IPv4zero) {
			out = append(out, c.bindAddr.IP)
		}
	}
	return out
}

// TestRunRelay_AddressReaddr_RebindsGiaddr proves the #3960 fix: when the relay
// interface's PRIMARY IPv4 changes under a STABLE ifindex (DHCP renew to a new
// IP, static readdress, HA VIP move on the same netdev), the relay tears down
// the session and rebuilds — re-resolving the giaddr so the server conn rebinds
// to the NEW giaddr:67. Asserted via the factory: gen-1 opens 2 conns bound to
// the old giaddr; after readdress the supervisor rebuilds, opening 2 more with
// the server conn bound to the NEW giaddr.
//
// FAIL-ON-REVERT: revert the #3960 re-resolution and the watcher never detects
// the address change → no rebuild → stuck at 2 factory calls → waitCalls times
// out → RED. The server stays bound to the old (now-invalid) giaddr:67 and every
// reply is blackholed.
func TestRunRelay_AddressReaddr_RebindsGiaddr(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)
	defer m.Stop()

	resolve, addr, _, _ := giaddrResolver(net.IPv4(10, 0, 0, 254))
	m.resolveGIAddr = resolve
	m.ifindexCheck = 5 * time.Millisecond // reuse the watcher cadence

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	calls := waitCalls(t, getCalls, 2, 2*time.Second) // gen-1 client + server

	if binds := serverConnBinds(calls); len(binds) != 1 ||
		!binds[0].Equal(net.IPv4(10, 0, 0, 254)) {
		t.Fatalf("gen-1 server conn binds = %v, want [10.0.0.254]", binds)
	}

	// Interface readdressed under the SAME ifindex.
	addr.Store(net.IPv4(10, 0, 0, 99))

	// The readdr watcher must cancel the session and the supervisor rebuild,
	// producing 2 more factory calls (gen-2 client + server).
	calls = waitCalls(t, getCalls, 4, 2*time.Second)

	binds := serverConnBinds(calls)
	if len(binds) < 2 {
		t.Fatalf("expected >=2 server conns (original + rebind), got %d: %v", len(binds), binds)
	}
	if last := binds[len(binds)-1]; !last.Equal(net.IPv4(10, 0, 0, 99)) {
		t.Errorf("rebound server conn bound %v, want the NEW giaddr 10.0.0.99 "+
			"(server replies to giaddr:67 blackhole on the old address, #3960)", last)
	}
}

// TestRunRelay_AddressReaddr_StampsNewGiaddr proves the request-side of the
// #3960 fix end to end: after a same-ifindex readdress the NEXT relayed request
// carries the NEW giaddr (not the stale one the server would reply to and
// blackhole). The gen-2 client conn is seeded with a DHCPREQUEST; the rebuilt
// session relays it stamped with the new address.
func TestRunRelay_AddressReaddr_StampsNewGiaddr(t *testing.T) {
	client1 := newFakeConn()
	server1 := newFakeConn()
	client2 := newFakeConn()
	client2.pending = [][]byte{makeRequest(t)}
	server2 := newFakeConn()
	factory, getCalls := recordingFactory(client1, server1, client2, server2)
	m := testManager(factory)
	defer m.Stop()

	resolve, addr, _, _ := giaddrResolver(net.IPv4(10, 0, 0, 254))
	m.resolveGIAddr = resolve
	m.ifindexCheck = 5 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second) // gen-1 client + server

	// Readdress -> rebuild -> gen-2 relays the seeded request.
	addr.Store(net.IPv4(10, 0, 0, 99))
	waitCalls(t, getCalls, 4, 2*time.Second) // gen-2 client + server

	deadline := time.Now().Add(2 * time.Second)
	for server2.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server2.writeCount() == 0 {
		t.Fatal("gen-2 session did not relay the request after readdress")
	}
	relayed, err := dhcpv4.FromBytes(server2.firstWrite(t))
	if err != nil {
		t.Fatalf("relayed datagram does not parse: %v", err)
	}
	if !relayed.GatewayIPAddr.Equal(net.IPv4(10, 0, 0, 99)) {
		t.Errorf("relayed giaddr = %v, want the NEW 10.0.0.99 "+
			"(stale giaddr -> server reply blackholed, #3960)", relayed.GatewayIPAddr)
	}
}

// TestRunRelay_AddressStable_NoRebind proves idempotency: with the primary IPv4
// never changing, the watcher re-resolves the giaddr repeatedly but never
// restarts the session. The factory is called exactly twice for the lifetime.
func TestRunRelay_AddressStable_NoRebind(t *testing.T) {
	factory, getCalls := recordingFactory()
	m := testManager(factory)
	defer m.Stop()

	resolve, _, _, calls := giaddrResolver(net.IPv4(10, 0, 0, 254))
	m.resolveGIAddr = resolve
	m.ifindexCheck = 2 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	// Let the watcher tick many times against a stable address.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) && calls.Load() < 10 {
		time.Sleep(2 * time.Millisecond)
	}
	if calls.Load() < 5 {
		t.Fatalf("giaddr watcher did not run enough to be meaningful (%d resolves)", calls.Load())
	}
	if got := len(getCalls()); got != 2 {
		t.Errorf("stable address must NOT rebind: got %d factory calls, want 2", got)
	}
}

// TestRunRelay_AddressResolveFailure_KeepsListener proves the tolerant-resolve
// invariant for #3960: a momentarily unaddressed interface (resolver errors "no
// IPv4 address") must NOT tear down a working session (no rebuild, no socket
// close) and must NOT stamp a bogus giaddr — the session keeps its
// last-known-good giaddr until a real new address appears.
func TestRunRelay_AddressResolveFailure_KeepsListener(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, getCalls := recordingFactory(client, server)
	m := testManager(factory)
	defer m.Stop()

	resolve, _, failing, calls := giaddrResolver(net.IPv4(10, 0, 0, 254))
	m.resolveGIAddr = resolve
	m.ifindexCheck = 2 * time.Millisecond

	m.Apply(context.Background(), singleInterfaceConfig())
	waitRelays(t, m, 1, 2*time.Second)
	waitCalls(t, getCalls, 2, 2*time.Second)

	// The interface loses its address on every subsequent re-resolve.
	failing.Store(true)

	deadline := time.Now().Add(200 * time.Millisecond)
	base := calls.Load()
	for time.Now().Before(deadline) && calls.Load() < base+10 {
		time.Sleep(2 * time.Millisecond)
	}

	if got := len(getCalls()); got != 2 {
		t.Errorf("giaddr resolve failure must NOT rebind: got %d factory calls, want 2", got)
	}
	if client.isClosed() || server.isClosed() {
		t.Error("giaddr resolve failure must NOT tear down the working listener")
	}
}

// makeRequest builds a DHCPREQUEST client packet for the master-gate tests.
func makeRequest(t *testing.T) []byte {
	t.Helper()
	req, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	req.OpCode = dhcpv4.OpcodeBootRequest
	req.ClientHWAddr = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x42}
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))
	return req.ToBytes()
}

// runGatedRelay starts a single-interface relay with the supplied master gate,
// feeds it one DHCPREQUEST, waits for the loop to consume it, and returns the
// number of datagrams relayed upstream plus the backup-drop counter.
func runGatedRelay(t *testing.T, gate masterGate) (relayed int, droppedBackup uint64) {
	t.Helper()
	client := newFakeConn()
	client.pending = [][]byte{makeRequest(t)}
	server := newFakeConn()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)
	m.SetMasterGate(gate)

	m.Apply(context.Background(), singleInterfaceConfig())
	defer m.Stop()

	// Wait until the loop has consumed the request (>=2 ReadFrom calls: the
	// first returns the pending datagram, the second blocks).
	deadline := time.Now().Add(2 * time.Second)
	for client.readCalls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	relayed = server.writeCount()
	for _, st := range m.Stats() {
		droppedBackup += st.RequestsDroppedBackup
	}
	return relayed, droppedBackup
}

// TestRunRelay_MasterGate_BackupDrops asserts the #2456 HA gate: a relay on a
// BACKUP node (gate returns false) does NOT forward the client request
// upstream and bumps the backup-drop counter. THIS is the fail-on-revert
// guard — without the gate check in the main loop the backup would relay the
// request and this test goes RED (relayed==1, droppedBackup==0).
func TestRunRelay_MasterGate_BackupDrops(t *testing.T) {
	relayed, dropped := runGatedRelay(t, func(string) bool { return false })
	if relayed != 0 {
		t.Fatalf("backup node relayed %d datagram(s) upstream; want 0 "+
			"(duplicate-relay regression — #2456 gate removed)", relayed)
	}
	if dropped != 1 {
		t.Fatalf("RequestsDroppedBackup = %d, want 1", dropped)
	}
}

// TestRunRelay_MasterGate_MasterRelays asserts a relay on the MASTER node
// (gate returns true) forwards the client request upstream exactly as today.
func TestRunRelay_MasterGate_MasterRelays(t *testing.T) {
	relayed, dropped := runGatedRelay(t, func(string) bool { return true })
	if relayed != 1 {
		t.Fatalf("master node relayed %d datagram(s); want 1", relayed)
	}
	if dropped != 0 {
		t.Fatalf("RequestsDroppedBackup = %d, want 0 on master", dropped)
	}
}

// TestRunRelay_MasterGate_StandaloneRelays asserts the nil-gate default
// (standalone / non-cluster build) always relays — the fail-open behavior.
func TestRunRelay_MasterGate_StandaloneRelays(t *testing.T) {
	relayed, dropped := runGatedRelay(t, nil)
	if relayed != 1 {
		t.Fatalf("standalone (nil gate) relayed %d datagram(s); want 1", relayed)
	}
	if dropped != 0 {
		t.Fatalf("RequestsDroppedBackup = %d, want 0 standalone", dropped)
	}
}

// TestRunRelay_MasterGate_PassesInterfaceName asserts the gate is queried with
// the relay's interface name, so a per-interface (per-RG) decision is possible.
func TestRunRelay_MasterGate_PassesInterfaceName(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	gate := func(iface string) bool {
		mu.Lock()
		seen[iface] = true
		mu.Unlock()
		return true
	}
	if relayed, _ := runGatedRelay(t, gate); relayed != 1 {
		t.Fatalf("relayed %d, want 1", relayed)
	}
	mu.Lock()
	defer mu.Unlock()
	if !seen["ge-0-0-0"] {
		t.Fatalf("gate was not queried with the relay interface name; saw %v", seen)
	}
}

// feedConn is a net.PacketConn whose ReadFrom blocks until a datagram is
// pushed on its channel (or it is closed). Unlike fakeConn's pre-seeded
// pending slice, it lets a test deliver a SECOND datagram after the relay
// loop has already consumed the first and is blocked in ReadFrom — required to
// prove the #2456 gate re-evaluates per packet across a mid-session failover.
type feedConn struct {
	mu      sync.Mutex
	closed  bool
	closeCh chan struct{}
	feed    chan []byte
	writes  int
}

func newFeedConn() *feedConn {
	return &feedConn{closeCh: make(chan struct{}), feed: make(chan []byte, 8)}
}

func (f *feedConn) push(b []byte) { f.feed <- b }

func (f *feedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case d := <-f.feed:
		n := copy(p, d)
		return n, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 68}, nil
	case <-f.closeCh:
		return 0, nil, net.ErrClosed
	}
}

func (f *feedConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, net.ErrClosed
	}
	f.writes++
	return len(p), nil
}

func (f *feedConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return net.ErrClosed
	}
	f.closed = true
	close(f.closeCh)
	return nil
}

func (f *feedConn) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

func (f *feedConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (f *feedConn) SetDeadline(t time.Time) error      { return nil }
func (f *feedConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *feedConn) SetWriteDeadline(t time.Time) error { return nil }

// TestRunRelay_MasterGate_FailoverStartsRelaying asserts the gate is read PER
// PACKET, so a backup that BECOMES master (VRRP failover) starts relaying
// immediately with no relay restart. The gate flips from false→true while the
// relay is running; the first request (gate closed) is dropped, the second
// (gate open, after failover) is relayed.
func TestRunRelay_MasterGate_FailoverStartsRelaying(t *testing.T) {
	var master atomic.Bool // starts false (BACKUP)

	client := newFeedConn()
	server := newFeedConn()
	// The factory hands out the client conn first, then the server conn.
	var fmu sync.Mutex
	idx := 0
	factory := func(_ context.Context, _ string, _, _ bool,
		_ *net.UDPAddr) (net.PacketConn, error) {
		fmu.Lock()
		defer fmu.Unlock()
		idx++
		if idx == 1 {
			return client, nil
		}
		return server, nil
	}
	m := testManager(factory)
	m.SetMasterGate(func(string) bool { return master.Load() })

	m.Apply(context.Background(), singleInterfaceConfig())
	defer m.Stop()

	// First request while BACKUP — must be dropped (no upstream relay).
	client.push(makeRequest(t))
	time.Sleep(50 * time.Millisecond)
	if server.writeCount() != 0 {
		t.Fatalf("backup relayed before failover: %d datagram(s)", server.writeCount())
	}

	// Failover: this node becomes MASTER, then a second request arrives. The
	// SAME running relay session must now forward it (per-packet re-eval).
	master.Store(true)
	client.push(makeRequest(t))

	deadline := time.Now().Add(2 * time.Second)
	for server.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.writeCount() != 1 {
		t.Fatalf("after failover the new master relayed %d datagram(s); want 1 "+
			"(gate must re-evaluate per packet, not cache at startup)", server.writeCount())
	}
}
