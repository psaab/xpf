package dhcprelay

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/net/ipv6"
)

const (
	dhcpv6RelayPort  = 547
	dhcpv6ClientPort = 546
	// RFC 8415 Table 1 sets the DHCPv6 Relay-Forward Hop Count limit to
	// eight; Section 19.1.2 requires discarding a packet at that limit.
	dhcpv6MaxHopCount    = 8
	dhcpv6RelayMulticast = "ff02::1:2"
)

// dhcpV6PacketConn is the client-facing socket surface. The relay must join
// ff02::1:2 on every configured client interface; keeping membership on this
// seam makes that lifecycle observable without requiring CAP_NET_RAW in tests.
type dhcpV6PacketConn interface {
	net.PacketConn
	JoinGroup(*net.Interface, *net.UDPAddr) error
	LeaveGroup(*net.Interface, *net.UDPAddr) error
}

type dhcpV6Sockets struct {
	client       dhcpV6PacketConn
	server       net.PacketConn
	serverShared bool
	iface        *net.Interface
	group        *net.UDPAddr
}

type dhcpV6ReplyTarget struct {
	relay       *dhcpV6Relay
	client      net.PacketConn
	servers     []*net.UDPAddr
	interfaceID []byte
	linkAddr    net.IP
}

type dhcpV6ReplyDispatcher struct {
	mu               sync.Mutex
	server           net.PacketConn
	shared           *dhcpV6SharedPacketConn
	serverCtx        context.Context
	serverCancel     context.CancelFunc
	running          bool
	targets          map[string][]*dhcpV6ReplyTarget
	newServer        func(context.Context) (net.PacketConn, error)
	droppedParse     atomic.Uint64
	droppedEmptyIID  atomic.Uint64
	droppedUnknown   atomic.Uint64
	droppedAmbiguous atomic.Uint64
}

func newDHCPV6ReplyDispatcher() *dhcpV6ReplyDispatcher {
	return &dhcpV6ReplyDispatcher{
		targets:   make(map[string][]*dhcpV6ReplyTarget),
		newServer: defaultDHCPV6ServerFactory,
	}
}

type dhcpV6ReplyDispatcherStats struct {
	parse     uint64
	emptyIID  uint64
	unknown   uint64
	ambiguous uint64
}

func (d *dhcpV6ReplyDispatcher) stats() dhcpV6ReplyDispatcherStats {
	if d == nil {
		return dhcpV6ReplyDispatcherStats{}
	}
	return dhcpV6ReplyDispatcherStats{
		parse:     d.droppedParse.Load(),
		emptyIID:  d.droppedEmptyIID.Load(),
		unknown:   d.droppedUnknown.Load(),
		ambiguous: d.droppedAmbiguous.Load(),
	}
}

type dhcpV6SharedPacketConn struct {
	mu     sync.RWMutex
	conn   net.PacketConn
	closed bool
}

func (c *dhcpV6SharedPacketConn) swap(conn net.PacketConn) {
	c.mu.Lock()
	old := c.conn
	c.conn = conn
	c.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}

func (c *dhcpV6SharedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.RLock()
	conn := c.conn
	closed := c.closed
	c.mu.RUnlock()
	if closed || conn == nil {
		return 0, nil, net.ErrClosed
	}
	return conn.ReadFrom(p)
}

func (c *dhcpV6SharedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.RLock()
	conn := c.conn
	closed := c.closed
	c.mu.RUnlock()
	if closed || conn == nil {
		return 0, net.ErrClosed
	}
	return conn.WriteTo(p, addr)
}

func (c *dhcpV6SharedPacketConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.closed = true
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *dhcpV6SharedPacketConn) LocalAddr() net.Addr {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return &net.UDPAddr{}
	}
	return conn.LocalAddr()
}

func (c *dhcpV6SharedPacketConn) SetDeadline(deadline time.Time) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return net.ErrClosed
	}
	return conn.SetDeadline(deadline)
}

func (c *dhcpV6SharedPacketConn) SetReadDeadline(deadline time.Time) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return net.ErrClosed
	}
	return conn.SetReadDeadline(deadline)
}

func (c *dhcpV6SharedPacketConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return net.ErrClosed
	}
	return conn.SetWriteDeadline(deadline)
}

// dhcpV6ClientSocket combines the ordinary net.PacketConn I/O API with x/net's
// IPv6 multicast membership operations. ipv6.PacketConn has richer ReadFrom
// signatures, so it is deliberately kept as a sidecar rather than replacing
// the PacketConn used by the relay loops.
type dhcpV6ClientSocket struct {
	net.PacketConn
	ipv6 *ipv6.PacketConn
}

func (c *dhcpV6ClientSocket) JoinGroup(iface *net.Interface, group *net.UDPAddr) error {
	return c.ipv6.JoinGroup(iface, group)
}

func (c *dhcpV6ClientSocket) LeaveGroup(iface *net.Interface, group *net.UDPAddr) error {
	return c.ipv6.LeaveGroup(iface, group)
}

type dhcpV6ConnFactory func(context.Context, string, net.IP) (dhcpV6Sockets, error)
type dhcpV6LinkResolver func(string) (net.IP, error)

type dhcpV6RelaySpec struct {
	servers     []string
	kernelName  string
	interfaceID string
}

func (s dhcpV6RelaySpec) equal(other dhcpV6RelaySpec) bool {
	if s.kernelName != other.kernelName || s.interfaceID != other.interfaceID || len(s.servers) != len(other.servers) {
		return false
	}
	for i := range s.servers {
		if s.servers[i] != other.servers[i] {
			return false
		}
	}
	return true
}

type dhcpV6Relay struct {
	ifaceName  string
	kernelName string
	spec       dhcpV6RelaySpec
	cancel     context.CancelFunc
	done       chan struct{}
	linkAddr   net.IP

	// maxPacketRate is the resolved per-interface ingress rate limit in
	// packets per second (#5670, P1-2). The DHCPv6 subset has no
	// `maximum-packet-rate` knob, so this is always the default (100); it is
	// a field rather than a constant so tests drive the bucket without
	// sleeping and a future knob wires through one assignment.
	maxPacketRate int

	// Per-reason counters (P2-5). All atomic: the client and server loops
	// run in separate goroutines and Manager.Stats reads without the
	// manager lock, mirroring interfaceRelay's discipline.
	requestsRelayed          atomic.Uint64
	repliesForwarded         atomic.Uint64
	requestsDroppedBackup    atomic.Uint64
	requestsDroppedRateLimit atomic.Uint64
	requestsDroppedNested    atomic.Uint64
	requestsDroppedParse     atomic.Uint64
	requestsDroppedPort      atomic.Uint64
	requestsDroppedPeer      atomic.Uint64
	requestsDroppedBuild     atomic.Uint64
	repliesDroppedUnknownSrv atomic.Uint64
	repliesDroppedIID        atomic.Uint64
	repliesDroppedParse      atomic.Uint64
	repliesDroppedInvalid    atomic.Uint64
	repliesDroppedNested     atomic.Uint64
}

type dhcpV6DesiredRelay struct {
	ifaceName  string
	kernelName string
	groupName  string
	spec       dhcpV6RelaySpec
	servers    []*net.UDPAddr
}

type dhcpV6Manager struct {
	mu              sync.Mutex
	relays          map[string]*dhcpV6Relay
	newConn         dhcpV6ConnFactory
	resolveLink     dhcpV6LinkResolver
	retryInterval   time.Duration
	replyDispatcher *dhcpV6ReplyDispatcher
	// resolveIfindex + ifindexCheck drive the #2347 drift detector for the
	// SO_BINDTODEVICE-pinned client listener (P2-3). now is the clock seam
	// for the #5670 ingress token bucket (P1-2). All three are seams so
	// tests drive drift, readdress, and refill deterministically.
	resolveIfindex ifindexResolver
	ifindexCheck   time.Duration
	now            func() time.Time
}

func newDHCPV6Manager() *dhcpV6Manager {
	return &dhcpV6Manager{
		relays:          make(map[string]*dhcpV6Relay),
		newConn:         defaultDHCPV6ConnFactory,
		resolveLink:     defaultDHCPV6LinkResolver,
		retryInterval:   startupRetryInterval,
		replyDispatcher: newDHCPV6ReplyDispatcher(),
		resolveIfindex:  defaultIfindexResolver,
		ifindexCheck:    ifindexCheckInterval,
		now:             time.Now,
	}
}

func (m *dhcpV6Manager) replyDispatcherSnapshot() *dhcpV6ReplyDispatcher {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	dispatcher := m.replyDispatcher
	m.mu.Unlock()
	return dispatcher
}

func (m *dhcpV6Manager) apply(ctx context.Context, cfg *config.DHCPRelayV6Config, resolveIfName func(string) string, shouldRelay func(string) bool) {
	if m == nil {
		return
	}
	desired := computeDHCPV6Desired(cfg, resolveIfName)
	m.mu.Lock()
	var stop []*dhcpV6Relay
	for name, relay := range m.relays {
		d, ok := desired[name]
		if !ok || !relay.spec.equal(d.spec) {
			stop = append(stop, relay)
			delete(m.relays, name)
		}
	}
	type startRelay struct {
		desired     dhcpV6DesiredRelay
		relay       *dhcpV6Relay
		ctx         context.Context
		shouldRelay func(string) bool
	}
	var start []startRelay
	for name, d := range desired {
		if _, ok := m.relays[name]; ok {
			continue
		}
		rctx, cancel := context.WithCancel(ctx)
		relay := &dhcpV6Relay{
			ifaceName:     d.ifaceName,
			kernelName:    d.kernelName,
			spec:          d.spec,
			maxPacketRate: defaultMaxPacketRate,
			cancel:        cancel,
			done:          make(chan struct{}),
		}
		m.relays[name] = relay
		start = append(start, startRelay{desired: d, relay: relay, ctx: rctx, shouldRelay: shouldRelay})
	}
	m.mu.Unlock()

	for _, relay := range stop {
		relay.cancel()
		<-relay.done
	}
	for _, s := range start {
		go func(s startRelay) {
			defer func() {
				m.mu.Lock()
				if current := m.relays[s.relay.ifaceName]; current == s.relay {
					delete(m.relays, s.relay.ifaceName)
				}
				m.mu.Unlock()
				close(s.relay.done)
			}()
			m.run(s.relay, s.ctx, s.desired.servers, s.shouldRelay)
		}(s)
		slog.Info("dhcpv6-relay: started", "interface", s.desired.ifaceName,
			"group", s.desired.groupName, "servers", s.desired.spec.servers)
	}
}

func (m *dhcpV6Manager) stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	all := make([]*dhcpV6Relay, 0, len(m.relays))
	for name, relay := range m.relays {
		all = append(all, relay)
		delete(m.relays, name)
	}
	m.mu.Unlock()
	for _, relay := range all {
		relay.cancel()
		<-relay.done
	}
}

func computeDHCPV6Desired(cfg *config.DHCPRelayV6Config, resolveIfName func(string) string) map[string]dhcpV6DesiredRelay {
	desired := make(map[string]dhcpV6DesiredRelay)
	if cfg == nil {
		return desired
	}
	if resolveIfName == nil {
		resolveIfName = func(name string) string { return name }
	}
	groupNames := make([]string, 0, len(cfg.Groups))
	for name := range cfg.Groups {
		groupNames = append(groupNames, name)
	}
	sort.Strings(groupNames)
	for _, groupName := range groupNames {
		group := cfg.Groups[groupName]
		if group == nil {
			continue
		}
		serverGroupName := group.ActiveServerGroup
		if serverGroupName == "" {
			serverGroupName = cfg.ActiveServerGroup
		}
		serverGroup := cfg.ServerGroups[serverGroupName]
		if serverGroup == nil {
			continue
		}
		var servers []*net.UDPAddr
		var serverStrings []string
		for _, raw := range serverGroup.Servers {
			ip := net.ParseIP(raw)
			if ip == nil || ip.To4() != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			serverStrings = append(serverStrings, raw)
			servers = append(servers, &net.UDPAddr{IP: ip, Port: dhcpv6RelayPort})
		}
		if len(servers) == 0 {
			continue
		}
		for _, ifaceName := range group.Interfaces {
			if _, exists := desired[ifaceName]; exists {
				continue
			}
			kernelName := resolveIfName(ifaceName)
			interfaceID := cfg.InterfaceIDOverride
			if group.InterfaceIDOverrideSet || group.InterfaceIDOverride != "" {
				interfaceID = group.InterfaceIDOverride
			}
			desired[ifaceName] = dhcpV6DesiredRelay{
				ifaceName:  ifaceName,
				kernelName: kernelName,
				groupName:  group.Name,
				spec: dhcpV6RelaySpec{
					servers:     serverStrings,
					kernelName:  kernelName,
					interfaceID: interfaceID,
				},
				servers: servers,
			}
		}
	}
	return desired
}

func defaultDHCPV6ConnFactory(ctx context.Context, ifaceName string, linkAddr net.IP) (dhcpV6Sockets, error) {
	clientListen := dhcpV6ListenConfig(ifaceName)
	clientRaw, err := clientListen.ListenPacket(ctx, "udp6", "[::]:547")
	if err != nil {
		return dhcpV6Sockets{}, err
	}
	udpClient, ok := clientRaw.(*net.UDPConn)
	if !ok {
		_ = clientRaw.Close()
		return dhcpV6Sockets{}, fmt.Errorf("DHCPv6 relay requires UDPConn, got %T", clientRaw)
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		_ = udpClient.Close()
		return dhcpV6Sockets{}, err
	}
	client := &dhcpV6ClientSocket{PacketConn: udpClient, ipv6: ipv6.NewPacketConn(udpClient)}
	group := &net.UDPAddr{IP: net.ParseIP(dhcpv6RelayMulticast)}
	if err := client.JoinGroup(iface, group); err != nil {
		_ = client.Close()
		return dhcpV6Sockets{}, fmt.Errorf("join DHCPv6 relay multicast group: %w", err)
	}
	if linkAddr != nil && linkAddr.IsLinkLocalUnicast() {
		// Link-local relays use the manager's centralized route-selected
		// receive socket so Interface-ID, not SO_REUSEPORT, chooses the relay.
		return dhcpV6Sockets{client: client, serverShared: true, iface: iface, group: group}, nil
	}
	serverListen := dhcpV6ListenConfig("")
	serverAddr := dhcpV6UpstreamBindAddr(linkAddr, "", dhcpv6RelayPort)
	server, err := serverListen.ListenPacket(ctx, "udp6", serverAddr)
	if err != nil {
		_ = client.LeaveGroup(iface, group)
		_ = client.Close()
		return dhcpV6Sockets{}, err
	}
	return dhcpV6Sockets{client: client, server: server, iface: iface, group: group}, nil
}

func dhcpV6UpstreamBindAddr(linkAddr net.IP, _ string, port int) string {
	if linkAddr != nil && linkAddr.To16() != nil && linkAddr.To4() == nil && !linkAddr.IsUnspecified() && !linkAddr.IsMulticast() && !linkAddr.IsLoopback() && !linkAddr.IsLinkLocalUnicast() && linkAddr.IsGlobalUnicast() {
		return (&net.UDPAddr{IP: linkAddr, Port: port}).String()
	}
	return (&net.UDPAddr{IP: net.IPv6unspecified, Port: port}).String()
}

func defaultDHCPV6ServerFactory(ctx context.Context) (net.PacketConn, error) {
	listen := dhcpV6ListenConfig("")
	return listen.ListenPacket(ctx, "udp6",
		dhcpV6UpstreamBindAddr(nil, "", dhcpv6RelayPort))
}

func (d *dhcpV6ReplyDispatcher) register(ctx context.Context, relay *dhcpV6Relay, client net.PacketConn, servers []*net.UDPAddr, interfaceID []byte) (net.PacketConn, func(), error) {
	if d == nil {
		return nil, nil, fmt.Errorf("DHCPv6 reply dispatcher is unavailable")
	}
	target := &dhcpV6ReplyTarget{
		relay:       relay,
		client:      client,
		servers:     append([]*net.UDPAddr(nil), servers...),
		interfaceID: append([]byte(nil), interfaceID...),
	}
	if relay != nil && relay.linkAddr != nil {
		target.linkAddr = append(net.IP(nil), relay.linkAddr.To16()...)
	}
	d.mu.Lock()
	if d.targets == nil {
		d.targets = make(map[string][]*dhcpV6ReplyTarget)
	}
	start := false
	if d.server == nil {
		factory := d.newServer
		if factory == nil {
			factory = defaultDHCPV6ServerFactory
		}
		generationCtx, generationCancel := context.WithCancel(context.Background())
		server, err := factory(ctx)
		if err != nil {
			generationCancel()
			d.mu.Unlock()
			return nil, nil, err
		}
		d.server = server
		d.shared = &dhcpV6SharedPacketConn{conn: server}
		d.serverCtx = generationCtx
		d.serverCancel = generationCancel
		d.running = true
		start = true
	}
	shared := d.shared
	underlying := d.server
	key := string(target.interfaceID)
	d.targets[key] = append(d.targets[key], target)
	d.mu.Unlock()
	if start {
		go d.run(underlying)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			d.unregister(target)
		})
	}
	return shared, release, nil
}

func (d *dhcpV6ReplyDispatcher) unregister(target *dhcpV6ReplyTarget) {
	if d == nil || target == nil {
		return
	}
	var shared *dhcpV6SharedPacketConn
	var serverCancel context.CancelFunc
	d.mu.Lock()
	key := string(target.interfaceID)
	targets := d.targets[key]
	for i, candidate := range targets {
		if candidate == target {
			targets = append(targets[:i], targets[i+1:]...)
			break
		}
	}
	if len(targets) == 0 {
		delete(d.targets, key)
	} else {
		d.targets[key] = targets
	}
	if len(d.targets) == 0 && d.server != nil {
		d.server = nil
		d.running = false
		shared = d.shared
		d.shared = nil
		serverCancel = d.serverCancel
		d.serverCtx = nil
		d.serverCancel = nil
	}
	d.mu.Unlock()
	if serverCancel != nil {
		serverCancel()
	}
	if shared != nil {
		_ = shared.Close()
	}
}

func (d *dhcpV6ReplyDispatcher) restart(failed net.PacketConn) net.PacketConn {
	for {
		d.mu.Lock()
		if d.server != failed {
			d.mu.Unlock()
			return nil
		}
		if len(d.targets) == 0 {
			d.server = nil
			d.running = false
			shared := d.shared
			d.shared = nil
			serverCancel := d.serverCancel
			d.serverCtx = nil
			d.serverCancel = nil
			d.mu.Unlock()
			if serverCancel != nil {
				serverCancel()
			}
			if shared != nil {
				_ = shared.Close()
			}
			return nil
		}
		factory := d.newServer
		if factory == nil {
			factory = defaultDHCPV6ServerFactory
		}
		generationCtx := d.serverCtx
		if generationCtx == nil {
			generationCtx = context.Background()
		}
		if d.shared != nil {
			d.shared.swap(nil)
		}
		d.mu.Unlock()

		server, err := factory(generationCtx)
		if err != nil {
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-generationCtx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			continue
		}

		d.mu.Lock()
		if d.server != failed {
			d.mu.Unlock()
			_ = server.Close()
			return nil
		}
		if len(d.targets) == 0 {
			d.server = nil
			d.running = false
			shared := d.shared
			d.shared = nil
			serverCancel := d.serverCancel
			d.serverCtx = nil
			d.serverCancel = nil
			d.mu.Unlock()
			_ = server.Close()
			if serverCancel != nil {
				serverCancel()
			}
			if shared != nil {
				_ = shared.Close()
			}
			return nil
		}
		d.server = server
		if d.shared == nil {
			d.shared = &dhcpV6SharedPacketConn{}
		}
		d.shared.swap(server)
		d.running = true
		d.mu.Unlock()
		return server
	}
}

func (d *dhcpV6ReplyDispatcher) dispatch(packet dhcpv6.DHCPv6, source net.Addr) bool {
	if d == nil {
		return false
	}
	interfaceID := dhcpV6RelayReplyInterfaceID(packet)
	if len(interfaceID) == 0 {
		d.droppedEmptyIID.Add(1)
		return false
	}
	d.mu.Lock()
	targets := d.targets[string(interfaceID)]
	target := dhcpV6ReplyTargetForPacket(packet, targets)
	d.mu.Unlock()
	if target == nil {
		if len(targets) > 1 {
			d.droppedAmbiguous.Add(1)
		} else {
			d.droppedUnknown.Add(1)
		}
		return false
	}
	processDHCPV6ServerPacket(target.relay, target.client, packet, source, target.servers, target.interfaceID)
	return true
}

func (d *dhcpV6ReplyDispatcher) run(server net.PacketConn) {
	buf := make([]byte, readBufSize)
	for {
		n, source, err := server.ReadFrom(buf)
		if err != nil {
			server = d.restart(server)
			if server == nil {
				return
			}
			continue
		}
		packet, err := dhcpv6.FromBytes(buf[:n])
		if err != nil {
			d.droppedParse.Add(1)
			continue
		}
		d.dispatch(packet, source)
	}
}

func dhcpV6ReplyTargetForPacket(packet dhcpv6.DHCPv6, targets []*dhcpV6ReplyTarget) *dhcpV6ReplyTarget {
	if len(targets) == 1 {
		return targets[0]
	}
	outer, ok := packet.(*dhcpv6.RelayMessage)
	if !ok || outer.LinkAddr == nil {
		return nil
	}
	var match *dhcpV6ReplyTarget
	for _, target := range targets {
		if target == nil || target.linkAddr == nil || !target.linkAddr.Equal(outer.LinkAddr) {
			continue
		}
		if match != nil {
			return nil
		}
		match = target
	}
	return match
}

func dhcpV6RelayReplyInterfaceID(packet dhcpv6.DHCPv6) []byte {
	relay, ok := packet.(*dhcpv6.RelayMessage)
	if !ok || relay.Type() != dhcpv6.MessageTypeRelayReply {
		return nil
	}
	return relay.Options.InterfaceID()
}

func dhcpV6ListenConfig(ifaceName string) net.ListenConfig {
	return net.ListenConfig{Control: func(network, address string, raw syscall.RawConn) error {
		var controlErr error
		if err := raw.Control(func(fd uintptr) {
			if err := setReusePort(fd); err != nil {
				controlErr = err
				return
			}
			if ifaceName != "" {
				controlErr = setBindToDevice(fd, ifaceName)
			}
		}); err != nil {
			return err
		}
		return controlErr
	}}
}

func defaultDHCPV6LinkResolver(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		if ip != nil {
			ips = append(ips, ip)
		}
	}
	return selectDHCPv6LinkAddress(ips)
}

// selectDHCPv6LinkAddress chooses an address usable as Relay-Forw
// link-address. RFC 8415 uses this field to identify the client link to the
// server. The first global unicast address (GUA or ULA) remains preferred;
// a link-local address is retained as a fallback for link-local-only links.
func selectDHCPv6LinkAddress(addrs []net.IP) (net.IP, error) {
	var linkLocal net.IP
	for _, ip := range addrs {
		if ip == nil || ip.To4() != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
			continue
		}
		if ip.IsLinkLocalUnicast() {
			if linkLocal == nil {
				linkLocal = append(net.IP(nil), ip.To16()...)
			}
			continue
		}
		if !ip.IsGlobalUnicast() {
			continue
		}
		return append(net.IP(nil), ip.To16()...), nil
	}
	if linkLocal != nil {
		return linkLocal, nil
	}
	return nil, fmt.Errorf("no usable IPv6 link-address")
}

func effectiveDHCPv6InterfaceID(override, authoredInterface string) []byte {
	if override != "" {
		return []byte(override)
	}
	return []byte(authoredInterface)
}

// relayForwardV6LinkAddress follows RFC 8415 §19.1.2 for a nested
// Relay-Forw. A downstream relay's global or ULA source identifies the link
// itself, so the new outer layer carries an unspecified link-address. A
// client or link-local downstream relay still needs the receiving interface's
// selected link-address for server link selection.
func relayForwardV6LinkAddress(interfaceLink, source net.IP, nested bool) net.IP {
	if nested && source != nil && source.IsGlobalUnicast() && !source.IsLinkLocalUnicast() {
		return net.IPv6unspecified
	}
	return interfaceLink
}
func validateRelayForwardChainV6(msg dhcpv6.DHCPv6) error {
	for depth := 0; msg != nil && msg.IsRelay(); depth++ {
		if depth >= dhcpv6MaxHopCount {
			return fmt.Errorf("DHCPv6 Relay-Forw encapsulation chain is too deep")
		}
		relay, ok := msg.(*dhcpv6.RelayMessage)
		if !ok || relay.Type() != dhcpv6.MessageTypeRelayForward {
			return fmt.Errorf("DHCPv6 Relay-Forw contains an unexpected relay type")
		}
		if relay.HopCount >= dhcpv6MaxHopCount {
			return fmt.Errorf("DHCPv6 Relay-Forw hop-count limit reached")
		}
		if relay.Options.RelayMessage() == nil {
			return fmt.Errorf("DHCPv6 Relay-Forw has no Relay Message option")
		}
		msg = relay.Options.RelayMessage()
	}
	if msg == nil || msg.Type() == dhcpv6.MessageTypeRelayReply {
		return fmt.Errorf("DHCPv6 Relay-Forw has invalid inner message")
	}
	return nil
}

func validateRelayReplyChainV6(msg dhcpv6.DHCPv6) error {
	for depth := 0; msg != nil && msg.IsRelay(); depth++ {
		if depth >= dhcpv6MaxHopCount {
			return fmt.Errorf("DHCPv6 Relay-Reply encapsulation chain is too deep")
		}
		relay, ok := msg.(*dhcpv6.RelayMessage)
		if !ok || relay.Type() != dhcpv6.MessageTypeRelayReply {
			return fmt.Errorf("DHCPv6 Relay-Reply contains an unexpected relay type")
		}
		if relay.HopCount > dhcpv6MaxHopCount {
			return fmt.Errorf("DHCPv6 Relay-Reply hop-count exceeds %d", dhcpv6MaxHopCount)
		}
		inner := relay.Options.RelayMessage()
		if inner == nil {
			return fmt.Errorf("DHCPv6 Relay-Reply has no Relay Message option")
		}
		msg = inner
	}
	return nil
}

func buildRelayForwardV6(msg dhcpv6.DHCPv6, linkAddr, peerAddr net.IP, interfaceID []byte) (*dhcpv6.RelayMessage, error) {
	if msg == nil {
		return nil, fmt.Errorf("invalid DHCPv6 message for Relay-Forw")
	}
	if err := validateRelayForwardChainV6(msg); err != nil {
		return nil, err
	}
	allowUnspecified := msg.IsRelay()
	if linkAddr == nil || linkAddr.To16() == nil || linkAddr.To4() != nil || (!allowUnspecified && linkAddr.IsUnspecified()) || linkAddr.IsMulticast() {
		return nil, fmt.Errorf("invalid DHCPv6 Relay-Forw link-address")
	}
	if !allowUnspecified && linkAddr.IsLinkLocalUnicast() && len(interfaceID) == 0 {
		return nil, fmt.Errorf("link-local DHCPv6 Relay-Forw requires Interface-ID")
	}
	if allowUnspecified && (linkAddr.To16() == nil || linkAddr.To4() != nil || linkAddr.IsMulticast() || linkAddr.IsLinkLocalUnicast()) {
		return nil, fmt.Errorf("invalid DHCPv6 nested Relay-Forw link-address")
	}
	if peerAddr == nil || peerAddr.To16() == nil || peerAddr.To4() != nil || peerAddr.IsUnspecified() || peerAddr.IsMulticast() {
		return nil, fmt.Errorf("invalid DHCPv6 Relay-Forw peer-address")
	}
	relay, err := dhcpv6.EncapsulateRelay(msg, dhcpv6.MessageTypeRelayForward, linkAddr, peerAddr)
	if err != nil {
		return nil, err
	}
	if relay.HopCount > dhcpv6MaxHopCount {
		return nil, fmt.Errorf("DHCPv6 relay hop-count exceeds %d", dhcpv6MaxHopCount)
	}
	if len(interfaceID) > 0 {
		relay.AddOption(dhcpv6.OptInterfaceID(append([]byte(nil), interfaceID...)))
	}
	return relay, nil
}

// decapsulateRelayReplyV6 removes exactly one Relay-Reply layer. The returned
// destination port is 546 for a client message and 547 for a downstream relay.
func decapsulateRelayReplyV6(packet dhcpv6.DHCPv6, expectedInterfaceID []byte) (dhcpv6.DHCPv6, *net.UDPAddr, error) {
	relay, ok := packet.(*dhcpv6.RelayMessage)
	if !ok || relay.Type() != dhcpv6.MessageTypeRelayReply {
		return nil, nil, fmt.Errorf("packet is not a DHCPv6 Relay-Reply")
	}
	if err := validateRelayReplyChainV6(packet); err != nil {
		return nil, nil, err
	}
	got := relay.Options.InterfaceID()
	if got == nil || !bytes.Equal(got, expectedInterfaceID) {
		return nil, nil, fmt.Errorf("DHCPv6 Relay-Reply missing or mismatched Interface-ID")
	}
	inner := relay.Options.RelayMessage()
	if relay.PeerAddr == nil || relay.PeerAddr.To16() == nil || relay.PeerAddr.To4() != nil || relay.PeerAddr.IsUnspecified() || relay.PeerAddr.IsMulticast() {
		return nil, nil, fmt.Errorf("DHCPv6 Relay-Reply has invalid peer-address")
	}
	peer := append(net.IP(nil), relay.PeerAddr.To16()...)
	port := dhcpv6ClientPort
	if inner.IsRelay() {
		port = dhcpv6RelayPort
	}
	return inner, &net.UDPAddr{IP: peer, Port: port}, nil
}

// run supervises startup separately from an established relay session. Apply
// runs at boot and commit, so a link or address that appears shortly after
// either event must not leave a permanently dead relay in m.relays (#9553).
func (m *dhcpV6Manager) run(relay *dhcpV6Relay, ctx context.Context, servers []*net.UDPAddr, shouldRelay func(string) bool) {
	for {
		if ctx.Err() != nil {
			return
		}
		linkAddr, err := m.resolveLink(relay.kernelName)
		if err != nil {
			slog.Warn("dhcpv6-relay: cannot resolve link-address", "interface", relay.ifaceName, "error", err)
			if !m.waitStartupRetry(ctx) {
				return
			}
			continue
		}
		relay.linkAddr = linkAddr
		sockets, err := m.newConn(ctx, relay.kernelName, linkAddr)
		if err != nil {
			closeDHCPV6Sockets(sockets)
			slog.Warn("dhcpv6-relay: cannot open sockets", "interface", relay.ifaceName, "error", err)
			if !m.waitStartupRetry(ctx) {
				return
			}
			continue
		}
		if sockets.client == nil {
			closeDHCPV6Sockets(sockets)
			slog.Warn("dhcpv6-relay: socket factory returned incomplete sockets", "interface", relay.ifaceName)
			if !m.waitStartupRetry(ctx) {
				return
			}
			continue
		}
		var releaseReplyDispatcher func()
		if sockets.serverShared && sockets.server == nil {
			m.mu.Lock()
			if m.replyDispatcher == nil {
				m.replyDispatcher = newDHCPV6ReplyDispatcher()
			}
			dispatcher := m.replyDispatcher
			m.mu.Unlock()
			server, release, err := dispatcher.register(ctx, relay, sockets.client, servers,
				effectiveDHCPv6InterfaceID(relay.spec.interfaceID, relay.ifaceName))
			if err != nil {
				closeDHCPV6Sockets(sockets)
				slog.Warn("dhcpv6-relay: cannot open shared DHCPv6 server socket", "interface", relay.ifaceName, "error", err)
				if !m.waitStartupRetry(ctx) {
					return
				}
				continue
			}
			sockets.server = server
			sockets.serverShared = true
			releaseReplyDispatcher = release
		}
		if sockets.server == nil {
			closeDHCPV6Sockets(sockets)
			slog.Warn("dhcpv6-relay: socket factory returned incomplete sockets", "interface", relay.ifaceName)
			if !m.waitStartupRetry(ctx) {
				return
			}
			continue
		}
		if sockets.group == nil {
			sockets.group = &net.UDPAddr{IP: net.ParseIP(dhcpv6RelayMulticast)}
		}
		m.runDHCPV6Session(relay, ctx, servers, shouldRelay, sockets)
		if releaseReplyDispatcher != nil {
			releaseReplyDispatcher()
		}
		if !m.waitStartupRetry(ctx) {
			return
		}
	}
}

func (m *dhcpV6Manager) waitStartupRetry(ctx context.Context) bool {
	interval := m.retryInterval
	if interval <= 0 {
		interval = startupRetryInterval
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func closeDHCPV6Sockets(sockets dhcpV6Sockets) {
	if sockets.client != nil {
		if sockets.iface != nil && sockets.group != nil {
			_ = sockets.client.LeaveGroup(sockets.iface, sockets.group)
		}
		_ = sockets.client.Close()
	}
	if sockets.server != nil && !sockets.serverShared {
		_ = sockets.server.Close()
	}
}

func (m *dhcpV6Manager) runDHCPV6Session(relay *dhcpV6Relay, ctx context.Context, servers []*net.UDPAddr, shouldRelay func(string) bool, sockets dhcpV6Sockets) {
	closeDone := make(chan struct{})
	sessionCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-sessionCtx.Done():
			_ = sockets.client.Close()
			if sockets.server != nil && !sockets.serverShared {
				_ = sockets.server.Close()
			}
		case <-closeDone:
		}
	}()
	defer func() {
		cancel()
		close(closeDone)
		closeDHCPV6Sockets(sockets)
	}()
	// The client socket is SO_BINDTODEVICE-pinned. GUA/ULA server sockets keep
	// their exact-IP binds; link-local relays use the shared route-selected
	// server socket and dispatch replies by Interface-ID. Re-resolve the client
	// interface index and selected link identity during a live session; either
	// drift makes this session stale and the supervisor reopens both sockets
	// (#2347/#3960, P2-3).
	var boundIfindex int
	if m.resolveIfindex != nil {
		if idx, err := m.resolveIfindex(relay.kernelName); err == nil && idx != 0 {
			boundIfindex = idx
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	if !sockets.serverShared {
		wg.Add(1)
	}
	if m.ifindexCheck > 0 && (m.resolveIfindex != nil || m.resolveLink != nil) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(m.ifindexCheck)
			defer ticker.Stop()
			for {
				select {
				case <-sessionCtx.Done():
					return
				case <-ticker.C:
					if m.resolveIfindex != nil {
						if idx, err := m.resolveIfindex(relay.kernelName); err == nil && idx != 0 {
							if boundIfindex == 0 {
								boundIfindex = idx
							} else if idx != boundIfindex {
								cancel()
								return
							}
						}
					}
					if m.resolveLink != nil {
						if current, err := m.resolveLink(relay.kernelName); err == nil && !current.Equal(relay.linkAddr) {
							cancel()
							return
						}
					}
				}
			}
		}()
	}
	go func() {
		defer wg.Done()
		defer cancel()
		m.runDHCPV6ClientLoop(sessionCtx, relay, sockets.client, sockets.server, relay.linkAddr, servers, shouldRelay)
	}()
	if !sockets.serverShared {
		go func() {
			defer wg.Done()
			defer cancel()
			m.runDHCPV6ServerLoop(sessionCtx, relay, sockets.server, sockets.client, servers,
				effectiveDHCPv6InterfaceID(relay.spec.interfaceID, relay.ifaceName), m.replyDispatcherSnapshot())
		}()
	}
	wg.Wait()
}

func (m *dhcpV6Manager) runDHCPV6ClientLoop(ctx context.Context, relay *dhcpV6Relay, client, server net.PacketConn, linkAddr net.IP, servers []*net.UDPAddr, shouldRelay func(string) bool) {
	interfaceID := effectiveDHCPv6InterfaceID(relay.spec.interfaceID, relay.ifaceName)
	rate := resolveMaxPacketRate(relay.maxPacketRate)
	rateBucket := newTokenBucket(rate, relayBurstFor(rate), m.now)
	warnedRateLimit := false
	buf := make([]byte, readBufSize)
	for {
		n, source, err := client.ReadFrom(buf)
		if err != nil {
			return
		}
		if !rateBucket.allow() {
			relay.requestsDroppedRateLimit.Add(1)
			if !warnedRateLimit {
				slog.Warn("dhcpv6-relay: client request rate limit exceeded, dropping excess",
					"interface", relay.ifaceName, "rate_pps", rate, "src", source)
				warnedRateLimit = true
			} else {
				slog.Debug("dhcpv6-relay: client request rate limit exceeded, dropping",
					"interface", relay.ifaceName, "src", source)
			}
			continue
		}
		if n > 0 && dhcpv6.MessageType(buf[0]) == dhcpv6.MessageTypeRelayReply {
			packet, err := dhcpv6.FromBytes(buf[:n])
			if err != nil {
				if dispatcher := m.replyDispatcherSnapshot(); dispatcher != nil {
					dispatcher.droppedParse.Add(1)
				}
				continue
			}
			if dispatcher := m.replyDispatcherSnapshot(); dispatcher != nil {
				dispatcher.dispatch(packet, source)
			}
			continue
		}
		sourceAddr, ok := source.(*net.UDPAddr)
		if !ok {
			relay.requestsDroppedParse.Add(1)
			continue
		}
		packet, err := dhcpv6.FromBytes(buf[:n])
		if err != nil {
			relay.requestsDroppedParse.Add(1)
			continue
		}
		expectedPort := dhcpv6ClientPort
		if packet.IsRelay() {
			expectedPort = dhcpv6RelayPort
		}
		if sourceAddr.Port != expectedPort {
			relay.requestsDroppedPort.Add(1)
			continue
		}
		if shouldRelay != nil && !shouldRelay(relay.ifaceName) {
			relay.requestsDroppedBackup.Add(1)
			continue
		}
		peer := udpAddrIP(source)
		if peer == nil || peer.To16() == nil || peer.To4() != nil || peer.IsUnspecified() || peer.IsMulticast() {
			relay.requestsDroppedPeer.Add(1)
			continue
		}
		if packet.IsRelay() {
			// A downstream relay can only be trusted with an explicit
			// trust policy. DHCPv6 has no such knob yet, so fail closed
			// rather than letting an on-link host steer link selection.
			relay.requestsDroppedNested.Add(1)
			continue
		}
		forwardLinkAddr := relayForwardV6LinkAddress(linkAddr, peer, false)
		forward, err := buildRelayForwardV6(packet, forwardLinkAddr, peer, interfaceID)
		if err != nil {
			relay.requestsDroppedBuild.Add(1)
			continue
		}
		data := forward.ToBytes()
		for _, destination := range servers {
			if _, err := server.WriteTo(data, destination); err == nil {
				relay.requestsRelayed.Add(1)
			}
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (m *dhcpV6Manager) runDHCPV6ServerLoop(ctx context.Context, relay *dhcpV6Relay, server, client net.PacketConn, servers []*net.UDPAddr, expectedInterfaceID []byte, dispatcher *dhcpV6ReplyDispatcher) {
	allowed := make([]*net.UDPAddr, 0, len(servers))
	for _, server := range servers {
		if server != nil {
			allowed = append(allowed, server)
		}
	}
	buf := make([]byte, readBufSize)
	for {
		n, source, err := server.ReadFrom(buf)
		if err != nil {
			return
		}
		packet, err := dhcpv6.FromBytes(buf[:n])
		if err != nil {
			relay.repliesDroppedParse.Add(1)
			continue
		}
		if packet.Type() == dhcpv6.MessageTypeRelayReply {
			if outer, ok := packet.(*dhcpv6.RelayMessage); ok {
				if got := outer.Options.InterfaceID(); got != nil && !bytes.Equal(got, expectedInterfaceID) {
					if dispatcher != nil {
						dispatcher.dispatch(packet, source)
						continue
					}
					relay.repliesDroppedIID.Add(1)
					continue
				}
			}
		}
		processDHCPV6ServerPacket(relay, client, packet, source, allowed, expectedInterfaceID)
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func processDHCPV6ServerPacket(relay *dhcpV6Relay, client net.PacketConn, packet dhcpv6.DHCPv6, source net.Addr, allowed []*net.UDPAddr, expectedInterfaceID []byte) {
	if !dhcpv6SourceAllowed(source, allowed) {
		relay.repliesDroppedUnknownSrv.Add(1)
		return
	}
	if packet.Type() != dhcpv6.MessageTypeRelayReply {
		relay.repliesDroppedInvalid.Add(1)
		return
	}
	if outer, ok := packet.(*dhcpv6.RelayMessage); ok {
		if inner := outer.Options.RelayMessage(); inner != nil && inner.IsRelay() {
			// A downstream Relay-Reply requires an explicit trust policy.
			// #9553 has no such knob, so fail closed before forwarding it
			// to an on-link relay at UDP/547.
			relay.repliesDroppedNested.Add(1)
			return
		}
	}
	inner, destination, err := decapsulateRelayReplyV6(packet, expectedInterfaceID)
	if err != nil {
		if outer, ok := packet.(*dhcpv6.RelayMessage); ok {
			got := outer.Options.InterfaceID()
			if got == nil || !bytes.Equal(got, expectedInterfaceID) {
				relay.repliesDroppedIID.Add(1)
			} else {
				relay.repliesDroppedInvalid.Add(1)
			}
		} else {
			relay.repliesDroppedInvalid.Add(1)
		}
		return
	}
	if destination.IP.IsLinkLocalUnicast() {
		destination.Zone = relay.kernelName
	}
	if _, err := client.WriteTo(inner.ToBytes(), destination); err == nil {
		relay.repliesForwarded.Add(1)
	}
}

func dhcpv6SourceAllowed(source net.Addr, allowed []*net.UDPAddr) bool {
	sourceAddr, ok := source.(*net.UDPAddr)
	if !ok {
		return false
	}
	for _, candidate := range allowed {
		if candidate != nil && candidate.Port == sourceAddr.Port && candidate.IP.Equal(sourceAddr.IP) {
			return true
		}
	}
	return false
}
