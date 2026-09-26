// Package lldp implements the Link Layer Discovery Protocol (IEEE 802.1AB).
//
// It provides periodic LLDP frame transmission and reception on configured
// interfaces, maintaining a neighbor table with TTL-based expiry.
package lldp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/linuxsock"
	"golang.org/x/sys/unix"
)

// LLDP constants.
var (
	// LLDPMulticast is the standard LLDP destination MAC address.
	LLDPMulticast = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
)

const (
	etherTypeLLDP = 0x88cc

	// TLV types per IEEE 802.1AB.
	tlvEnd            = 0
	tlvChassisID      = 1
	tlvPortID         = 2
	tlvTTL            = 3
	tlvPortDesc       = 4
	tlvSystemName     = 5
	tlvSystemDesc     = 6
	tlvSystemCap      = 7
	tlvManagementAddr = 8

	// Chassis ID subtypes.
	chassisSubtypeMACAddr = 4

	// Port ID subtypes.
	portSubtypeIfName = 5

	// Default LLDP transmit interval and hold multiplier.
	defaultInterval       = 30 * time.Second
	defaultHoldMultiplier = 4

	// Ethernet header length.
	ethHdrLen = 14
)

// Neighbor represents a discovered LLDP neighbor on an interface.
type Neighbor struct {
	ChassisID  string // chassis identifier (MAC or string)
	PortID     string // port identifier (interface name)
	TTL        int    // advertised hold time in seconds
	SystemName string
	SystemDesc string
	PortDesc   string
	LastSeen   time.Time
	ExpiresAt  time.Time
	Interface  string // local interface where neighbor was seen
}

// LLDPInterface holds per-interface LLDP configuration.
type LLDPInterface struct {
	Name    string
	Disable bool // per-interface disable
}

// LLDPConfig holds LLDP protocol configuration.
type LLDPConfig struct {
	Interfaces     []LLDPInterface // interfaces to enable LLDP on
	Interval       int             // transmit interval in seconds (0 = default 30)
	HoldMultiplier int             // hold multiplier (0 = default 4)
	SystemName     string          // system name TLV (defaults to hostname)
	SystemDesc     string          // system description TLV
	Disable        bool            // globally disable LLDP
}

// neighborKey identifies a learned LLDP neighbor.
//
// It is a STRUCT rather than a separator-joined string, and that is the whole
// point (#7176 C179-026). Two of its three components — ChassisID and PortID —
// are peer-controlled TLV strings taken straight off the wire by ParseTLVs, and
// port IDs legitimately contain "/" (a Junos-style `ge-0/0/1`). A
// "%s/%s/%s"-formatted key therefore cannot represent them unambiguously:
// chassis="a/b" port="c" and chassis="a" port="b/c" format to the same string.
//
// That ambiguity was not cosmetic. A TTL=0 LLDPDU is an explicit withdrawal
// (IEEE 802.1AB) and withdrawNeighbor deletes by key, so a peer able to choose
// its own ChassisID/PortID could forge the key of a DIFFERENT neighbor and
// evict an entry it does not own — remote-input-driven deletion of another
// peer's state.
//
// A comparable struct makes the collision UNREPRESENTABLE rather than escaped:
// there is no separator to smuggle, so no escaping rule to get wrong later and
// no encoder/decoder pair that can drift apart.
type neighborKey struct {
	Iface     string
	ChassisID string
	PortID    string
}

// neighborKeyFor builds the table key for a neighbor learned on ifaceName.
//
// Split out of the receive loop so the REAL construction is drivable by a test.
// The collision this key type exists to prevent is created exactly here — where
// peer-controlled TLV strings become a key — and a test that assembles keys by
// hand cannot observe a regression at this site: it would keep passing while the
// production path went back to joining the components into one string.
func neighborKeyFor(ifaceName string, n *Neighbor) neighborKey {
	return neighborKey{Iface: ifaceName, ChassisID: n.ChassisID, PortID: n.PortID}
}

// Manager runs LLDP transmit/receive goroutines and maintains the neighbor table.
type Manager struct {
	// lifecycleMu serializes the Apply/Stop generation transition. Apply (a
	// config commit) and Stop (daemon shutdown) can run concurrently — the
	// shutdown path calls Stop() without the applySem that Apply runs under, so
	// a SIGTERM mid-commit races them. Without this lock that race is real
	// (#5121): Apply's wg.Add(1) races Stop's wg.Wait() (a WaitGroup misuse that
	// can panic or lose a goroutine from the join), the m.cancel write/read is a
	// data race, and Stop can snapshot the session set before Apply finishes
	// publishing later sessions — leaving those interfaces' RX goroutines parked
	// in recv forever (their fds never get closed), which hangs shutdown and
	// leaks sockets/goroutines. Holding lifecycleMu across the whole transition
	// makes each of build (Apply) and teardown (Stop) atomic with respect to the
	// other.
	//
	// It is deliberately NOT m.mu: the TX/RX/expiry goroutines take only m.mu
	// (never lifecycleMu), so holding lifecycleMu across stopLocked's wg.Wait()
	// cannot deadlock against the goroutines being joined. Apply calls the
	// internal stopLocked() (not Stop()) to avoid a self-deadlock on the
	// non-reentrant lock.
	lifecycleMu sync.Mutex

	mu        sync.RWMutex
	neighbors map[neighborKey]*Neighbor
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	// sessions are the per-interface RX/TX sockets for the current Apply
	// generation. Stop() closes each one to unblock the parked RX Recvfrom
	// immediately, so shutdown does not wait out a read timeout. Guarded by mu.
	sessions []*ifSession

	// applyCount counts Apply() calls. It exists so the daemon's day-2 reconcile
	// diff-guard (#2372) can be regression-tested — an unrelated commit must not
	// re-Apply (which would Stop()/rebuild the generation and wipe the neighbor
	// table). Atomic so a test reading it does not race a concurrent Apply.
	applyCount atomic.Uint64

	// capEvictLastWarn rate-limits the per-interface "neighbor table full"
	// warning. Keyed by interface name and guarded by mu; see #4044.
	capEvictLastWarn map[string]time.Time
}

// ifSession owns the RX and TX AF_PACKET sockets for one interface for the life
// of an Apply() generation. close() shuts down and closes rxFD, which makes a
// parked unix.Recvfrom in the RX goroutine return immediately, so Stop() does
// not block waiting out a read timeout. This mirrors the close-to-unblock
// pattern VRRP uses for its receiver (pkg/vrrp/instance.go stop()).
type ifSession struct {
	iface     *net.Interface
	rxFD      int // AF_PACKET bound to ifindex, ETH_P_LLDP
	txFD      int // AF_PACKET for periodic Sendto, opened once and reused
	closeOnce sync.Once

	// recvFn, when non-nil, replaces the real unix.Recvfrom-based recv. It is
	// the test seam for exercising rxLoop's transient-error handling (EINTR /
	// EAGAIN retry vs fatal exit) and the PACKET_OUTGOING self-frame filter
	// deterministically, without a real socket or signal delivery. The middle
	// return value is the AF_PACKET sll_pkttype of the received frame (e.g.
	// unix.PACKET_HOST for an inbound peer frame, unix.PACKET_OUTGOING for the
	// host's own transmitted frame looped back on the socket). Production leaves
	// it nil.
	recvFn func(buf []byte) (int, int, error)
}

// interfaceByNameFn is the interface-resolution seam. Tests override it to
// assert Apply resolves the kernel (dash-form) device name before the lookup,
// and to avoid depending on a host device being present.
var interfaceByNameFn = net.InterfaceByName

// newIfSessionFn is the construction seam for ifSession. Tests override it to
// inject a socketpair(2)-backed session so the Stop-unblocks-recv contract can
// be exercised without CAP_NET_RAW or a real interface.
var newIfSessionFn = newIfSession

// newIfSession opens and binds the RX socket and opens the TX socket for one
// interface. Both fds live for the Apply generation and are released by close().
func newIfSession(iface *net.Interface) (*ifSession, error) {
	rxFD, err := linuxsock.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(etherTypeLLDP)))
	if err != nil {
		return nil, fmt.Errorf("lldp: rx socket: %w", err)
	}
	if err := unix.Bind(rxFD, &unix.SockaddrLinklayer{
		Protocol: htons(etherTypeLLDP),
		Ifindex:  iface.Index,
	}); err != nil {
		unix.Close(rxFD)
		return nil, fmt.Errorf("lldp: rx bind: %w", err)
	}
	// No SO_RCVTIMEO: recv blocks indefinitely and is unblocked by closing the
	// fd in close(), not by a polling timeout.

	txFD, err := linuxsock.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		unix.Close(rxFD)
		return nil, fmt.Errorf("lldp: tx socket: %w", err)
	}

	return &ifSession{iface: iface, rxFD: rxFD, txFD: txFD}, nil
}

// recv reads one frame from the RX socket. It blocks until a frame arrives or
// the fd is closed by close(). It returns the number of bytes read and the
// AF_PACKET packet type (sll_pkttype) from the returned sockaddr_ll. The packet
// type lets rxLoop distinguish a genuine inbound peer frame (PACKET_HOST /
// PACKET_MULTICAST / PACKET_BROADCAST) from the host's own transmitted frame
// that the kernel loops back on the same AF_PACKET socket (PACKET_OUTGOING).
// Without that distinction the daemon learns its own LLDP advertisements as a
// neighbor (#2992).
func (s *ifSession) recv(buf []byte) (int, int, error) {
	if s.recvFn != nil {
		return s.recvFn(buf)
	}
	n, from, err := unix.Recvfrom(s.rxFD, buf, 0)
	if err != nil {
		return n, 0, err
	}
	pkttype := 0
	if sll, ok := from.(*unix.SockaddrLinklayer); ok {
		pkttype = int(sll.Pkttype)
	}
	return n, pkttype, err
}

// send transmits an LLDP frame to the multicast destination on the bound
// interface over the reused TX socket.
func (s *ifSession) send(frame []byte) error {
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(etherTypeLLDP),
		Ifindex:  s.iface.Index,
		Halen:    6,
	}
	copy(addr.Addr[:6], LLDPMulticast)
	return unix.Sendto(s.txFD, frame, 0, addr)
}

// close releases both sockets. It is idempotent (closeOnce) so a double-close
// from a racing Stop cannot panic or double-free.
//
// shutdown(SHUT_RDWR) precedes close on rxFD on purpose: closing an fd that
// another goroutine is actively blocked reading on is NOT a reliable wakeup —
// the fd number is freed but the in-flight Recvfrom can stay parked. shutdown
// reliably wakes a blocked reader. On a connectionless AF_PACKET socket shutdown
// returns ENOTCONN (harmless, ignored) and the subsequent close is what tears
// down the RX queue and unblocks recv (the pattern VRRP relies on); on a
// connection-oriented socket (the socketpair used in tests) shutdown is the
// authoritative wakeup. Doing both is correct for either socket family.
func (s *ifSession) close() {
	s.closeOnce.Do(func() {
		_ = unix.Shutdown(s.rxFD, unix.SHUT_RDWR)
		unix.Close(s.rxFD)
		if s.txFD != s.rxFD {
			unix.Close(s.txFD)
		}
	})
}

// New creates a new LLDP manager.
func New() *Manager {
	return &Manager{
		neighbors:        make(map[neighborKey]*Neighbor),
		capEvictLastWarn: make(map[string]time.Time),
	}
}

// Apply starts LLDP on the configured interfaces.
//
// It holds lifecycleMu for the entire generation transition so a concurrent
// Stop() (daemon shutdown) cannot interleave with the teardown-then-rebuild:
// the tear-down of the previous generation, the cancel/session publication of
// the new one, and every wg.Add(1) all happen atomically with respect to a
// racing Stop (#5121). The internal teardown uses stopLocked() (not Stop) to
// avoid re-acquiring the non-reentrant lifecycleMu.
// #6794: Apply is PARTIAL and reports it. Each configured interface is brought
// up independently and a failure skips just that one — so a "successful" call
// can leave part of the generation dark. It returns the interfaces that failed
// NAME RESOLUTION, which is the recoverable half: the NIC is simply not there
// yet (renamed later by a .link file, created later as a VLAN/tunnel, or not
// yet up). A caller that guards on unchanged config MUST consult this, or the
// reconcile that would have recovered those interfaces is skipped forever.
//
// A socket-setup failure (CAP_NET_RAW, bind) is deliberately NOT reported here:
// it is logged and the interface is skipped, but it does not self-heal within a
// process the way an absent NIC does, so surfacing it as retry debt would make
// every later commit rebuild the whole generation — wiping the neighbor table
// on a condition that will not change.
func (m *Manager) Apply(ctx context.Context, cfg *LLDPConfig) (unresolved []string) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()

	m.applyCount.Add(1)
	m.stopLocked()

	if cfg == nil || cfg.Disable || len(cfg.Interfaces) == 0 {
		return nil
	}

	lldpCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	// #8642: bounded at the conversion. The old `interval <= 0` check below is
	// blind to overflow — past MaxDurationSeconds the multiply wraps to a
	// 512ns-multiple POSITIVE residue, which sails through it and makes txLoop
	// emit an LLDP frame every 512ns on every configured interface.
	interval := config.SecondsToDuration(cfg.Interval, 0)
	if interval <= 0 {
		interval = defaultInterval
	}
	holdMult := cfg.HoldMultiplier
	if holdMult <= 0 {
		holdMult = defaultHoldMultiplier
	}

	sysName := cfg.SystemName
	if sysName == "" {
		sysName = "xpf"
	}

	for _, lldpIf := range cfg.Interfaces {
		if lldpIf.Disable {
			continue
		}
		// Config interfaces carry Junos display names (ge-0/0/0, reth0.50);
		// xpfd renames the kernel device to dash form (ge-0-0-0) via .link
		// files, so net.InterfaceByName must be handed the kernel name — a
		// slash never appears in a kernel ifname and the lookup would fail,
		// silently skipping LLDP on exactly the renamed data ports. LinuxIfName
		// is a no-op on a name that is already kernel-form (no slash).
		kernelName := config.LinuxIfName(lldpIf.Name)
		iface, err := interfaceByNameFn(kernelName)
		if err != nil {
			slog.Warn("LLDP: interface not found", "interface", lldpIf.Name,
				"kernel", kernelName, "err", err)
			// #6794: REPORTED, not just logged. This is the recoverable
			// failure — the interface simply is not there yet (renamed later,
			// created later, brought up later) — so the caller needs to know
			// this generation is incomplete, or its unchanged-config guard
			// will skip the reconcile that would have fixed it.
			unresolved = append(unresolved, lldpIf.Name)
			continue
		}

		// Open the RX+TX sockets once for this interface. A CAP_NET_RAW or bind
		// failure now surfaces here (logged, interface skipped) instead of
		// silently per-frame.
		sess, err := newIfSessionFn(iface)
		if err != nil {
			slog.Warn("LLDP: socket setup failed, skipping interface",
				"interface", lldpIf.Name, "err", err)
			continue
		}
		m.mu.Lock()
		m.sessions = append(m.sessions, sess)
		m.mu.Unlock()

		// Start TX goroutine.
		m.wg.Add(1)
		go func(sess *ifSession) {
			defer m.wg.Done()
			m.txLoop(lldpCtx, sess, interval, holdMult, sysName, cfg.SystemDesc)
		}(sess)

		// Start RX goroutine.
		m.wg.Add(1)
		go func(sess *ifSession) {
			defer m.wg.Done()
			m.rxLoop(lldpCtx, sess)
		}(sess)

		slog.Info("LLDP started", "interface", lldpIf.Name, "interval", interval)
	}

	sort.Strings(unresolved)

	// Start neighbor expiry goroutine.
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.expiryLoop(lldpCtx)
	}()
	return unresolved
}

// InterfaceResolvable reports whether a configured LLDP interface name resolves
// to a kernel interface right now (#6794). It is the same lookup Apply performs
// — the SAME name conversion and the SAME seam — so a caller deciding whether a
// previously-unresolved interface has appeared cannot disagree with the code
// that will act on that decision.
func InterfaceResolvable(name string) bool {
	_, err := interfaceByNameFn(config.LinuxIfName(name))
	return err == nil
}

// Stop halts all LLDP goroutines and clears the neighbor table. It holds
// lifecycleMu so a concurrent Apply() (config commit) cannot interleave its
// build with this teardown (#5121); the actual work is in stopLocked.
func (m *Manager) Stop() {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.stopLocked()
}

// stopLocked performs the generation teardown. The caller MUST hold
// lifecycleMu (Stop acquires it; Apply already holds it), which is what
// serializes the cancel/wg access against a racing Apply/Stop.
//
// Ordering is load-bearing: cancel the context (stops the timer-driven TX and
// expiry loops), then close every session's sockets (unblocks any RX goroutine
// parked in recv immediately), then wg.Wait(). Closing the fds BEFORE the wait
// is what makes Stop bounded — waiting first would re-introduce the read-timeout
// stall. The close-under-read race is benign: a recv on a just-closed fd returns
// an error and the RX loop treats any post-cancel error as "shutdown, return".
func (m *Manager) stopLocked() {
	m.mu.Lock()
	sessions := m.sessions
	m.sessions = nil
	m.mu.Unlock()

	if m.cancel != nil {
		m.cancel()
		// Close sockets to unblock any blocking Recvfrom in rxLoop.
		for _, s := range sessions {
			s.close()
		}
		m.wg.Wait()
		m.cancel = nil
	} else {
		// Defensive: close any sessions even if cancel was never set (no
		// goroutines should be running, but never leak an fd).
		for _, s := range sessions {
			s.close()
		}
	}

	m.mu.Lock()
	m.neighbors = make(map[neighborKey]*Neighbor)
	m.capEvictLastWarn = make(map[string]time.Time)
	m.mu.Unlock()
}

// Running reports whether a live LLDP generation is active — i.e. Apply() has
// started the TX/RX/expiry goroutines and Stop() has not since torn them down.
// It lets the daemon's day-2 reconcile (and tests of it) observe the
// start/stop transition without reaching into unexported fields. The result is
// the m.sessions snapshot: Apply appends sessions under mu and Stop nils them
// under mu, so a non-empty session set is the race-free witness that a
// generation is live (cancel is set/cleared by the apply-serialized caller, but
// sessions are the mu-guarded state). A generation with zero usable interfaces
// (all InterfaceByName lookups failed) reports false — there is nothing running
// to reconcile away.
func (m *Manager) Running() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions) > 0
}

// ApplyCount returns the number of times Apply() has been called on this
// manager. It exists for the day-2 reconcile diff-guard regression test
// (#2372): an unrelated commit must leave this unchanged.
func (m *Manager) ApplyCount() uint64 {
	return m.applyCount.Load()
}

// Neighbors returns a sorted snapshot of all discovered neighbors.
func (m *Manager) Neighbors() []*Neighbor {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]neighborKey, 0, len(m.neighbors))
	for k := range m.neighbors {
		keys = append(keys, k)
	}
	// Deterministic order, field by field. The previous sort.Strings over the
	// joined key ordered by the same components in the same precedence; sorting
	// the fields directly keeps that without reintroducing a separator.
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Iface != b.Iface {
			return a.Iface < b.Iface
		}
		if a.ChassisID != b.ChassisID {
			return a.ChassisID < b.ChassisID
		}
		return a.PortID < b.PortID
	})

	out := make([]*Neighbor, 0, len(keys))
	for _, k := range keys {
		n := m.neighbors[k]
		cp := *n
		out = append(out, &cp)
	}
	return out
}

// txLoop periodically sends LLDP frames on the session's interface, reusing the
// session's TX socket for every advertisement.
func (m *Manager) txLoop(ctx context.Context, sess *ifSession, interval time.Duration, holdMult int, sysName, sysDesc string) {
	ttl := int(interval.Seconds()) * holdMult

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Send first frame immediately.
	m.sendFrame(sess, ttl, sysName, sysDesc)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.sendFrame(sess, ttl, sysName, sysDesc)
		}
	}
}

// sendFrame builds and sends a single LLDP frame over the session's reused TX
// socket.
func (m *Manager) sendFrame(sess *ifSession, ttl int, sysName, sysDesc string) {
	iface := sess.iface
	frame, err := BuildFrame(iface.HardwareAddr, iface.Name, ttl, sysName, sysDesc)
	if err != nil {
		// Fail closed: skip this advertisement rather than send a malformed
		// frame with a wrapped TLV length (#2036).
		slog.Warn("LLDP TX: skipping frame with overlength TLV", "interface", iface.Name, "err", err)
		return
	}

	if err := sess.send(frame); err != nil {
		slog.Debug("LLDP TX: send error", "interface", iface.Name, "err", err)
	}
}

// rxErrorBackoff is how long rxLoop waits after an unexpected (non-transient,
// non-shutdown) recv error before retrying. A persistent operational error
// (e.g. an interface flapped down so recv keeps erroring) must not become a
// tight busy-spin, but it also must not permanently kill the receiver — nothing
// restarts rxLoop within a generation. rxLoop lives only for the life of the
// Apply() that started it; the daemon re-Apply()s only on a `protocols lldp`
// change (#2372 diff-guard), which Stop()s the old generation and starts a
// fresh one. So a permanent exit on a transient flap would silently kill
// discovery until the next LLDP config change or a daemon restart. A var so
// tests can shrink it; production keeps the 1s default.
var rxErrorBackoff = 1 * time.Second

// rxLoop receives LLDP frames on the session's interface and updates the
// neighbor table. The RX socket has no read timeout: recv blocks until a frame
// arrives or Stop() closes the fd. On Stop() the closed fd makes recv return an
// error and, because the context is cancelled, the loop exits promptly without
// waiting out a read timeout. On an UNEXPECTED recv error while the context is
// still live (e.g. a transient interface flap), the loop backs off and retries
// rather than terminating — it survives operational errors for the life of the
// Apply() generation and exits only on shutdown.
func (m *Manager) rxLoop(ctx context.Context, sess *ifSession) {
	iface := sess.iface
	buf := make([]byte, 1600)
	for {
		n, pkttype, err := sess.recv(buf)
		if err != nil {
			// Transient, non-fatal recv errors must not kill neighbor
			// discovery on a long-running daemon. EINTR can be delivered to a
			// goroutine (e.g. a signal forwarded through the Go runtime before
			// it can be masked); EAGAIN/EWOULDBLOCK is the spurious-wakeup case
			// (the RX socket is blocking with no SO_RCVTIMEO, so this should not
			// occur, but retrying is the only safe response if it ever does).
			// Retry immediately rather than terminating the RX loop.
			if err == unix.EINTR || err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			// recv was unblocked by something other than a transient error. If
			// the context is cancelled, this is the expected close-to-unblock on
			// Stop(): the fd is closed, return immediately.
			if ctx.Err() != nil {
				return
			}
			// Context is still live, so this is an unexpected operational error
			// (e.g. the interface flapped down — ENETDOWN — or the link is
			// briefly gone). The old timeout-poll loop survived these by
			// continuing; the close-to-unblock redesign must NOT regress to
			// permanently killing discovery, because nothing restarts rxLoop
			// outside a daemon restart. Back off (so a persistent error does not
			// become a tight busy-spin) and retry. The backoff is interruptible:
			// a concurrent Stop() cancels ctx and we return promptly instead of
			// sleeping out the delay.
			slog.Debug("LLDP RX: transient recv error, backing off then retrying",
				"interface", iface.Name, "err", err, "backoff", rxErrorBackoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(rxErrorBackoff):
			}
			continue
		}
		if n < ethHdrLen {
			continue
		}

		// Skip the host's own transmitted LLDP frames. The RX AF_PACKET socket
		// is bound to ETH_P_LLDP and also receives this host's own outgoing LLDP
		// advertisements (the kernel loops every transmitted frame of the bound
		// protocol back to AF_PACKET listeners, marked PACKET_OUTGOING). Parsing
		// them would learn the firewall as its own neighbor on every LLDP-enabled
		// link, polluting `show lldp neighbors` (#2992). The EtherType and the
		// well-known multicast destination are already kernel-filtered; the
		// remaining self-frame source is the loopback of our own transmissions,
		// which the kernel marks PACKET_OUTGOING. Genuine inbound peer frames
		// carry PACKET_HOST / PACKET_MULTICAST / PACKET_BROADCAST and are kept.
		if pkttype == unix.PACKET_OUTGOING {
			continue
		}

		// Skip Ethernet header (dst[6] + src[6] + ethertype[2]).
		neighbor := ParseTLVs(buf[ethHdrLen:n])
		if neighbor == nil {
			continue
		}

		key := neighborKeyFor(iface.Name, neighbor)

		// IEEE 802.1AB shutdown semantics: a TTL=0 LLDPDU is an explicit
		// withdrawal, not a neighbor advertisement. Remove any existing entry
		// for this key immediately under the neighbor lock and do NOT cache the
		// frame. Storing it as an ordinary neighbor (as a non-zero TTL frame is)
		// would set ExpiresAt==now and leave the departed peer visible in
		// Neighbors() until the next ~10s expiryLoop tick — a peer that has
		// announced its departure must disappear now, not up to 10s later
		// (#5123).
		if neighbor.TTL == 0 {
			m.withdrawNeighbor(key)
			continue
		}

		neighbor.Interface = iface.Name
		now := time.Now()
		neighbor.LastSeen = now
		neighbor.ExpiresAt = now.Add(time.Duration(neighbor.TTL) * time.Second)
		m.learnNeighbor(key, neighbor)
	}
}

// maxNeighborsPerInterface bounds the number of distinct LLDP neighbors the
// receive path caches per local interface. LLDP is an unauthenticated L2
// protocol: any device on the segment can flood frames carrying arbitrary
// (spoofed) chassis-id / port-id values. The cap prevents a flood from growing
// the table without bound. A real switch port sees one, occasionally a handful
// of LLDP neighbors; 64 is far above any legitimate topology. When the cap is
// full, learnNeighbor replaces the least-recently-seen entry so a transient
// flood cannot squat on every slot until its advertised TTL expires. The legal
// 16-bit wire TTL, including 65535 seconds, is preserved; a new neighbor is
// admitted immediately on receipt even when the interface is full. The
// effective global bound is this cap times the number of LLDP-enabled
// interfaces, so no separate global cap is needed (#4044, #10898).
const maxNeighborsPerInterface = 64

// capEvictWarnInterval rate-limits the per-interface "neighbor table full"
// warning so an ongoing flood does not flood the log.
const capEvictWarnInterval = 60 * time.Second

// learnNeighbor installs or refreshes a received neighbor under the
// per-interface cap. A refresh of an already-known (ifname/chassis/port) key
// updates in place. A new neighbor at the cap replaces the least-recently-seen
// entry on that interface and is admitted; this bounds transient-flood recovery
// to processing the first subsequent advertisement rather than waiting for an
// attacker-controlled TTL to expire (#10898). Received TTL is not clamped, so a
// valid maximum-TTL peer remains represented with its full advertised TTL.
// Returns true if the neighbor was stored.
func (m *Manager) learnNeighbor(key neighborKey, n *Neighbor) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.neighbors[key]; exists {
		// Refresh of a known neighbor: update in place. Does not grow the map.
		m.neighbors[key] = n
		return true
	}

	// Find the least-recently-seen neighbor on this interface while counting
	// its bounded table. LastSeen is assigned by rxLoop on every advertisement.
	count := 0
	var oldestKey neighborKey
	var oldest *Neighbor
	for existingKey, existing := range m.neighbors {
		if existing.Interface != n.Interface {
			continue
		}
		count++
		if oldest == nil || existing.LastSeen.Before(oldest.LastSeen) {
			oldestKey = existingKey
			oldest = existing
		}
	}
	if count >= maxNeighborsPerInterface {
		// A full table necessarily has an oldest entry. Replace it atomically
		// under m.mu so another receiver cannot consume the freed slot first.
		delete(m.neighbors, oldestKey)
		m.warnNeighborCapEvictedLocked(n.Interface)
	}
	m.neighbors[key] = n
	return true
}

// withdrawNeighbor removes the neighbor identified by key, if present. It is the
// immediate-withdrawal path for a TTL=0 shutdown LLDPDU (IEEE 802.1AB §"the
// receiving LLDP agent shall delete the associated information"): the neighbor
// is dropped as soon as the shutdown frame is received rather than lingering
// until the periodic expiryLoop tick. A TTL=0 frame for a key that is not in the
// table is a no-op — no error, no spurious insert. It takes the same m.mu the
// learn and expiry paths use, so the delete is serialized against concurrent
// refreshes and reaps. A shutdown is a rare per-neighbor event (not per-packet),
// so the state-transition log mirrors expiryLoop's "expired" line.
func (m *Manager) withdrawNeighbor(key neighborKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.neighbors[key]
	if !ok {
		return
	}
	slog.Info("LLDP neighbor withdrawn (TTL=0 shutdown)",
		"interface", n.Interface,
		"chassis", n.ChassisID,
		"port", n.PortID)
	delete(m.neighbors, key)
}

// warnNeighborCapEvictedLocked logs (at most once per capEvictWarnInterval per
// interface) that the neighbor table is full and its oldest entry was evicted.
// The caller must hold m.mu.
func (m *Manager) warnNeighborCapEvictedLocked(iface string) {
	now := time.Now()
	if last, ok := m.capEvictLastWarn[iface]; ok && now.Sub(last) < capEvictWarnInterval {
		return
	}
	m.capEvictLastWarn[iface] = now
	slog.Warn("LLDP: neighbor table full, evicting least-recently-seen neighbor",
		"interface", iface, "cap", maxNeighborsPerInterface)
}

// expiryLoop periodically removes expired neighbors.
func (m *Manager) expiryLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			m.mu.Lock()
			for key, n := range m.neighbors {
				if now.After(n.ExpiresAt) {
					slog.Info("LLDP neighbor expired",
						"interface", n.Interface,
						"chassis", n.ChassisID,
						"port", n.PortID)
					delete(m.neighbors, key)
				}
			}
			m.mu.Unlock()
		}
	}
}

// BuildFrame constructs a complete LLDP Ethernet frame. It fails closed if any
// variable-length identity TLV (system name/description, port description)
// exceeds the 9-bit TLV length limit, rather than emitting a malformed
// advertisement (#2036).
func BuildFrame(srcMAC net.HardwareAddr, portName string, ttl int, sysName, sysDesc string) ([]byte, error) {
	var tlvs []byte
	// Chassis ID (MAC = 7 bytes) and TTL (2 bytes) are compile-time bounded.
	tlvs = append(tlvs, mustEncodeTLV(tlvChassisID, encodeChassisID(srcMAC))...)
	// Port ID carries portName which is caller-supplied: propagate error rather
	// than panic so BuildFrame stays consistently fail-closed (#2036).
	portIDEnc, err := EncodeTLV(tlvPortID, encodePortID(portName))
	if err != nil {
		return nil, err
	}
	tlvs = append(tlvs, portIDEnc...)
	tlvs = append(tlvs, mustEncodeTLV(tlvTTL, encodeTTL(ttl))...)
	// Variable-length identity TLVs: fail closed on overlength rather than
	// shipping a frame whose wrapped 9-bit length desynchronizes the receiver.
	optional := []struct {
		typ int
		val []byte
		on  bool
	}{
		{tlvSystemName, []byte(sysName), sysName != ""},
		{tlvSystemDesc, []byte(sysDesc), sysDesc != ""},
		{tlvPortDesc, []byte(portName), portName != ""},
	}
	for _, o := range optional {
		if !o.on {
			continue
		}
		enc, err := EncodeTLV(o.typ, o.val)
		if err != nil {
			return nil, err
		}
		tlvs = append(tlvs, enc...)
	}
	tlvs = append(tlvs, mustEncodeTLV(tlvEnd, nil)...) // End TLV

	// Build Ethernet frame: dst(6) + src(6) + ethertype(2) + payload.
	frame := make([]byte, 0, ethHdrLen+len(tlvs))
	frame = append(frame, LLDPMulticast...)
	if len(srcMAC) >= 6 {
		frame = append(frame, srcMAC[:6]...)
	} else {
		frame = append(frame, 0, 0, 0, 0, 0, 0)
	}
	frame = append(frame, byte(etherTypeLLDP>>8), byte(etherTypeLLDP&0xff))
	frame = append(frame, tlvs...)
	return frame, nil
}

// maxTLVValueLen is the largest value an LLDP TLV can carry: the length field
// is 9 bits, so 511 bytes. A larger value would wrap the header length while
// the full payload stayed in the frame, so a receiver would misparse the
// overflow as following TLVs — a malformed advertisement (#2036).
const maxTLVValueLen = 0x1ff

// EncodeTLV encodes a single LLDP TLV (type-length-value). It FAILS CLOSED on
// an overlength value rather than masking the 9-bit length and emitting a
// malformed frame — advertised identity must not be silently lossy.
// TLV header: 7 bits type + 9 bits length = 2 bytes.
func EncodeTLV(tlvType int, value []byte) ([]byte, error) {
	length := len(value)
	if length > maxTLVValueLen {
		return nil, fmt.Errorf("lldp: TLV type %d value is %d bytes, exceeds the %d-byte (9-bit) length limit",
			tlvType, length, maxTLVValueLen)
	}
	header := uint16(tlvType&0x7f)<<9 | uint16(length&0x1ff)
	out := make([]byte, 2+length)
	binary.BigEndian.PutUint16(out[:2], header)
	copy(out[2:], value)
	return out, nil
}

// mustEncodeTLV is EncodeTLV for callers whose value length is bounded at
// compile time (the End TLV) or by a hard OS/protocol limit (chassis ID = MAC
// = 7 bytes, TTL = 2 bytes) and so can never exceed the 9-bit limit. It panics
// if that invariant is ever violated rather than returning a malformed frame.
// Caller-supplied strings such as port ID must use EncodeTLV directly.
func mustEncodeTLV(tlvType int, value []byte) []byte {
	out, err := EncodeTLV(tlvType, value)
	if err != nil {
		panic(err)
	}
	return out
}

func encodeChassisID(mac net.HardwareAddr) []byte {
	// Subtype (1 byte) + MAC address (6 bytes).
	val := make([]byte, 7)
	val[0] = chassisSubtypeMACAddr
	if len(mac) >= 6 {
		copy(val[1:], mac[:6])
	}
	return val
}

func encodePortID(name string) []byte {
	// Subtype (1 byte) + interface name.
	val := make([]byte, 1+len(name))
	val[0] = portSubtypeIfName
	copy(val[1:], name)
	return val
}

func encodeTTL(seconds int) []byte {
	// The LLDP TTL TLV is a 16-bit unsigned value (IEEE 802.1AB); the wire
	// TTL is msgTxInterval × msgTxHold, which the standard caps at
	// txTTL = min(65535, msgTxInterval × msgTxHold). Clamp to [0, 0xffff]
	// here so a large transmit-interval × hold-multiplier product cannot
	// wrap uint16 back to a small or zero TTL (a TTL of 0 makes every peer
	// IMMEDIATELY expire this neighbor — #4596). The schema validators on
	// transmit-interval / hold-multiplier keep operator input in a sane
	// range; this clamp is the defensive backstop for any in-range-but-large
	// product (e.g. 16384s × 4 = 65536) and for constructed callers.
	if seconds < 0 {
		seconds = 0
	}
	if seconds > 0xffff {
		seconds = 0xffff
	}
	val := make([]byte, 2)
	binary.BigEndian.PutUint16(val, uint16(seconds))
	return val
}

// sanitizeTLVString neutralizes display controls in an LLDP TLV string
// received from the wire before it is stored in the neighbor table — and so
// before expiryLoop logs it or a `show lldp neighbors` renderer displays it.
// LLDP is unauthenticated L2 input: any device on the segment can send a frame
// whose free-text identifier carries ANSI escapes, line breaks, bidi overrides,
// or zero-width format characters. C0/C1 controls, DEL, Unicode format runes
// (Cf), and U+2028/U+2029 are replaced by spaces. A legitimate multi-byte UTF-8
// name otherwise passes through unchanged; invalid UTF-8 bytes become U+FFFD.
//
// The fast path returns s verbatim only when it has none of those display
// controls and is valid UTF-8. A bare 0x9B is NOT a control rune — it decodes to
// U+FFFD — so the utf8.ValidString check ensures an invalid byte cannot reach
// a terminal or log unmodified (#6482, #10899).
func sanitizeTLVString(s string) string {
	if strings.IndexFunc(s, isUnsafeTLVStringRune) < 0 && utf8.ValidString(s) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isUnsafeTLVStringRune(r) {
			return ' '
		}
		return r
	}, s)
}

func isUnsafeTLVStringRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
		r == '\u2028' || r == '\u2029'
}

// ParseTLVs parses LLDP TLVs from raw payload (after Ethernet header).
// Returns nil if any mandatory TLV (Chassis ID, Port ID, TTL) is missing OR
// truncated: a mandatory TLV is only counted present once its value parsed
// into a valid identifier (non-empty Chassis/Port ID, a 2-byte TTL). A
// truncated mandatory TLV would otherwise be accepted with an empty key and
// poison the neighbor cache as "ifname//" with TTL 0 (#2551).
func ParseTLVs(data []byte) *Neighbor {
	n := &Neighbor{}
	hasChassis, hasPort, hasTTL := false, false, false

	for len(data) >= 2 {
		header := binary.BigEndian.Uint16(data[:2])
		tlvType := int(header >> 9)
		tlvLen := int(header & 0x1ff)
		data = data[2:]

		if tlvLen > len(data) {
			break
		}
		value := data[:tlvLen]
		data = data[tlvLen:]

		switch tlvType {
		case tlvEnd:
			goto done
		case tlvChassisID:
			// Mark the Chassis ID present ONLY when the value is long enough
			// to yield a real identifier. A subtype byte alone (len < 2) or a
			// MAC-subtype value short of the 6-byte address (len < 7) is a
			// truncated TLV: leaving hasChassis false makes the terminal check
			// reject the frame rather than caching it under an empty key
			// (#2551).
			if len(value) >= 2 && value[0] == chassisSubtypeMACAddr {
				if len(value) >= 7 {
					n.ChassisID = net.HardwareAddr(value[1:7]).String()
					hasChassis = true
				}
				// MAC subtype with len 2..6 is truncated for its own subtype —
				// do not accept it.
			} else if len(value) >= 2 {
				// Non-MAC chassis-id subtypes carry a free-text identifier
				// straight off the wire — sanitize display controls (#4043, #10899).
				n.ChassisID = sanitizeTLVString(string(value[1:]))
				hasChassis = true
			}
		case tlvPortID:
			// Same gating as Chassis ID: a subtype byte with no identifier
			// (len < 2) is truncated, so leave hasPort false (#2551).
			if len(value) >= 2 {
				// Port-id is untrusted L2 input — sanitize display controls so a
				// crafted TLV can't inject ANSI/CRLF or bidi/format controls into
				// the log or `show lldp neighbors` table (#4043, #10899).
				n.PortID = sanitizeTLVString(string(value[1:]))
				hasPort = true
			}
		case tlvTTL:
			// hasTTL gates on the 2-byte PARSE succeeding, not on a non-zero
			// value: a valid 2-byte TTL of 0 is a legitimate shutdown advert
			// (RFC IEEE 802.1AB) and must be accepted; only a TLV shorter than
			// 2 bytes is truncated and leaves hasTTL false (#2551).
			if len(value) >= 2 {
				n.TTL = int(binary.BigEndian.Uint16(value[:2]))
				hasTTL = true
			}
		case tlvSystemName:
			// Operator-visible free-text TLVs from an untrusted neighbor —
			// sanitize display controls before storing (#4043, #10899).
			n.SystemName = sanitizeTLVString(string(value))
		case tlvSystemDesc:
			n.SystemDesc = sanitizeTLVString(string(value))
		case tlvPortDesc:
			n.PortDesc = sanitizeTLVString(string(value))
		}
	}

done:
	if !hasChassis || !hasPort || !hasTTL {
		return nil
	}
	return n
}

func htons(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return binary.NativeEndian.Uint16(b)
}
