package ra

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
)

const (
	// Default RA timing per RFC 4861.
	defaultMaxAdvInterval = 600  // seconds
	defaultRouterLifetime = 1800 // seconds

	// minAdvInterval is the hard runtime floor for the unsolicited periodic
	// RA timer (#4525). RFC 4861 §6.2.1 requires MinRtrAdvInterval >= 3s, but
	// a legacy/mis-typed config (e.g. max-advertisement-interval 1 committed
	// before the schema floor existed, so minI derives to 0) could otherwise
	// draw a 0-second delay. advTimer.Reset(0) fires immediately → sendRA →
	// re-arm → CPU spin + RA/ND flood. Flooring the drawn interval at 1s makes
	// the hot-loop unreachable regardless of how the config reaches the sender
	// (commit, tolerant load, or HA peer-sync). The RFC-4861 §6.2.1 [4,1800]
	// commit-time schema floor is the primary guard; this is the belt.
	minAdvInterval = 1 * time.Second

	// RFC 4861 §6.2.6: minimum delay between multicast RAs triggered by RS.
	minRAMulticastDelay = 3 * time.Second

	// Maximum random delay before responding to an RS.
	maxRSDelay = 500 * time.Millisecond

	// Number of goodbye RAs to send (for reliability).
	goodbyeCount = 3
	// Delay between goodbye RAs.
	goodbyeDelay = 50 * time.Millisecond
	// Number of startup RAs to send so hosts quickly relearn a default router
	// after daemon restart, failover, or link flap.
	startupBurstCount = 3
	// Delay between startup RAs.
	startupBurstDelay = 100 * time.Millisecond

	// Default prefix lifetimes per RFC 4861.
	defaultValidLifetime     = 2592000 // 30 days
	defaultPreferredLifetime = 604800  // 7 days

	// writeDeadline bounds every owner WriteTo so a stuck socket cannot wedge
	// withdrawal (#2033 I18 / Codex r3 MODERATE #4). Because the owner always
	// returns promptly, owner-performs-the-close (I17) is safe for both modes.
	writeDeadline = 1 * time.Second

	// rsReadDeadline bounds each rsReceiver ReadFrom so it can observe stopCh.
	rsReadDeadline = 1 * time.Second
	// rsErrBackoff is applied after a persistent (non-deadline) read error so
	// rsReceiver cannot hot-loop at 100% CPU if the interface dies while stopCh
	// is still open (#2033 I10 / AGY r4 MINOR #4).
	rsErrBackoff = 200 * time.Millisecond
)

// shutdownMode is the arbitrated teardown intent for a sender. It is set
// (atomically) BEFORE stopCh is closed, so any owner wakeup that observes the
// closed channel also observes the mode. graceful UPGRADES hard (never the
// reverse) — see signalStop (#2033 I13/I17).
type shutdownMode int32

const (
	modeNone     shutdownMode = iota // running
	modeHard                         // stop without a goodbye (Clear / Apply-remove)
	modeGraceful                     // emit the lifetime-0 goodbye as the final write
)

// ndpConn is the minimal subset of *ndp.Conn that sender uses. It exists as a
// compile-time seam so tests can substitute a recorder/injector (fakeConn)
// without a live NDP socket. The signatures MUST match mdlayher/ndp v1.1.0
// exactly: ndp.Message + *ipv6.ControlMessage + netip.Addr on WriteTo/ReadFrom,
// *ipv6.ICMPFilter on SetICMPFilter, netip.Addr group on JoinGroup,
// ipv6.ControlFlags + on/off on SetControlMessage. Do not widen this interface
// beyond what sender needs.
type ndpConn interface {
	WriteTo(m ndp.Message, cm *ipv6.ControlMessage, dst netip.Addr) error
	ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error)
	Close() error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	JoinGroup(group netip.Addr) error
	SetICMPFilter(f *ipv6.ICMPFilter) error
	// SetControlMessage enables/disables per-packet control-message fields on
	// receive. sender enables ipv6.FlagHopLimit so rsReceiver can enforce the
	// RFC 4861 §6.1.1 Hop-Limit==255 check on Router Solicitations (#5095).
	SetControlMessage(cf ipv6.ControlFlags, on bool) error
}

// listenFn opens an ndpConn for the interface. Overridable in tests; defaults
// to the real mdlayher/ndp Listen.
var listenFn = func(iface *net.Interface, addr ndp.Addr) (ndpConn, netip.Addr, error) {
	return ndp.Listen(iface, addr)
}

// ensureLinkLocalFn lets tests stub the link-local setup (a pure netlink
// AddrAdd after #2034) so the goodbye-only WithdrawOnce path can be asserted to
// SKIP it entirely (#2033 I12 — it must not even attempt to add a link-local on
// a demoting interface). Defaults to the real implementation.
var ensureLinkLocalFn = ensureLinkLocal

// interfaceByNameFn re-resolves a *net.Interface (ifindex + hardware address)
// by name. It backs both listen()'s bind-retry re-read and the pre-burst MAC
// refresh (#5302). Overridable in tests so a MAC change can be injected without
// a real netlink round-trip. Defaults to net.InterfaceByName.
var interfaceByNameFn = net.InterfaceByName

// sender is a per-interface RA sender goroutine.
//
// Single-owner contract (#2033, Path A): run() is the SOLE writer/closer of the
// NDP connection — startup burst, periodic RAs, RS-triggered RAs AND the
// goodbye all flow through it. No other goroutine calls conn.WriteTo or
// conn.Close. Shutdown is signalled via signalStop (sets mode, closes stopCh
// once); the owner reads mode after waking and, on modeGraceful, emits the
// lifetime-0 goodbye as its FINAL action in finishShutdown — guaranteeing no
// lifetime>0 RA follows the goodbye on the wire.
type sender struct {
	cfg   *config.RAInterfaceConfig
	iface *net.Interface
	conn  ndpConn

	// srcAddr is the bound link-local source address. Since openConn now runs
	// in the owner goroutine (#2453), the owner WRITES srcAddr without m.mu
	// while Manager.Status READS it under m.mu — so it must carry its own
	// guard. srcMu is that guard; use getSrcAddr/setSrcAddr, never the field
	// directly off-goroutine.
	srcMu   sync.Mutex
	srcAddr netip.Addr

	mode     atomic.Int32 // shutdownMode; set BEFORE close(stopCh)
	stopOnce sync.Once    // guards close(stopCh)
	stopCh   chan struct{}
	stopped  chan struct{}
	burstCh  chan struct{} // buffered(1): request a re-burst (ResendBurst)

	// connReady is closed by the owner goroutine ONCE the openConn attempt has
	// resolved (whether it opened the conn or gave up). It lets a caller observe
	// the end of the async socket-open window without blocking the owner under
	// m.mu. connOpened records whether that resolution actually produced a live
	// conn (true) or gave up / was pre-empted by a stop (false). The manager's
	// changed-config replace path waits on connReady so Apply returns only once
	// the REPLACEMENT RA conn is live — a make-before-break guarantee that there
	// is no observable 0-live-conn window across a config replace (#2834). Both
	// are written exactly once by the owner before any waiter is released:
	// connOpened is stored BEFORE close(connReady), so a waiter that observes the
	// closed channel also observes the stored value (Go memory model).
	connReady    chan struct{}
	connReadyOne sync.Once
	connOpened   atomic.Bool

	// goodbyeEmitted records whether finishShutdown actually emitted the
	// lifetime-0 goodbye. The manager reads it AFTER the join (<-stopped) to
	// decide whether it still OWES a standalone goodbye for a graceful
	// withdrawal that lost the upgrade race (the owner already read modeHard
	// and exited before the graceful upgrade landed — a dead sender cannot be
	// resurrected). This makes "exactly one goodbye per withdrawn interface" a
	// post-mortem fact, not a timing gamble (#2033 MAJOR 2 / restart window).
	goodbyeEmitted atomic.Bool

	lastRAMu sync.Mutex
	lastRA   time.Time // rate-limit RS responses; owner writes, Status reads
}

func newSender(cfg *config.RAInterfaceConfig, iface *net.Interface) *sender {
	return &sender{
		cfg:       cfg,
		iface:     iface,
		stopCh:    make(chan struct{}),
		stopped:   make(chan struct{}),
		burstCh:   make(chan struct{}, 1),
		connReady: make(chan struct{}),
	}
}

// start launches the sender goroutine. It does NOT open the NDP connection
// itself — the socket open (ensureLinkLocal + the link-local bind RETRY, which
// sleeps up to ~2s while a settling/RETH link-local appears) is performed by
// the owner goroutine in openConn() BEFORE it enters its main loop (#2453).
//
// Why the open moved off this path: start() is called from
// Manager.startLocked while the manager mutex m.mu is held. Doing the
// multi-second bind retry under m.mu serialized every other RA manager op
// (a VRRP-failover Withdraw, or an Apply on a DIFFERENT interface) behind the
// retry — control-plane latency up to ~2s. Launching the goroutine and
// returning immediately keeps the m.mu critical section to just the
// s.senders bookkeeping; the bind retry runs fully UNLOCKED.
//
// start() therefore never returns a listen/bind error (the open is async); the
// only error it can return is a programming-level one, and there are none here.
// A bind that ultimately fails is logged by openConn and the owner exits
// cleanly (closing s.stopped) so the manager's join/release path still
// completes. s.conn is opened, used, and closed solely by the owner goroutine,
// preserving the single-owner contract (#2033).
func (s *sender) start() error {
	go s.run()
	return nil
}

// signalConnReady records the result of the owner's openConn attempt and
// releases any waiter on connReady. Owner-only; idempotent. opened MUST be
// stored before the channel is closed so a waiter that observes the close also
// observes the value.
func (s *sender) signalConnReady(opened bool) {
	s.connReadyOne.Do(func() {
		s.connOpened.Store(opened)
		close(s.connReady)
	})
}

// waitConnReady blocks until the owner's openConn attempt has resolved (the
// conn is live or the open gave up / was pre-empted by a stop), or until the
// bounded deadline elapses. It returns true only when a live conn was actually
// opened. It is used by the changed-config replace path so Apply returns only
// once the REPLACEMENT RA conn is live — closing the make-before-break gap that
// would otherwise leave a brief 0-live-conn window after a config replace
// (#2834). It NEVER holds m.mu: the wait is the async socket-open latency, which
// must not serialize other RA manager operations.
func (s *sender) waitConnReady(timeout time.Duration) bool {
	// #4830: time.After inside a select leaks its Timer in the runtime's
	// timer heap until it fires (up to `timeout`) whenever the OTHER case
	// (s.connReady) wins the select first — which is the common, fast path
	// here. time.NewTimer + a deferred Stop reclaims it immediately instead.
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-s.connReady:
		return s.connOpened.Load()
	case <-t.C:
		return false
	}
}

// openConn performs the (potentially slow) NDP socket open for the owner
// goroutine: ensure a link-local exists, then bind with the bounded retry. It
// is INTERRUPTIBLE by stopCh — a withdraw/clear signalled while the bind is
// still retrying aborts promptly instead of blocking up to ~2s. It returns
// false if no connection was opened (bind failed after all retries, or a stop
// was signalled mid-retry); in that case the owner must go straight to
// finishShutdown without a live conn.
//
// On success s.conn / s.srcAddr are set (owner-only writes), the all-routers
// group is joined, and the RS-only ICMPv6 filter is installed.
func (s *sender) openConn() bool {
	// A stop signalled before we even begin: do not open a conn.
	select {
	case <-s.stopCh:
		return false
	default:
	}

	if err := ensureLinkLocalFn(s.iface); err != nil {
		slog.Warn("ra: failed to ensure link-local", "interface", s.iface.Name, "err", err)
	}

	conn, srcAddr, err := s.listen()
	if err != nil {
		slog.Warn("ra: failed to open NDP connection (giving up after retries)",
			"interface", s.cfg.Interface, "err", err)
		return false
	}
	s.conn = conn
	s.setSrcAddr(srcAddr)

	// Request the received IP Hop Limit on each packet so rsReceiver can enforce
	// the RFC 4861 §6.1.1 Router Solicitation check (Hop Limit MUST be 255 — a
	// value forwarding would have decremented, so 255 proves the RS originated
	// on-link). If the socket cannot report the hop limit, rsReceiver fails
	// closed (rejects all RS): solicited RAs pause until the next periodic RA
	// rather than answering a possibly off-link/spoofed solicitation (#5095).
	if err := s.conn.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
		slog.Warn("ra: failed to request RS hop-limit control message; "+
			"solicited RAs will be held (periodic RAs continue)",
			"interface", s.cfg.Interface, "err", err)
	}

	// Join all-routers multicast to receive Router Solicitations.
	allRouters := netip.MustParseAddr("ff02::2")
	if err := s.conn.JoinGroup(allRouters); err != nil {
		slog.Warn("ra: failed to join all-routers group",
			"interface", s.cfg.Interface, "err", err)
	}

	// Set ICMPv6 filter to accept only Router Solicitations (type 133).
	var f ipv6Filter
	f.setAllowRS()
	if err := s.conn.SetICMPFilter(f.filter()); err != nil {
		slog.Warn("ra: failed to set ICMPv6 filter",
			"interface", s.cfg.Interface, "err", err)
	}
	return true
}

// errGoodbyeWrite is returned by the standalone goodbye path when the bind
// succeeded but the lifetime-0 RA write itself failed. Callers (WithdrawOnce /
// the daemon cold-boot one-shot) MUST surface this and retain retry debt rather
// than record a false success — a swallowed write failure lets the old IPv6
// default-router identity live on hosts (ECMP to an inactive node) until Router
// Lifetime expiry while operators see success (#5093).
var errGoodbyeWrite = errors.New("ra: goodbye RA write failed")

// errGoodbyeIfaceMissing marks a goodbye that could not even be attempted
// because the netdev no longer exists. It is PERMANENT, unlike errGoodbyeWrite
// and a bind failure: there is no link to emit on and no host behind it left to
// hear a lifetime-0 RA, so the #6777 retry debt deliberately does NOT retain it
// (see recordGoodbyeDebtLocked). Retaining it would make a legitimately removed
// interface a permanent Apply error, suppressing the daemon's RA reconcile
// digest forever.
var errGoodbyeIfaceMissing = errors.New("ra: goodbye interface missing")

// sendGoodbyeStandalone is the WithdrawOnce goodbye-only entry point. It opens
// a connection, emits the lifetime-0 goodbye, and closes — WITHOUT launching
// run() and WITHOUT the startup burst (so it never re-advertises the router it
// is withdrawing — fixes S1). Per #2033 I12 it MUST NOT toggle the link: if no
// usable link-local exists, ndp.Listen fails and the goodbye is skipped
// best-effort rather than cycling a demoting interface (which may be mid-RETH-
// MAC-cycle). It returns nil only when the goodbye actually went out; a bind
// failure OR a lifetime-0 write failure returns a non-nil error so the caller
// can surface it and retry (#5093). The conn is opened and closed here.
func (s *sender) sendGoodbyeStandalone() error {
	conn, srcAddr, err := s.listen()
	if err != nil {
		return err
	}
	s.conn = conn
	s.setSrcAddr(srcAddr)
	defer s.conn.Close()
	if !s.sendGoodbyeRA() {
		return fmt.Errorf("%w on %s", errGoodbyeWrite, s.cfg.Interface)
	}
	return nil
}

// getSrcAddr / setSrcAddr guard the bound source address against the
// owner-writes / Status-reads race (#2453). See the srcMu field comment.
func (s *sender) getSrcAddr() netip.Addr {
	s.srcMu.Lock()
	defer s.srcMu.Unlock()
	return s.srcAddr
}

func (s *sender) setSrcAddr(a netip.Addr) {
	s.srcMu.Lock()
	s.srcAddr = a
	s.srcMu.Unlock()
}

// listen opens the NDP connection with the configured bind address, retrying
// while the link-local address settles after ensureLinkLocal.
func (s *sender) listen() (ndpConn, netip.Addr, error) {
	var bindAddr ndp.Addr = ndp.LinkLocal
	if s.cfg.SourceLinkLocal != "" {
		bindAddr = ndp.Addr(s.cfg.SourceLinkLocal)
	}

	var conn ndpConn
	var srcAddr netip.Addr
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		conn, srcAddr, err = listenFn(s.iface, bindAddr)
		if err == nil {
			return conn, srcAddr, nil
		}
		// Re-read interface (link-local may appear after addr add). The sleep is
		// interruptible by stopCh (#2453): a withdraw/clear signalled while the
		// bind is still retrying aborts the retry promptly rather than running
		// the full ~2s. Since this loop now runs in the owner goroutine
		// (unlocked), the abort frees nothing held by the manager — it just lets
		// the owner reach finishShutdown sooner.
		t := time.NewTimer(200 * time.Millisecond)
		select {
		case <-s.stopCh:
			t.Stop()
			return nil, netip.Addr{}, err
		case <-t.C:
		}
		if iface, e := interfaceByNameFn(s.iface.Name); e == nil {
			s.iface = iface
		}
	}
	return nil, netip.Addr{}, err
}

// signalStop publishes the teardown intent then closes stopCh exactly once.
//
// The mode store happens-before the close (which in turn happens-before the
// owner's wakeup on the closed channel — Go memory model), so the owner that
// observes the closed stopCh also observes the mode.
//
// GRACEFUL UPGRADES HARD (#2033 I13/I17): in cluster mode a demotion Withdraw
// (VRRP-event goroutine, no applySem) can race a config-apply Clear for the
// same sender — pkg/ra's m.mu is the ONLY serialization. First-writer-wins
// would let a benign Clear drop the demotion goodbye (the exact bug). So a
// graceful request wins over a hard one: graceful is stored unconditionally,
// hard only if nothing was set yet. NEVER downgrade graceful->hard. Because
// the owner performs conn.Close AFTER emitting the goodbye (finishShutdown,
// I17), a racing hard close can never kill the upgraded goodbye. The only
// residual is the sub-microsecond window where the owner already read modeHard
// before the upgrade store — accepted as best-effort (the new primary's RA is
// the real recovery).
func (s *sender) signalStop(m shutdownMode) {
	if m == modeGraceful {
		s.mode.Store(int32(modeGraceful))
	} else {
		s.mode.CompareAndSwap(int32(modeNone), int32(modeHard))
	}
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// stop tears the sender down WITHOUT a goodbye (Clear / Apply-remove). The
// owner closes the conn in finishShutdown.
func (s *sender) stop() { s.signalStop(modeHard); <-s.stopped }

// withdrawAndStop tears the sender down emitting the lifetime-0 goodbye as the
// final write (graceful demotion).
func (s *sender) withdrawAndStop() { s.signalStop(modeGraceful); <-s.stopped }

// requestBurst asks the owner to re-emit the startup burst (after a RETH MAC
// link cycle killed the socket). Non-blocking: if a burst is already queued or
// the sender is draining, the request is dropped.
func (s *sender) requestBurst() {
	if s.draining() {
		return
	}
	select {
	case s.burstCh <- struct{}{}:
	default:
	}
}

// draining reports whether a shutdown has been signalled. It is a best-effort
// early-out for the burst/RS paths; the correctness mechanism is that the
// goodbye is owner-emitted on exit (so any in-flight normal RA necessarily
// PRECEDES it).
func (s *sender) draining() bool { return s.mode.Load() != int32(modeNone) }

// refreshInterfaceForBurst re-resolves s.iface (ifindex + hardware address) via
// interfaceByNameFn so a post-link-cycle burst advertises the CURRENT source
// link-layer address, not the net.Interface value snapshot cached at Start
// (#5302, codex-review-178 A5-b1-F5). A day-2 RETH/VLAN virtual-MAC change
// (failover / becomeMaster) reprograms the MAC while the RA config is
// unchanged, so RA reconciliation keeps this sender and only requests a burst.
// Without this re-resolve the burst marshals the OLD cached MAC into the SLLA
// option, and hosts point the router's neighbor entry at a MAC the active node
// no longer owns — an IPv6 blackhole, the exact opposite of the burst's
// neighbor-repair intent.
//
// Owner-only WRITE: the write s.iface = iface below runs in the run() goroutine,
// the sole writer of s.iface (listen()'s bind-retry re-read runs only during
// openConn before the main loop, never concurrently). The only cross-goroutine
// READER of s.iface — rsReceiver's RFC 4861 §6.1.1 discard log — now reads the
// immutable s.cfg.Interface instead, so no lock is needed: s.iface is written by
// a single goroutine and read by none other. (s.iface.Name is invariant across
// the write anyway — net.InterfaceByName returns an iface whose Name equals the
// queried name — so even the prior read was value-benign.) A successful refresh
// also freshens the MAC used by subsequent periodic sendRA calls. On failure it
// returns false and logs; the caller then SKIPS the burst rather than advertise
// a known-stale SLLA (advertising a stale MAC is worse than sending nothing —
// host NUD and the next successful refresh recover neighbor state).
func (s *sender) refreshInterfaceForBurst() bool {
	iface, err := interfaceByNameFn(s.iface.Name)
	if err != nil {
		slog.Warn("ra: failed to refresh interface before burst; skipping burst to avoid advertising a stale source link-layer address",
			"interface", s.iface.Name, "err", err)
		return false
	}
	s.iface = iface
	return true
}

// dead reports whether this sender's owner goroutine resolved its openConn
// attempt WITHOUT producing a live NDP conn — i.e. the bind gave up after all
// retries, or a stop pre-empted the open before it succeeded. Such a sender
// will never emit an RA: its run() goes straight to finishShutdown and exits.
//
// connOpened is stored BEFORE close(connReady) (signalConnReady), so observing
// the closed channel guarantees the stored value is visible (Go memory model).
// A sender whose open is still in flight (connReady not yet closed) is NOT
// dead — it may still come up — so this returns false until the attempt has
// resolved. The manager uses this in its Apply reconcile to REBUILD a sender
// that failed its initial open instead of treating the config-unchanged entry
// as healthy and skipping it forever (#2865): a transient boot-time bind
// failure (link still doing DAD / link-local not yet present) then recovers on
// the next reconcile without any config change.
func (s *sender) dead() bool {
	select {
	case <-s.connReady:
		return !s.connOpened.Load()
	default:
		return false
	}
}

// run is the single-owner sender loop. It is the ONLY goroutine that writes or
// closes the connection.
func (s *sender) run() {
	defer close(s.stopped)

	// Open the NDP conn (ensureLinkLocal + the bounded, interruptible bind
	// retry) HERE, in the owner goroutine, not under the manager mutex (#2453).
	// If it fails (bind gave up, or a stop was signalled mid-retry) there is no
	// conn to emit on: go straight to finishShutdown, which tolerates a nil conn
	// (no goodbye is written, goodbyeEmitted stays false → the manager's
	// release-time backstop emits a standalone goodbye if one was owed).
	if !s.openConn() {
		// The open attempt resolved (failed or pre-empted by a stop). Release any
		// waiter on connReady BEFORE finishShutdown so a make-before-break Apply
		// does not block for the full timeout on a sender that will never serve.
		s.signalConnReady(false)
		s.finishShutdown()
		return
	}
	s.signalConnReady(true)

	// A stop may have been signalled while the conn was opening. Honor it before
	// emitting the startup burst (burstInterruptible also short-circuits, but
	// this avoids even the first burst RA after a withdraw).
	if s.draining() {
		s.finishShutdown()
		return
	}

	// Interruptible startup burst so a withdraw during startup cannot leave a
	// normal RA after the goodbye.
	s.burstInterruptible()
	if s.draining() {
		s.finishShutdown()
		return
	}

	advTimer := time.NewTimer(s.randomAdvInterval())
	defer advTimer.Stop()

	rsCh := make(chan netip.Addr, 8)
	go s.rsReceiver(rsCh)

	for {
		select {
		case <-s.stopCh:
			s.finishShutdown()
			return

		case <-s.burstCh:
			// #5302: re-resolve the interface's current MAC BEFORE the burst so
			// the SLLA reflects a post-link-cycle virtual-MAC change; skip the
			// burst on a refresh failure rather than advertise a stale SLLA.
			if s.refreshInterfaceForBurst() {
				s.burstInterruptible()
			}

		case <-advTimer.C:
			s.sendRA()
			advTimer.Reset(s.randomAdvInterval())

		case _, ok := <-rsCh:
			if !ok {
				// rsReceiver only closes rsCh after observing stopCh (I14),
				// so this implies shutdown is already in progress.
				s.finishShutdown()
				return
			}
			// Rate-limit multicast RA responses per RFC 4861 §6.2.6.
			if time.Since(s.getLastRA()) < minRAMulticastDelay {
				continue
			}
			// Random delay before responding, interruptible by shutdown.
			t := time.NewTimer(time.Duration(rand.IntN(int(maxRSDelay))))
			select {
			case <-s.stopCh:
				t.Stop()
				s.finishShutdown()
				return
			case <-t.C:
			}
			s.sendRA()
			// Re-pace the unsolicited schedule off this solicited RA (RFC 4861
			// §6.2.6). This Reset is not preceded by a drain of advTimer.C, so
			// in the rare interleave where advTimer fired while this RS was being
			// handled and select picked the RS arm, the next loop iteration may
			// read a stale fire and emit one early unsolicited RA. That is a
			// benign, idempotent extra RA (never a goodbye-ordering violation),
			// so the drain dance is intentionally omitted in this single-owner
			// loop.
			advTimer.Reset(s.randomAdvInterval())
		}
	}
}

// finishShutdown is the ONLY place the goodbye is emitted AND the ONLY place
// the conn is closed (#2033 I17). It runs on the owner after the loop is gone,
// so no normal RA can follow the goodbye. The mode is re-read here, honoring a
// graceful upgrade that landed before the owner woke. The conn is closed AFTER
// the goodbye, which also unblocks the detached rsReceiver's ReadFrom (I10).
func (s *sender) finishShutdown() {
	// No conn was ever opened (openConn failed or a stop landed mid bind-retry).
	// There is nothing to emit on and nothing to close. Leave goodbyeEmitted=
	// false so the manager's release-time backstop (sendOneGoodbye on a FRESH
	// conn) still emits a standalone goodbye if a graceful withdraw owed one
	// (#2453). This mirrors the conn==nil tail below; we return early so the
	// graceful branch never dereferences a nil conn.
	if s.conn == nil {
		return
	}
	if shutdownMode(s.mode.Load()) == modeGraceful {
		// Record the fact for the manager's post-join owes-a-goodbye check, but
		// ONLY if the goodbye actually went out. On a write failure (interface
		// down mid-withdraw) leave goodbyeEmitted=false so the manager's
		// release-time backstop (ra.go: !goodbyeEmitted) retries the goodbye on
		// a FRESH conn (sendOneGoodbye -> newSender) — the owner's conn is
		// closed just below and cannot be retried here. Goodbyes are idempotent
		// (repeated lifetime=0) and the backstop emits only goodbyes, so the
		// retry cannot violate the goodbye-is-last ordering invariant.
		// Set AFTER the send and BEFORE close(s.stopped) (the caller's defer),
		// so a manager that observes <-stopped also observes this store.
		if s.sendGoodbyeRA() {
			s.goodbyeEmitted.Store(true)
		}
	}
	if s.conn != nil {
		s.conn.Close()
	}
}

// burstInterruptible emits the startup burst (startupBurstCount normal RAs),
// checking draining()/stopCh between sends so a concurrent withdraw stops the
// burst immediately. A legitimate start emits all RAs (I3); a draining sender
// short-circuits (I11/I15).
func (s *sender) burstInterruptible() {
	for i := 0; i < startupBurstCount; i++ {
		if s.draining() {
			return
		}
		s.sendRA()
		if i < startupBurstCount-1 {
			t := time.NewTimer(startupBurstDelay)
			select {
			case <-s.stopCh:
				t.Stop()
				return
			case <-t.C:
			}
		}
	}
}

// rsReceiver reads Router Solicitations and forwards them to the channel. It is
// a detached goroutine bounded by the owner's conn.Close (I10): the owner exits
// on stopCh regardless of rsCh state, then closes the conn, which unblocks this
// ReadFrom within one deadline at worst. It backs off on a persistent
// non-deadline read error so it cannot hot-loop if the interface dies while
// stopCh is still open (I10 / AGY r4 MINOR #4). It returns (closing rsCh) ONLY
// after observing stopCh (I14), so the owner's "rsCh closed" branch always
// implies shutdown is already in progress.
func (s *sender) rsReceiver(ch chan<- netip.Addr) {
	defer close(ch)
	for {
		s.conn.SetReadDeadline(time.Now().Add(rsReadDeadline))
		msg, cm, src, err := s.conn.ReadFrom()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
			}
			// Not shutting down: a deadline timeout is the expected poll
			// signal; any other persistent error must not hot-loop.
			if !isTimeout(err) {
				t := time.NewTimer(rsErrBackoff)
				select {
				case <-s.stopCh:
					t.Stop()
					return
				case <-t.C:
				}
			}
			continue
		}

		if _, ok := msg.(*ndp.RouterSolicitation); !ok {
			continue
		}

		// RFC 4861 §6.1.1 Router Solicitation receive validation: silently
		// discard an RS that fails the on-link / source-scope checks so an
		// off-link or spoofed solicitation cannot trigger a multicast RA
		// (RA-injection / DoS surface, #5095). Fail closed.
		if !validRSReceive(cm, src) {
			slog.Debug("ra: discarding Router Solicitation failing RFC 4861 §6.1.1 "+
				"receive validation (hop-limit != 255 or off-link source)",
				"interface", s.cfg.Interface, "src", src)
			continue
		}

		select {
		case ch <- src:
		default:
		}
	}
}

// validRSReceive applies the RFC 4861 §6.1.1 Router Solicitation receive checks
// that guard the RA-trigger path (#5095):
//
//   - the IP Hop Limit MUST be 255 — a value that IP forwarding would have
//     decremented, so 255 proves the RS provably originated on-link; and
//   - the IP source address MUST be the unspecified address (::) or a
//     link-local unicast (fe80::/10) — the only sources a conformant solicitor
//     uses. Any global/ULA/multicast source is rejected.
//
// A nil control message means the received hop limit is unavailable, so it
// fails closed. This blocks an off-link or spoofed RS from triggering an RA.
func validRSReceive(cm *ipv6.ControlMessage, src netip.Addr) bool {
	if cm == nil || cm.HopLimit != 255 {
		return false
	}
	src = src.Unmap()
	return src.IsUnspecified() || src.IsLinkLocalUnicast()
}

// isTimeout reports whether err is an i/o deadline timeout (the expected
// rsReceiver poll signal) rather than a genuine socket error.
func isTimeout(err error) bool {
	type timeout interface{ Timeout() bool }
	te, ok := err.(timeout)
	return ok && te.Timeout()
}

// getLastRA returns the last-RA timestamp under lastRAMu.
func (s *sender) getLastRA() time.Time {
	s.lastRAMu.Lock()
	defer s.lastRAMu.Unlock()
	return s.lastRA
}

// setLastRA records the last-RA timestamp under lastRAMu.
func (s *sender) setLastRA(t time.Time) {
	s.lastRAMu.Lock()
	s.lastRA = t
	s.lastRAMu.Unlock()
}

// sendRA sends a normal Router Advertisement to all-nodes multicast (ff02::1).
// Owner-only.
func (s *sender) sendRA() {
	ra := s.buildRA()
	allNodes := netip.MustParseAddr("ff02::1")
	s.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
	if err := s.conn.WriteTo(ra, nil, allNodes); err != nil {
		slog.Warn("ra: failed to send RA",
			"interface", s.cfg.Interface, "err", err)
		return
	}
	s.setLastRA(time.Now())
	slog.Debug("ra: sent RA", "interface", s.cfg.Interface)
}

// sendGoodbyeRA sends goodbye RAs (lifetime=0) multiple times for reliability.
// Owner-only — emitted as the final write in finishShutdown. It returns true
// only when the full sequence was written without error; a write failure
// returns false so finishShutdown leaves goodbyeEmitted=false and the manager's
// release-time backstop retries the goodbye on a fresh conn. The standalone
// backstop path, sendGoodbyeStandalone, now surfaces this bool as an error
// (errGoodbyeWrite, #5093) so its caller (WithdrawOnce) reports the failure and
// the cold-boot one-shot retains retry debt for the reconcile ticker to retry.
func (s *sender) sendGoodbyeRA() bool {
	ra := s.buildRA()
	ra.RouterLifetime = 0
	allNodes := netip.MustParseAddr("ff02::1")

	for i := 0; i < goodbyeCount; i++ {
		s.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
		if err := s.conn.WriteTo(ra, nil, allNodes); err != nil {
			slog.Warn("ra: failed to send goodbye RA",
				"interface", s.cfg.Interface, "err", err)
			return false
		}
		if i < goodbyeCount-1 {
			time.Sleep(goodbyeDelay)
		}
	}
	slog.Info("ra: goodbye RA sent (lifetime=0)", "interface", s.cfg.Interface)
	return true
}

// buildRA constructs a Router Advertisement from the config.
func (s *sender) buildRA() *ndp.RouterAdvertisement {
	// #4119: an EXPLICIT default-lifetime (DefaultLifetimeSet) is honored
	// verbatim, including 0 — RFC 4861 §6.2.1 Router Lifetime 0 means "this
	// router is NOT a default router" (hosts drop it from their default-router
	// list but may still use the prefixes/PREF64 it advertises). Only an UNSET
	// default-lifetime falls back to defaultRouterLifetime (1800). The old
	// `if lifetime <= 0` coercion made an explicit 0 indistinguishable from
	// unset and forced it to 1800, so xpf could never advertise "not a default
	// router" and hijacked host default-route selection on multi-router LANs.
	lifetime := defaultRouterLifetime
	if s.cfg.DefaultLifetimeSet {
		lifetime = s.cfg.DefaultLifetime
	}

	// Dependent options (RDNSS, PREF64) that inherit a lifetime default MUST
	// NOT collapse to 0 just because the ROUTER lifetime is an explicit 0:
	// their independent lifetimes govern whether hosts keep using the DNS
	// server / NAT64 prefix, and the whole point of Router Lifetime 0 is to
	// keep advertising those while declining default-router duty. Fall back to
	// the standard 1800s default for a dependent option whenever the resolved
	// router lifetime is not positive (identical to the pre-#4119 value, which
	// was always >= 1800). The Prefix Information options are unaffected — they
	// carry their own valid/preferred lifetimes (30d/7d) already.
	optLifetime := lifetime
	if optLifetime <= 0 {
		optLifetime = defaultRouterLifetime
	}

	ra := &ndp.RouterAdvertisement{
		CurrentHopLimit:      64,
		ManagedConfiguration: s.cfg.ManagedConfig,
		OtherConfiguration:   s.cfg.OtherStateful,
		// #8597 (muse-004 K72): bound the three RA header timers before they
		// reach ndp's unsigned marshal. The typed-leaf schema bounds all three
		// to [0, max] at strict commit, and that gate is STRICT-only: the
		// tolerant Load / peer-sync ingress downgrades it to a warning, so a
		// negative or oversized value reaches here intact.
		//
		// Measured on the wire before the fix (ndp.MarshalMessage of buildRA):
		//
		//	DefaultLifetime = -1  ->  Router Lifetime 65535  (~18 hours)
		//	ReachableTime   = -1  ->  4294967295 ms          (~49 days)
		//	RetransTimer    = -1  ->  4294967295 ms
		//
		// A NEGATIVE router lifetime therefore advertises this box as a default
		// router for the MAXIMUM the field can express — the opposite of what a
		// nonsensical value should mean, and the field's own neutral (0 = "not
		// a default router") was one clamp away.
		//
		// pruneUnmarshalableOptions probes only the OPTIONS for a marshal
		// abort; the header fields marshal without complaint precisely because
		// they wrap silently.
		//
		// Flooring at 0 does not invent an intent: 0 is the documented neutral
		// for all three fields — "not a default router" for the lifetime,
		// "unspecified, use your own defaults" for the other two — and is what
		// the RA already carried before these leaves existed. Saturating at the
		// top is the honest encoding of "as long as the field allows" and is
		// monotone, where wrapping is not.
		RouterLifetime: time.Duration(clampRAHeaderSeconds(lifetime)) * time.Second,
		// RFC 4861 §4.2 Reachable Time / Retrans Timer (#4307). ndp
		// marshals these as ms (Duration/time.Millisecond -> uint32); a
		// configured 0 keeps the "unspecified" default the RA carried
		// before these leaves existed.
		ReachableTime:   time.Duration(clampRAHeaderMillis(s.cfg.ReachableTime)) * time.Millisecond,
		RetransmitTimer: time.Duration(clampRAHeaderMillis(s.cfg.RetransTimer)) * time.Millisecond,
	}

	// Router selection preference.
	switch s.cfg.Preference {
	case "high":
		ra.RouterSelectionPreference = ndp.High
	case "low":
		ra.RouterSelectionPreference = ndp.Low
	default:
		ra.RouterSelectionPreference = ndp.Medium
	}

	// Source link-layer address (includes RETH virtual MAC).
	ra.Options = append(ra.Options, &ndp.LinkLayerAddress{
		Direction: ndp.Source,
		Addr:      s.iface.HardwareAddr,
	})

	// Prefix Information options.
	for _, pfx := range s.cfg.Prefixes {
		prefix, err := netip.ParsePrefix(pfx.Prefix)
		if err != nil {
			slog.Warn("ra: invalid prefix, skipping",
				"prefix", pfx.Prefix, "err", err)
			continue
		}

		validLife := pfx.ValidLifetime
		if validLife <= 0 {
			validLife = defaultValidLifetime
		}
		prefLife := pfx.PreferredLife
		if prefLife <= 0 {
			prefLife = defaultPreferredLifetime
		}

		// RFC 4861 §4.6.2: the Preferred Lifetime MUST NOT exceed the Valid
		// Lifetime. A PrefixInformation that violates this is malformed; per
		// RFC 4862 §5.5.3 a conforming host treats prefLife>validLife as an
		// error and ignores the prefix, so a misconfigured pair (operator types
		// preferred-lifetime larger than valid-lifetime, or a 0-defaulted valid
		// life paired with a large explicit preferred life) could silently drop
		// the prefix on every host. Clamp prefLife DOWN to validLife — never the
		// reverse, since extending the valid lifetime would advertise a
		// longer-lived prefix than the operator configured. Both values are plain
		// non-negative seconds (the schema gate rejects negatives, and a 0 has
		// already been replaced by its SLAAC default above), so the comparison is
		// a straight integer ordering check. "Infinite" is simply the largest
		// value the operator can express; the same clamp keeps it ordered (a
		// finite valid life still pulls an over-large preferred life down to it,
		// and an infinite valid life leaves any preferred life unchanged).
		if prefLife > validLife {
			prefLife = validLife
		}

		// #6587: refuse to advertise a DELEGATED /0.
		//
		// #6581 closed this at the DHCPv6 decoder, which is the right primary
		// place — an IA_PD prefix-length of 0 or >128 is refused before it
		// becomes a DelegatedPrefix. This is the defense-in-depth layer that
		// PR deliberately did not add, and the reason it could not add it
		// naively is recorded in its own test: at this point a delegated /0 is
		// "indistinguishable from an operator-authored
		// `set interfaces <if> ipv6 router-advertisement prefix ::/0`", which
		// is legitimate configuration. RAPrefix.Delegated supplies the
		// provenance that was missing, so the floor applies to exactly the
		// population that can never be intentional.
		//
		// A /0 here would be advertised on-link AND autonomous to the LAN:
		// every SLAAC host would treat the entire IPv6 address space as
		// on-link and stop routing through this firewall.
		//
		// Only 0 is reachable: netip.ParsePrefix succeeded above, so Bits() is
		// in [0,128] and the uint8 conversion below cannot wrap.
		if pfx.Delegated && prefix.Bits() == 0 {
			slog.Warn("ra: refusing to advertise a delegated /0 prefix",
				"prefix", pfx.Prefix, "interface", s.cfg.Interface)
			continue
		}

		ra.Options = append(ra.Options, &ndp.PrefixInformation{
			PrefixLength:                   uint8(prefix.Bits()),
			OnLink:                         pfx.OnLink,
			AutonomousAddressConfiguration: pfx.Autonomous,
			ValidLifetime:                  time.Duration(validLife) * time.Second,
			PreferredLifetime:              time.Duration(prefLife) * time.Second,
			Prefix:                         prefix.Masked().Addr(),
		})
	}

	// Recursive DNS Servers.
	if len(s.cfg.DNSServers) > 0 {
		var servers []netip.Addr
		for _, dns := range s.cfg.DNSServers {
			addr, err := netip.ParseAddr(dns)
			if err != nil {
				slog.Warn("ra: invalid DNS server address",
					"addr", dns, "err", err)
				continue
			}
			servers = append(servers, addr)
		}
		if len(servers) > 0 {
			ra.Options = append(ra.Options, &ndp.RecursiveDNSServer{
				Lifetime: time.Duration(optLifetime) * time.Second,
				Servers:  servers,
			})
		}
	}

	// PREF64 (NAT64 prefix).
	if s.cfg.NAT64Prefix != "" {
		prefix, err := netip.ParsePrefix(s.cfg.NAT64Prefix)
		if err == nil {
			pref64Life := s.cfg.NAT64PrefixLife
			if pref64Life <= 0 {
				pref64Life = optLifetime
			}
			ra.Options = append(ra.Options, &ndp.PREF64{
				Lifetime: time.Duration(pref64Life) * time.Second,
				Prefix:   prefix,
			})
		} else {
			slog.Warn("ra: invalid NAT64 prefix",
				"prefix", s.cfg.NAT64Prefix, "err", err)
		}
	}

	// Link MTU. RFC 8200 §5 requires at least 1280 bytes, while the
	// configured leaf is an int and tolerant load / peer-sync can deliver
	// values outside the on-wire uint16 contract. Keep 0 as the documented
	// "omit" sentinel; saturate every positive value at the owning send sink
	// so a stale config cannot advertise an unusable or wrapped MTU.
	if s.cfg.LinkMTU > 0 {
		ra.Options = append(ra.Options, ndp.NewMTU(uint32(clampLinkMTU9914(s.cfg.LinkMTU))))
	}

	// #3895 defense-in-depth: drop any option that fails to marshal so one bad
	// option degrades to "missing that option" instead of aborting the whole
	// RA. The commit-time schema bounds (pkg/config router-advertisement
	// lifetimes) are the primary guard; this backstops any un-bounded field
	// that could still overflow its on-wire encoding at send time.
	ra.Options = pruneUnmarshalableOptions(s.cfg.Interface, ra.Options)

	return ra
}

// pruneUnmarshalableOptions returns the subset of opts that marshal
// successfully, logging and dropping any option whose ndp encoding fails.
//
// This is defense-in-depth for the RA send path (#3895). The whole Router
// Advertisement is built and sent in a single WriteTo, which internally
// marshals every option; a single option that fails to marshal — e.g. an
// ndp.PREF64 whose scaled lifetime overflows the RFC 8781 13-bit field, or any
// future option with an out-of-range field — would return an error from that
// one WriteTo and abort the ENTIRE advertisement. The segment then silently
// stops receiving RAs and hosts lose their default route / SLAAC config when
// the current advertisements expire (an IPv6 blackhole). Skipping the bad
// option keeps the rest of the RA on the wire.
//
// NDP options are independent on the wire — marshalOptions simply concatenates
// each option's bytes with no cross-option state — so probing each option in
// isolation is faithful to how the combined RA marshals. The probe reuses
// ndp.MarshalMessage (the same encoder the real conn.WriteTo uses) on a
// throwaway RA holding just that one option.
func pruneUnmarshalableOptions(iface string, opts []ndp.Option) []ndp.Option {
	kept := opts[:0] // filter in place; buildRA hands us a fresh slice
	for _, opt := range opts {
		probe := &ndp.RouterAdvertisement{Options: []ndp.Option{opt}}
		if _, err := ndp.MarshalMessage(probe); err != nil {
			slog.Warn("ra: dropping un-marshalable option from RA (rest of RA still sent)",
				"interface", iface,
				"option", fmt.Sprintf("%T", opt),
				"err", err)
			continue
		}
		kept = append(kept, opt)
	}
	return kept
}

// randomAdvInterval returns a random duration between MinRtrAdvInterval and
// MaxRtrAdvInterval per RFC 4861.
func (s *sender) randomAdvInterval() time.Duration {
	maxI := s.cfg.MaxAdvInterval
	if maxI <= 0 {
		maxI = defaultMaxAdvInterval
	}
	minI := s.cfg.MinAdvInterval
	if minI <= 0 {
		minI = maxI / 3
	}
	if minI >= maxI {
		minI = maxI / 3
	}

	interval := minI + rand.IntN(maxI-minI+1)
	// #8642: bound the conversion, not just the drawn zero.
	//
	// The #4525 floor below already covers the dangerous HALF of overflow: a
	// wrapped value that lands negative or small-positive is `< minAdvInterval`
	// and gets floored, so the RA hot-loop it was written for cannot happen.
	// What it does not cover is a wrap landing LARGE positive — the residues are
	// 512ns multiples across the whole int64 range, not just near zero — which
	// silently stretches the advertisement interval instead of shrinking it.
	// Hosts then lose their default route when RouterLifetime expires with no
	// RA to refresh it. Quieter than a storm and just as much a loss of service.
	d := config.SecondsToDuration(interval, defaultMaxAdvInterval*time.Second)
	// #4525: never arm the periodic timer with a 0 (or sub-second) delay. A
	// drawn 0 — reachable when a legacy/mis-typed max-advertisement-interval
	// of 1-2s made minI derive to 0 — would Reset the advTimer to fire
	// immediately, spinning sendRA in a tight loop and flooding RA/ND. The
	// RFC-4861 §6.2.1 commit-time schema floor now rejects such values, but
	// floor here too so a config that bypassed the strict gate (tolerant load
	// / HA peer-sync of a stale config) still cannot hot-loop.
	if d < minAdvInterval {
		d = minAdvInterval
	}
	return d
}

// eui64LinkLocal derives the EUI-64 IPv6 link-local address (fe80::/64) from a
// 6-byte MAC. It returns nil if the MAC is not exactly 6 bytes. This mirrors
// the daemon's ensureRethLinkLocal (pkg/daemon/daemon_reth.go) so the RA sender
// and the apply path converge on one well-reviewed derivation. Kept as a pure
// function so the byte math is unit-testable without a netlink socket.
func eui64LinkLocal(mac net.HardwareAddr) net.IP {
	if len(mac) != 6 {
		return nil
	}
	return net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]}
}

// ensureLinkLocal makes sure the interface has an IPv6 link-local address for
// the RA sender's NDP socket. RETH members run with addr_gen_mode=1
// (stable-privacy) to suppress kernel EUI-64 auto-generation and the MLDv2
// noise it creates (pkg/daemon setRethIPv6Knobs), so on those interfaces no
// link-local may exist yet when the sender starts.
//
// If a link-local is already present (a daemon-managed stable or EUI-64 LLA, or
// a kernel-generated one on a non-suppressed interface), this returns early. If
// none exists, it adds the EUI-64 link-local directly via netlink with
// IFA_F_NODAD — the same primitive the daemon uses in ensureRethLinkLocal /
// addStableLLToInterface. It never mutates addr_gen_mode and never cycles the
// link: addr_gen_mode=1 is a contract the apply path sets deliberately, and an
// out-of-band link DOWN/UP from inside the RA manager would un-reconcile VIPs /
// stable LLAs and race the AF_XDP dataplane rebind.
func ensureLinkLocal(iface *net.Interface) error {
	link, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return err
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if a.IP.IsLinkLocalUnicast() {
			return nil // already have one
		}
	}

	// No link-local. Synthesize the EUI-64 fe80::/64 from the MAC and add it
	// with NODAD — the same primitive the daemon uses for RETH link-locals
	// (ensureRethLinkLocal / addStableLLToInterface). NODAD is set for
	// consistency with that apply path and to suppress the DAD / MLDv2 solicit
	// noise on addr_gen_mode=1 interfaces; it is not required to avoid a
	// peer collision here, because the EUI-64 derivation folds in the RETH
	// virtual MAC's node_id byte (RethMAC -> 02:bf:72:CC:RR:NN), so each node
	// derives a distinct LLA. (The address that *is* shared across nodes is
	// the daemon's stable fe80::bf:72:CC:RR LLA, which carries no node_id and
	// is added NODAD for exactly that reason — a different address than this
	// fallback.)
	ll := eui64LinkLocal(iface.HardwareAddr)
	if ll == nil {
		return fmt.Errorf("ensure link-local: interface %s has no usable MAC", iface.Name)
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{IP: ll, Mask: net.CIDRMask(64, 128)},
		Flags: unix.IFA_F_NODAD,
	}
	logAdded, err := classifyAddrAddResult(netlink.AddrAdd(link, addr))
	if err != nil {
		return fmt.Errorf("add link-local %s on %s: %w", ll, iface.Name, err)
	}
	if logAdded {
		slog.Info("ra: added link-local for RA sender",
			"interface", iface.Name, "addr", ll)
	}
	return nil
}

// classifyAddrAddResult interprets the result of netlink.AddrAdd for the RA
// link-local fallback. ensureLinkLocal already lists existing IPv6 link-locals
// before attempting the add, but another goroutine or process can still win the
// race between the list and the add. A nil error is a genuine add (log it). An
// EEXIST means the address is already present — a silent success: do NOT log
// "added", since claiming a new address was created makes the RA startup trace
// inaccurate during debugging. Any other error is a real failure.
func classifyAddrAddResult(addErr error) (logAdded bool, err error) {
	switch {
	case addErr == nil:
		return true, nil
	case errors.Is(addErr, syscall.EEXIST):
		return false, nil
	default:
		return false, addErr
	}
}

// clampRAHeaderSeconds bounds the RA header Router Lifetime to the range the
// 16-bit seconds field can carry, using the SAME constant the commit-time
// typed-leaf gate uses (#8597, muse-004 K72).
//
// Binding to config.RARouterMaxLifetimeSeconds rather than a local 65535 is the
// point: the gate and the sender must not be able to disagree about where the
// ceiling is. See the comment at the call site for what the unbounded version
// put on the wire.
func clampRAHeaderSeconds(v int) int {
	if v < 0 {
		return 0
	}
	if int64(v) > config.RARouterMaxLifetimeSeconds {
		return config.RARouterMaxLifetimeSeconds
	}
	return v
}

// clampRAHeaderMillis bounds the RA header Reachable Time / Retrans Timer to
// the range their 32-bit millisecond fields can carry (#8597).
func clampRAHeaderMillis(v int) int {
	if v < 0 {
		return 0
	}
	if int64(v) > config.RAReachableRetransMaxMillis {
		return config.RAReachableRetransMaxMillis
	}
	return v
}

// clampLinkMTU9914 saturates a positive configured MTU at the RFC 8200
// minimum and the uint16 configuration ceiling. Zero/negative values are not
// passed here: buildRA preserves them as the documented "omit" sentinel.
func clampLinkMTU9914(v int) int {
	if v < config.RALinkMTUMin {
		return config.RALinkMTUMin
	}
	if int64(v) > config.RALinkMTUMax {
		return config.RALinkMTUMax
	}
	return v
}
