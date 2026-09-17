// Package dhcp implements DHCPv4 and DHCPv6 clients for obtaining
// addresses on firewall interfaces configured with "family inet { dhcp; }"
// or "family inet6 { dhcpv6; }".
package dhcp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/vishvananda/netlink"
)

// AddressFamily selects DHCPv4 or DHCPv6.
type AddressFamily int

const (
	AFInet  AddressFamily = 4
	AFInet6 AddressFamily = 6
)

// dhcpExchangeMode selects which RFC exchange a renewal cycle step runs.
// The pre-#2994 client ran a full DISCOVER/Rapid-Solicit (exchangeAcquire)
// at every T1/T2; the fix sends a true unicast RENEW at T1 and a broadcast
// REBIND at T2, falling back to a full acquisition only on lease expiry.
type dhcpExchangeMode int

const (
	exchangeAcquire dhcpExchangeMode = iota // DHCPv4 DISCOVER / DHCPv6 SOLICIT
	exchangeRenew                           // T1: unicast REQUEST(RENEW) / RENEW
	exchangeRebind                          // T2: broadcast REQUEST(REBIND) / REBIND
)

func (mode dhcpExchangeMode) String() string {
	switch mode {
	case exchangeRenew:
		return "renew"
	case exchangeRebind:
		return "rebind"
	default:
		return "acquire"
	}
}

type clientKey struct {
	iface  string
	family AddressFamily
}

type dhcpClient struct {
	cancel context.CancelFunc
	done   chan struct{}
	// fingerprint is the client's config identity (options/DUID type)
	// captured at Start time. Reconcile compares it against the
	// fingerprint of the newly committed config to decide whether the
	// client must be restarted. It NEVER includes lease or address
	// state — see Reconcile.
	fingerprint string
}

// DHCPv4Options holds client behavior options for DHCPv4.
type DHCPv4Options struct {
	LeaseTime              int  // requested lease time in seconds (0 = server default)
	RetransmissionAttempt  int  // max retransmission attempts (0 = unlimited)
	RetransmissionInterval int  // base interval in seconds between retransmissions (0 = 1s default)
	ForceDiscover          bool // always start with DISCOVER (skip REQUEST for renewal)
}

// DHCPv6Options holds client behavior options for DHCPv6.
type DHCPv6Options struct {
	Stateless bool // true = send Information-Request only (no IA_NA/IA_PD)
	// UpdateDNS retired (#1715): the DHCP client no longer writes
	// /etc/resolv.conf. The daemon's reconcileDNS always merges
	// DHCP-learned servers (from Leases()) with static config regardless
	// of any per-client flag, so the box is never resolver-less.
	IATypes    []string // "ia-na", "ia-pd" — which IA types to request
	PDPrefLen  int      // preferred prefix length hint for IA_PD (0 = no hint)
	PDSubLen   int      // sub-prefix length for deriving /64s (0 = not set)
	ReqOptions []string // additional options to request: "dns-server", "domain-name"
	RAIface    string   // interface to update with RA prefix from delegated prefix
}

// DelegatedPrefix holds a prefix received via DHCPv6 Prefix Delegation.
type DelegatedPrefix struct {
	Interface         string
	Prefix            netip.Prefix
	PreferredLifetime time.Duration
	ValidLifetime     time.Duration
	Obtained          time.Time
}

// Manager manages DHCP clients for multiple interfaces.
type Manager struct {
	mu              sync.Mutex
	clients         map[clientKey]*dhcpClient
	leases          map[clientKey]*Lease
	delegatedPDs    map[string][]DelegatedPrefix // interface name -> delegated prefixes
	duids           map[string]dhcpv6.DUID       // interface name -> cached DUID
	duidTypes       map[string]string            // interface name -> "duid-ll" or "duid-llt"
	v4opts          map[string]*DHCPv4Options    // interface name -> DHCPv4 options
	v6opts          map[string]*DHCPv6Options    // interface name -> DHCPv6 options
	onAddressChange func()
	// onGatewayChange fires whenever the gateway-relevant lease state
	// of any interface changes (#1844): a lease committed with a
	// new/changed gateway, a first lease acquired, or a lease record
	// removed on client termination. Immutable after New (a setter on
	// a live manager would be a data race — client goroutines read
	// this outside m.mu) and ALWAYS fired outside m.mu, so the
	// consumer (the ipmon engine's NotifyNextHopChange, whose resolver
	// calls back into LeaseFor under Engine.mu → dhcp.mu) can never
	// deadlock against us. Bounded-blocking: the hook may wait on
	// Engine.mu held across an overlay build.
	onGatewayChange func()
	nlHandle        *netlink.Handle
	recompileTimer  *time.Timer
	// quiesced latches the #6788 shutdown quiesce: once set, scheduleRecompile
	// arms nothing and an already-elapsed timer's callback returns without
	// dispatching. Guarded by mu.
	quiesced bool
	// recompileWG tracks an in-flight recompile callback so Quiesce can JOIN
	// one that started before the latch. Add(1) happens under mu in
	// scheduleRecompile (so it cannot race the latch), Done in the timer func.
	// RenewalBindingStats counters count replies that pass transaction/client
	// identity checks but fail the stored granting-server identity check.
	renewV4ServerIdentityRejects atomic.Uint64
	renewV6ServerIdentityRejects atomic.Uint64
	recompileWG                  sync.WaitGroup
	stateDir                     string

	// runClientForTest replaces the per-family run goroutine body in
	// tests so reconcile/registry behavior can be exercised without
	// real DHCP traffic. nil in production.
	runClientForTest func(ctx context.Context, ifaceName string, af AddressFamily)

	// Renewal seams (#2994). When non-nil they replace the real wire
	// exchange / the renewal wait so the run-loop state machine (the
	// DISCOVER→RENEW→REBIND→re-acquire transitions) is unit-testable
	// without sockets or the 30 s T1 clamp. nil in production.
	doV4ExchangeForTest func(ctx context.Context, ifaceName string, mode dhcpExchangeMode, prev *Lease) (*Lease, error)
	doV6ExchangeForTest func(ctx context.Context, ifaceName string, mode dhcpExchangeMode, prev *Lease, prevPDs []DelegatedPrefix) (*dhcpv6Result, error)
	afterForTest        func(d time.Duration) <-chan time.Time
	// waitLinkLocalForTest replaces the DHCPv6 link-local wait so the v6
	// run loop is drivable without a real interface. nil in production.
	waitLinkLocalForTest func(ctx context.Context, ifaceName string, timeout time.Duration) error
}

// RenewalBindingStats reports renewal replies that were ignored because
// their server identity did not match the committed lease binding.
type RenewalBindingStats struct {
	DHCPv4ServerIdentityRejects uint64
	DHCPv6ServerIdentityRejects uint64
}

// RenewalBindingStats returns a snapshot of the server-identity rejection
// counters.
func (m *Manager) RenewalBindingStats() RenewalBindingStats {
	return RenewalBindingStats{
		DHCPv4ServerIdentityRejects: m.renewV4ServerIdentityRejects.Load(),
		DHCPv6ServerIdentityRejects: m.renewV6ServerIdentityRejects.Load(),
	}
}

// New creates a DHCP manager. stateDir is where DUID files are persisted.
// The onAddressChange callback is called (debounced by 2 seconds) when a
// lease changes an interface address. The onGatewayChange callback (#1844,
// may be nil) fires — undebounced, outside m.mu — whenever gateway-relevant
// lease state changes: first lease, gateway delta on commit, or lease
// record removal on client termination; see the Manager field doc.
func New(stateDir string, onAddressChange, onGatewayChange func()) (*Manager, error) {
	nlh, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("netlink handle: %w", err)
	}
	return &Manager{
		clients:         make(map[clientKey]*dhcpClient),
		leases:          make(map[clientKey]*Lease),
		delegatedPDs:    make(map[string][]DelegatedPrefix),
		duids:           make(map[string]dhcpv6.DUID),
		duidTypes:       make(map[string]string),
		v4opts:          make(map[string]*DHCPv4Options),
		v6opts:          make(map[string]*DHCPv6Options),
		onAddressChange: onAddressChange,
		onGatewayChange: onGatewayChange,
		nlHandle:        nlh,
		stateDir:        stateDir,
	}, nil
}

// fireGatewayChange invokes the optional gateway-change hook. Callers
// must NOT hold m.mu (the hook's consumer takes Engine.mu and its
// resolver re-enters LeaseFor — firing under m.mu would invert the
// one-way Engine.mu → dhcp.mu lock order).
func (m *Manager) fireGatewayChange() {
	if m.onGatewayChange != nil {
		m.onGatewayChange()
	}
}

// SetDUIDType configures the DUID type for an interface's DHCPv6 client.
// Must be called before Start(). Valid types: "duid-ll", "duid-llt".
func (m *Manager) SetDUIDType(ifaceName, duidType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.duidTypes[ifaceName] = duidType
}

// SetDHCPv4Options configures DHCPv4 client behavior for an interface.
// Must be called before Start().
func (m *Manager) SetDHCPv4Options(ifaceName string, opts *DHCPv4Options) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.v4opts[ifaceName] = opts
}

// SetDHCPv6Options configures DHCPv6 client behavior for an interface.
// Must be called before Start().
func (m *Manager) SetDHCPv6Options(ifaceName string, opts *DHCPv6Options) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.v6opts[ifaceName] = opts
}

// DelegatedPrefixes returns a snapshot of all delegated prefixes from DHCPv6 PD.
func (m *Manager) DelegatedPrefixes() []DelegatedPrefix {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []DelegatedPrefix
	for _, pds := range m.delegatedPDs {
		result = append(result, pds...)
	}
	return result
}

// PDRAMapping holds a delegated prefix and the downstream interface
// where it should be advertised via Router Advertisement.
type PDRAMapping struct {
	DelegatedPrefix
	RAIface    string // downstream interface for RA
	SubPrefLen int    // sub-prefix length (0 = use delegated prefix as-is)
}

// DelegatedPrefixesForRA returns delegated prefixes that have an RA target
// interface configured, along with the target interface and sub-prefix length.
func (m *Manager) DelegatedPrefixesForRA() []PDRAMapping {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []PDRAMapping
	for ifName, pds := range m.delegatedPDs {
		opts := m.v6opts[ifName]
		if opts == nil || opts.RAIface == "" {
			continue
		}
		for _, dp := range pds {
			result = append(result, PDRAMapping{
				DelegatedPrefix: dp,
				RAIface:         opts.RAIface,
				SubPrefLen:      opts.PDSubLen,
			})
		}
	}
	return result
}

// Start begins a DHCP client for the given interface and address family.
// Start reports whether a client for the key is registered when it
// returns: true if this call started one or one was already running,
// false if the key has no option state (the desired-config signal —
// SetDHCPv*Options/Reconcile install it, Reconcile prunes it for
// removed clients). The membership check lives INSIDE the registration
// lock so check-and-register is atomic: a Renew racing a removal
// Reconcile cannot observe membership, lose the lock, and register a
// client for a key the Reconcile just deconfigured (Codex review on
// PR #1815, round 5).
func (m *Manager) Start(ctx context.Context, ifaceName string, af AddressFamily) bool {
	key := clientKey{iface: ifaceName, family: af}

	m.mu.Lock()
	if _, exists := m.clients[key]; exists {
		m.mu.Unlock()
		return true
	}
	desired := false
	switch af {
	case AFInet:
		_, desired = m.v4opts[ifaceName]
	case AFInet6:
		_, desired = m.v6opts[ifaceName]
	}
	if !desired {
		m.mu.Unlock()
		slog.Info("DHCP: start refused; no option state for client",
			"interface", ifaceName, "family", af)
		return false
	}

	// Use an independent context so DHCP clients are decoupled from the
	// daemon lifecycle. Only an explicit stop (Reconcile removal, Renew,
	// StopAll) cancels a client. During graceful restart (SIGTERM), the
	// process exits without calling StopAll(), so addresses stay on
	// interfaces for the next daemon to reuse.
	cctx, cancel := context.WithCancel(context.Background())
	dc := &dhcpClient{
		cancel:      cancel,
		done:        make(chan struct{}),
		fingerprint: m.configFingerprintLocked(key),
	}
	m.clients[key] = dc
	runFn := m.runClientForTest
	m.mu.Unlock()

	slog.Info("DHCP: starting client", "interface", ifaceName, "family", af)

	go func() {
		// Defer order matters: finishClient (deregister + lease/address
		// cleanup) runs BEFORE close(done), so anyone waiting on done
		// observes a clean registry. The deregistration covers ALL
		// terminal exits (#1793) — cancellation, DHCPv4 max
		// retransmissions, DHCPv6 link-local abort — not just Renew,
		// so a future Start for this key is never a permanent no-op.
		defer close(dc.done)
		defer m.finishClient(key, dc)
		if runFn != nil {
			runFn(cctx, ifaceName, af)
			return
		}
		switch af {
		case AFInet:
			m.runDHCPv4(cctx, ifaceName)
		case AFInet6:
			m.runDHCPv6(cctx, ifaceName)
		}
	}()
	return true
}

// finishClient runs in the client goroutine's defer on every exit path.
// It deregisters the registry entry (only if it still maps to this exact
// client — Renew deletes/re-adds entries, so a pointer compare guards
// against clobbering a successor) and cleans up any lease record and
// interface address the run loop left behind (some cancellation
// interleavings exit the run loop without hitting its own ctx.Done
// cleanup branches).
//
// #1844: this is the lease-record removal owner — it covers the
// terminal exits the run-loop ctx.Done branches never see (cancel
// mid-exchange, DHCPv4 max-retransmission, DHCPv6 link-local abort) —
// so the gateway-change hook fires here unconditionally on the real
// cleanup path. Firing only from the run-loop inline delete sites
// would leave a stale gateway in the ip-monitoring overlay after such
// an exit (a silent blackhole). The successor-guard early return does
// NOT fire (this call changed no lease state). If lease expiry is ever
// implemented per RFC 2131 §4.4.5, the record removal must keep
// routing through a hook-firing path so the overlay withdraws in
// lock-step with the address.
func (m *Manager) finishClient(key clientKey, dc *dhcpClient) {
	m.mu.Lock()
	cur, ok := m.clients[key]
	if !ok || cur != dc {
		// A successor client already replaced (or removed) this key.
		// Its lease / delegated-PD records belong to the successor —
		// a delayed defer from the OLD client must not delete them
		// (AGY review on PR #1815: unguarded cleanup let a slow old
		// defer clobber the new client's lease).
		m.mu.Unlock()
		return
	}
	delete(m.clients, key)
	lease := m.leases[key]
	delete(m.leases, key)
	if key.family == AFInet6 {
		delete(m.delegatedPDs, key.iface)
	}
	m.mu.Unlock()

	if lease != nil && lease.Address.IsValid() {
		m.removeAddress(key.iface, lease)
	}
	m.fireGatewayChange()
	// #4874 A2: a terminal exit that removed a committed lease/PD must
	// also re-render compiled state. The FRR DHCP default/classless
	// routes and the v6 RA prefix are regenerated ONLY by applyConfig
	// (from Leases() / DelegatedPrefixesForRA()), which onGatewayChange
	// does NOT drive — it only marks the ip-monitoring overlay dirty. So
	// without a recompile the withdrawn gateway/prefix keep being
	// advertised until some unrelated commit (indefinitely on a DHCPv4
	// max-retransmission exit that returns while a #1844-retained lease is
	// still recorded). Fire only when a lease record actually existed: the
	// pure-failure exits (no lease ever acquired) have nothing to withdraw,
	// and the ctx.Done cancellation paths already deleted the record and
	// are re-rendered by their surrounding applyConfig (Reconcile) or the
	// re-acquire that follows (Renew), so they need no recompile here.
	if lease != nil {
		m.scheduleRecompile()
	}
}

// Renew restarts the DHCP client for the specified interface and address
// family, causing it to go through a fresh DISCOVER/REQUEST cycle.
// Returns an error if no DHCP client is running for the interface.
func (m *Manager) Renew(ifaceName string) error {
	// Try both v4 and v6
	renewed := false
	for _, af := range []AddressFamily{AFInet, AFInet6} {
		key := clientKey{iface: ifaceName, family: af}
		m.mu.Lock()
		dc, exists := m.clients[key]
		m.mu.Unlock()

		if !exists {
			continue
		}

		// Stop the existing client. Do NOT pre-delete the registry
		// entry: finishClient owns deregistration and the lease /
		// delegated-PD / address cleanup, and its pointer guard
		// early-returns when the entry is already gone — a pre-delete
		// here would skip that cleanup entirely when cancellation
		// lands mid-exchange (Codex review on PR #1815). Waiting on
		// done guarantees finishClient has completed before restart.
		dc.cancel()
		<-dc.done

		// Restart. Renew is reachable from gRPC outside applySem, so a
		// concurrent Reconcile may have removed this client from
		// config after we captured dc above; Start performs the
		// desired-set membership check atomically with registration
		// (under m.mu) and refuses to resurrect a deconfigured client
		// — a check here would go stale before Start takes the lock
		// (Codex review on PR #1815, rounds 3-5).
		if !m.Start(context.Background(), ifaceName, af) {
			slog.Info("DHCP: renew skipped restart; client removed from config",
				"interface", ifaceName, "family", af)
			continue
		}
		renewed = true
		slog.Info("DHCP client renewed", "interface", ifaceName, "family", af)
	}
	if !renewed {
		return fmt.Errorf("no DHCP client running on interface %s", ifaceName)
	}
	return nil
}

// StopAll stops all running DHCP clients and releases leases. Registry
// entries are cleared by each client's finishClient defer, which runs
// before its done channel closes, so the registry is empty when StopAll
// returns.
func (m *Manager) StopAll() {
	m.mu.Lock()
	clients := make(map[clientKey]*dhcpClient, len(m.clients))
	for k, v := range m.clients {
		clients[k] = v
	}
	m.mu.Unlock()

	for _, dc := range clients {
		dc.cancel()
		<-dc.done
	}

	m.mu.Lock()
	if m.recompileTimer != nil {
		m.recompileTimer.Stop()
		m.recompileTimer = nil
	}
	m.mu.Unlock()
}

// Close releases the netlink handle.
func (m *Manager) Close() {
	if m.nlHandle != nil {
		m.nlHandle.Close()
	}
}

// applyAddress sets the DHCP-obtained address on the interface via netlink,
// and installs a default route via the gateway if provided.
func (m *Manager) applyAddress(ifaceName string, lease *Lease) error {
	if m.nlHandle == nil {
		return nil // test-constructed Manager without netlink
	}
	link, err := m.nlHandle.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("link lookup %s: %w", ifaceName, err)
	}

	addr := &netlink.Addr{
		IPNet: prefixToIPNet(lease.Address),
	}

	if err := m.nlHandle.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("addr replace: %w", err)
	}

	// Routes are programmed via FRR by the daemon's recompile callback.

	return nil
}

// removeAddress removes the DHCP address and default route from the interface.
func (m *Manager) removeAddress(ifaceName string, lease *Lease) {
	if m.nlHandle == nil {
		return // test-constructed Manager without netlink
	}
	link, err := m.nlHandle.LinkByName(ifaceName)
	if err != nil {
		return
	}

	addr := &netlink.Addr{
		IPNet: prefixToIPNet(lease.Address),
	}
	if err := m.nlHandle.AddrDel(link, addr); err != nil {
		slog.Warn("DHCP: failed to remove address",
			"interface", ifaceName, "address", lease.Address, "err", err)
	}

	// Routes are cleaned up via FRR config removal.
}

// recompileDebounce is how long scheduleRecompile coalesces address-change
// notifications before dispatching the callback. It is a package var only so a
// test can drive the post-quiesce timer race deterministically in milliseconds
// instead of sleeping past a 2s wall clock; production never changes it.
//
// The DURATION is itself part of the #6788 hazard: 2s is long enough for a
// lease event arriving just before SIGTERM to fire its callback after the
// shutdown apply drain has already completed.
var recompileDebounce = 2 * time.Second

// Quiesce stops the address-change callback machinery WITHOUT stopping the
// DHCP clients or touching a single lease (#6788).
//
// It is deliberately NOT StopAll, and the difference is the whole point.
// StopAll cancels every client, and a cancelled client runs finishClient, which
// calls removeAddress: on a box whose management interface is DHCP (fxp0), that
// strips the management address during shutdown and leaves it stripped across a
// graceful restart. The comment on the client context in startClient states
// that contract explicitly — clients are decoupled from the daemon lifecycle so
// "during graceful restart (SIGTERM), the process exits without calling
// StopAll(), so addresses stay on interfaces for the next daemon to reuse".
// Quiesce preserves that: leases, addresses and client goroutines are left
// exactly as they are, and only the notification path is shut off.
//
// What it stops is the debounce timer armed by scheduleRecompile, whose 2s
// delay is long enough to outlive the shutdown apply drain and fire the
// lease-change callback into a half-torn-down daemon. The latch makes that
// one-way: a scheduleRecompile that races Quiesce arms nothing, and a timer
// that has ALREADY fired and is running its callback is joined before Quiesce
// returns, so the caller can order its own teardown after it.
//
// Idempotent, and safe on a nil-ish Manager built by a test.
func (m *Manager) Quiesce() {
	m.mu.Lock()
	m.quiesced = true
	if m.recompileTimer != nil {
		m.recompileTimer.Stop()
		m.recompileTimer = nil
	}
	m.mu.Unlock()
	// Join a callback that was already in flight when the latch was set.
	// scheduleRecompile's timer func takes recompileWG before it dispatches, so
	// after the latch no new callback can start and this waits out the one that
	// may already be running.
	m.recompileWG.Wait()
}

// Quiesced reports whether Quiesce has latched (#6788). Exported so a caller
// that owns teardown ordering can assert the latch rather than infer it.
func (m *Manager) Quiesced() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.quiesced
}

// scheduleRecompile debounces address change notifications.
func (m *Manager) scheduleRecompile() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// #6788: once quiesced, arm nothing. Without this a lease event racing
	// shutdown re-arms the 2s timer after Quiesce stopped it, and the callback
	// lands after the apply drain — the exact ordering this closes.
	if m.quiesced {
		return
	}
	if m.recompileTimer != nil {
		m.recompileTimer.Stop()
	}
	m.recompileTimer = time.AfterFunc(recompileDebounce, func() {
		// Re-test the latch and take the WaitGroup under the SAME lock, then
		// dispatch. Both halves matter:
		//
		//   - The re-test is needed because time.Timer.Stop cannot un-fire an
		//     already-elapsed timer, so this func can be entered concurrently
		//     with Quiesce; a callback that dispatches after the latch is
		//     exactly the late apply #6788 closes.
		//   - Add(1) must happen HERE, not at arm time, and under mu. At arm
		//     time it would never be matched: Quiesce stops the timer, the func
		//     never runs, Done is never called, and Quiesce's Wait blocks
		//     forever. Under mu it is also race-free against Wait — Quiesce sets
		//     quiesced under mu before waiting, so a callback either registers
		//     before the latch (and is joined) or observes the latch and never
		//     registers. The counter cannot rise from zero concurrently with
		//     Wait. Same Add/Wait discipline as configstore's archiveWG (#5869).
		m.mu.Lock()
		if m.quiesced {
			m.mu.Unlock()
			return
		}
		m.recompileWG.Add(1)
		m.mu.Unlock()
		defer m.recompileWG.Done()

		if m.onAddressChange != nil {
			m.onAddressChange()
		}
	})
}

// prefixToIPNet converts netip.Prefix to *net.IPNet.
func prefixToIPNet(p netip.Prefix) *net.IPNet {
	addr := p.Addr()
	bits := p.Bits()
	if addr.Is4() {
		return &net.IPNet{
			IP:   addr.AsSlice(),
			Mask: net.CIDRMask(bits, 32),
		}
	}
	return &net.IPNet{
		IP:   addr.AsSlice(),
		Mask: net.CIDRMask(bits, 128),
	}
}
