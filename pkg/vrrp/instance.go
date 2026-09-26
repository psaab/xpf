package vrrp

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/vishvananda/netlink"
)

// VRRPState represents the VRRPv3 state machine state.
type VRRPState int

const (
	StateInitialize VRRPState = iota
	StateBackup
	StateMaster
)

// addressOwnerPriority is the VRRP priority reserved for the IP address owner
// (RFC 5798 §5.2.4). An instance configured with this priority owns the virtual
// address and, per RFC 5798 §6.1, MUST preempt a lower-priority master
// "irrespective of the setting of" the preempt flag — the owner always reclaims
// mastership. See getPreempt / shouldPreemptObservedMaster (owner-preempt), and
// getPriority (track.go — the owner is also exempt from track-down demotion).
const addressOwnerPriority = 255

// minLearnedMasterAdverInterval is the absolute lower bound applied to a
// Master_Adver_Interval learned from a peer advertisement (recordMasterAdvert,
// #4548). It matches the schema minimum for `chassis cluster
// reth-advertise-interval` (10 ms; pkg/config/schema_chassis.go) — the smallest
// cadence the system will ever legitimately run at. It is only the backstop for
// the degenerate case where the local configured interval is somehow unset; the
// primary floor is the node's own configured advertise interval (see
// masterAdverFloor). RFC 5798 §6.1/§6.4.2 requires a BACKUP to time its master
// out on the master's advertised cadence, but a buggy or misconfigured peer that
// advertises Max Adver Int=1 (10 ms) must not be allowed to drive a 30 ms RETH
// node's Master_Down_Interval down to ~30 ms and flap mastership on ordinary
// scheduling/network jitter.
const minLearnedMasterAdverInterval = 10 * time.Millisecond

func (s VRRPState) String() string {
	switch s {
	case StateInitialize:
		return "INIT"
	case StateBackup:
		return "BACKUP"
	case StateMaster:
		return "MASTER"
	default:
		return "UNKNOWN"
	}
}

// VRRPEvent is emitted when a VRRP instance changes state.
type VRRPEvent struct {
	Interface string
	Family    string
	GroupID   int
	State     VRRPState
	VIPs      []string
}

// deafMasterDownInterval is the master-down interval used while this node is
// NOT preempting and has heard no peer advertisement — the window in which it
// cannot yet distinguish "there is no master" from "I am not listening yet".
//
// A BACKUP promotes when the master-down timer expires, and that arm is
// deliberately ungated by `preempt` (RFC 5798: preempt governs displacing a
// master you can HEAR, not filling an apparent vacancy). So during any window
// where this node is deaf, the ~97ms timer that a 30ms RETH advertise interval
// produces is the only thing standing between a healthy peer and a second
// MASTER claiming its VIPs.
//
// TWO such windows exist and both are now covered:
//
//   - process start, before the AF_PACKET receiver is capturing (the original
//     mitigation, in run());
//   - sync-hold release (#7579), which fires as bulk session sync completes —
//     when a just-rebooted node is installing synced sessions and about to do
//     VIP work, so a ~97ms scheduling gap on the receiver is unremarkable.
//
// Self-limiting in both: handleBackupRx resets the timer to the normal short
// interval on the FIRST advert received, so this interval only ever applies
// while nothing has been heard.
const deafMasterDownInterval = 3 * time.Second

// vrrpInstance is a per-VRRP-group state machine goroutine.
type vrrpInstance struct {
	mu               sync.RWMutex
	cfg              Instance
	desiredPreempt   bool // configured preempt value (may differ from cfg.Preempt during sync hold)
	forcePreemptOnce bool // one-shot preempt override from ForceRGMaster (auto-cleared after use)
	// skipNextPreemptHold makes the next masterDownTimer expiry promote
	// immediately, bypassing the preempt hold-time (#2850). Set when the
	// master resigns (priority-0) so a graceful, planned failover is never
	// delayed by the hold-time — there is no live master to blackhole.
	// One-shot: cleared by the masterDownTimer.C handler. Guarded by mu.
	skipNextPreemptHold bool

	// preemptHoldArmed tracks whether the preempt hold-time countdown (#2850)
	// is currently running (#2900). It is set when stepBackup arms the
	// preemptHoldTimer and cleared whenever the timer is stopped or fires. A
	// config update arriving during the hold window (updateConfig → the
	// configUpdatedCh case in stepBackup) reads this flag to decide whether an
	// in-flight hold must be torn down because the new config no longer
	// warrants it (preempt disabled, priority demoted, or hold-time changed).
	// Mutated only by the run-loop goroutine (arm/disarm helpers); read under
	// mu so a future cross-goroutine reader stays race-clean. Guarded by mu.
	preemptHoldArmed bool

	trackDown bool // tracked interface (cfg.TrackInterface) is down (#1814); guarded by mu

	// Last-seen master advertisement (#2082). Recorded by handleBackupRx /
	// handleMasterRx for every non-zero-priority advert from a peer, and read
	// by shouldPreemptObservedMaster to gate the non-force sync-hold preempt
	// shortcut on a strictly-higher effective priority (RFC 5798 §6.4.2). Both
	// writers and the gate reader run in the run-loop goroutine, so they are
	// already serialized with respect to each other; mu makes the writes/reads
	// race-clean for any future cross-goroutine reader. Priority-0
	// (resignation) adverts are NOT recorded — post-resign takeover flows
	// through the ungated masterDownTimer path. Guarded by mu.
	lastMasterPriority int       // last non-zero peer advert priority
	lastMasterSeen     time.Time // when lastMasterPriority was recorded
	// lastMasterIPv4 / lastMasterIPv6 store the learned nonzero-priority source
	// per family — the currently-known master identity the #10719 detector
	// compares against. They are recorded by recordMasterAdvert alongside
	// lastMasterPriority/lastMasterSeen; the Known flags distinguish cold start.
	// Two fixed-size slots, not one, because a dual-stack instance hears its
	// master from two UNRELATED sources (v4 from getLocalIP, v6 from the
	// link-local) — a single slot would flip-flop and misreport every legitimate
	// cross-family advert as unknown. Priority-0 adverts are NOT recorded (same
	// early return as the priority), so a resignation never overwrites the
	// identity it is resigning FROM. Guarded by mu.
	lastMasterIPv4      [4]byte
	lastMasterIPv4Known bool
	lastMasterIPv6      [16]byte
	lastMasterIPv6Known bool

	// masterAdverInterval is the advertisement interval LEARNED from the
	// current master's advertisement — RFC 5798 §6.1/§6.4.2 Master_Adver_Interval
	// — derived from the received advert's Max Adver Int field (centiseconds on
	// the wire, 10 ms units, converted to a Duration). A BACKUP must compute its
	// Master_Down_Interval + Skew_Time from the MASTER's advertised cadence, NOT
	// its own locally-configured cfg.AdvertiseInterval: when the master and
	// backup are configured with different intervals (a rolling change or a
	// misconfig), timing the master out on the local interval fails over too
	// early (shorter local interval → flapping) or too late (longer → traffic
	// loss). Recorded by recordMasterAdvert for every non-zero-priority advert,
	// alongside lastMasterPriority/lastMasterSeen. 0 = none learned yet
	// (cold-start / pre-first-advert), in which case the local interval is the
	// fallback. Guarded by mu.
	masterAdverInterval time.Duration

	state   VRRPState
	iface   *net.Interface
	eventCh chan<- VRRPEvent

	// localIP / localIPv6 are our IPv4 address (for filtering self-sent
	// adverts) and our link-local IPv6 address (source for IPv6 VRRP
	// adverts). They are resolved once at openSocket() time, BEFORE any
	// goroutine is started — but that resolution can come back empty (no
	// IPv4 address assigned yet, or IPv6 DAD still running). In that case
	// sendPacket()/sendPacketIPv6() perform a one-shot lazy resolve from
	// the run-loop goroutine. Meanwhile the receiver goroutines
	// (receiver/receiverIPv6/parseAfPacketIPv4/parseAfPacketIPv6) read
	// these fields to filter self-sent packets. The lazy-resolve write
	// thus races the receiver reads (#2258), so the fields are
	// atomic.Pointer[net.IP] accessed only via getLocalIP/setLocalIP and
	// getLocalIPv6/setLocalIPv6. A nil pointer means unresolved; the
	// resolve semantics are preserved (the address still becomes available
	// once resolvable). Mirrors the lastDropWarn atomic pattern (#2225).
	localIP   atomic.Pointer[net.IP] // our IPv4 address on this interface
	localIPv6 atomic.Pointer[net.IP] // our link-local IPv6 address

	// #7334: the receive-path self-frame check's address SETS. See
	// isLocalAddr (instance_addr.go) for why these differ from the send
	// sources above and why an unresolved set fails OPEN.
	localAddrSet   atomic.Pointer[[]string]
	localAddrSetV6 atomic.Pointer[[]string]

	// Per-instance raw socket and receiver.
	conn    net.PacketConn
	rawConn *ipv4.RawConn

	// IPv6 raw socket for sending VRRPv3 advertisements.
	// nil when no IPv6 VIPs are configured.
	ipv6Conn net.PacketConn
	ipv6FD   int // raw fd for setsockopt (hop limit, multicast)

	// ipv6Send is the seam used by sendPacketIPv6 to write an IPv6 advert
	// with an explicit IPV6_PKTINFO control message. The control message
	// pins the OUTER IPv6 source to the same link-local address the
	// pseudo-header checksum was computed over (#2644). Without it the
	// kernel performs independent RFC 6724 source selection on the
	// wildcard-bound (`::`) socket; with more than one link-local on the
	// interface it can pick a different source than the checksum used, so
	// the receiver's pseudo-header checksum mismatches and the advert is
	// silently dropped -> dual-master split-brain. Defaults to a wrapper
	// over ipv6.NewPacketConn(ipv6Conn).WriteTo; overridden in tests to
	// capture the control message.
	ipv6Send func(data []byte, cm *ipv6.ControlMessage, dst net.Addr) error

	// ipv6Recv is the seam used by receiverIPv6 to read an IPv6 advert together
	// with its arrival interface and IPv6 hop limit (the per-packet control
	// message). It returns the byte count, the arrival ifindex (0 if the
	// platform did not report one), the received hop limit (0 if the platform
	// did not report one), and the source address. Production leaves it nil and
	// receiverIPv6 lazily builds a wrapper over ipv6.NewPacketConn(ipv6Conn)
	// with FlagInterface and FlagHopLimit enabled; tests override it to inject
	// synthetic adverts with a chosen arrival ifindex and hop limit (the #2886
	// cross-VLAN filter seam and the GTSM hop-limit gate). Capturing the arrival
	// ifindex is required because the IPv6 raw socket on a VLAN sub-interface is
	// wildcard-bound (no SO_BINDTODEVICE — see manager.go), so the kernel fans a
	// proto-112 frame out to every sibling-VLAN socket; the VRID/hop-limit/self
	// gates alone let same-VRID siblings cross-process (#2886). Capturing the
	// hop limit is required to enforce RFC 5798 §5.1.2.3 (hop limit MUST be 255)
	// — the kernel strips the IPv6 header on a raw ip6:112 socket, so the value
	// is only reachable via the IPV6_RECVHOPLIMIT control message (#4549 F8).
	ipv6Recv func(buf []byte) (n int, ifindex int, hopLimit int, src net.Addr, err error)

	// AF_PACKET socket for receiving on VLAN sub-interfaces.
	// Raw IP sockets don't reliably receive multicast on VLAN
	// sub-interfaces (kernel limitation). AF_PACKET captures at
	// the link layer and works correctly. -1 means not used.
	afPacketFD int

	preemptNowCh    chan struct{} // signals coordinated preemption from ReleaseSyncHold
	resignCh        chan struct{} // signals forced resignation (manual failover)
	configUpdatedCh chan struct{} // signals updateConfig mutated cfg (#2900 hold re-validate)

	rxCh    chan *VRRPPacket
	stopCh  chan struct{}
	stopped chan struct{}

	// RX backpressure counters (atomic).
	rxDrops    atomic.Uint64 // packets dropped due to full rxCh
	rxReceived atomic.Uint64 // total packets delivered to rxCh
	// lastDropWarn is the Unix-nanos timestamp of the last drop warning we
	// logged (rate-limited). It is an atomic.Int64 because warnRXDrop is
	// called concurrently from both receiver() and receiverIPv6() on the
	// AF_PACKET-fallback path (#2225); a plain time.Time would be a data
	// race. Mirrors the lastGARPTime atomic pattern below.
	lastDropWarn atomic.Int64
	// unrecognizedMasterAdverts counts priority-0 resignation and priority-255
	// owner adverts whose source does not match the last nonzero-priority source
	// learned for that family (#10719). The VRRP wire carries no authentication
	// (RFC 5798 removed it), so this is an unknown-source signal, not proof of
	// spoofing. Exposed via RXDropStats as
	// "<key>/unrecognized_master_adverts". Atomic for lock-free status readers.
	unrecognizedMasterAdverts atomic.Uint64
	// lastUnknownMasterWarn is the Unix-nanos timestamp of the last
	// unknown-source priority-0/255 warning (#10719). Same once-per-10s
	// CompareAndSwap dampener as lastDropWarn (#2225): the counter above
	// advances per advert, the log line at most once per interval.
	lastUnknownMasterWarn atomic.Int64

	// GARP suppression for strict-vip-ownership mode.
	suppressGARP     atomic.Bool   // when true, becomeMaster() skips GARP/NA
	garpEpoch        atomic.Uint64 // incremented on each becomeMaster()/ReconcileVIPs transition
	lastGARPEpoch    atomic.Uint64 // epoch of last completed sendGARP()
	lastGARPTime     atomic.Int64  // Unix nanos of last GARP send
	lastGARPOwnerGen atomic.Uint64 // owner generation in which the last GARP completed
	// lastMasterReaffirmTime independently rate-limits winner-side refreshes
	// triggered by repeated peer MASTER advertisements.
	lastMasterReaffirmTime atomic.Int64 // Unix nanos of the last winner-side neighbor refresh.
	garpClampWarned        atomic.Bool  // #5695: guards a once-per-instance warn when a configured GARPCount is clamped (never per-send)

	// ownerGen is the identity of the current Master/Backup ownership tenure
	// (#5082). setState bumps it whenever the state actually changes, so every
	// state transition begins a fresh generation. Code that actuates the VIP
	// set via netlink (becomeMaster, ReconcileVIPs) captures the generation
	// before the netlink op and revalidates it afterward: if a demotion raced
	// in and bumped ownerGen, the actuation is stale — roll back the added VIPs
	// and do NOT advertise/emit/GARP for a tenure we have already left. Atomic
	// so log/test readers stay lock-free; the load-bearing check-then-act runs
	// under vipMu below.
	ownerGen atomic.Uint64

	// vipMu serializes VIP netlink actuation (addVIPs/removeVIPs) plus the
	// ownership-generation revalidation across the two goroutines that touch
	// VIPs: the run-loop (becomeMaster/becomeBackup) and the manager's
	// ReconcileVIPs. Holding vipMu across "read gen + actuate + revalidate"
	// makes the check-then-act atomic so a demotion cannot interleave a
	// ReconcileVIPs re-add and strand a BACKUP announcing VIPs (#5082). The
	// lock is uncontended on the normal failover path (ReconcileVIPs is a rare
	// post-programRethMAC reconcile), so it adds no latency to ~60ms failover.
	vipMu sync.Mutex

	// VIP/role divergence accounting for the BACKUP side (#5482). becomeMaster
	// is already fail-closed (#5082): it refuses to publish MASTER when the VIP
	// add fails. The symmetric BACKUP hazard remained: becomeBackup published the
	// BACKUP role via emitEvent even when removeVIPs failed, so a swallowed
	// netlink error left this now-BACKUP node still answering ARP for a VIP it no
	// longer owns (duplicate-address hazard against the new master). We must still
	// publish BACKUP (we ARE stepping down — refusing to emit risks split-brain),
	// so instead of hiding the failure we surface it: vipRemoveFailures is a
	// monotonic count of BACKUP transitions whose synchronous VIP removal failed,
	// and vipDiverged flags that a stale VIP may still be on the wire (cleared once
	// an async reconcile removes it). Atomic so log/test readers stay lock-free.
	vipRemoveFailures atomic.Uint64
	vipDiverged       atomic.Bool

	// vipReconcileBackoff overrides the spacing between stale-VIP remove-reconcile
	// retries (#5482). Zero ⇒ defaultVIPReconcileBackoff. A per-instance field
	// (not a package var) so unit tests shorten it without a shared-global data
	// race against another instance's still-running reconcile goroutine. Set once
	// before the reconcile goroutine starts; the goroutine only reads it.
	vipReconcileBackoff time.Duration

	// netlink seams for VIP actuation. Production leaves them nil and the
	// helpers call netlink live; unit tests inject them to drive addVIPs down
	// a chosen success/failure path without a real kernel interface (#5082).
	linkByNameFn func(name string) (netlink.Link, error)
	addrAddFn    func(link netlink.Link, addr *netlink.Addr) error
	addrDelFn    func(link netlink.Link, addr *netlink.Addr) error

	// onEventDrop is called when an event is dropped due to a full eventCh.
	// Set by the manager to trigger immediate reconciliation.
	onEventDrop func()

	// addrsFn, when non-nil, overrides interface address enumeration. Unit
	// tests inject it to simulate an address change without a real kernel
	// interface (#2528). Production leaves it nil and interfaceAddrs() queries
	// vi.iface.Addrs() live on every resolve.
	addrsFn func() ([]net.Addr, error)

	// resignAckMu guards resignAcks: the set of #6177 ResignBarriers waiting
	// for THIS instance to finish RELEASING its virtual addresses after a
	// forced resignation. A barrier is armed by the manager BEFORE
	// triggerResign, and reported to from the sites that actually complete a
	// VIP release, so a waiter can never be told "released" by a code path
	// that only signalled the resignation.
	//
	// Arming does NOT shortcut on state: reading "already BACKUP" and
	// completing the barrier immediately would be wrong exactly when it
	// matters, because becomeBackup publishes BACKUP (setState) BEFORE it
	// runs removeVIPs — the VIP can still be on the wire while the state
	// already reads BACKUP. Instead the BACKUP arm of the run loop consumes
	// the resign token and reports there, so a genuinely already-resigned
	// instance completes the barrier on the next loop hop rather than
	// stalling it.
	resignAckMu sync.Mutex
	resignAcks  []*ResignBarrier

	// advertCapacityErr is non-nil when this instance's configured VIP set
	// cannot produce a legal VRRPv3 advertisement, so becomeMaster must not
	// claim ownership (#6779). Computed once by instanceAdvertCapacityErr
	// (advert_capacity.go); read-only after construction.
	advertCapacityErr error
}

func newInstance(cfg Instance, iface *net.Interface, eventCh chan<- VRRPEvent, onEventDrop func()) *vrrpInstance {
	capErr := instanceAdvertCapacityErr(cfg) // #6779, advert_capacity.go
	return &vrrpInstance{
		cfg:               cfg,
		desiredPreempt:    cfg.Preempt,
		state:             StateInitialize,
		iface:             iface,
		eventCh:           eventCh,
		afPacketFD:        -1,
		ipv6FD:            -1,
		preemptNowCh:      make(chan struct{}, 1),
		resignCh:          make(chan struct{}, 1),
		configUpdatedCh:   make(chan struct{}, 1),
		rxCh:              make(chan *VRRPPacket, 64),
		stopCh:            make(chan struct{}),
		stopped:           make(chan struct{}),
		onEventDrop:       onEventDrop,
		advertCapacityErr: capErr,
	}
}

func (vi *vrrpInstance) key() string {
	return StateKey(vi.cfg.Interface, vi.cfg.GroupID, vi.cfg.Family)
}

// updateConfig updates priority, preempt, interface-tracking,
// advertise-interval, and gratuitous-ARP-count config in-place without
// restarting.
//
// It runs on the manager goroutine, NOT the run-loop goroutine that owns the
// preemptHoldTimer (#2900). It therefore mutates cfg under mu and then signals
// the run loop via configUpdatedCh rather than touching the timer directly —
// the run loop tears down an in-flight hold whose premise the new config has
// invalidated (preempt disabled, priority demoted, or hold-time changed). This
// keeps all preemptHoldTimer Stop/Reset calls on the single run-loop goroutine.
//
// AdvertiseInterval and GARPCount are copied so a day-2 change reaches the
// running instance (#5087). Both are re-read from cfg by the run loop and the
// failover path, so no explicit timer poke is needed: the MASTER advert timer
// re-arms via advertTimer.Reset(vi.advertInterval()) on its next fire, the
// BACKUP master-down horizon re-reads cfg.AdvertiseInterval via
// masterDownInterval(), and the next failover's sendGARP re-reads
// cfg.GARPCount. Before this copy a commit changing only
// reth-advertise-interval or gratuitous-arp-count left the running instance at
// its stale value until an unrelated restart.
func (vi *vrrpInstance) updateConfig(cfg Instance) {
	vi.mu.Lock()
	vi.cfg.Priority = clampConfigPriority(cfg.Priority)
	vi.cfg.Preempt = cfg.Preempt
	vi.cfg.PreemptHoldTime = cfg.PreemptHoldTime
	vi.cfg.AdvertiseInterval = cfg.AdvertiseInterval
	vi.cfg.GARPCount = cfg.GARPCount
	vi.cfg.TrackInterface = cfg.TrackInterface
	vi.cfg.TrackPriorityCost = cfg.TrackPriorityCost
	vi.desiredPreempt = cfg.Preempt
	vi.mu.Unlock()

	// Wake the BACKUP select so an armed preempt hold-time can be re-validated
	// against the new config. Non-blocking: a coalesced pending signal is fine
	// (the handler re-reads the current cfg, not a per-update delta).
	select {
	case vi.configUpdatedCh <- struct{}{}:
	default:
	}
}

// stepBackup runs one iteration of the StateBackup select. It is called by the
// run loop AND directly by unit tests (the run() preamble unconditionally
// spawns a receiver goroutine that nil-derefs vi.conn on a test instance, so
// tests must not call run() — they drive this seam instead). It returns true
// when the instance has been told to stop (the caller's run loop should
// return).
//
// preemptHoldTimer carries the optional `preempt hold-time` delay (#2850): when
// the masterDownTimer fires while a live lower-priority master is still
// present and a hold-time is configured, the promotion is deferred by arming
// preemptHoldTimer instead of becoming MASTER immediately. handleBackupRx
// cancels the armed hold if a >= -priority master returns.
//
// While the hold is armed, armPreemptHold ALSO keeps masterDownTimer running as
// a liveness watchdog (#4584): a fire while preemptHoldArmed means the held
// master may have gone silent. The masterDownTimer.C case checks
// heldMasterIsStale() — a stale (dead) held master triggers immediate takeover,
// a still-live one re-arms the watchdog and lets the hold run to natural
// expiry — so a held VIP-owning master that dies mid-hold no longer blackholes
// for the full hold-time.
func (vi *vrrpInstance) stepBackup(masterDownTimer, advertTimer, preemptHoldTimer *time.Timer) (stop bool) {
	select {
	case <-vi.stopCh:
		return true
	case pkt := <-vi.rxCh:
		vi.handleBackupRx(pkt, masterDownTimer, preemptHoldTimer)
	case <-masterDownTimer.C:
		// If a preempt hold-time is currently armed, this masterDownTimer fire
		// is the #4584 liveness watchdog, NOT a fresh master-down. armPreemptHold
		// re-armed the timer so a held VIP-owning lower-priority master that DIES
		// mid-hold is detected within one master-down horizon instead of only
		// when the (possibly long) hold-time elapses.
		vi.mu.RLock()
		holdArmed := vi.preemptHoldArmed
		vi.mu.RUnlock()
		if holdArmed {
			if vi.heldMasterIsStale() {
				// The held lower-priority master went SILENT (died) during the
				// hold — nothing is forwarding, so restore the "dead master →
				// immediate takeover" invariant: disarm the hold and become
				// MASTER now instead of blackholing the VIP until the hold
				// expires.
				slog.Info("vrrp: held master silent during preempt hold-time, immediate takeover",
					"key", vi.key())
				vi.disarmPreemptHold(preemptHoldTimer)
				if vi.becomeMaster() {
					advertTimer.Reset(vi.advertInterval())
				} else {
					vi.rearmForRetry(masterDownTimer)
				}
			} else {
				// The held master is still alive (adverts keep arriving and
				// refreshing lastMasterSeen). Preserve the preempt-hold intent:
				// re-arm the watchdog and let the hold run to its natural expiry.
				stopAndDrainTimer(masterDownTimer)
				masterDownTimer.Reset(vi.masterDownInterval())
			}
			return false
		}
		// Master timed out. If this is preemption of a still-live
		// lower-priority master AND a preempt hold-time is configured,
		// defer the takeover by arming the hold timer rather than
		// becoming MASTER now (#2850). Otherwise (no hold-time, the
		// master is genuinely gone, or the one-shot resign bypass is
		// set) become MASTER immediately — today's behavior, unchanged.
		vi.mu.Lock()
		skipHold := vi.skipNextPreemptHold
		vi.skipNextPreemptHold = false
		vi.mu.Unlock()
		if hold := vi.preemptHoldDuration(); !skipHold && hold > 0 && vi.preemptingLiveLowerMaster() {
			slog.Info("vrrp: preempt deferred by hold-time",
				"key", vi.key(), "hold", hold)
			vi.armPreemptHold(masterDownTimer, preemptHoldTimer, hold)
			return false
		}
		if vi.becomeMaster() {
			advertTimer.Reset(vi.advertInterval())
		} else {
			vi.rearmForRetry(masterDownTimer)
		}
	case <-preemptHoldTimer.C:
		// The preempt hold-time elapsed (#2850). The hold is no longer
		// armed; clear the flag before deciding (#2900).
		vi.mu.Lock()
		vi.preemptHoldArmed = false
		vi.mu.Unlock()
		// RE-VALIDATE before taking over (#2900). A >= -priority master
		// returning during the hold would have re-armed masterDownTimer and
		// stopped this timer (handleBackupRx), but two state changes during
		// the hold window are NOT seen on the wire and so do not cancel it:
		// preempt being disabled, or our effective priority being demoted
		// below the live master by a track-interface link-down. Re-running
		// the same gate the force/sync-hold path uses
		// (shouldPreemptObservedMaster) honours both: preempt must still be
		// enabled AND, when a live master is still present, our effective
		// priority must be strictly higher than its last advert (RFC 5798
		// §6.4.2). A master that went silent during the hold reads as stale
		// (beyond the master-down horizon) and the gate returns true, so a
		// genuine dead-master takeover is still immediate.
		if vi.shouldPreemptObservedMaster() {
			slog.Info("vrrp: preempt hold-time elapsed, taking over",
				"key", vi.key())
			if vi.becomeMaster() {
				advertTimer.Reset(vi.advertInterval())
				masterDownTimer.Stop()
			} else {
				vi.rearmForRetry(masterDownTimer)
			}
		} else {
			// Preemption is no longer warranted — do NOT become MASTER.
			// Return to a normal BACKUP tenure by re-arming masterDownTimer
			// so a later silent-master death still triggers takeover. A
			// still-present live master's adverts will keep resetting it
			// (handleBackupRx), so we stay BACKUP as long as it forwards.
			slog.Info("vrrp: preempt hold-time elapsed but preemption no longer valid, staying BACKUP",
				"key", vi.key())
			stopAndDrainTimer(masterDownTimer)
			masterDownTimer.Reset(vi.masterDownInterval())
		}
	case <-vi.resignCh:
		// #6177 item 1: a forced resignation arrived while this instance is
		// ALREADY BACKUP — a cluster demotion for an RG whose VRRP tenure had
		// already ended (peer preempted us, a link-down demotion landed first,
		// a reconcile-driven re-resign). There is no MASTER tenure to tear
		// down, so nothing more will remove VIPs on our behalf and the token
		// would otherwise sit unread in resignCh forever, stalling the fence
		// barrier until its timeout and downgrading a clean failover to a hold.
		//
		// Consume it here and report the honest verdict: a clean release
		// unless a PREVIOUS removal failed and its #5482 reconcile has not yet
		// cleared the address, in which case a VIP may still be answering ARP
		// and this is not a two-owner-safe resignation.
		vi.notifyResigned(vi.staleVIPResignErr())
	case <-vi.configUpdatedCh:
		// A config update landed (updateConfig) while this BACKUP select was
		// running (#2900). If a preempt hold-time is armed, the new config may
		// have invalidated its premise — preempt disabled, priority demoted so
		// we no longer outrank the live master, or a changed hold-time. The
		// simplest correct response is to tear the in-flight hold down and
		// re-arm masterDownTimer: the next expiry re-evaluates against the
		// fresh config (preemptingLiveLowerMaster + the current hold-time) and
		// either re-arms the hold with the NEW duration, takes over, or stays
		// BACKUP. This never silently keeps a stale duration or a stale
		// preempt decision.
		vi.mu.RLock()
		armed := vi.preemptHoldArmed
		vi.mu.RUnlock()
		if armed {
			slog.Info("vrrp: config update during preempt hold — re-validating",
				"key", vi.key())
			vi.disarmPreemptHold(preemptHoldTimer)
			stopAndDrainTimer(masterDownTimer)
			masterDownTimer.Reset(vi.masterDownInterval())
		}
	case <-vi.preemptNowCh:
		// Coordinated preemption from ReleaseSyncHold or forced transition
		// from ForceRGMaster. The forcePreemptOnce flag allows a one-shot
		// preemption even when preempt=false, without leaking into the
		// configured preempt value.
		//
		// force=true (ForceRGMaster) is cluster-authoritative and bypasses
		// the peer-priority gate unconditionally. The non-force sync-hold
		// path is gated on shouldPreemptObservedMaster (#2082): a
		// lower-priority preempt-enabled node no longer transiently becomes
		// a second MASTER while a higher-priority peer is legitimately MASTER.
		vi.mu.Lock()
		force := vi.forcePreemptOnce
		vi.forcePreemptOnce = false
		vi.mu.Unlock()
		if force || vi.shouldPreemptObservedMaster() {
			if vi.becomeMaster() {
				advertTimer.Reset(vi.advertInterval())
				masterDownTimer.Stop()
				// A coordinated/forced promotion supersedes any pending
				// preempt hold-time countdown (#2850).
				vi.disarmPreemptHold(preemptHoldTimer)
			} else {
				vi.rearmForRetry(masterDownTimer)
			}
			break
		}
		// #7579: the release did NOT promote (preempt=false and no
		// address-owner override), and this is the second deafness window.
		//
		// run() already extends the masterDown timer at STARTUP for exactly
		// this reason — see the comment there: with a 30ms RETH interval the
		// ~97ms timer can fire before the AF_PACKET receiver is capturing peer
		// adverts, and the node then promotes into a healthy peer. That shield
		// is one-shot: handleBackupRx drops the timer back to the short
		// interval on the first advert received, so by the time the sync hold
		// releases — typically seconds later — it is long spent.
		//
		// Sync-hold release is at least as predictable a deaf moment as
		// startup. It fires the instant bulk session sync completes, which is
		// when a just-rebooted node is installing synced sessions and is about
		// to do VIP work; a ~97ms scheduling gap on the receiver goroutine
		// there is unremarkable. The masterDownTimer arm is UNGATED by
		// `preempt` — correctly, since RFC 5798's preempt governs displacing a
		// master you can HEAR, not filling an apparent vacancy — so nothing
		// else stops the promotion, and the observed result was a 12.95s
		// window in which both nodes held RG0 and GARP'd for the same RETH
		// VIPs (#7579).
		//
		// Re-arming costs a delayed takeover ONLY while no advert has been
		// heard since the release, because handleBackupRx resets to the short
		// interval on the first one. So a peer that is actually alive costs
		// nothing, and a peer that genuinely died during the hold is taken over
		// after this interval instead of ~97ms — bounded, and cheap against a
		// dual-owner window.
		if d, rearm := vi.masterDownAfterSyncHoldRelease(); rearm {
			stopAndDrainTimer(masterDownTimer)
			masterDownTimer.Reset(d)
			slog.Info("vrrp: sync hold released without preemption — extending the "+
				"master-down timer while no peer advert has been heard (#7579)",
				"key", vi.key(), "interval", d)
		}
	}
	return false
}

// run is the main state machine loop. Must be called as a goroutine.
func (vi *vrrpInstance) run() {
	defer close(vi.stopped)

	// #8597 (muse-004 K20): Interface and GroupID are immutable for an
	// instance's lifetime (a change rebuilds it), but Priority and Preempt are
	// mu-guarded and written by updateConfig on the manager goroutine.
	startPriority, startPreempt := vi.startupLogFields()
	slog.Info("vrrp: instance starting",
		"key", vi.key(),
		"interface", vi.cfg.Interface,
		"vrid", vi.cfg.GroupID,
		"priority", startPriority,
		"preempt", startPreempt)

	// Start per-instance receiver goroutine.
	// AF_PACKET captures at the link layer before generic XDP, ensuring
	// reliable multicast reception on all interface types.
	if vi.afPacketFD >= 0 {
		go vi.receiverAfPacket()
	} else {
		// Start one raw receiver per configured family. A family-specific
		// generic instance must never feed the other family's adverts into its
		// state machine; an empty-family RETH instance has both sockets and keeps
		// the historical dual-stack behavior.
		if vi.rawConn != nil {
			go vi.receiver()
		}
		if vi.ipv6Conn != nil {
			slog.Warn("vrrp: af_packet unavailable, using separate IPv6 raw socket fallback",
				"key", vi.key())
			go vi.receiverIPv6()
		}
	}

	// Transition to Backup state.
	// Remove any stale VIPs that may be on the interface from a previous
	// daemon run or config apply. This ensures BACKUP nodes don't have VIPs.
	// setState precedes surfaceStaleVIP so the async reconcile's state guard sees
	// BACKUP; a swallowed removal failure here would start us as a BACKUP still
	// answering ARP for a stale VIP (#5482).
	staleErr := vi.removeVIPs()
	vi.setState(StateBackup)
	vi.surfaceStaleVIP(staleErr, "run-startup")
	vi.emitEvent()

	// Use an extended initial masterDown timer when preempt is disabled
	// (either from config or sync hold). With short RETH intervals (30ms),
	// the normal masterDown timer (~97ms) can fire before the AF_PACKET
	// receiver starts capturing peer adverts — causing the returning node
	// to erroneously become MASTER. An extended initial timer gives enough
	// time for the receiver to initialize and for the cluster election to
	// determine our role. After the first received advert, handleBackupRx
	// resets the timer to the normal short interval.
	//
	// #7579: the SAME window reopens at sync-hold release; see the
	// preemptNowCh case in stepBackup, which re-arms this interval.
	initialMasterDown := vi.initialMasterDownInterval()
	masterDownTimer := time.NewTimer(initialMasterDown)
	defer masterDownTimer.Stop()

	// Not used until we become Master.
	advertTimer := time.NewTimer(0)
	advertTimer.Stop()
	defer advertTimer.Stop()

	// Preempt hold-time timer (#2850): armed only when the masterDownTimer
	// fires while a live lower-priority master is present and a hold-time is
	// configured. Idle otherwise.
	preemptHoldTimer := time.NewTimer(0)
	preemptHoldTimer.Stop()
	stopAndDrainTimer(preemptHoldTimer)
	defer preemptHoldTimer.Stop()

	for {
		state := vi.getState()

		switch state {
		case StateBackup:
			if vi.stepBackup(masterDownTimer, advertTimer, preemptHoldTimer) {
				return
			}

		case StateMaster:
			select {
			case <-vi.stopCh:
				vi.resignForShutdown()
				return
			case pkt := <-vi.rxCh:
				vi.handleMasterRx(pkt, masterDownTimer, advertTimer)
			case <-advertTimer.C:
				vi.sendAdvert(vi.getPriority())
				advertTimer.Reset(vi.advertInterval())
			case <-vi.resignCh:
				// Forced resignation removes and publishes BACKUP before telling
				// the peer to take over. A failed removal is surfaced by
				// becomeBackup and deliberately does not send priority zero.
				slog.Info("vrrp: forced resignation", "key", vi.key())
				if err := vi.becomeBackup(masterDownTimer, advertTimer); err == nil {
					for range 3 {
						vi.sendAdvert(0)
					}
				}
				// Use an extended safety-net timer instead of stopping entirely.
				// With short RETH intervals (30ms), the normal masterDown timer
				// at priority 0 is only ~120ms, which can re-elect us before the
				// peer starts advertising.
				safetyTimeout := 3 * vi.masterDownInterval()
				if safetyTimeout < 500*time.Millisecond {
					safetyTimeout = 500 * time.Millisecond
				}
				masterDownTimer.Reset(safetyTimeout)
			}
		}
	}
}

// resignForShutdown makes the final VIP removal before publishing BACKUP or
// sending priority-zero advertisements. Netlink removal can fail transiently
// during interface teardown, so keep vipMu held and retry before surrendering.
// If every attempt fails, retain MASTER publication and do not expedite peer
// takeover; the release barrier receives the failure instead.
func (vi *vrrpInstance) resignForShutdown() {
	vi.vipMu.Lock()
	backoff := vi.vipReconcileBackoff
	if backoff <= 0 {
		backoff = defaultVIPReconcileBackoff
	}
	var err error
	for attempt := 0; attempt <= vipRemoveReconcileMax; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
		}
		err = vi.removeVIPsLocked(nil)
		if err == nil {
			vi.setState(StateBackup)
			vi.vipDiverged.Store(false)
			break
		}
	}
	vi.vipMu.Unlock()

	if err != nil {
		vi.vipDiverged.Store(true)
		slog.Error("vrrp: VIP removal failed during resignation shutdown after retries; "+
			"withholding BACKUP publication and priority-zero advertisements",
			"key", vi.key(), "err", err, "attempts", vipRemoveReconcileMax+1)
		vi.notifyResigned(err)
		return
	}
	vi.emitEvent()
	for range 3 {
		vi.sendAdvert(0)
	}
	vi.notifyResigned(nil)
}

// stop signals the instance goroutine to stop and waits for it to finish.
func (vi *vrrpInstance) stop() {
	close(vi.stopCh)

	// Close descriptors to unblock receiver syscalls, but keep the pointer/fd
	// fields stable for the retired instance's lifetime. The receiver goroutines
	// are not separately joined; clearing these fields would race receiver()'s
	// vi.conn and receiverAfPacket()'s vi.afPacketFD reads.
	vi.closeSocketDescriptors()
	<-vi.stopped
	// #6177: the run loop has exited. Anything armed after its final release
	// (or armed against an instance that was never MASTER) will never be
	// reported by the loop, so report it here rather than leaving the caller's
	// fence to burn its timeout. The instance is retired: it holds no VIP
	// tenure, so a clean verdict is honest unless a removal is known to have
	// failed and not been reconciled.
	vi.notifyResigned(vi.staleVIPResignErr())
}

// clampConfigPriority bounds a CONFIGURED VRRP priority to the domain the wire
// field can carry, before it is stored on the instance.
//
// Applied at the two CONFIG entry points — the manager's config->instance
// install (manager.go) and updateConfig — and deliberately NOT inside
// newInstance. newInstance is a plain constructor, also used to model states
// the runtime reaches by MUTATION rather than from config: ResignRG sets
// cfg.Priority to 0 under the instance lock, and 0 there is the correct
// representation of a resigning master. Clamping in the constructor made that
// state unconstructible and broke TestGetPriority_TrackMatrix's
// priority-0-resign-passthrough case, which was right to fail.
//
// #8597 / gemini-review-048 finding 17. `instance_send.go` puts
// `uint8(priority)` on the wire while the local state machine compares
// `vi.cfg.Priority` as an int (instance_preempt.go reads it directly, three
// sites). A configured 256 truncated to 0 — and 0 is not merely a low
// priority, it is the RFC 5798 RESIGNATION beacon this package uses to hand
// mastership over (manager.go ResignRG). The node would advertise "take over
// now" forever while believing itself the most preferred candidate.
//
// #8321 recorded this finding's mechanism as real and its REACHABILITY as
// unestablished: "I have not found such a path and I am not asserting there is
// none." muse-004 K17 supplies it, and it is verified by execution rather than
// argued — the `vrrp-group ... priority` leaf carries `ValidateInteger(1, 255)`,
// which the tolerant Store.Load / Store.SyncApply ingress downgrades to a
// warning per #1960, exactly as its chassis-cluster sibling does. Both
// protocols reach a narrow wire field from a wide config int through the same
// door.
//
// The two clamp targets are deliberately different values:
//
//   - Below range -> 1, never 0. Clamping to 0 would install the resignation
//     sentinel from config, which is the bug rather than a bound.
//   - Above range -> 254, never 255. 255 is the IP-ADDRESS-OWNER priority, and
//     it carries semantics beyond "most preferred": preemptEnabled() treats an
//     owner as always-preempting, and track.go exempts it from track-down
//     demotion. Saturating to 255 would silently grant a config those
//     properties. 254 is the highest value that means only "most preferred".
//
// An explicit 255 is passed through untouched: it is in range and it is how an
// operator legitimately declares the address owner.
func clampConfigPriority(p int) int {
	if p == addressOwnerPriority {
		return addressOwnerPriority
	}
	if p < 1 {
		return 1
	}
	if p > 254 {
		return 254
	}
	return p
}
