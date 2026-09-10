package vrrp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
)

// instanceKey identifies a unique VRRP instance.
//
// family distinguishes a dual-stack VRRP group (#5083): an IPv4 and an IPv6
// group configured on the SAME unit with the SAME VRID are two independent
// VRRP protocol instances (distinct multicast groups / adverts), and the
// generic collector emits one Instance per family. Without family in the key
// they would collapse to one map entry and UpdateInstances would silently drop
// a family (last-wins). The unit is already encoded in iface — the collector
// stores the resolved KERNEL device name, so a VLAN sub-interface / non-zero
// unit yields a distinct iface (ge-0-0-0.100) on its own. Generic instances
// carry inet/inet6 even when single-stack; implicit RETH instances leave family
// empty so their keys remain byte-identical to before.
type instanceKey struct {
	iface   string
	groupID int
	family  string
}

type electionKey struct {
	iface   string
	groupID int
}

type electionDomains struct {
	mixed bool
	inet  bool
	inet6 bool
}

func (d *electionDomains) conflictingFamily(family string) (string, bool) {
	switch family {
	case "":
		// Empty-family RETH consumes both wire families and therefore overlaps
		// every existing domain. Keep the reported conflict deterministic.
		if d.mixed {
			return "", true
		}
		if d.inet {
			return "inet", true
		}
		if d.inet6 {
			return "inet6", true
		}
	case "inet", "inet6":
		if d.mixed {
			return "", true
		}
	}
	return "", false
}

func (d *electionDomains) add(family string) {
	switch family {
	case "":
		d.mixed = true
	case "inet":
		d.inet = true
	case "inet6":
		d.inet6 = true
	}
}

// validateInstanceFamily enforces the generic-collector family identity at
// the manager boundary. RETH instances intentionally leave Family empty and
// may carry both families in one state machine; a family-tagged generic
// instance must carry only VIPs from that election domain. The config commit
// path normally guarantees this, but lenient/peer loads and direct callers
// can reach the manager, where accepting a mismatch would reintroduce
// cross-family election coupling under a misleading key.
func validateInstanceFamily(inst *Instance) error {
	if inst == nil {
		return fmt.Errorf("nil VRRP instance")
	}
	if inst.Family == "" {
		return nil
	}
	if inst.Family != "inet" && inst.Family != "inet6" {
		return fmt.Errorf("invalid VRRP family %q on interface %q VRID %d", inst.Family, inst.Interface, inst.GroupID)
	}
	for _, vip := range inst.VirtualAddresses {
		if family := familyOfAddrs([]string{vip}); family != "" && family != inst.Family {
			return fmt.Errorf(
				"VRRP family %q on interface %q VRID %d conflicts with VIP %q (%s)",
				inst.Family, inst.Interface, inst.GroupID, vip, family,
			)
		}
	}
	return nil
}

// isRethInstance distinguishes the implicit cluster/RETH state machines from
// generic standalone VRRP. CollectRethInstances deliberately leaves Family
// empty; CollectInstances always assigns inet/inet6. Cluster control methods
// must not commandeer a valid standalone VRID that happens to equal 100+RG.
func isRethInstance(inst Instance) bool {
	return inst.Family == ""
}

// Manager manages all VRRP instances.
type Manager struct {
	mu             sync.RWMutex
	instances      map[instanceKey]*vrrpInstance
	eventCh        chan VRRPEvent
	closeEventOnce sync.Once // guards closing eventCh
	cancel         context.CancelFunc
	syncHold       bool        // suppress preemption until session sync completes
	syncHoldTimer  *time.Timer // safety timeout to release hold
	syncHoldReason string      // "bulk-sync-complete" or "timeout-degraded"
	onEventDrop    func()      // called when an event is dropped (full channel)

	// Interface tracking (#1814): ONE singleton link-watcher goroutine
	// feeds trackDown into instances whose cfg.TrackInterface matches.
	watcherRunning  bool          // guarded by mu — singleton latch
	watcherStarts   int           // guarded by mu — observability/test seam
	watcherStop     chan struct{} // closed by Stop()
	watcherStopOnce sync.Once

	// Injectable link-state seams (unit tests must not require real
	// netlink). Production defaults are set in NewManager.
	linkState      func(name string) (bool, error)
	subscribeLinks func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error

	// linkNames is the link-watcher's ifindex -> current-name cache (#2944).
	// The kernel emits a runtime rename as a SINGLE RTM_NEWLINK carrying the
	// SAME ifindex with the NEW name and NO RTM_DELLINK for the old name, so
	// name-only matching would leave an instance tracking the old name stuck at
	// its last (typically up) state forever. Keying on the stable ifindex lets
	// the watcher notice that an ifindex's name CHANGED and re-evaluate the old
	// (now-vanished) name so the tracking instance demotes. Guarded by mu;
	// owned by the singleton link-watcher goroutine and reset per run.
	linkNames map[int]string

	// Source-address watcher (#2528): ONE singleton goroutine subscribing to
	// netlink ADDRESS updates so an instance's cached advert source
	// (localIP/localIPv6) is re-resolved when the interface's address changes
	// — closes the stale-source split-brain window opened by the RETH MAC
	// reprogram cycle. Distinct latch from the link-watcher; both share
	// m.watcherStop for cancellation. subscribeAddrs defaults to
	// netlink.AddrSubscribe and is injectable so unit tests need no real
	// netlink.
	addrWatcherRunning bool // guarded by mu — singleton latch
	addrWatcherStarts  int  // guarded by mu — observability/test seam
	subscribeAddrs     func(ch chan<- netlink.AddrUpdate, done <-chan struct{}) error

	// desiredIfaces is the set of interface NAMES from the most recent
	// UpdateInstances desired set (#2788). It lets the addr-watcher recognise
	// an address event for a CONFIGURED interface that has no instance yet —
	// the late-appearing-interface case: a member/VLAN/RETH netdev that did
	// not exist (or was unresolvable) at the UpdateInstances that last ran, so
	// resolveIface failed and no instance was built and added to m.instances.
	// Such an interface is absent from BOTH addrwatch match loops (cached
	// ifindex and name-drift), so its first address event would be dropped and
	// the instance would wait up to ~2s for the periodic reconcile to retry
	// the build. Recording the desired names lets us schedule an immediate
	// reconcile on that first event instead. Guarded by mu.
	desiredIfaces map[string]struct{}

	// unbuiltDesired records the desired VRRP keys from the most recent
	// UpdateInstances that have NO live instance in m.instances — a key whose
	// build failed (interface resolve failure / socket bind failure / family
	// capability failure) or that was never yet built. It is the source of
	// truth RGVRRPReady consults so a PARTIALLY-built RG is not reported ready
	// (#5641): before this, RGVRRPReady returned READY as soon as ANY single
	// instance existed for the RG's VRID, so if one of several desired member /
	// VLAN-sub / family keys failed to build, its VIP was silently dark while
	// the cluster state machine released the sync hold / preempted / claimed
	// ownership. The value is a human-readable failure reason. Recomputed
	// wholesale each reconcile off the authoritative desiredMap-vs-m.instances
	// diff, so a key that recovers on a later pass clears itself. Guarded by mu.
	unbuiltDesired map[instanceKey]string

	// resolveLinkName maps a kernel ifindex to its current link NAME. The
	// addr-watcher (#2707) calls it ONLY on a cached-ifindex miss — when an
	// address event arrives for an ifindex no instance is bound to. A
	// VLAN/GRE/WireGuard link that is deleted+recreated (config change, driver
	// restart, link-cycle recovery) gets a NEW ifindex, so the cached
	// vi.iface.Index no longer matches and every subsequent address event on
	// the recreated link would be ignored until the ~2s reconcile noticed the
	// drift. Resolving the event ifindex back to a name lets us re-match the
	// instance by its STABLE configured name and trigger an immediate
	// reconcile. Defaults to a netlink.LinkByIndex wrapper; injectable so unit
	// tests need no real netlink.
	resolveLinkName func(ifindex int) (string, error)

	// Injectable instance-lifecycle seams (#2156). Unit tests must not
	// require real raw sockets or a live run() goroutine to exercise the
	// build-before-teardown ordering in UpdateInstances. Production
	// defaults are set in NewManager:
	//   resolveIface       -> net.InterfaceByName
	//   openInstanceSocket -> vi.openSocket()   (the "proof" step)
	//   runInstance        -> `go vi.run()`     (the "commit" step)
	//   stopInstance       -> vi.stop()
	resolveIface       func(name string) (*net.Interface, error)
	openInstanceSocket func(vi *vrrpInstance) error
	runInstance        func(vi *vrrpInstance)
	stopInstance       func(vi *vrrpInstance)
}

// SetOnEventDrop registers a callback invoked when a VRRP event is dropped
// due to a full channel. The daemon uses this to schedule an immediate
// reconciliation pass.
func (m *Manager) SetOnEventDrop(fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onEventDrop = fn
}

// NewManager creates a new VRRP manager.
func NewManager() *Manager {
	return &Manager{
		instances:          make(map[instanceKey]*vrrpInstance),
		unbuiltDesired:     make(map[instanceKey]string),
		eventCh:            make(chan VRRPEvent, 256),
		watcherStop:        make(chan struct{}),
		linkNames:          make(map[int]string),
		linkState:          netlinkLinkState,
		subscribeLinks:     netlinkLinkSubscribe,
		subscribeAddrs:     netlink.AddrSubscribe,
		resolveLinkName:    netlinkLinkName,
		resolveIface:       net.InterfaceByName,
		openInstanceSocket: func(vi *vrrpInstance) error { return vi.openSocket() },
		runInstance:        func(vi *vrrpInstance) { go vi.run() },
		stopInstance:       func(vi *vrrpInstance) { vi.stop() },
	}
}

// Start initializes the manager (no shared socket — each instance has its own).
//
// Start is reuse-safe: a Manager that was previously Stop()ped can be
// Start()ed again. Stop() closes the run-scoped channels (watcherStop,
// eventCh) and cancels the context; Start() re-allocates those channels,
// resets the sync.Once guards, and clears the singleton watcher latches so
// the next UpdateInstances cleanly re-spawns the link/addr watchers
// (#2625). Without this re-init a Stop->Start cycle would: hand callers a
// closed eventCh (send-on-closed panic), make every freshly-spawned
// watcher observe the already-closed watcherStop and exit immediately, and
// leave watcherRunning/addrWatcherRunning latched true so ensure*Locked
// never re-spawns. Production creates the Manager once and only Stop()s at
// shutdown, so this is a latent-lifecycle fix; the unit tests are the
// safety net (the cluster failover gate exercises the single-run path).
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	m.resetRunStateLocked()
	_, m.cancel = context.WithCancel(ctx)
	m.mu.Unlock()
	slog.Info("vrrp: manager started")
	return nil
}

// resetRunStateLocked re-initializes the per-run channels, once-guards, and
// singleton watcher latches so the Manager is safe to Start() after a Stop().
// Caller MUST hold m.mu. It is also invoked implicitly from NewManager's
// equivalent field initialization — the values here mirror NewManager's
// run-scoped defaults so a fresh-construct and a reuse-after-Stop converge on
// the same state. It deliberately does NOT touch instances, seams
// (linkState/subscribe*/resolve*/run/stop/open), or the onEventDrop callback:
// those are construction-time or caller-owned, not run-scoped.
func (m *Manager) resetRunStateLocked() {
	m.watcherStop = make(chan struct{})
	m.watcherStopOnce = sync.Once{}
	m.eventCh = make(chan VRRPEvent, 256)
	m.closeEventOnce = sync.Once{}
	m.watcherRunning = false
	m.addrWatcherRunning = false
	// Drop the previous run's ifindex->name cache (#2944): a re-subscribe
	// re-seeds it from current kernel state (ListExisting), so a stale mapping
	// from before the Stop() must not survive into the new run.
	m.linkNames = make(map[int]string)
}

// Stop stops all instances, removes VIPs, and cancels the context.
func (m *Manager) Stop() {
	m.mu.Lock()
	if m.syncHoldTimer != nil {
		m.syncHoldTimer.Stop()
	}
	instances := make(map[instanceKey]*vrrpInstance, len(m.instances))
	for k, v := range m.instances {
		instances[k] = v
	}
	m.instances = make(map[instanceKey]*vrrpInstance)
	// Drop the desired-vs-built record too (#5641): with no instances left it
	// must not report stale un-built keys as un-ready across a Stop()/Start()
	// reuse; the next UpdateInstances recomputes it wholesale.
	m.unbuiltDesired = make(map[instanceKey]string)
	// Capture a CONSISTENT once/channel pair (and the channel) under the lock
	// so the close below operates on a matched generation. This keeps the
	// realistic sequential reuse correct: Stop() closes generation N's
	// channels, then a later Start() re-allocates generation N+1's via
	// resetRunStateLocked (also under m.mu).
	//
	// It does NOT make a concurrent Stop()+Start() race-free: the once-guard
	// Do() and the channel reads run AFTER the lock is released (they must —
	// vi.stop() below blocks on each run() goroutine exiting and cannot hold
	// m.mu, and the close has to follow the instance teardown ordering). A
	// hypothetical concurrent Start() resetting watcherStopOnce / re-allocating
	// the channels could still interleave. That is not reachable today: the
	// Manager is not designed for concurrent Stop/Start — its sole caller (the
	// daemon) does Start-once at init and Stop-once at shutdown, never
	// concurrently (#2625). No locking machinery is added for the unreachable
	// case; the capture is only to keep the pair self-consistent.
	watcherStop := m.watcherStop
	watcherStopOnce := &m.watcherStopOnce
	eventCh := m.eventCh
	closeEventOnce := &m.closeEventOnce
	cancel := m.cancel
	m.mu.Unlock()

	// Stop all instances (removes VIPs, sends priority-0, closes per-instance
	// socket) BEFORE closing eventCh: the stopCh shutdown arm in run() does not
	// emitEvent, but stopping instances first keeps the channel-close strictly
	// after all senders are quiesced regardless.
	for _, vi := range instances {
		vi.stop()
	}

	// Stop the singleton link/addr watchers (done-channel cancellation; the
	// netlink subscriptions observe the same channel). Both watchers pinned
	// this exact channel at spawn time, so closing it cancels precisely this
	// run generation's goroutines; a later Start() re-allocates a fresh one.
	watcherStopOnce.Do(func() { close(watcherStop) })

	// Close events channel so watchers (e.g. daemon's watchVRRPEvents) unblock.
	closeEventOnce.Do(func() { close(eventCh) })

	if cancel != nil {
		cancel()
	}
	slog.Info("vrrp: manager stopped")
}

// SetSyncHold enables sync hold mode — all VRRP instances start with
// preempt=false regardless of config, suppressing preemption until session
// sync completes. A safety timeout releases the hold if sync never arrives.
func (m *Manager) SetSyncHold(timeout time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if m.syncHoldTimer != nil {
		m.syncHoldTimer.Stop()
		m.syncHoldTimer = nil
	}
	wasHeld := m.syncHold
	m.syncHold = true
	m.syncHoldReason = ""
	if !wasHeld {
		for _, vi := range m.instances {
			vi.suppressPreempt()
		}
	}
	m.syncHoldTimer = time.AfterFunc(timeout, func() {
		slog.Warn("vrrp: sync-hold timeout: bulk sync did not complete within timeout, releasing in degraded mode",
			"timeout", timeout)
		m.releaseSyncHoldWithReason("timeout-degraded")
	})
	slog.Info("vrrp: sync hold active, preemption disabled", "timeout", timeout)
}

// ReleaseSyncHold restores configured preempt values on all instances,
// allowing normal VRRP preemption to proceed. Records reason as
// "bulk-sync-complete" (the normal path).
func (m *Manager) ReleaseSyncHold() {
	m.releaseSyncHoldWithReason("bulk-sync-complete")
}

// releaseSyncHoldWithReason is the internal release path that records why
// the sync hold was released.
func (m *Manager) releaseSyncHoldWithReason(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.syncHold {
		return
	}
	m.syncHold = false
	m.syncHoldReason = reason
	if m.syncHoldTimer != nil {
		m.syncHoldTimer.Stop()
		m.syncHoldTimer = nil
	}
	for _, vi := range m.instances {
		vi.restorePreempt()
		vi.triggerPreemptNow()
	}
	slog.Info("vrrp: sync hold released, preemption enabled", "reason", reason)
}

// InSyncHold returns true if the manager is in sync-hold state (startup,
// waiting for session sync before allowing preemption).
func (m *Manager) InSyncHold() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.syncHold
}

// SyncHoldReason returns why the sync hold was released: "bulk-sync-complete"
// for normal operation, "timeout-degraded" if the safety timeout fired before
// bulk sync arrived, or "" if sync hold was never set or is still active.
func (m *Manager) SyncHoldReason() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.syncHoldReason
}

// Events returns the event channel for state change notifications.
func (m *Manager) Events() <-chan VRRPEvent {
	return m.eventCh
}

// UpdateInstances diffs the current instances against the desired set and
// adds/removes/updates as needed.
func (m *Manager) UpdateInstances(desired []*Instance) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Build desired map. Also record the set of desired interface NAMES so the
	// addr-watcher can recognise an address event for a configured interface
	// that has no instance built yet (#2788, late-appearing interface).
	desiredMap := make(map[instanceKey]*Instance, len(desired))
	domainsByElection := make(map[electionKey]*electionDomains, len(desired))
	desiredIfaces := make(map[string]struct{}, len(desired))
	needsLinkWatcher := false
	for _, inst := range desired {
		if err := validateInstanceFamily(inst); err != nil {
			return err
		}
		// #4573 defensive VRID range guard. The GroupID is truncated onto the
		// single VRID wire byte (uint8(vi.cfg.GroupID) in instance.go). An
		// out-of-range id normally cannot reach here — the config commit gate
		// (validateVRRPGroupIDStrict) rejects it — but the tolerant load /
		// HA-sync path downgrades that gate to a warning (#1960 no-brick), so a
		// bad id could slip through and advertise the reserved VRID 0 (256→0) or
		// an aliased VRID (257→1). Refuse to build such an instance rather than
		// emit a wrong-VRID advert that a strict RFC peer discards.
		if inst.GroupID < MinVRID || inst.GroupID > MaxVRID {
			slog.Warn("vrrp: skipping instance with out-of-range VRID",
				"interface", inst.Interface, "group_id", inst.GroupID,
				"valid_range", fmt.Sprintf("%d..%d", MinVRID, MaxVRID))
			continue
		}
		// #6779 defensive advert-capacity guard, same doctrine as the VRID guard
		// above. A VIP set carrying more addresses of one family than the u8
		// "Count IPvX Addr" field can express makes every Marshal for that
		// family fail — and sendAdvert discards that error at
		// slog.Debug. Building the instance anyway would put a node in the
		// election that claims VIPs and never advertises: the peer times out and
		// promotes too (dual-master), or the VIP is stranded. The config commit
		// gate (validateVRRPVIPCountStrict, pkg/config) rejects such a set, but
		// the tolerant load / HA-sync path downgrades it to a warning (#1960
		// no-brick), so refuse to build the instance rather than seat a silent
		// non-advertiser.
		if err := checkAdvertCapacity(inst.VirtualAddresses); err != nil {
			slog.Warn("vrrp: skipping instance whose virtual addresses cannot "+
				"produce a legal advertisement",
				"interface", inst.Interface, "group_id", inst.GroupID,
				"vip_count", len(inst.VirtualAddresses), "err", err)
			continue
		}
		key := instanceKey{iface: inst.Interface, groupID: inst.GroupID, family: inst.Family}
		if _, exists := desiredMap[key]; exists {
			return fmt.Errorf(
				"duplicate VRRP instance identity interface=%q VRID=%d family=%q; refusing non-deterministic last-wins reconciliation",
				inst.Interface, inst.GroupID, inst.Family,
			)
		}
		wireKey := electionKey{iface: inst.Interface, groupID: inst.GroupID}
		domains := domainsByElection[wireKey]
		if domains == nil {
			domains = &electionDomains{}
			domainsByElection[wireKey] = domains
		}
		if conflict, overlaps := domains.conflictingFamily(inst.Family); overlaps {
			first, second := conflict, inst.Family
			if second < first {
				first, second = second, first
			}
			return fmt.Errorf(
				"overlapping VRRP election domains interface=%q VRID=%d families=%q,%q; empty-family RETH overlaps both wire families",
				inst.Interface, inst.GroupID, first, second,
			)
		}
		domains.add(inst.Family)
		desiredMap[key] = inst
		desiredIfaces[inst.Interface] = struct{}{}
		if inst.TrackInterface != "" {
			needsLinkWatcher = true
		}
	}
	// Start watchers only after the entire desired set passes validation. A
	// duplicate/malformed identity returns transactionally without publishing
	// a partial desired-name set or starting background work for a rejected
	// reconcile.
	if needsLinkWatcher {
		// Lazily start the singleton link watcher once any instance tracks an
		// interface (#1814). Idempotent under m.mu.
		m.ensureLinkWatcherLocked()
	}
	if len(desiredMap) > 0 {
		// Every VRRP interface needs its advert source re-resolved when its
		// address changes (#2528), not just tracked ones.
		m.ensureAddrWatcherLocked()
	}
	// Publish the desired-name set for the addr-watcher (#2788). Replaced
	// wholesale every reconcile so a removed interface stops being treated as
	// late-appearing.
	m.desiredIfaces = desiredIfaces

	// Remove instances no longer desired.
	for key, vi := range m.instances {
		if _, ok := desiredMap[key]; !ok {
			slog.Info("vrrp: removing instance", "key", vi.key())
			vi.stop()
			delete(m.instances, key)
		}
	}

	// buildFailReason records, per desired key, WHY its build did not complete
	// on this pass (resolve / socket / family capability). It annotates the
	// #5641 unbuilt-desired record computed after the loop; keys that build
	// successfully are absent. A key whose build fails while an OLD instance
	// keeps advertising (build-before-teardown, #2156) stays in m.instances
	// under its key and is therefore NOT counted as unbuilt below — the RG is
	// still in election with its previous VIP set, not dark.
	buildFailReason := make(map[instanceKey]string)

	// Add or update instances.
	for key, inst := range desiredMap {
		existing, ok := m.instances[key]
		if ok {
			// #2294: detect ifindex drift on an otherwise-unchanged
			// instance. The per-instance AF_PACKET / raw / IPv6 sockets are
			// bound to the member interface's kernel ifindex at openSocket()
			// time. If the netdev is deleted+recreated or renamed
			// (carrier/VLAN flap that fully removes and re-adds the link) its
			// ifindex changes while the xpf config stays byte-identical, so
			// the no-change and in-place (priority-only) branches below would
			// leave the instance bound to the STALE ifindex — its sockets can
			// no longer send/receive VRRP adverts and the RG goes permanently
			// silent (split-brain / blackhole) until an operator re-commit or
			// daemon restart. When the live ifindex differs from the bound
			// one we force the build-before-teardown restart path below (a
			// fresh socket is mandatory; a config-only in-place update cannot
			// rebind).
			//
			// The probe is a cheap, TOLERANT name->ifindex resolve: a resolve
			// FAILURE is treated as "no drift" so a transient netlink hiccup
			// never blocks a time-critical priority/preempt in-place update
			// (failover priority, sync-hold release) — those paths
			// historically never touched netlink, and the build block below
			// already owns the resolve-failure-keeps-old-instance recovery.
			// Detection is idempotent: an unchanged ifindex returns false and
			// the normal no-change / in-place path runs with no churn. This
			// runs every ~2s reconcile tick (daemon reconcileVRRPInstances),
			// so it neither allocates nor restarts on a steady config.
			ifindexChanged := false
			if probe, perr := m.resolveIface(inst.Interface); perr == nil && probe.Index != existing.iface.Index {
				ifindexChanged = true
			}

			// Check if config changed (and the live ifindex is unchanged).
			// AdvertiseInterval (advert timer / masterDown / wire Max-Adver-Int)
			// and GARPCount (per-VIP gratuitous-ARP burst on failover) are wire/
			// timer/burst fields the run loop re-reads from cfg, so a day-2 change
			// to EITHER must break the no-change shortcut and take the in-place
			// updateConfig arm below — otherwise a commit changing only
			// reth-advertise-interval or gratuitous-arp-count is silently dropped
			// until an unrelated restart (#5087).
			if !ifindexChanged &&
				existing.cfg.Priority == inst.Priority &&
				existing.cfg.Preempt == inst.Preempt &&
				existing.cfg.PreemptHoldTime == inst.PreemptHoldTime &&
				existing.cfg.AdvertiseInterval == inst.AdvertiseInterval &&
				existing.cfg.GARPCount == inst.GARPCount &&
				existing.cfg.TrackInterface == inst.TrackInterface &&
				existing.cfg.TrackPriorityCost == inst.TrackPriorityCost &&
				vipsEqual(existing.cfg.VirtualAddresses, inst.VirtualAddresses) {
				continue // No change.
			}
			// If only priority/preempt/tracking/advertise-interval/GARP-count
			// changed (and the ifindex is unchanged), update in-place without
			// stopping. Restarting would cause a 3s master-down gap where the
			// node falsely becomes MASTER before hearing the peer. An ifindex
			// change is NOT in-place-updatable — it requires a fresh socket — so
			// it skips this arm and falls through to the build-before-teardown
			// path.
			if !ifindexChanged && vipsEqual(existing.cfg.VirtualAddresses, inst.VirtualAddresses) {
				slog.Info("vrrp: priority update", "key", existing.key(),
					"old_pri", existing.cfg.Priority, "new_pri", inst.Priority)
				trackIfaceChanged := existing.cfg.TrackInterface != inst.TrackInterface
				instCfg := *inst
				if m.syncHold {
					instCfg.Preempt = false
				}
				existing.updateConfig(instCfg)
				if m.syncHold {
					existing.setDesiredPreempt(inst.Preempt)
				}
				if trackIfaceChanged {
					m.seedTrackState(existing, inst.TrackInterface)
				}
				continue
			}
			// VIPs changed OR the ifindex drifted — the instance must be
			// restarted (changing the VIP set or rebinding to a new ifindex
			// requires re-opening sockets and re-running the state machine).
			// BUILD THE REPLACEMENT BEFORE TEARING DOWN the old one (#2156):
			// a transient member-link failure (carrier flap, mid-rename by
			// networkd) used to delete the working instance and then
			// `continue` on InterfaceByName/openSocket error, orphaning the
			// RG out of VRRP election until an operator re-commit. Falls
			// through to the shared build block below; the old instance is
			// only stopped+replaced on a fully-built replacement. The restart
			// preserves the configured priority/preempt/tracking (it rebuilds
			// from the same desired `inst`) and re-applies sync-hold
			// suppression below, so an ifindex rebind cannot spuriously
			// preempt or break the sync hold. RG role in the cluster state
			// machine is driven separately (heartbeat / debounced priority),
			// not reset here.
			if ifindexChanged {
				slog.Info("vrrp: restarting instance (ifindex changed)",
					"key", existing.key(), "old_ifindex", existing.iface.Index)
			} else {
				slog.Info("vrrp: restarting instance", "key", existing.key(),
					"old_pri", existing.cfg.Priority, "new_pri", inst.Priority)
			}
		}

		// Build the (possibly replacement) instance. On ANY build failure we
		// leave m.instances untouched: an existing instance keeps advertising
		// its old VIP set (strictly better than dropping out of election), and
		// a brand-new key is simply not created yet. The 2s reconcile re-drive
		// (daemon reconcileVRRPInstances) and the two existing UpdateInstances
		// callers retry until the interface returns. No placeholder state is
		// added to m.instances; a brand-new key with no live instance is instead
		// recorded in m.unbuiltDesired below (#5641) so RGVRRPReady reports the
		// RG NOT ready while a sibling VIP is dark, rather than reporting ready
		// off the mere existence of one built key. This resolve is the
		// authoritative one bound into the new instance; the #2294 drift probe
		// above is only a cheap detector.
		iface, err := m.resolveIface(inst.Interface)
		if err != nil {
			slog.Warn("vrrp: interface not found, keeping existing instance",
				"interface", inst.Interface, "have_existing", ok, "err", err)
			buildFailReason[key] = fmt.Sprintf("interface %q resolve failed: %v", inst.Interface, err)
			continue
		}

		instCfg := *inst
		if m.syncHold {
			instCfg.Preempt = false
		}
		// #8597: bound the CONFIGURED priority here, at the config->instance
		// boundary, rather than inside newInstance. newInstance is also the
		// constructor tests use to model states the runtime reaches by
		// MUTATION — notably the priority-0 resignation the run loop installs
		// via ResignRG — and clamping there would make the constructor unable
		// to express a state production genuinely holds. See
		// clampConfigPriority (instance.go) for why an unbounded config
		// priority is a resignation beacon rather than a wrong number.
		instCfg.Priority = clampConfigPriority(instCfg.Priority)
		vi := newInstance(instCfg, iface, m.eventCh, m.onEventDrop)
		// Store the real configured preempt value for when sync hold releases.
		vi.desiredPreempt = inst.Preempt

		// Seed tracked-link state before the state machine starts so the
		// first advert already carries the effective priority (#1814).
		if inst.TrackInterface != "" {
			m.seedTrackState(vi, inst.TrackInterface)
		}

		// PROOF step: open the per-instance socket. This is the operation
		// that fails on a transient member-link problem. On failure the new
		// instance is discarded WITHOUT touching m.instances — the old one
		// (if any) keeps running and advertising its old VIPs
		// (build-before-teardown). run() has NOT been started, so there is
		// no goroutine to stop and no fd leak (openSocket closes its own
		// conn on error).
		if err := m.openInstanceSocket(vi); err != nil {
			slog.Warn("vrrp: failed to open socket, keeping existing instance",
				"interface", inst.Interface, "have_existing", ok, "err", err)
			buildFailReason[key] = fmt.Sprintf("interface %q socket open failed: %v", inst.Interface, err)
			continue
		}

		// COMMIT step: the replacement is proven buildable. Only now tear
		// down the old instance, then swap in and start the new one. stop()
		// blocks on the old run() goroutine exiting before the new run()
		// owns the key, so the two state machines never run concurrently
		// for the same key (no double-run).
		if ok {
			m.stopInstance(existing)
		}
		m.instances[key] = vi
		m.runInstance(vi)
	}

	// #5641: record every desired key that has NO live instance after this
	// reconcile so RGVRRPReady can refuse to report a partially-built RG as
	// ready. The authoritative test is desiredMap-vs-m.instances (not "did a
	// continue fire"): a key kept alive by the build-before-teardown path is
	// still in m.instances and correctly excluded, while a brand-new key or a
	// sibling member/VLAN-sub/family key that failed to build is flagged with
	// its captured reason (or a generic fallback if it was omitted upstream,
	// e.g. the out-of-range VRID guard). Replaced wholesale so recovered keys
	// clear.
	unbuilt := make(map[instanceKey]string, len(buildFailReason))
	for key := range desiredMap {
		if _, built := m.instances[key]; built {
			continue
		}
		reason := buildFailReason[key]
		if reason == "" {
			reason = "instance not built"
		}
		unbuilt[key] = reason
	}
	m.unbuiltDesired = unbuilt

	return nil
}

// ResignRG forces all VRRP instances for the given redundancy group
// to resign by sending priority-0 adverts and transitioning to BACKUP.
// Also immediately sets the instance priority to 0 to prevent
// re-election before the debounced priority update fires.
// Used when cluster state transitions from Primary to Secondary
// (manual failover, weight drop, etc.) in non-preempt mode.
//
// The returned ResignBarrier completes when every targeted instance has
// physically released its virtual addresses (#6177 item 1). The priority-0
// write is synchronous, but triggerResign is not: the advert burst and the
// becomeBackup VIP removal run on each instance's own goroutine, so ResignRG
// returning means "resignation signalled and priority driven to 0", NOT "the
// VIPs are off the wire". A caller fencing a remote failover against a
// two-owner window must wait on the barrier; a caller that only needs the
// election result (the reconcile safety net) may ignore it. Never nil: an RG
// with no matching instances yields an already-complete barrier.
func (m *Manager) ResignRG(rgID int) *ResignBarrier {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vrid := 100 + rgID
	var targets []*vrrpInstance
	for _, vi := range m.instances {
		if isRethInstance(vi.cfg) && vi.cfg.GroupID == vrid {
			targets = append(targets, vi)
		}
	}
	barrier := newResignBarrier(len(targets))
	for _, vi := range targets {
		// Arm the barrier BEFORE the trigger so the run loop cannot complete
		// the release in the gap and leave this registration unreported.
		vi.armResignAck(barrier)
		// Set priority to 0 BEFORE triggering resign. Without this,
		// the masterDown timer (~97ms) can fire before the debounced
		// priority update (500ms), causing the instance to re-elect
		// at the old high priority and knock the peer back to BACKUP.
		vi.mu.Lock()
		vi.cfg.Priority = 0
		vi.mu.Unlock()
		vi.triggerResign()
	}
	return barrier
}

// UpdateRGPriority immediately sets the VRRP priority for all instances
// belonging to the given redundancy group. Used to restore priority
// after ResignRG set it to 0 — e.g. when a cluster event transitions
// the RG back to Primary before the debounced VRRP update fires.
func (m *Manager) UpdateRGPriority(rgID int, priority int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vrid := 100 + rgID
	for _, vi := range m.instances {
		if isRethInstance(vi.cfg) && vi.cfg.GroupID == vrid {
			vi.mu.Lock()
			old := vi.cfg.Priority
			vi.cfg.Priority = priority
			vi.mu.Unlock()
			if old != priority {
				slog.Info("vrrp: immediate priority update",
					"key", vi.key(), "old_pri", old, "new_pri", priority)
			}
		}
	}
}

// ForceRGMaster forces all VRRP instances for the given redundancy group
// to become MASTER, even with preempt=false. Used when the cluster state
// machine has determined this node is primary for the RG but VRRP hasn't
// transitioned (e.g. after failover reset with preempt=false).
// Uses a one-shot forcePreemptOnce flag instead of modifying cfg.Preempt,
// so the configured preempt value is never leaked.
func (m *Manager) ForceRGMaster(rgID int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vrid := 100 + rgID
	for _, vi := range m.instances {
		if isRethInstance(vi.cfg) && vi.cfg.GroupID == vrid && vi.getState() != StateMaster {
			slog.Info("vrrp: forcing MASTER (cluster authoritative)",
				"key", vi.key())
			vi.mu.Lock()
			vi.forcePreemptOnce = true
			vi.mu.Unlock()
			vi.triggerPreemptNow()
		}
	}
}

// ReconcileVIPs re-adds VIPs on any MASTER instances. Call this after
// operations that may remove addresses (e.g. programRethMAC link down/up).
func (m *Manager) ReconcileVIPs() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, vi := range m.instances {
		vi.reconcileVIP()
	}
}

// SetGARPSuppression enables or disables GARP/NA suppression for all VRRP
// instances belonging to the given redundancy group. Used by strict-vip-ownership
// mode to prevent duplicate GARP/NA during failover windows.
func (m *Manager) SetGARPSuppression(rgID int, suppress bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	vrid := 100 + rgID
	for _, vi := range m.instances {
		if isRethInstance(vi.cfg) && vi.cfg.GroupID == vrid {
			// Swap (not Store) so we can detect the true->false EDGE.
			// Lifting suppression on an instance that is ALREADY MASTER
			// (common in active-active strict-vip negotiation where the
			// secondary briefly won the election before this node was
			// promoted to RG primary) does NOT trigger any VRRP state
			// transition, so becomeMaster's GARP/NA burst never fires —
			// the VIP stays silent and traffic blackholes until the
			// periodic timer eventually announces it. Fire a forced burst
			// on the unsuppress edge to refresh neighbor MAC bindings
			// immediately (#2940).
			old := vi.suppressGARP.Swap(suppress)
			slog.Info("vrrp: GARP suppression updated",
				"key", vi.key(), "rgID", rgID, "suppress", suppress)
			if old && !suppress && vi.getState() == StateMaster {
				// force=true bypasses ONLY the 500ms time dampener so a
				// routine GARP within the prior 500ms cannot swallow this
				// announce; the per-epoch dedup still applies, so an
				// idempotent re-unsuppress (or an epoch already announced)
				// does not re-emit. Async, matching becomeMaster, so the
				// cluster event handler is never blocked. sendGARP emits
				// both IPv4 GARP and IPv6 NA in one burst.
				slog.Info("vrrp: forcing GARP/NA on unsuppress while MASTER",
					"key", vi.key(), "rgID", rgID)
				go vi.sendGARP(true)
			}
		}
	}
}

// RGVRRPReady reports whether EVERY desired VRRP instance for the given
// redundancy group has a live state machine — not merely whether one exists.
// The RG ID is mapped to VRID as 100 + rgID (the standard RETH VRID
// convention). hasRETH indicates whether the RG has any RETH interfaces
// configured. Returns (true, nil) if ready, (false, reasons) if not.
//
// #5641: an RG commonly has SEVERAL desired RETH keys under one VRID — a
// VLAN-tagged reth yields one instance per sub-interface (reth0.50, reth0.80),
// and multiple reths can share the RG. If one key's build failed (interface
// resolve failure / socket bind failure / family capability failure) its VIP
// is dark even though a sibling instance for the same VRID is live. Reporting
// READY off the mere existence of one instance let the cluster state machine
// release the sync hold / preempt / claim ownership while that VIP never
// advertised. This consults m.unbuiltDesired (populated by UpdateInstances) so
// any un-built desired key for the RG forces (false, reasons) naming it. This
// is a pure readiness READ; it does not touch advert timing, sockets, or the
// failover datapath.
func (m *Manager) RGVRRPReady(rgID int, hasRETH bool) (bool, []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	vrid := 100 + rgID

	// A desired RETH key for this RG that failed to build leaves a dark VIP.
	// RETH keys carry an empty family; VRID == 100+rgID maps a key to this RG.
	// A family-tagged generic VRRP key that happens to share the numeric VRID
	// is a separate election domain and must not gate this RG.
	var unready []string
	for key, reason := range m.unbuiltDesired {
		if key.family == "" && key.groupID == vrid {
			unready = append(unready, fmt.Sprintf(
				"vrrp: desired RETH instance %s (VRID %d) not built: %s",
				key.iface, vrid, reason))
		}
	}
	if len(unready) > 0 {
		sort.Strings(unready) // deterministic reasons for logs/tests
		return false, unready
	}

	for _, vi := range m.instances {
		if isRethInstance(vi.cfg) && vi.cfg.GroupID == vrid {
			return true, nil // an instance exists AND no desired key is un-built
		}
	}

	// No instance for this RG. If the RG has no RETH interfaces
	// (e.g. RG 0 is control-plane only), it has no VRRP requirement.
	if !hasRETH {
		return true, nil
	}

	// RG has RETH interfaces but no VRRP instance yet — not ready.
	return false, []string{fmt.Sprintf("vrrp: no instance for RG %d (VRID %d)", rgID, vrid)}
}

// States returns the current state of all instances.
// Key format: "VI_<iface>_<group>[_<family>]" → "MASTER", "BACKUP", "INIT".
func (m *Manager) States() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	states := make(map[string]string, len(m.instances))
	for _, vi := range m.instances {
		states[vi.key()] = vi.getState().String()
	}
	return states
}

// InstanceStates returns structured per-instance state. Each entry contains
// the interface name, group ID, and current VRRP state. Used by the
// reconciliation loop to verify that rg_active and blackhole routes match
// actual VRRP state.
func (m *Manager) InstanceStates() []VRRPEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]VRRPEvent, 0, len(m.instances))
	for _, vi := range m.instances {
		out = append(out, VRRPEvent{
			Interface: vi.cfg.Interface,
			Family:    vi.cfg.Family,
			GroupID:   vi.cfg.GroupID,
			State:     vi.getState(),
		})
	}
	return out
}

// RXDropStats returns per-instance RX drop and received counts.
// Key format: "VI_<iface>_<group>[_<family>]".
func (m *Manager) RXDropStats() map[string]uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]uint64, len(m.instances)*2)
	for _, vi := range m.instances {
		k := vi.key()
		stats[k+"/drops"] = vi.rxDrops.Load()
		stats[k+"/received"] = vi.rxReceived.Load()
	}
	return stats
}

// Status returns a formatted multi-line status string.
func (m *Manager) Status() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.instances) == 0 {
		return "VRRP: no instances configured\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("VRRP: %d instance(s) running\n\n", len(m.instances)))

	// Sort keys for deterministic output.
	keys := make([]instanceKey, 0, len(m.instances))
	for k := range m.instances {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].iface != keys[j].iface {
			return keys[i].iface < keys[j].iface
		}
		if keys[i].groupID != keys[j].groupID {
			return keys[i].groupID < keys[j].groupID
		}
		return keys[i].family < keys[j].family
	})

	for _, key := range keys {
		vi := m.instances[key]
		state := vi.getState()
		// #5718 (codex-182 C-HA C01c): snapshot the mutable cfg fields under
		// vi.mu.RLock before formatting. Priority/Preempt/AdvertiseInterval are
		// mutated under vi.mu.Lock (updateConfig, UpdateRGPriority,
		// suppressPreempt/restorePreempt); reading them here while holding only
		// m.mu.RLock races a concurrent failover priority update — a
		// diagnostic-only data race go test -race flags. Mirrors the snapshot
		// idiom in advertInterval/getPriority (#6230). VirtualAddresses is
		// immutable per instance (a VIP change rebuilds the whole instance under
		// m.mu.Lock, see instance_addr.go vipAddrSet / instance.go vipFamilies),
		// so reading it under only m.mu.RLock was already race-free; it is
		// deep-copied here defensively alongside the genuinely-raced fields.
		// getState() already RLocks internally, so it stays outside this block;
		// vi.key() reads only immutable identity fields.
		vi.mu.RLock()
		priority := vi.cfg.Priority
		preempt := vi.cfg.Preempt
		interval := vi.cfg.AdvertiseInterval
		vips := append([]string(nil), vi.cfg.VirtualAddresses...)
		vi.mu.RUnlock()
		sb.WriteString(fmt.Sprintf("  %s: state=%s, priority=%d, preempt=%t, interval=%dms\n",
			vi.key(), state, priority, preempt, interval))
		for _, vip := range vips {
			sb.WriteString(fmt.Sprintf("    VIP: %s\n", vip))
		}
	}

	return sb.String()
}

// bindSocketToDevice applies SO_BINDTODEVICE to fd, pinning it to ifName. It
// is a package var so tests can intercept the call and assert whether the
// per-interface raw-socket setup binds to the device (it must on a plain
// interface, must NOT on a VLAN sub-interface) without needing CAP_NET_RAW or
// a real socket fd. Both the IPv4 (openPerInterfaceSocket) and IPv6
// (openIPv6Socket) paths route through this seam so the VLAN-skip decision is
// observable and stays symmetric across families (#2786).
var bindSocketToDevice = func(fd int, ifName string) error {
	return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifName)
}

// maybeBindToDevice applies SO_BINDTODEVICE to fd ONLY when ifName is a plain
// (non-VLAN) interface. On a VLAN sub-interface it is a no-op: generic-XDP
// VLAN tag handling makes the kernel's interface association unpredictable, so
// pinning the socket to the sub-interface index can drop VRRP multicast. Both
// the IPv4 (openPerInterfaceSocket) and IPv6 (openIPv6Socket) raw-socket paths
// MUST route their device bind through this single decision so the two
// families behave identically on a VLAN RETH member — an asymmetry here lets
// one family miss peer adverts and split-brain (#2786).
func maybeBindToDevice(fd int, ifName string, isVLAN bool) error {
	if isVLAN {
		return nil
	}
	return bindSocketToDevice(fd, ifName)
}

// openPerInterfaceSocket creates a raw IP socket (proto 112) and joins the
// VRRP multicast group (224.0.0.18) on the given interface.
// For non-VLAN interfaces, SO_BINDTODEVICE is used for isolation.
// For VLAN sub-interfaces, SO_BINDTODEVICE is skipped because generic XDP
// VLAN handling makes the kernel's interface association unpredictable —
// the packet may be delivered on the parent or sub-interface depending on
// when VLAN stripping occurs. The VRID filter in receiver() provides demuxing.
func openPerInterfaceSocket(ifName string, iface *net.Interface, isVLAN bool) (*ipv4.RawConn, net.PacketConn, error) {
	// Open raw socket for VRRP (protocol 112).
	conn, err := net.ListenPacket("ip4:112", "0.0.0.0")
	if err != nil {
		return nil, nil, fmt.Errorf("listen ip4:112: %w", err)
	}

	// For plain (non-VLAN) interfaces, bind to the interface via SyscallConn
	// (avoids File() which sets blocking mode and removes the fd from Go's
	// poller). maybeBindToDevice skips the bind on VLAN sub-interfaces.
	if !isVLAN {
		sc, err := conn.(*net.IPConn).SyscallConn()
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("syscall conn: %w", err)
		}
		var bindErr error
		if err := sc.Control(func(fd uintptr) {
			bindErr = maybeBindToDevice(int(fd), ifName, isVLAN)
		}); err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("control: %w", err)
		}
		if bindErr != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("SO_BINDTODEVICE %s: %w", ifName, bindErr)
		}
	}

	rawConn, err := ipv4.NewRawConn(conn)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("raw conn: %w", err)
	}

	// Do not loop our own adverts back to local sockets (#6560). This socket
	// both sends and receives, and it joins 224.0.0.18 below, so with the
	// default IP_MULTICAST_LOOP=1 the kernel clones every advert we transmit
	// back up the local receive path and into this very socket. The option is
	// per-SENDING-socket, so it suppresses only the loopback of our own
	// transmissions; a peer's advert arriving from the wire is unaffected.
	if err := rawConn.SetMulticastLoopback(false); err != nil {
		slog.Debug("vrrp: disable ipv4 multicast loopback failed", "interface", ifName, "err", err)
	}

	// Join VRRP multicast group on this interface.
	group := net.IPv4(224, 0, 0, 18)
	if err := rawConn.JoinGroup(iface, &net.IPAddr{IP: group}); err != nil {
		slog.Debug("vrrp: join multicast failed", "interface", ifName, "err", err)
	}

	return rawConn, conn, nil
}

// afPacketSocket is the socket(2) entry point used by openAfPacketReceiver.
// It is a package var so tests can intercept the call and assert the type
// flags (notably SOCK_CLOEXEC) without needing CAP_NET_RAW.
var afPacketSocket = unix.Socket

// afPacketSetsockoptInt is the setsockopt(2) entry point used by
// openAfPacketReceiver for PACKET_IGNORE_OUTGOING. Package var for the same
// reason as afPacketSocket: it lets a test assert the EXACT (level, option,
// value) the call site uses, deterministically and without CAP_NET_RAW.
var afPacketSetsockoptInt = unix.SetsockoptInt

// VRRP advertisement multicast destination MACs. IPv4 VRRP adverts go to
// 224.0.0.18 which maps to the Ethernet multicast MAC 01:00:5e:00:00:12; IPv6
// VRRP adverts go to ff02::12 which maps to 33:33:00:00:00:12. These are kept
// as named constants for documentation and for any future PACKET_MR_MULTICAST
// (specific-group) membership; the current receiver joins via ALLMULTI (see
// buildAfPacketMembership / #2870).
var (
	vrrpGroupMACv4 = [6]byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0x12}
	vrrpGroupMACv6 = [6]byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x12}
)

// buildAfPacketMembership builds the PACKET_ADD_MEMBERSHIP request that the
// VRRP AF_PACKET receiver applies to its capture socket. It returns a
// PACKET_MR_ALLMULTI membership (receive all multicast) rather than
// PACKET_MR_PROMISC (receive everything) -- ALLMULTI delivers the VRRP group
// multicast adverts without disabling unicast hardware filtering, fixing the
// tenant-unicast leak and the all-frames-to-CPU overhead of promisc (#2870).
// Factored out so a unit test can assert the membership type without needing
// CAP_NET_RAW.
func buildAfPacketMembership(ifIndex int) unix.PacketMreq {
	return unix.PacketMreq{
		Ifindex: int32(ifIndex),
		Type:    unix.PACKET_MR_ALLMULTI,
	}
}

// vrrpCBPFFilter returns the AF_PACKET SOCK_RAW cBPF prefilter that admits VRRP
// adverts and kernel-drops everything else, cutting RX-goroutine wakeups on a
// data-bearing RETH VLAN. SOCK_RAW includes the Ethernet header.
// Protocol/next-header offsets:
//
//	IPv4 untagged:  ethertype 0x0800 @12, proto @23 (14+9)
//	IPv6 untagged:  ethertype 0x86DD @12, next-hdr @20 (14+6)
//	IPv4 single-tag: outer 0x8100/0x88a8 @12, real 0x0800 @16, proto @27 (18+9)
//	IPv6 single-tag: outer 0x8100/0x88a8 @12, real 0x86DD @16, next-hdr @24 (18+6)
//
// #5088: the outer-VLAN check admits BOTH 802.1Q (0x8100) AND 802.1ad (0x88a8)
// — a single S-tag has the identical layout (real ethertype @16), and the Go
// receiver (parseAfPacket, instance.go) already accepts both. Before this the
// prefilter matched only 0x8100, so on an S-tagged / provider-bridged segment
// the kernel dropped every advert before Go saw it and BOTH nodes went mutually
// deaf → split-brain despite the parser's advertised 802.1ad support. The kernel
// prefilter and the userspace parser MUST admit the same encapsulation set.
// DOUBLE-tag QinQ (0x88a8 then 0x8100, real ethertype @20) is deliberately NOT
// admitted here because the Go parser does not decode it either (a single-tag
// walk); the shared contract stays "untagged + single-tag {0x8100, 0x88a8}".
//
// IPv4 matches base proto == 112 (the IPv4 arm re-validates IHL + TTL in Go, so
// it tolerates IPv4 options). IPv6 must additionally admit VRRP adverts carrying
// IPv6 extension headers (#2155): the base Next-Header is then the FIRST
// ext-header's type, not 112. A fixed-offset cBPF cannot walk an ext-header
// chain, so the IPv6 arm matches the base Next-Header against the small set
//
//	{112 VRRP, 0 Hop-by-Hop, 43 Routing, 60 Dest-Opts}
//
// (approach A2). Fragment (44) and AH (51) are deliberately NOT admitted (VRRP
// adverts are never fragmented or AH-wrapped). The authoritative ext-header walk
// + proto-112 + hop-limit-255 + VRID validation happens in Go; the cBPF is only
// an in-kernel volume reducer.
//
// Jump offsets (Jt/Jf) are relative to the NEXT instruction; they were recomputed
// for the inserted 0x88a8 instruction (#5088). A bpf.VM test
// (cbpf_8021ad_5088_test.go) runs this exact array against synthetic frames.
func vrrpCBPFFilter() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: 0x28, K: 12},                    //  0: ldh [12] — ethertype
		{Code: 0x15, Jt: 8, Jf: 0, K: 0x0800},  //  1: jeq 0x0800 → 10 (check_ipv4)
		{Code: 0x15, Jt: 15, Jf: 0, K: 0x86DD}, //  2: jeq 0x86DD → 18 (check_ipv6)
		{Code: 0x15, Jt: 2, Jf: 0, K: 0x8100},  //  3: jeq 0x8100 → 6 (check_vlan)
		{Code: 0x15, Jt: 1, Jf: 0, K: 0x88a8},  //  4: jeq 0x88a8 → 6 (check_vlan); else reject
		{Code: 0x06, K: 0},                     //  5: ret reject
		// check_vlan: single-tag (0x8100 or 0x88a8) → real ethertype @16
		{Code: 0x28, K: 16},                    //  6: ldh [16] — real ethertype
		{Code: 0x15, Jt: 6, Jf: 0, K: 0x0800},  //  7: jeq 0x0800 → 14 (check_ipv4_vlan)
		{Code: 0x15, Jt: 16, Jf: 0, K: 0x86DD}, //  8: jeq 0x86DD → 25 (check_ipv6_vlan)
		{Code: 0x06, K: 0},                     //  9: ret reject
		// check_ipv4: proto at 14+9=23
		{Code: 0x30, K: 23},                // 10: ldb [23]
		{Code: 0x15, Jt: 0, Jf: 1, K: 112}, // 11: jeq 112 → accept; else reject
		{Code: 0x06, K: 0xFFFFFFFF},        // 12: ret accept
		{Code: 0x06, K: 0},                 // 13: ret reject
		// check_ipv4_vlan: proto at 18+9=27
		{Code: 0x30, K: 27},                // 14: ldb [27]
		{Code: 0x15, Jt: 0, Jf: 1, K: 112}, // 15: jeq 112 → accept; else reject
		{Code: 0x06, K: 0xFFFFFFFF},        // 16: ret accept
		{Code: 0x06, K: 0},                 // 17: ret reject
		// check_ipv6: base next-header at 14+6=20. Accept {112,0,43,60}.
		{Code: 0x30, K: 20},                // 18: ldb [20]
		{Code: 0x15, Jt: 4, Jf: 0, K: 112}, // 19: jeq 112 → 24 accept
		{Code: 0x15, Jt: 3, Jf: 0, K: 0},   // 20: jeq 0   → 24 accept (Hop-by-Hop)
		{Code: 0x15, Jt: 2, Jf: 0, K: 43},  // 21: jeq 43  → 24 accept (Routing)
		{Code: 0x15, Jt: 1, Jf: 0, K: 60},  // 22: jeq 60  → 24 accept (Dest-Opts)
		{Code: 0x06, K: 0},                 // 23: ret reject
		{Code: 0x06, K: 0xFFFFFFFF},        // 24: ret accept
		// check_ipv6_vlan: base next-header at 18+6=24. Same accept set.
		{Code: 0x30, K: 24},                // 25: ldb [24]
		{Code: 0x15, Jt: 4, Jf: 0, K: 112}, // 26: jeq 112 → 31 accept
		{Code: 0x15, Jt: 3, Jf: 0, K: 0},   // 27: jeq 0   → 31 accept (Hop-by-Hop)
		{Code: 0x15, Jt: 2, Jf: 0, K: 43},  // 28: jeq 43  → 31 accept (Routing)
		{Code: 0x15, Jt: 1, Jf: 0, K: 60},  // 29: jeq 60  → 31 accept (Dest-Opts)
		{Code: 0x06, K: 0},                 // 30: ret reject
		{Code: 0x06, K: 0xFFFFFFFF},        // 31: ret accept
	}
}

// openAfPacketReceiver opens an AF_PACKET SOCK_RAW socket bound to the
// given interface for receiving VRRP packets. This is used on VLAN sub-
// interfaces where raw IP sockets don't reliably receive multicast.
// SOCK_RAW keeps the Ethernet header — the cBPF VLAN filter and the Go
// parser both expect data starting at the L2 header.
func openAfPacketReceiver(ifIndex int) (int, error) {
	// Use ETH_P_ALL (same as tcpdump) — VLAN sub-interface + multicast
	// delivery is unreliable with ETH_P_IP protocol filtering.
	proto := htons(unix.ETH_P_ALL)
	// SOCK_CLOEXEC is OR'd into the type so the raw packet-capture fd is set
	// close-on-exec ATOMICALLY at creation. A raw unix.Socket does NOT get
	// CLOEXEC by default (unlike Go net sockets), so without this the fd would
	// be inherited by every child the daemon execs (frr-reload.py, swanctl,
	// dhcp helpers) — an fd leak and a security boundary issue (a child could
	// read raw VRRP frames off the capture socket). The atomic OR-into-type
	// avoids the fork race of a separate post-creation fcntl(FD_CLOEXEC).
	fd, err := afPacketSocket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		return -1, fmt.Errorf("af_packet socket: %w", err)
	}

	// Ask the kernel not to deliver our OWN transmissions to this capture
	// socket (#6560).
	//
	// This socket is an ETH_P_ALL tap, which is what tcpdump uses and why it
	// shows egress traffic: dev_queue_xmit_nit clones every outbound frame to
	// each ptype_all tap with skb->pkt_type = PACKET_OUTGOING, and packet_rcv
	// drops only PACKET_LOOPBACK. Adverts leave on the raw AF_INET/AF_INET6
	// sockets, but they egress the very netdev this socket is bound to, so a
	// MASTER's own advertisement lands in its own receive queue -- passing the
	// cBPF filter, which matches ethertype and IP protocol only and has no
	// pkttype ancillary load.
	//
	// Set BEFORE bind, deliberately. socket(AF_PACKET, SOCK_RAW,
	// htons(ETH_P_ALL)) with a non-zero protocol is already capturing on every
	// interface at creation, so setting this after bind would leave a window in
	// which our own frames could already be queued.
	//
	// Best-effort: PACKET_IGNORE_OUTGOING is Linux >= 4.20. An older kernel
	// returns ENOPROTOOPT and keeps working, because the receive loop's
	// sll_pkttype check (receiverAfPacket) is the belt this is the braces for.
	if err := afPacketSetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1); err != nil {
		slog.Debug("vrrp: PACKET_IGNORE_OUTGOING unavailable; relying on the sll_pkttype check",
			"ifindex", ifIndex, "err", err)
	}

	// Bind to specific interface.
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: proto,
		Ifindex:  ifIndex,
	}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind af_packet to ifindex %d: %w", ifIndex, err)
	}

	// Receive timeout so the receiver goroutine can check stopCh.
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("set rcvtimeo: %w", err)
	}

	// Put the NIC into receive-all-multicast (ALLMULTI) mode rather than full
	// promiscuous mode (#2870). VRRP advertisements are ALWAYS sent to a
	// multicast destination MAC -- 01:00:5e:00:00:12 for IPv4 (224.0.0.18) and
	// 33:33:00:00:00:12 for IPv6 (ff02::12) -- so ALLMULTI delivers every frame
	// the old PROMISC membership delivered for VRRP, while leaving hardware
	// UNICAST filtering intact. That closes two PROMISC problems: the NIC no
	// longer copies every tenant unicast frame on a data-bearing RETH VLAN to
	// the host CPU (perf), and the raw capture socket no longer sees other
	// tenants' unicast traffic (isolation).
	//
	// ALLMULTI is provably non-regressive for VRRP reception relative to the
	// previous PROMISC: on a VLAN sub-interface both flags propagate to the
	// physical parent through the SAME kernel path (vlan_dev_change_rx_flags ->
	// dev_set_allmulti / dev_set_promiscuity on the real device), and every
	// frame PROMISC delivered with a multicast destination MAC is also
	// delivered under ALLMULTI. The only frames no longer delivered are unicast
	// frames not addressed to our MAC -- exactly the leak we are closing.
	//
	// A tighter PACKET_MR_MULTICAST membership for just the two VRRP group MACs
	// (hardware-filtering to the group instead of all multicast) is the
	// theoretical optimum, but it routes through a different propagation path
	// (dev_mc_add -> dev_mc_sync -> the VF's rx-mode programming) whose
	// reliability on the mlx5 SR-IOV VFs under a VLAN sub-interface is not
	// confirmed; a silent MC-filter miss there would drop adverts and cause
	// split-brain. ALLMULTI is the conservative correct choice. See
	// docs/vrrp-afpacket-receiver.md.
	mreq := buildAfPacketMembership(ifIndex)
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
		slog.Debug("vrrp: failed to set allmulti", "err", err)
	}

	// cBPF prefilter: accept VRRP for untagged + single-tag {802.1Q, 802.1ad}
	// variants (#5088). Built by vrrpCBPFFilter so the exact instruction array
	// the kernel runs can be exercised against synthetic frames in a bpf.VM.
	filter := vrrpCBPFFilter()
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("attach bpf filter: %w", err)
	}

	return fd, nil
}

// openIPv6Socket creates a raw IPv6 socket (IPPROTO_VRRP = 112) bound to
// the given interface for sending VRRPv3 IPv6 advertisements.
// Returns the PacketConn and the raw fd for setsockopt operations.
//
// SO_BINDTODEVICE is applied identically to the IPv4 path
// (openPerInterfaceSocket): used on plain interfaces for isolation, but
// SKIPPED on VLAN sub-interfaces. Generic-XDP VLAN tag handling makes the
// kernel's interface association unpredictable — pinning the socket to the
// VLAN sub-interface index can drop incoming/locally-looped multicast when
// the tag is stripped/modified before delivery. Before #2786 the IPv6 path
// bound unconditionally while IPv4 skipped, so the two families saw VRRP
// traffic differently on a VLAN RETH member (e.g. reth0.50/reth0.80): the
// IPv6 instance could miss peer adverts entirely and both nodes would hold
// MASTER → split-brain / dual-MASTER. IPv6 multicast egress is still steered
// by IPV6_MULTICAST_IF below, which does not depend on SO_BINDTODEVICE.
func openIPv6Socket(ifName string, iface *net.Interface, isVLAN bool) (net.PacketConn, int, error) {
	conn, err := net.ListenPacket("ip6:112", "::")
	if err != nil {
		return nil, -1, fmt.Errorf("listen ip6:112: %w", err)
	}

	sc, err := conn.(*net.IPConn).SyscallConn()
	if err != nil {
		conn.Close()
		return nil, -1, fmt.Errorf("syscall conn: %w", err)
	}

	var fd int
	var bindErr error
	if err := sc.Control(func(rawfd uintptr) {
		fd = int(rawfd)
		// Bind to interface — skip on VLAN sub-interfaces (matches the IPv4
		// path; see openPerInterfaceSocket and the doc comment above).
		bindErr = maybeBindToDevice(fd, ifName, isVLAN)
		if bindErr != nil {
			return
		}
		// Set hop limit to 255 (RFC 5798 requirement).
		bindErr = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255)
		if bindErr != nil {
			return
		}
		bindErr = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, 255)
		if bindErr != nil {
			return
		}
		// Set multicast interface.
		bindErr = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_IF, iface.Index)
	}); err != nil {
		conn.Close()
		return nil, -1, fmt.Errorf("control: %w", err)
	}
	if bindErr != nil {
		conn.Close()
		return nil, -1, fmt.Errorf("ipv6 socket setup on %s: %w", ifName, bindErr)
	}

	// Join VRRP IPv6 multicast group (ff02::12).
	mreq := &unix.IPv6Mreq{
		Interface: uint32(iface.Index),
	}
	copy(mreq.Multiaddr[:], net.ParseIP("ff02::12").To16())
	if err := sc.Control(func(rawfd uintptr) {
		// Ignore error — may fail if group already joined.
		_ = unix.SetsockoptIPv6Mreq(int(rawfd), unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, mreq)
		// Do not loop our own adverts back to local sockets (#6560) — the v6
		// twin of the IP_MULTICAST_LOOP disable on the IPv4 raw conn. Same
		// reasoning: this socket sends AND joins ff02::12, so the default
		// loopback delivers our own adverts straight back into it.
		if err := unix.SetsockoptInt(int(rawfd), unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_LOOP, 0); err != nil {
			slog.Debug("vrrp: disable ipv6 multicast loopback failed", "interface", ifName, "err", err)
		}
	}); err != nil {
		slog.Debug("vrrp: ipv6 join multicast failed", "interface", ifName, "err", err)
	}

	return conn, fd, nil
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	b := [2]byte{}
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// vipsEqual compares two VIP slices for equality.
func vipsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
