package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// daemon_dhcp_lease_sync.go: the #2239 HA DHCP-server lease-sync push/seed
// orchestration (PATH C). It re-instantiates the IPsec-SA-sync precedent
// (syncIPsecSAPeriodic + reinitiateIPsecSAs) for Kea leases:
//
//   - syncDHCPLeasesPeriodic — the RG-MASTER push loop. A slow heartbeat tick
//     (lease-sync re-push of the full set, so a freshly-restarted standby is
//     never empty) PLUS a fast change-detect tick (an on-grant push: it reads
//     the active set and pushes ONLY when it differs from the last push,
//     bounding the duplicate-allocation window far tighter than the heartbeat
//     interval — Q1). Gated on DHCPLeaseSync + the same node-level MASTER gate
//     the DDNS loop uses (dhcpLeaseSyncGateOpen).
//   - seedDHCPLeasesFromPeer — the takeover seed. After this node becomes
//     MASTER and Kea is (re)started, the held peer lease set is re-anchored to
//     the local clock and written into Kea via lease{4,6}-add (Q3 backstop).
//     The pre-Kea-start memfile pre-seed (which FULLY closes the dup-alloc
//     window) is done by preSeedDHCPLeaseMemfile before the Kea ApplyAsync.
//
// CONTROL-SOCKET RULE (CLAUDE.md): this loop talks to KEA's own unix socket and
// the CLUSTER sync channel only — NEVER the userspace-helper control socket. It
// cannot starve session installs. The push is coalesced (change-detect) and the
// heartbeat is slow, keeping the cluster channel budget well under the
// per-second session sweep.

const (
	// dhcpLeaseSyncHeartbeat is the full-set re-push cadence. It keeps a
	// restarted standby from staying empty (Q7) and bounds steady-state
	// staleness. Matches the IPsec SA 30s parity; far above any control-socket
	// throttle (which it does not touch).
	dhcpLeaseSyncHeartbeat = 30 * time.Second
	// dhcpLeaseSyncChangePoll is the fast change-detect cadence (the on-grant
	// push, Q1). It reads the active lease set and pushes ONLY on a change, so
	// a new grant reaches the standby within this interval, shrinking the
	// duplicate-allocation window from the heartbeat interval to ~2s. A no-op
	// poll is a cheap socket read; an idle DHCP server pushes nothing.
	dhcpLeaseSyncChangePoll = 2 * time.Second
	// dhcpLeaseReadTimeout bounds one lease read pass.
	dhcpLeaseReadTimeout = 5 * time.Second
	// dhcpLeaseSeedSocketWait bounds the post-start control-socket-ready wait
	// before seeding on takeover.
	dhcpLeaseSeedSocketWait = 10 * time.Second
)

// dhcpLeaseSyncState groups the #2239 HA DHCP-server lease-sync (PATH C)
// runtime state that used to live as flat dhcpLease* fields on Daemon
// (#4407 god-struct decomposition, increment 1). The push loop runs on the
// RG-MASTER, reads the active lease set (Kea control socket → memfile
// fallback), and replicates it over the cluster sync channel; the standby
// holds the peer set in SessionSync.peerDHCPLeases{4,6} and seeds Kea on
// takeover. The loop talks ONLY to Kea's own socket + the cluster channel —
// never the userspace-helper control socket (CLAUDE.md rule). Grouping only;
// no field semantics, locking, or lifecycle changed.
type dhcpLeaseSyncState struct {
	nowCh      chan struct{} // nudge: grant/commit/MASTER takeover
	inFlight   atomic.Bool   // no-freeze skip-if-in-flight guard
	lastSentMu sync.Mutex
	lastSent4  string // last-pushed v4 set fingerprint (change-detect)
	lastSent6  string // last-pushed v6 set fingerprint (change-detect)

	// #10170: the sender's ownership generation stays stable across lease
	// heartbeat pushes and advances on a MASTER apply. A snapshot is marked
	// Applied only after the corresponding local Kea apply succeeds.
	authorityMu            sync.Mutex
	authorityGeneration    uint64
	pendingApplyGeneration uint64
	appliedGeneration      uint64

	// loopMu guards the push-loop lifecycle (#4647). loopCancel is the
	// cancel func of the currently-running push loop's context (nil when the
	// loop is not running). ensureDHCPLeaseSyncLoop starts/stops the loop
	// idempotently on a `dhcp-lease-synchronization` knob toggle so a runtime
	// commit — not only a daemon restart — (re)launches it.
	loopMu     sync.Mutex
	loopCancel context.CancelFunc
}

// dhcpLeaseSyncEnabled reports whether #2239 lease sync is configured for this
// commit: a cluster with the `dhcp-lease-synchronization` knob set. Standalone
// (no cluster) is always false. Used to gate the Kea control-socket/hook
// emission AND the push loop. The cfg argument carries the just-committed
// config's cluster knob (the daemon's clusterConfig() reads the ACTIVE config,
// which during commitAndApply may lag the candidate being applied).
func (d *Daemon) dhcpLeaseSyncEnabled(cfg *config.Config) bool {
	if d.cluster == nil || cfg == nil || cfg.Chassis.Cluster == nil {
		return false
	}
	return cfg.Chassis.Cluster.DHCPLeaseSync
}

// dhcpLeaseSyncGateOpen reports whether this node should PUSH leases now: the
// node-level MASTER gate, identical in shape to ddnsWriterGateOpen. SOUND
// without per-lease RG attribution for the same reason: the Kea config each
// node serves is MASTER-FILTERED (filterDHCPConfigForMasterRGs), so this node's
// lease set is ONLY its own MASTER-RG leases and the two nodes' sets are
// disjoint by RG ownership. Standalone is never a pusher (the loop never runs).
func (d *Daemon) dhcpLeaseSyncGateOpen() bool {
	if d.cluster == nil {
		return false
	}
	for _, isMaster := range d.snapshotRethMasterState() {
		if isMaster {
			return true
		}
	}
	return false
}

// ensureDHCPLeaseSyncLoop starts or stops the #2239 lease-sync push loop to
// match the `dhcp-lease-synchronization` knob at runtime (#4647). It is
// idempotent and safe to call from both the cluster connect-time launch
// (daemon_ha_sync.go) and the config-apply path (daemon_apply.go): a commit
// that toggles the knob (re)launches or stops the loop WITHOUT a daemon
// restart. Before #4647 the loop was launched only from the connect-time block,
// so a knob-ON commit on a running cluster was a silent no-op (counters stayed
// 0/0 until a restart).
//
// The loop is scoped to the live cluster comms context (clusterCommsCtx) so it
// shares the lifetime of the session-sync channel it pushes over; a comms
// restart / stopClusterComms tears it down and the next connect-time launch
// starts a fresh loop (see resetDHCPLeaseSyncLoop).
func (d *Daemon) ensureDHCPLeaseSyncLoop(enabled bool) {
	d.dhcpLeaseSync.loopMu.Lock()
	defer d.dhcpLeaseSync.loopMu.Unlock()

	if !enabled {
		if d.dhcpLeaseSync.loopCancel != nil {
			d.dhcpLeaseSync.loopCancel()
			d.dhcpLeaseSync.loopCancel = nil
			slog.Info("cluster: DHCP lease-sync push loop stopped (knob disabled)")
		}
		return
	}
	if d.dhcpLeaseSync.loopCancel != nil {
		return // already running — idempotent (guards double-launch)
	}
	// Comms must be up: the loop reads the peer session-sync channel and
	// early-returns if either dhcpServer or sessionSync is nil. When they are
	// not ready yet (e.g. the apply path runs before the peer connects), skip
	// here — the connect-time launch calls this again once sessionSync is
	// established, so the knob-ON state is not lost.
	commsCtx := d.getClusterCommsCtx()
	if d.dhcpServer == nil || d.getSessionSync() == nil || commsCtx == nil {
		return
	}
	loopCtx, cancel := context.WithCancel(commsCtx)
	d.dhcpLeaseSync.loopCancel = cancel
	go d.runDHCPLeaseSyncLoop(loopCtx)
	slog.Info("cluster: DHCP lease-sync push loop started")
}

// resetDHCPLeaseSyncLoop clears the push-loop lifecycle handle when cluster
// comms are torn down (#4647). The loop's context derives from the comms
// context, so cancelling comms already stops the goroutine; this only clears
// the cancel handle so the next comms session's connect-time launch starts a
// fresh loop instead of no-oping on a stale handle.
func (d *Daemon) resetDHCPLeaseSyncLoop() {
	d.dhcpLeaseSync.loopMu.Lock()
	d.dhcpLeaseSync.loopCancel = nil
	d.dhcpLeaseSync.loopMu.Unlock()
}

// runDHCPLeaseSyncLoop is the supervised lease-sync push loop. It runs for the
// lifetime of the cluster comms session (joined via the comms context) and
// exits on ctx cancellation. It is (re)launched idempotently by
// ensureDHCPLeaseSyncLoop in cluster mode with the knob enabled.
func (d *Daemon) runDHCPLeaseSyncLoop(ctx context.Context) {
	if d.dhcpServer == nil || d.getSessionSync() == nil {
		return
	}
	heartbeat := time.NewTicker(dhcpLeaseSyncHeartbeat)
	defer heartbeat.Stop()
	change := time.NewTicker(dhcpLeaseSyncChangePoll)
	defer change.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			// Heartbeat: full re-push regardless of change (defeats the
			// change-detect fingerprint) so a reconnected/restarted standby
			// is refreshed even if the set is unchanged.
			d.dispatchDHCPLeasePush(ctx, true)
		case <-change.C:
			d.dispatchDHCPLeasePush(ctx, false)
		case <-d.dhcpLeaseSync.nowCh:
			// Nudge: commit or MASTER takeover or peer-connected → push now.
			d.dispatchDHCPLeasePush(ctx, true)
		}
	}
}

// dispatchDHCPLeasePush runs one push pass in a guarded goroutine
// (skip-if-in-flight), mirroring runGuardedDDNSReconcile, so a slow Kea socket
// read can never wedge the loop. force=true bypasses the change-detect (full
// re-push); force=false pushes only when the set changed since the last push.
func (d *Daemon) dispatchDHCPLeasePush(ctx context.Context, force bool) {
	if !d.dhcpLeaseSync.inFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.dhcpLeaseSync.inFlight.Store(false)
		d.pushDHCPLeasesOnce(ctx, force)
	}()
}

// pushDHCPLeasesOnce reads this node's active lease set and replicates it to
// the peer, per family. Fail-open: a read/send error is logged + counted and
// never blocks serving. Only the RG-MASTER pushes (the gate).
func (d *Daemon) pushDHCPLeasesOnce(ctx context.Context, force bool) {
	cc := d.clusterConfig()
	if cc == nil || !cc.DHCPLeaseSync || d.dhcpServer == nil {
		return
	}
	if !d.dhcpLeaseSyncGateOpen() {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, dhcpLeaseReadTimeout)
	defer cancel()
	now := time.Now()

	if cfg.System.DHCPServer.DHCPLocalServer != nil {
		leases, err := d.dhcpServer.GetSyncLeases4(rctx, now)
		if err != nil {
			slog.Debug("cluster: DHCP v4 lease read failed (retrying)", "err", err)
		} else {
			d.maybePushFamily(4, d.makeDHCPLeaseSnapshot(cfg, 4, leases), force)
		}
	}
	if cfg.System.DHCPServer.DHCPv6LocalServer != nil {
		leases, err := d.dhcpServer.GetSyncLeases6(rctx, now)
		if err != nil {
			slog.Debug("cluster: DHCP v6 lease read failed (retrying)", "err", err)
		} else {
			d.maybePushFamily(6, d.makeDHCPLeaseSnapshot(cfg, 6, leases), force)
		}
	}
}

func (d *Daemon) makeDHCPLeaseSnapshot(cfg *config.Config, family int, leases []dhcpserver.SyncLease) dhcpserver.LeaseSyncSnapshot {
	d.dhcpLeaseSync.authorityMu.Lock()
	if d.dhcpLeaseSync.authorityGeneration == 0 {
		d.dhcpLeaseSync.authorityGeneration = 1
	}
	generation := d.dhcpLeaseSync.authorityGeneration
	d.dhcpLeaseSync.authorityMu.Unlock()

	masters := d.snapshotRethMasterState()
	scopes := dhcpLeaseScopeAuthorities(cfg, family, generation, false, masters)
	resultGeneration, resultScopes, _ := d.dhcpServer.LeaseAuthorityResult(family)
	if resultGeneration == generation &&
		dhcpLeaseAuthorityScopesMatchCurrent(scopes, resultScopes, family, generation) {
		scopes = resultScopes
	}
	return dhcpserver.LeaseSyncSnapshot{
		Leases:     leases,
		Generation: generation,
		Scopes:     scopes,
		Received:   true,
	}
}

func dhcpLeaseAuthorityScopesMatchCurrent(current, result []dhcpserver.LeaseScopeAuthority, family int, generation uint64) bool {
	if len(current) != len(result) {
		return false
	}
	remaining := make(map[string]bool, len(current))
	for _, scope := range current {
		if scope.Family != family || scope.Generation != generation {
			return false
		}
		cidr := canonicalLeaseScopeCIDR(scope.CIDR)
		if cidr == "" {
			return false
		}
		key := fmt.Sprintf("%d|%d|%s", family, scope.RGID, cidr)
		if remaining[key] {
			return false
		}
		remaining[key] = scope.Served
	}
	for _, scope := range result {
		if scope.Family != family || scope.Generation != generation {
			return false
		}
		cidr := canonicalLeaseScopeCIDR(scope.CIDR)
		if cidr == "" {
			return false
		}
		key := fmt.Sprintf("%d|%d|%s", family, scope.RGID, cidr)
		served, ok := remaining[key]
		if !ok || served != scope.Served {
			return false
		}
		delete(remaining, key)
	}
	return len(remaining) == 0
}

func canonicalLeaseScopeCIDR(cidr string) string {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	return network.String()
}

// maybePushFamily pushes the family's lease set when force=true or the set
// changed since the last push.
func (d *Daemon) maybePushFamily(family int, snapshot dhcpserver.LeaseSyncSnapshot, force bool) {
	fp := dhcpLeaseSetFingerprint(snapshot.Leases)
	d.dhcpLeaseSync.lastSentMu.Lock()
	prev := d.dhcpLeaseSync.lastSent4
	if family == 6 {
		prev = d.dhcpLeaseSync.lastSent6
	}
	changed := fp != prev
	if force || changed {
		if family == 6 {
			d.dhcpLeaseSync.lastSent6 = fp
		} else {
			d.dhcpLeaseSync.lastSent4 = fp
		}
	}
	d.dhcpLeaseSync.lastSentMu.Unlock()
	if !force && !changed {
		return
	}
	if ss := d.getSessionSync(); ss != nil {
		ss.QueueDHCPLeaseSnapshot(family, snapshot)
	}
}

// dhcpLeaseSetFingerprint computes a stable, order-independent fingerprint of a
// lease set for change detection. It deliberately EXCLUDES Remaining so the
// per-second countdown does not look like a change; an on-grant/renewal (which
// changes ValidLife or the membership) does change it.
func dhcpLeaseSetFingerprint(leases []dhcpserver.SyncLease) string {
	if len(leases) == 0 {
		return ""
	}
	keys := make([]string, 0, len(leases))
	for _, l := range leases {
		keys = append(keys, fmt.Sprintf("%s#%d#%s", l.IdentityKey(), l.ValidLife, l.Hostname))
	}
	sort.Strings(keys)
	return strings.Join(keys, "|")
}

// nudgeDHCPLeaseSync requests an immediate full-set lease push (config commit,
// MASTER takeover, peer reconnect). Non-blocking depth-1 send, coalescing a
// burst. Safe before the loop starts.
func (d *Daemon) nudgeDHCPLeaseSync() {
	if d.dhcpLeaseSync.nowCh == nil {
		return
	}
	select {
	case d.dhcpLeaseSync.nowCh <- struct{}{}:
	default:
	}
}

// preSeedDHCPLeaseMemfile writes leases into the Kea memfile CSV(s) BEFORE Kea
// is (re)started on takeover (#2239 Q3, the dup-alloc-window closer per SMR
// NIT-1). Pre-seeding the memfile means the just-started Kea loads the in-use
// bindings into its lease manager at boot, so it can NEVER answer a DISCOVER
// with an in-use address even in the brief window before the post-start lease-add
// seed runs. Best-effort + fail-open: a write failure is logged; the post-start
// lease-add (seedDHCPLeasesFromPeer) is the backstop.
//
// #5040: the pre-seed writes the UNION of this node's current local active
// leases and the held peer leases, NOT the peer-only set. On a per-RG
// active-active takeover this node is already MASTER for some RGs whose leases
// are live locally; overwriting the shared memfile with peer-only rows wiped
// those still-mastered leases and let Kea re-allocate their in-use addresses.
// The merge (PreSeedMemfileMerged{4,6}) reads the local set and fails closed on
// an untrusted local source rather than replacing it. If Kea is down while
// another RG remains MASTER, stillMastering preserves the fallback union and
// avoids deleting LFC generations; only a pure-backup transition may use
// peer-only replacement.
//
// Called from the MASTER-takeover path BEFORE dhcpServer.ApplyAsync(start).
func (d *Daemon) preSeedDHCPLeaseMemfile(stillMastering bool) {
	ss := d.getSessionSync()
	if ss == nil || d.dhcpServer == nil {
		return
	}
	cc := d.clusterConfig()
	if cc == nil || !cc.DHCPLeaseSync {
		return
	}
	cfg := d.store.ActiveConfig()
	ctx, cancel := context.WithTimeout(context.Background(), dhcpLeaseReadTimeout)
	defer cancel()
	now := time.Now()
	for _, family := range []int{4, 6} {
		var snapshot dhcpserver.LeaseSyncSnapshot
		if family == 4 {
			snapshot = ss.PeerDHCPLeaseSnapshot4()
		} else {
			snapshot = ss.PeerDHCPLeaseSnapshot6()
		}
		if !snapshot.Received {
			continue
		}
		authority := d.dhcpLeaseAuthority(cfg, family)
		if preSeeder, ok := d.dhcpServer.(interface {
			PreSeedMemfileMerged4WithAuthority(context.Context, dhcpserver.LeaseSyncSnapshot, time.Time, bool, dhcpserver.LeaseSyncAuthority) error
			PreSeedMemfileMerged6WithAuthority(context.Context, dhcpserver.LeaseSyncSnapshot, time.Time, bool, dhcpserver.LeaseSyncAuthority) error
		}); ok {
			var err error
			if family == 4 {
				err = preSeeder.PreSeedMemfileMerged4WithAuthority(ctx, snapshot, now, stillMastering, authority)
			} else {
				err = preSeeder.PreSeedMemfileMerged6WithAuthority(ctx, snapshot, now, stillMastering, authority)
			}
			if err != nil {
				slog.Warn("cluster: DHCP lease memfile pre-seed failed (post-start lease-add is backstop)", "family", family, "err", err)
			}
			continue
		}
		leases := dhcpserver.PeerLeasesForAuthority(snapshot, family, authority)
		var err error
		if family == 4 {
			err = d.dhcpServer.PreSeedMemfileMerged4(ctx, leases, now, stillMastering)
		} else {
			err = d.dhcpServer.PreSeedMemfileMerged6(ctx, leases, now, stillMastering)
		}
		if err != nil {
			slog.Warn("cluster: DHCP lease memfile pre-seed failed (post-start lease-add is backstop)", "family", family, "err", err)
		} else {
			slog.Info("cluster: DHCP leases pre-seeded into memfile before Kea start", "family", family, "count", len(leases))
		}
	}
}

// seedDHCPLeasesFromPeer seeds the just-started Kea with the held peer leases
// via lease{4,6}-add over the control socket. It uses the same authority
// filter as memfile pre-seeding, so an unproven or mismatched scope remains
// conservative while a proven peer snapshot cannot seed another RG.
func (d *Daemon) seedDHCPLeasesFromPeer(ctx context.Context) {
	ss := d.getSessionSync()
	if ss == nil || d.dhcpServer == nil {
		return
	}
	cc := d.clusterConfig()
	if cc == nil || !cc.DHCPLeaseSync {
		return
	}
	cfg := d.store.ActiveConfig()
	snap4 := ss.PeerDHCPLeaseSnapshot4()
	snap6 := ss.PeerDHCPLeaseSnapshot6()
	leases4 := dhcpserver.PeerLeasesForAuthority(snap4, 4, d.dhcpLeaseAuthority(cfg, 4))
	leases6 := dhcpserver.PeerLeasesForAuthority(snap6, 6, d.dhcpLeaseAuthority(cfg, 6))
	if len(leases4) == 0 && len(leases6) == 0 {
		return
	}
	now := time.Now()
	want4 := cfg != nil && cfg.System.DHCPServer.DHCPLocalServer != nil && len(leases4) > 0
	want6 := cfg != nil && cfg.System.DHCPServer.DHCPv6LocalServer != nil && len(leases6) > 0

	if want4 {
		if d.dhcpServer.WaitControlSocket4(ctx, dhcpLeaseSeedSocketWait) {
			n, err := d.dhcpServer.SeedSyncLeases4(ctx, leases4, now)
			ss.RecordDHCPLeasesSeeded(n)
			if err != nil {
				slog.Warn("cluster: DHCP v4 lease seed had errors (fail-open)", "seeded", n, "err", err)
			} else {
				slog.Info("cluster: DHCP v4 leases seeded into Kea on takeover", "count", n)
			}
		} else {
			slog.Warn("cluster: DHCP v4 control socket not ready; relying on memfile pre-seed")
		}
	}
	if want6 {
		if d.dhcpServer.WaitControlSocket6(ctx, dhcpLeaseSeedSocketWait) {
			n, err := d.dhcpServer.SeedSyncLeases6(ctx, leases6, now)
			ss.RecordDHCPLeasesSeeded(n)
			if err != nil {
				slog.Warn("cluster: DHCP v6 lease seed had errors (fail-open)", "seeded", n, "err", err)
			} else {
				slog.Info("cluster: DHCP v6 leases seeded into Kea on takeover", "count", n)
			}
		} else {
			slog.Warn("cluster: DHCP v6 control socket not ready; relying on memfile pre-seed")
		}
	}
}
func (d *Daemon) dhcpLeaseAuthority(cfg *config.Config, family int) dhcpserver.LeaseSyncAuthority {
	return dhcpserver.LeaseSyncAuthority{Scopes: dhcpLeaseScopeAuthorities(cfg, family, 0, false, d.snapshotRethMasterState())}
}

// dhcpLeaseScopeAuthorities derives ownership by configured subnet CIDR and
// the RG that serves its unambiguous DHCP group. A group narrowed at runtime,
// or spanning multiple RGs/node-local interfaces, is intentionally omitted:
// without a pool-to-RG edge, excluding a row would be unsafe.
func dhcpLeaseScopeAuthorities(cfg *config.Config, family int, generation uint64, applied bool, masters map[int]bool) []dhcpserver.LeaseScopeAuthority {
	if cfg == nil {
		return nil
	}
	var groups map[string]*config.DHCPServerGroup
	switch family {
	case 4:
		if cfg.System.DHCPServer.DHCPLocalServer != nil {
			groups = cfg.System.DHCPServer.DHCPLocalServer.Groups
		}
	case 6:
		if cfg.System.DHCPServer.DHCPv6LocalServer != nil {
			groups = cfg.System.DHCPServer.DHCPv6LocalServer.Groups
		}
	}
	owners := cfg.RethRGOwners()
	var scopes []dhcpserver.LeaseScopeAuthority
	for _, group := range groups {
		if group == nil || group.MembersFiltered {
			continue
		}
		rgs := make(map[int]struct{})
		unattributed := false
		for _, iface := range group.Interfaces {
			rg, ok := dhcpLeaseRGForInterface(cfg, iface, owners)
			if !ok {
				unattributed = true
				break
			}
			rgs[rg] = struct{}{}
		}
		if unattributed {
			continue
		}
		if len(rgs) != 1 {
			continue
		}
		var rgID int
		for rg := range rgs {
			rgID = rg
		}
		for _, pool := range group.Pools {
			if pool == nil || pool.Subnet == "" {
				continue
			}
			_, network, err := net.ParseCIDR(pool.Subnet)
			if err != nil {
				continue
			}
			scopes = append(scopes, dhcpserver.LeaseScopeAuthority{
				Family:     family,
				CIDR:       network.String(),
				RGID:       rgID,
				Generation: generation,
				Served:     masters[rgID],
				Applied:    applied,
			})
		}
	}
	sort.Slice(scopes, func(i, j int) bool {
		if scopes[i].CIDR != scopes[j].CIDR {
			return scopes[i].CIDR < scopes[j].CIDR
		}
		return scopes[i].RGID < scopes[j].RGID
	})
	return scopes
}

func dhcpLeaseRGForInterface(_ *config.Config, iface string, owners map[string]int) (int, bool) {
	base := strings.SplitN(iface, ".", 2)[0]
	rg, ok := owners[base]
	return rg, ok && rg > 0
}
func (d *Daemon) nextDHCPLeaseApplyAuthority(cfg *config.Config, masterState ...map[int]bool) dhcpserver.LeaseApplyAuthority {
	d.dhcpLeaseSync.authorityMu.Lock()
	if d.dhcpLeaseSync.authorityGeneration == 0 {
		d.dhcpLeaseSync.authorityGeneration = 1
	} else {
		d.dhcpLeaseSync.authorityGeneration++
	}
	generation := d.dhcpLeaseSync.authorityGeneration
	d.dhcpLeaseSync.authorityMu.Unlock()
	var masters map[int]bool
	if len(masterState) > 0 {
		masters = masterState[0]
	} else {
		masters = d.snapshotRethMasterState()
	}
	return dhcpserver.LeaseApplyAuthority{
		Generation: generation,
		Scopes4:    dhcpLeaseScopeAuthorities(cfg, 4, generation, false, masters),
		Scopes6:    dhcpLeaseScopeAuthorities(cfg, 6, generation, false, masters),
	}
}

func (d *Daemon) enqueueDHCPApply(cfg *config.DHCPServerConfig, reason string) {
	masters := d.snapshotRethMasterState()
	fullCfg := d.store.ActiveConfig()
	d.enqueueDHCPApplyWithAuthorityState(cfg, reason, fullCfg, masters)
}

func (d *Daemon) enqueueDHCPApplyWithAuthorityState(cfg *config.DHCPServerConfig, reason string, fullCfg *config.Config, masters map[int]bool) {
	if d.dhcpServer == nil {
		return
	}
	if cfg == nil {
		fullCfg = nil
	}
	authority := d.nextDHCPLeaseApplyAuthority(fullCfg, masters)
	d.dhcpServer.ApplyAsyncWithLeaseAuthority(cfg, reason, authority)
}
