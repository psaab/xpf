package daemon

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// daemon_ddns.go: the DHCP dynamic-DNS reconcile loop + node-level HA gate
// (#1387 increment 2, docs/research/1387-inc2-ddns-backend/plan.md §4.2/§4.3).
//
// The loop is an always-on guarded background goroutine modeled on the
// neighbor periodic loop (runGuardedNeighborPhase / neighborPeriodicLoop):
// it ticks on a slow cadence AND is nudged for an immediate pass on config
// commit and on VRRP MASTER takeover. Every pass runs in a guarded
// goroutine (skip-if-in-flight) so a hung DNS server can never wedge the
// loop or starve the nudge channel; a per-pass context timeout bounds the
// network calls.
//
// CRITICAL (CLAUDE.md control-socket rule): this loop does FILE I/O (the Kea
// memfile CSVs) + DNS network only. It NEVER touches the userspace-helper
// control socket, so it cannot starve session installs or status polls.

const (
	// ddnsReconcileInterval is the periodic poll cadence. DNS records are
	// not latency-critical; this is far above the 1/s control-socket
	// throttle (which it does not touch) and well under any lease time. A
	// new mid-interval lease shows up in DNS within one tick; config/MASTER
	// changes are immediate via the nudge channel.
	ddnsReconcileInterval = 30 * time.Second
	// ddnsReconcileTimeout bounds one whole reconcile pass (all DNS
	// UPDATEs for the current lease set). The backend's own per-exchange
	// timeout is shorter; this is the outer ceiling so a misbehaving
	// server can only delay one pass, never the loop.
	ddnsReconcileTimeout = 60 * time.Second
)

// ddnsNodeIDSeed reads the cluster node-id file for the DDNS owner
// watermark seed. The seed is a node-stable HINT only (never the
// delete-matching key, Inc-1 ddns.go ownerWatermark), so a missing file
// (standalone mode) yields an empty seed, which is harmless.
func ddnsNodeIDSeed() string {
	data, err := os.ReadFile(nodeIDFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// runDDNSReconcileLoop is the supervised DDNS reconcile loop. It runs for
// the daemon's lifetime (joined via wg) and exits on ctx cancellation.
func (d *Daemon) runDDNSReconcileLoop(ctx context.Context) {
	if d.ddns == nil {
		return
	}
	// Immediate first pass so a daemon restart re-publishes / withdraws
	// without waiting a full tick (the store + current leases drive it).
	d.runGuardedDDNSReconcile(ctx)

	ticker := time.NewTicker(ddnsReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.runDDNSReconcileTick(ctx)
		case <-d.ddnsReconcileNowCh:
			// Nudge: commit or MASTER takeover. Run an immediate pass.
			d.runDDNSReconcileTick(ctx)
		}
	}
}

// runDDNSReconcileTick is the for-select tick callback, split out so a unit
// test can drive it directly with a synthetic config + injected updater and
// assert convergence. It is O(1) on the loop goroutine — the actual work
// dispatches into a guarded goroutine.
func (d *Daemon) runDDNSReconcileTick(ctx context.Context) {
	d.runGuardedDDNSReconcile(ctx)
}

// runGuardedDDNSReconcile dispatches one reconcile pass into a guarded
// goroutine (skip-if-in-flight), mirroring runGuardedNeighborPhase. A pass
// still running when the next tick/nudge fires is skipped rather than
// overlapped, so a wedged DNS server leaks at most one goroutine and the
// loop keeps servicing ctx + the nudge channel.
func (d *Daemon) runGuardedDDNSReconcile(ctx context.Context) {
	d.ddnsResetMu.Lock()
	defer d.ddnsResetMu.Unlock()
	if d.isResetting() {
		return
	}
	if !d.ddnsReconcileInFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.ddnsReconcileInFlight.Store(false)
		d.reconcileDDNSOnce(ctx)
	}()
}

// reconcileDDNSOnce runs one DDNS reconcile pass under the node-level HA
// gate (plan §4.3). It is the single decision point for "should this node
// publish DDNS right now": the gate is OPEN when this node is MASTER for
// >=1 RG (cluster mode) or always (standalone). When the gate is CLOSED
// (BACKUP for all RGs) the node STOPS writing — it does NOT withdraw valid
// records (the peer MASTER owns them and keeps them fresh; deletion is
// lease-state / config-removal driven only, never local-ownership-loss
// driven, plan risk R3).
func (d *Daemon) reconcileDDNSOnce(ctx context.Context) {
	if d.ddns == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	if !d.ddnsWriterGateOpen() {
		// BACKUP for all RGs: cheap short-circuit — stop emitting entirely. No
		// withdraw (plan R3). This is the node-level fast path; the per-scope
		// gate below makes the publish decision PER RG so a node MASTER for one
		// RG and BACKUP for another publishes only its own RG's leases (#2664).
		slog.Debug("ddns: skipping reconcile — node is not MASTER for any RG")
		return
	}
	rctx, cancel := context.WithTimeout(ctx, ddnsReconcileTimeout)
	defer cancel()
	// #2691 P1b / #2664: drive the SCOPED reconcile with a per-RG writer gate +
	// a lease→RG resolver. Standalone (no cluster) passes nil gate/resolver
	// (every scope writable — today's behaviour). In a cluster the resolver
	// attributes each lease to its owning RG (by stable pool-subnet CIDR
	// membership, NOT the per-render-unstable Kea subnet_id) and the gate admits
	// a scope IFF this node is MASTER for that RG — FAIL-CLOSED for an
	// unattributable lease (an address in no known master-owned subnet is not
	// published, but its owned record is never withdrawn either).
	opts := d.ddnsReconcileOptions(cfg)
	if err := d.ddns.ReconcileScoped(rctx, &cfg.System.DHCPServer, opts); err != nil {
		// Fail-open for DHCP (plan risk R9): a DNS failure is logged +
		// counted (by the manager) and retried next cycle; it NEVER
		// propagates to the Kea apply path or to commit.
		slog.Warn("ddns: reconcile pass had errors (retrying next cycle)", "err", err)
	}
}

// ddnsReconcileOptions builds the per-scope HA wiring for one reconcile pass
// (#2691 P1b / #2664). Standalone (no cluster) returns the zero options (nil
// gate + resolver) so the engine treats every scope as writable — byte-for-byte
// today's behaviour. In a cluster it builds:
//
//   - a lease→RG RESOLVER from the committed DHCP config: an address is mapped
//     to its pool subnet (stable CIDR membership) → group → interface →
//     redundancy-group. This is the SAME RG attribution the Kea master-filter
//     uses (rethInterfacesForRG), but keyed on the lease ADDRESS, not on the
//     Kea subnet_id (which is map-order-assigned and unstable per render, plan
//     §6 fork 2). A lease whose address falls in no known pool subnet is
//     UNATTRIBUTABLE → ok=false → fail-closed (not published).
//   - a per-RG GATE: a scope is writable IFF this node is MASTER for
//     scope.RGOwner. RGOwner 0 (a lease in a non-RETH / non-HA pool) is admitted
//     when the node is the writer at all (the node-level short-circuit already
//     ran): such a pool is not HA-owned, so there is no peer to double-write.
func (d *Daemon) ddnsReconcileOptions(cfg *config.Config) ddns.ReconcileOptions {
	if cfg == nil {
		return ddns.ReconcileOptions{}
	}
	// #5070: thread the SSOT Junos→kernel interface-name resolver so a
	// destination-interface binding on the RFC 2136 backend resolves to the
	// local node's real kernel device (reth→member, unit-0 collapse, unit≠vlan-id)
	// before SO_BINDTODEVICE. Applied in BOTH standalone and cluster modes.
	base := ddns.ReconcileOptions{InterfaceResolver: cfg.ResolveKernelIfName}
	if d.cluster == nil {
		return base
	}
	subnetRG := d.buildLeaseSubnetRGMap(cfg)
	master := d.snapshotRethMasterState()

	// anyRGOwnedPool reports whether the config has ANY redundancy-group-owned
	// pool at all. When it does NOT, the cluster has no HA-owned DHCP scope, so
	// an unattributable lease is just a standalone-style pool (no peer
	// double-write hazard) and is admitted as RG 0; the per-RG gate is moot.
	anyRGOwnedPool := false
	for _, s := range subnetRG {
		if s.rg > 0 {
			anyRGOwnedPool = true
			break
		}
	}

	resolver := func(l ddns.Lease) (ddns.ScopeKey, bool) {
		rg, ok := rgForLeaseAddress(l.Address, subnetRG)
		if !ok {
			// Unattributable: an address in no known pool subnet.
			//
			//   - If there ARE RG-owned pools, an address that falls in NONE of
			//     them is ambiguous w.r.t. HA ownership — FAIL-CLOSED (#2664 /
			//     plan §5.6: uncertain RG ownership → do not write). This is the
			//     split-brain guard: a stale memfile row for a subnet we no
			//     longer serve must not be republished from here.
			//   - If there are NO RG-owned pools, the cluster has no HA-owned
			//     DHCP scope (e.g. a non-RETH DHCP group in a cluster used for
			//     other HA services). There is no peer to double-write, so admit
			//     as RG 0 — the node-level writer gate already authorized the
			//     pass.
			if anyRGOwnedPool {
				return ddns.ScopeKey{Family: ddns.Family(l.Family)}, false
			}
			return ddns.ScopeKey{Family: ddns.Family(l.Family), RGOwner: 0}, true
		}
		return ddns.ScopeKey{Family: ddns.Family(l.Family), RGOwner: rg}, true
	}
	gate := func(s ddns.ScopeKey) bool {
		if s.RGOwner == 0 {
			// Non-RG-owned pool (no RETH / no HA attribution): not a
			// double-write hazard. The node-level writer gate already gated
			// the whole pass, so admit.
			return true
		}
		return master[s.RGOwner]
	}
	base.Gate = gate
	base.Resolver = resolver
	return base
}

// leaseSubnetRG pairs a parsed pool subnet (CIDR) with the redundancy group
// that owns the interfaces of the group the pool belongs to (#2664).
type leaseSubnetRG struct {
	net *net.IPNet
	rg  int
}

// buildLeaseSubnetRGMap walks the committed DHCP config and pairs each pool
// subnet with its owning redundancy group, by mapping group → interfaces →
// redundancy-group (#2664). A group whose interfaces are not RETH / not
// RG-owned yields rg 0 (a non-HA pool: admitted by the gate as a non-double-
// write hazard). This is the lease→RG attribution source for the resolver; it
// is rebuilt per reconcile so a commit takes effect on the next pass.
func (d *Daemon) buildLeaseSubnetRGMap(cfg *config.Config) []leaseSubnetRG {
	var out []leaseSubnetRG
	collect := func(ls *config.DHCPLocalServerConfig) {
		if ls == nil {
			return
		}
		for _, g := range ls.Groups {
			rg := rgForInterfaces(cfg, g.Interfaces)
			for _, p := range g.Pools {
				if p.Subnet == "" {
					continue
				}
				_, ipnet, err := net.ParseCIDR(p.Subnet)
				if err != nil || ipnet == nil {
					continue
				}
				out = append(out, leaseSubnetRG{net: ipnet, rg: rg})
			}
		}
	}
	collect(cfg.System.DHCPServer.DHCPLocalServer)
	collect(cfg.System.DHCPServer.DHCPv6LocalServer)
	// Deterministic attribution (#2664 review MINOR): the source iterates Go
	// maps (ls.Groups) in RANDOMIZED order, so a first-match resolver over an
	// unsorted slice would attribute an address that falls in two OVERLAPPING
	// pool subnets owned by DIFFERENT RGs non-deterministically — the gate would
	// then FLAP between passes for that address. Sort MOST-SPECIFIC FIRST (longer
	// prefix wins), with a stable tie-break (CIDR string, then RG) for
	// equal-length prefixes, so rgForLeaseAddress's first-match is both
	// longest-prefix-correct AND stable across reconciles.
	sort.Slice(out, func(i, j int) bool {
		oi, _ := out[i].net.Mask.Size()
		oj, _ := out[j].net.Mask.Size()
		if oi != oj {
			return oi > oj // longer prefix (more specific) first
		}
		if si, sj := out[i].net.String(), out[j].net.String(); si != sj {
			return si < sj
		}
		return out[i].rg < out[j].rg
	})
	return out
}

// rgForInterfaces returns the redundancy group that owns the given DHCP-group
// interfaces (#2664). An interface that is a RETH member maps to its
// RedundancyGroup; the first RG-owned interface wins (a DHCP group binds to one
// HA-owned segment in practice). Returns 0 when no interface is RG-owned (a
// non-HA pool).
func rgForInterfaces(cfg *config.Config, ifaces []string) int {
	if cfg == nil {
		return 0
	}
	for _, name := range ifaces {
		// The configured interface name may be the RETH logical name (reth0.0)
		// or a unit form; match against the config's interface table by the
		// base interface name.
		base := name
		if i := strings.IndexByte(base, '.'); i >= 0 {
			base = base[:i]
		}
		if ifc, ok := cfg.Interfaces.Interfaces[base]; ok && ifc != nil {
			if ifc.RedundancyGroup > 0 {
				return ifc.RedundancyGroup
			}
		}
	}
	return 0
}

// rgForLeaseAddress maps a lease address to its owning redundancy group via the
// pool-subnet→RG map (#2664). It is the stable, render-independent attribution
// the per-RG gate keys on (CIDR membership, NOT the Kea subnet_id). Returns
// ok=false when the address parses but falls in no known pool subnet
// (unattributable → fail-closed at the caller) or does not parse.
func rgForLeaseAddress(addr string, subnetRG []leaseSubnetRG) (int, bool) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return 0, false
	}
	for _, s := range subnetRG {
		if s.net.Contains(ip) {
			return s.rg, true
		}
	}
	return 0, false
}

// ddnsWriterGateOpen reports whether this node should publish DDNS now
// (plan §4.3, node-level gate). SOUND without per-lease RG attribution
// because the Kea config each node serves is rendered MASTER-FILTERED
// (filterDHCPConfigForMasterRGs), so this node's memfile already contains
// ONLY its own MASTER-RG leases — reading the whole memfile cannot see a
// peer-owned lease, and the two nodes' input sets are disjoint by RG
// ownership. The gate reads snapshotRethMasterState ONLY (the SAME source
// the Kea manager uses), never any per-lease subnet_id (which is
// map-order-assigned and per-render unstable, plan §6 fork 2).
//
//   - Standalone (no cluster): always the writer — the gate is open.
//   - Cluster: open IFF this node is MASTER for at least one RG.
func (d *Daemon) ddnsWriterGateOpen() bool {
	if d.cluster == nil {
		return true
	}
	for _, isMaster := range d.snapshotRethMasterState() {
		if isMaster {
			return true
		}
	}
	return false
}

// nudgeDDNSReconcile requests an immediate DDNS reconcile pass (config
// commit or VRRP MASTER takeover). Non-blocking depth-1 send: coalesces a
// burst into one pending wakeup. Safe to call before the loop starts (the
// buffered send is simply consumed by the loop's first select).
//
// Async-takeover ordering note (plan §4.3 / M-r2-2): on a MASTER takeover
// the Kea reconcile is enqueued ASYNC (dhcpServer.ApplyAsync), so this
// nudge may run BEFORE Kea has repopulated this node's memfile. That is
// BENIGN: the reconcile is store-driven and add-only-from-current-leases —
// a too-early pass simply sees fewer/no leases and can only ADD on the next
// cycle once Kea has repopulated; it never deletes a record on the strength
// of a not-yet-written lease (a delete requires the record to be in this
// node's own ownership store). No ordering barrier is required.
func (d *Daemon) nudgeDDNSReconcile() {
	if d.ddnsReconcileNowCh == nil {
		return
	}
	select {
	case d.ddnsReconcileNowCh <- struct{}{}:
	default:
	}
}

// DDNSStats returns the current DHCP dynamic-DNS counter snapshot for the
// API collector / show command, or nil when the manager is not constructed
// (NoDataplane). The api.Server reads this via an injected function so it
// does not import the daemon's manager type directly.
func (d *Daemon) DDNSStats() *dhcpserver.DDNSStats {
	if d.ddns == nil {
		return nil
	}
	st := d.ddns.Stats()
	return &st
}

// OwnedDDNSRecords returns a human-readable summary of the DDNS records this
// node currently owns, for `show system services dhcp-server dynamic-dns
// detail`. Empty when the manager is absent.
func (d *Daemon) OwnedDDNSRecords() []dhcpserver.DDNSOwnedRecordView {
	if d.ddns == nil {
		return nil
	}
	return d.ddns.OwnedRecordViews()
}
