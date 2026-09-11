// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// mgmtVRFIfaceSet returns the currently-published management-VRF interface
// set (nil before the first apply). The returned map is immutable — the apply
// path publishes a fresh map wholesale via publishMgmtVRFIfaces and never
// mutates it in place — so callers read it lock-free. See the
// mgmtVRFInterfaces field doc (daemon.go) for the #5113 concurrency contract.
func (d *Daemon) mgmtVRFIfaceSet() map[string]bool {
	if p := d.mgmtVRFInterfaces.Load(); p != nil {
		return *p
	}
	return nil
}

// publishMgmtVRFIfaces atomically publishes m as the management-VRF interface
// set. Called only from the apply path under applySem; the atomic Store makes
// the field publication safe for the lock-free DHCP-callback readers (#5113).
// m must be treated as immutable after this call.
func (d *Daemon) publishMgmtVRFIfaces(m map[string]bool) {
	d.mgmtVRFInterfaces.Store(&m)
}

// dhcpLeaseKeysForMember enumerates every interface-name spelling under which
// a DHCP lease learned on routing-instance member `member` can be keyed, so
// dhcpRouteVRFMap's PRODUCER side is reachable by the CONSUMER's key.
//
// The two sides genuinely disagree on spelling and neither is free to change:
//
//   - the producer is `RoutingInstance.Interfaces`, which the compiler appends
//     VERBATIM from the config token (compiler_routing.go), so the canonical
//     Junos form carries SLASHES — `ge-0/0/1.0`;
//   - the consumer is `lease.Interface` = `config.DHCPLeaseIfName`, i.e.
//     `LinuxIfName` (slashes -> dashes) unconditionally, plus a `.<vlan-id>`
//     suffix for a TAGGED unit — so `ge-0-0-1`, or `ge-0-0-3.50`.
//
// #9135: keying on the raw member made the #8963 remedy INERT for the canonical
// slash spelling — every VRF-attached DHCP route fell back to `vrf == ""` and
// was emitted in the DEFAULT context, which is the behaviour #8963 was filed
// against. Only a dash-authored config ever resolved.
//
// Three things follow from `DHCPLeaseIfName` being the consumer's rule, and
// they are why this builds the keys it does and no others:
//
//  1. A lease key can NEVER contain a slash, so the raw config token is not a
//     candidate key at all. It is not inserted (pre-#9135 it was, uselessly);
//     a dash-authored member reaches the same key through LinuxIfName.
//  2. A lease key NEVER carries a unit NUMBER — DHCPLeaseIfName has no
//     unit-number fallback, and its own doc calls unit number and VLAN ID
//     "distinct concepts". So `logicalUnitDeviceKey`'s `base.<unit>` arm, which
//     is right for the netdev-name family (#8321/#8597), is wrong here.
//  3. A member naming the WHOLE DEVICE (`ge-0/0/3`, the #9063 reading) claims
//     every unit on it, and a tagged unit's lease is keyed `base.<vlan-id>` —
//     a key the base alone cannot produce. Those are enumerated.
//
// reth is deliberately NOT resolved. `buildDHCPClientSpecs` keys the lease on
// the CONFIG interface name with no `ResolveReth` (daemon_dhcp.go), so a reth
// DHCP client's lease is keyed `reth0` — which `base` already covers. Inserting
// the physical member's name would add a key no lease presents and could
// mis-attribute a lease genuinely learned on that member.
func dhcpLeaseKeysForMember(cfg *config.Config, member string) []string {
	if member == "" {
		return nil
	}
	baseRef, unitTok, hasUnit := strings.Cut(config.CanonicalInterfaceUnitRef(member), ".")
	base := config.LinuxIfName(baseRef)

	// The member may be authored in either spelling while cfg.Interfaces is
	// keyed by the spelling the `interfaces` stanza used, and the two need not
	// agree (#8829). Match on the kernel name, which both reduce to.
	var ifc *config.InterfaceConfig
	if cfg != nil {
		for name, candidate := range cfg.Interfaces.Interfaces {
			if candidate != nil && config.LinuxIfName(name) == base {
				ifc = candidate
				break
			}
		}
	}

	if !hasUnit {
		// Whole-device member: it claims every unit on the device (#9063's
		// reading of the same list), and each unit's lease is keyed
		// independently — a tagged one by its VLAN ID, which the device name
		// on its own cannot produce.
		if ifc == nil {
			// The instance names an interface with no `interfaces` stanza.
			// That is legal (bindRoutingInstanceMembers tolerates a member
			// absent on this chassis) and it also happens transiently, between
			// deleting the stanza and the DHCP client reconcile retiring the
			// lease. No unit is knowable, so the device name is the only key.
			return []string{base}
		}
		keys := make([]string, 0, len(ifc.Units))
		for _, u := range ifc.Units {
			keys = append(keys, config.DHCPLeaseIfName(base, u))
		}
		return keys
	}
	var unit *config.InterfaceUnit
	if unitNum, _, err := config.CanonicalLogicalUnit(unitTok); err == nil && ifc != nil {
		unit = ifc.Units[unitNum]
	}
	// A nil unit (stanza absent, or an unparseable unit token) yields the bare
	// base — which is what an untagged lease is keyed by, so this degrades to
	// the pre-#9135 dash-spelling behaviour rather than to an empty key.
	return []string{config.DHCPLeaseIfName(base, unit)}
}

// dhcpLeaseRoutingInstances maps a lease's interface name to the routing
// instance that owns it, "" for the default context (#8963).
//
// This is the SINGLE authority for "which routing instance did this lease come
// from", shared by every lease consumer that has to answer it — the FRR route
// tagger (collectDHCPRoutes) and the resolver merge (mergeDNSInput, #9138).
// They are the same question about the same objects, and answering it twice
// invites the two to drift; a filter derived independently would also have to
// re-learn the #9135 key-shape rule below.
//
// Keyed on the KERNEL/lease interface name. #9135: the instance member list is
// stored in whatever spelling the operator authored (canonically Junos slashes),
// while the lease is keyed in the kernel spelling, so each member is inserted
// under every spelling a lease can actually present — see
// dhcpLeaseKeysForMember for why that set is what it is.
func dhcpLeaseRoutingInstances(cfg *config.Config) map[string]string {
	out := map[string]string{}
	if cfg == nil {
		return out
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		for _, member := range ri.Interfaces {
			for _, k := range dhcpLeaseKeysForMember(cfg, member) {
				out[k] = ri.Name
			}
		}
	}
	return out
}

// dhcpRouteVRFMap is dhcpLeaseRoutingInstances over the ACTIVE config.
func (d *Daemon) dhcpRouteVRFMap() map[string]string {
	return dhcpLeaseRoutingInstances(d.store.ActiveConfig())
}

// collectDHCPRoutes builds FRR DHCPRoute entries from active DHCP leases.
// Interfaces bound to the management VRF are excluded — their routes are
// programmed directly via netlink into the VRF table by applyMgmtVRFRoutes.
func (d *Daemon) collectDHCPRoutes() []frr.DHCPRoute {
	if d.dhcp == nil {
		return nil
	}
	mgmtSet := d.mgmtVRFIfaceSet()
	// #8963: the routing instance the LEARNING interface belongs to. Without
	// it every DHCP-learned route was emitted in the default FRR context, even
	// when its interface sat in a routing instance -- so the instance did not
	// get the route it learned and the default context got one it should not
	// have. Static routes have carried a `vrf <name>` clause since #5557.
	ifaceVRF := d.dhcpRouteVRFMap()
	var routes []frr.DHCPRoute
	for _, lease := range d.dhcp.Leases() {
		if mgmtSet[lease.Interface] {
			continue
		}
		vrf := ifaceVRF[lease.Interface]
		isIPv6 := lease.Family == dhcp.AFInet6
		// Default route (option-3 gateway, or option-121 0.0.0.0/0 entry).
		if lease.Gateway.IsValid() {
			routes = append(routes, frr.DHCPRoute{
				Gateway:   lease.Gateway.String(),
				Interface: lease.Interface,
				IsIPv6:    isIPv6,
				VRF:       vrf,
			})
		}
		// RFC 3442 classless static routes (option 121 / legacy 249). A
		// lease may carry these with or without a default gateway.
		for _, cr := range lease.ClasslessRoutes {
			routes = append(routes, frr.DHCPRoute{
				Destination: cr.Destination.String(),
				Gateway:     cr.Gateway.String(),
				Interface:   lease.Interface,
				IsIPv6:      isIPv6,
				VRF:         vrf,
			})
		}
	}
	return routes
}

// mgmtVRFTableID is the kernel routing table backing the management VRF, for
// the netlink route reconcile below (#9622: config.ManagementVRFTableID).
const mgmtVRFTableID = config.ManagementVRFTableID

// The management-VRF route reconcile (applyMgmtVRFRoutes / applyMgmtVRFRoutesTo /
// reconcileMgmtVRFRouteDeletes) programs the DHCP-learned routes for the
// management VRF table (999). Leases on management interfaces (fxp*/fab*/em*) are
// not owned by FRR — FRR does not manage the management VRF — so their default
// gateway (option 3, or the option-121 0.0.0.0/0 entry) and RFC 3442 classless
// static routes (option 121 / legacy 249) are programmed directly via netlink.
//
// This is a full reconcile, not an append-only apply (#5108). Every route xpf
// installs here is stamped RTPROT_DHCP so it can be distinguished from
// operator/kernel routes sharing the table. Each apply:
//
//  1. RouteReplaces each desired lease route (idempotent add-or-update) and, on
//     SUCCESS, records the route's FULL identity (destination + gateway + output
//     link, mgmtRouteAppliedKey) in the `applied` protect-set (#5867).
//  2. Lists the xpf-owned (RTPROT_DHCP) routes in the table and RouteDels any
//     whose full identity is NOT in `applied` — a withdrawn route OR a stale
//     route whose replacement failed.
//
// Step 2 runs UNCONDITIONALLY — including when `applied` is empty (the management
// lease was disabled, or an option-121 route was withdrawn). Early-returning on
// an empty set was the #5108 bug (a stale route left in the table could blackhole
// or misdirect management/HA traffic to a prior DHCP router). Keying the
// protect-set on the FULL applied identity — and adding a route to it only after
// its RouteReplace succeeds — is the #5867 fix: a route that keeps its
// destination but changes gateway/output-interface and then FAILS to replace no
// longer keeps its stale predecessor protected. The delete is scoped to
// RTPROT_DHCP so operator routes are never touched; ESRCH (already gone) is
// tolerated, any other RouteDel error is surfaced into the returned error so the
// commit fails closed.
//
// mgmtRouteProgrammer is the netlink surface applyMgmtVRFRoutesTo needs: resolve
// interfaces, replace routes, and (via the embedded mgmtRouteReconciler)
// list+delete for the cleanup pass. *netlink.Handle satisfies it in production;
// a test injects a fake to drive a RouteReplace failure without a real handle
// (#5867).
type mgmtRouteProgrammer interface {
	LinkByName(name string) (netlink.Link, error)
	RouteReplace(route *netlink.Route) error
	mgmtRouteReconciler
}

// applyMgmtVRFRoutes reconciles the DHCP-learned routes in the management VRF and
// returns the joined netlink errors so the commit path can fail closed. It is a
// thin wrapper: it acquires a real netlink handle and delegates the programming +
// cleanup to applyMgmtVRFRoutesTo (the injectable, unit-tested core).
func (d *Daemon) applyMgmtVRFRoutes() error {
	if d.dhcp == nil {
		return nil
	}
	nlh, err := netlink.NewHandle()
	if err != nil {
		slog.Warn("mgmt VRF routes: failed to get netlink handle", "err", err)
		return fmt.Errorf("mgmt VRF routes: netlink handle: %w", err)
	}
	defer nlh.Close()
	return d.applyMgmtVRFRoutesTo(nlh, d.dhcp.Leases(), d.mgmtVRFIfaceSet())
}

// applyMgmtVRFRoutesTo programs each management interface's DHCP-learned routes
// through nlh, then reconciles away every xpf-owned route in the table that is
// not currently APPLIED. Split out from applyMgmtVRFRoutes so a test can inject a
// fake programmer + lease set and drive a RouteReplace failure (#5867).
//
// #5867 (desired-vs-applied identity): the reconcile protect-set (`applied`) keys
// on the FULL managed-route identity — destination + gateway + output link index
// (mgmtRouteAppliedKey) — and a route joins it ONLY AFTER its RouteReplace
// SUCCEEDS. The pre-#5867 code keyed the protect-set on destination+family alone
// and inserted the key BEFORE RouteReplace ran, so a route that kept its
// destination but changed gateway or output interface and then FAILED to replace
// left the OLD (stale) route in the kernel yet STILL protected from cleanup —
// management traffic pinned to a stale gateway/interface (possibly a
// de-authorized tenant path) while the commit reported success. Keying `applied`
// on the full identity means a stale same-destination route (old gateway/ifindex)
// matches no applied identity, so the cleanup pass removes it; the RouteReplace
// error is also returned so the commit fails closed rather than silently
// acknowledging the stale pin. A SUCCESSFUL gateway change still replaces cleanly
// (RouteReplace overwrites the same-destination entry) and the new identity is
// protected — the happy path is unchanged.
func (d *Daemon) applyMgmtVRFRoutesTo(nlh mgmtRouteProgrammer, leases []*dhcp.Lease, mgmtSet map[string]bool) error {
	var errs []error
	// applied records the FULL identity of each route whose RouteReplace SUCCEEDED
	// (#5867). When no management interface has a route-bearing lease it stays
	// empty and the reconcile deletes every xpf-owned route in the table.
	applied := make(map[string]struct{})
	for _, lease := range leases {
		if !mgmtSet[lease.Interface] {
			continue
		}
		// A lease may carry a default gateway (option 3 or the option-121
		// 0.0.0.0/0 entry) and/or RFC 3442 classless static routes (option
		// 121 / legacy 249). Program each into the management VRF table.
		if !lease.Gateway.IsValid() && len(lease.ClasslessRoutes) == 0 {
			continue
		}
		nlFamily := netlink.FAMILY_V4
		if lease.Family == dhcp.AFInet6 {
			nlFamily = netlink.FAMILY_V6
		}
		link, err := nlh.LinkByName(lease.Interface)
		if err != nil {
			// A missing interface (renaming churn) is not a route-apply failure;
			// log and skip. Any stale route for it is left OUT of `applied`, so
			// the cleanup pass removes it.
			slog.Warn("mgmt VRF route: interface not found",
				"interface", lease.Interface, "err", err)
			continue
		}
		linkIndex := link.Attrs().Index

		if lease.Gateway.IsValid() {
			var dst *net.IPNet
			if lease.Family == dhcp.AFInet6 {
				dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
			} else {
				dst = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
			}
			gwSlice := lease.Gateway.AsSlice()
			route := &netlink.Route{
				LinkIndex: linkIndex,
				Dst:       dst,
				Gw:        net.IP(gwSlice),
				Table:     mgmtVRFTableID,
				Protocol:  unix.RTPROT_DHCP,
			}
			if err := nlh.RouteReplace(route); err != nil {
				slog.Warn("mgmt VRF route: failed to add default route",
					"interface", lease.Interface, "gw", lease.Gateway, "table", mgmtVRFTableID, "err", err)
				errs = append(errs, fmt.Errorf("mgmt VRF default route via %s dev %s: %w",
					lease.Gateway, lease.Interface, err))
			} else {
				// #5867: protect ONLY the identity that actually applied.
				applied[mgmtRouteAppliedKey(dst, nlFamily, route.Gw, route.LinkIndex)] = struct{}{}
				slog.Info("mgmt VRF default route installed",
					"interface", lease.Interface, "gw", lease.Gateway, "table", mgmtVRFTableID)
			}
		}

		// RFC 3442 classless static routes.
		for _, cr := range lease.ClasslessRoutes {
			dst := &net.IPNet{
				IP:   net.IP(cr.Destination.Addr().AsSlice()),
				Mask: net.CIDRMask(cr.Destination.Bits(), cr.Destination.Addr().BitLen()),
			}
			route := &netlink.Route{
				LinkIndex: linkIndex,
				Dst:       dst,
				Gw:        net.IP(cr.Gateway.AsSlice()),
				Table:     mgmtVRFTableID,
				Protocol:  unix.RTPROT_DHCP,
			}
			if err := nlh.RouteReplace(route); err != nil {
				slog.Warn("mgmt VRF route: failed to add classless route",
					"interface", lease.Interface, "dst", cr.Destination, "gw", cr.Gateway,
					"table", mgmtVRFTableID, "err", err)
				errs = append(errs, fmt.Errorf("mgmt VRF classless route %s via %s dev %s: %w",
					cr.Destination, cr.Gateway, lease.Interface, err))
			} else {
				// #5867: protect ONLY the identity that actually applied.
				applied[mgmtRouteAppliedKey(dst, nlFamily, route.Gw, route.LinkIndex)] = struct{}{}
				slog.Info("mgmt VRF classless route installed",
					"interface", lease.Interface, "dst", cr.Destination, "gw", cr.Gateway,
					"table", mgmtVRFTableID)
			}
		}
	}

	// Delete xpf-owned routes in the table whose FULL identity is not in
	// `applied` — a withdrawn route OR a stale route whose replacement failed
	// (#5867). Runs even when applied is empty (disabled lease / withdrawn route).
	if err := d.reconcileMgmtVRFRouteDeletes(nlh, mgmtVRFTableID, applied); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// mgmtRouteReconciler is the minimal netlink surface reconcileMgmtVRFRouteDeletes
// needs. *netlink.Handle satisfies it in production; tests inject a fake.
type mgmtRouteReconciler interface {
	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
	RouteDel(route *netlink.Route) error
}

// reconcileMgmtVRFRouteDeletes removes xpf-owned (RTPROT_DHCP) routes from the
// management VRF table that are not in the desired destination-key set. It lists
// both address families (RouteListFiltered is per-family) scoped to
// table+protocol so operator/kernel routes are never considered. ESRCH (the
// route is already gone) is tolerated; any other delete error is surfaced.
func (d *Daemon) reconcileMgmtVRFRouteDeletes(nlh mgmtRouteReconciler, tableID int, applied map[string]struct{}) error {
	var errs []error
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		current, err := nlh.RouteListFiltered(family, &netlink.Route{
			Table:    tableID,
			Protocol: unix.RTPROT_DHCP,
		}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
		if err != nil {
			slog.Warn("mgmt VRF route: failed to list routes for reconcile",
				"family", family, "table", tableID, "err", err)
			continue
		}
		for _, rt := range mgmtVRFRoutesToDelete(current, applied, family) {
			rt := rt
			if err := nlh.RouteDel(&rt); err != nil && !errors.Is(err, unix.ESRCH) {
				slog.Warn("mgmt VRF route: failed to delete withdrawn route",
					"dst", rt.Dst, "table", tableID, "err", err)
				// #5867: a stale route we resolved to remove could NOT be
				// deleted — surface it so the commit fails closed rather than
				// acknowledging a management route the reconcile could not clean up.
				errs = append(errs, fmt.Errorf("mgmt VRF route delete %v: %w", rt.Dst, err))
			} else {
				slog.Info("mgmt VRF route withdrawn",
					"dst", rt.Dst, "table", tableID)
			}
		}
	}
	return errors.Join(errs...)
}

// mgmtVRFRoutesToDelete returns the subset of current routes (already scoped to
// xpf-owned RTPROT_DHCP routes in the management VRF table) whose destination is
// not present in the desired set. Pure — the reconcile diff is unit-tested here
// so a regression to the pre-#5108 no-delete behavior fails the test.
func mgmtVRFRoutesToDelete(current []netlink.Route, applied map[string]struct{}, family int) []netlink.Route {
	var del []netlink.Route
	for i := range current {
		// #5867: match on the FULL identity (destination + gateway + output
		// link), not the destination alone, so a stale same-destination route
		// (old gateway/ifindex, left behind by a failed replacement) is NOT
		// protected and is eligible for cleanup.
		key := mgmtRouteAppliedKey(current[i].Dst, family, current[i].Gw, current[i].LinkIndex)
		if _, ok := applied[key]; !ok {
			del = append(del, current[i])
		}
	}
	return del
}

// mgmtRouteDstKey canonicalizes a route destination into a comparable key so a
// desired route (built from lease data) and a listed kernel route with the same
// destination match. A nil or all-zeros /0 destination is the family default
// route (netlink returns the default route with a nil Dst); everything else keys
// on the masked network address and prefix length.
func mgmtRouteDstKey(dst *net.IPNet, family int) string {
	if dst == nil {
		if family == netlink.FAMILY_V6 {
			return "::/0"
		}
		return "0.0.0.0/0"
	}
	ones, bits := dst.Mask.Size()
	if ones == 0 && bits != 0 {
		if bits == 128 || family == netlink.FAMILY_V6 {
			return "::/0"
		}
		return "0.0.0.0/0"
	}
	ip := dst.IP
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return fmt.Sprintf("%s/%d", ip.Mask(dst.Mask).String(), ones)
}

// mgmtRouteAppliedKey canonicalizes the FULL identity of an xpf-managed VRF route
// — destination (via mgmtRouteDstKey) PLUS gateway and output link index — into a
// comparable key (#5867). The cleanup protect-set keys on this full identity, not
// just the destination, so a route whose replacement FAILED (its stale
// predecessor — same destination, different gateway/ifindex — still in the
// kernel) matches no applied identity and is therefore eligible for cleanup.
// Table and protocol are constant for every managed route (the reconcile list is
// filtered on them), so they are not part of the discriminating key. The gateway
// is canonicalized through net.IP.String so a 4- vs 16-byte representation of the
// same address compares equal.
func mgmtRouteAppliedKey(dst *net.IPNet, family int, gw net.IP, linkIndex int) string {
	gwStr := ""
	if gw != nil {
		gwStr = gw.String()
	}
	return fmt.Sprintf("%s|gw=%s|if=%d", mgmtRouteDstKey(dst, family), gwStr, linkIndex)
}

// logFinalStats reads and logs global counter summary before shutdown.
//
// The signature uses the daemon-local dataplaneReadyProbe
// (runtime_probes.go) + dataplane.Telemetry runtime domain so the
// shutdown path no longer touches the legacy BPF-shaped DataPlane
// surface (#1519). Telemetry().GlobalCounter is structurally
// identical to the previous dp.ReadGlobalCounter call and routes
// to the same underlying BPF map read on both backends.
//
// Ordering invariant (see daemon_run.go shutdown sequence): this
// runs AFTER d.cluster.Stop() / d.sessionSync.Stop() and BEFORE
// the dataplane's Close()/Teardown(), so the Telemetry provider is
// still backed by a live bpfShim on the userspace path. AGY
// round-1 walked-trace confirmation: manager.bpfShim teardown
// only happens inside manager.Close()/Teardown().
func logFinalStats(ready dataplaneReadyProbe, telemetry dataplane.Telemetry) {
	if ready == nil || !ready.IsLoaded() {
		return
	}
	if telemetry == nil {
		return
	}
	indices := []struct {
		idx  uint32
		name string
	}{
		{dataplane.GlobalCtrRxPackets, "rx_packets"},
		{dataplane.GlobalCtrTxPackets, "tx_packets"},
		{dataplane.GlobalCtrDrops, "drops"},
		{dataplane.GlobalCtrSessionsNew, "sessions_created"},
		{dataplane.GlobalCtrSessionsClosed, "sessions_closed"},
		{dataplane.GlobalCtrScreenDrops, "screen_drops"},
		{dataplane.GlobalCtrPolicyDeny, "policy_denies"},
	}

	attrs := make([]any, 0, len(indices)*2)
	for _, n := range indices {
		v, err := telemetry.GlobalCounter(n.idx)
		if err != nil {
			continue
		}
		attrs = append(attrs, n.name, v)
	}

	slog.Info("final statistics", attrs...)
}

// stopFlowExporter stops the running NetFlow v9 exporter (shutdown).
//
// #2075: the exporter is now (re)started by reconcileFlowExporters, not
// startFlowExporter. This stop is called only at shutdown. It takes
// flowReconMu so it cannot race a concurrent reconcile swap, and it is
// nil-safe / idempotent (a reconcile that already stopped the exporter
// leaves flowCancel/flowExporter nil; context.CancelFunc is idempotent).
func (d *Daemon) stopFlowExporter() {
	d.flowReconMu.Lock()
	defer d.flowReconMu.Unlock()
	// Unpublish the bundle before teardown (#3742), then cancel + wait +
	// close via the shared helper (flowWg is now a nil-safe pointer).
	d.flowBundle.Store(&exporterBundle{})
	d.teardownV9Locked()
	d.flowExportErr = nil
}

// stopIPFIXExporter stops the running IPFIX exporter (shutdown).
func (d *Daemon) stopIPFIXExporter() {
	d.ipfixReconMu.Lock()
	defer d.ipfixReconMu.Unlock()
	d.ipfixBundlePtr.Store(&ipfixBundle{})
	d.teardownIPFIXLocked()
	d.ipfixExportErr = nil
}

// parseAddrPair parses "ip:port" or "[ip]:port" into net.IPs and IPv6 flag.
func parseAddrPair(src, dst string) (srcIP, dstIP net.IP, isV6 bool) {
	srcIP = parseHost(src)
	dstIP = parseHost(dst)
	isV6 = srcIP != nil && srcIP.To4() == nil
	return
}

func parseHost(addr string) net.IP {
	// Handle "[ipv6]:port" format
	if len(addr) > 0 && addr[0] == '[' {
		end := 0
		for i, c := range addr {
			if c == ']' {
				end = i
				break
			}
		}
		if end > 1 {
			return net.ParseIP(addr[1:end])
		}
	}
	// Handle "ipv4:port" format
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return net.ParseIP(addr[:i])
		}
	}
	return net.ParseIP(addr)
}

func parseSrcPort(addr string) uint16 {
	// Find last colon
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			// Accumulate into a wider integer so an out-of-range port
			// string does not silently wrap the uint16 accumulator mod
			// 65536 (e.g. "70000" -> 4464, #6214), which would corrupt
			// the source/destination port carried in NetFlow v9 / IPFIX
			// flow records. A real port never exceeds 65535, so treat
			// anything larger as unparseable and return the 0 "no port"
			// sentinel (the same value the no-colon path returns).
			var port uint32
			for _, c := range addr[i+1:] {
				if c >= '0' && c <= '9' {
					port = port*10 + uint32(c-'0')
					if port > 65535 {
						return 0
					}
				}
			}
			return uint16(port)
		}
	}
	return 0
}

// archiveConfig transfers the active config to remote archive sites
// when system { archival { configuration { transfer-on-commit; } } } is set.
//
// #3867: the uploaded bytes are the CURRENT ACTIVE configuration serialized
// from the configstore — the same hierarchical text `show configuration`
// renders via Store.ShowActive() and the same source the local auto-archive
// (writeArchive) uses — NOT d.opts.ConfigFile. The boot file
// /etc/xpf/xpf.conf is written once at install and is never rewritten after
// the configstore became DB-canonical, so scp'ing it uploaded the day-0
// config on every commit: the DR/compliance archive silently diverged from
// the running config from the first commit onward while scp still logged
// success. We serialize the just-committed active config to a temp file and
// scp THAT, preserving the historical remote filename (the boot-file
// basename) and the scp transport.
func (d *Daemon) archiveConfig(cfg *config.Config) {
	if cfg.System.Archival == nil || !cfg.System.Archival.TransferOnCommit {
		return
	}
	if len(cfg.System.Archival.ArchiveSites) == 0 {
		return
	}
	d.archiveToSites(cfg.System.Archival.ArchiveSites)
}

// archiveToSites serializes the CURRENT active configuration (Store.ShowActive
// — the same hierarchical text `show configuration` renders) to a transient
// 0600 temp file and uploads it to every archive site via the archiveTransfer
// seam (default scpArchiveTransfer). It is the shared archive-to-site path used
// by BOTH transfer-on-commit (archiveConfig, invoked on each commit apply) and
// the periodic transfer-interval timer (runArchiveTimer, #4078) — the periodic
// path reuses this exact transport rather than reimplementing it. The uploaded
// remote filename preserves the historical basename (the boot-file basename,
// default xpf.conf).
func (d *Daemon) archiveToSites(sites []string) {
	if len(sites) == 0 {
		return
	}
	if d.store == nil {
		slog.Warn("config archival skipped: no configuration store")
		return
	}

	// Serialize the CURRENT active config (the just-committed tree) — the
	// same hierarchical text `show configuration` renders. This is the
	// config the operator expects the DR/compliance archive to reflect, not
	// the stale install-time boot file.
	active := d.store.ShowActive()
	if active == "" {
		slog.Warn("config archival skipped: active configuration is empty")
		return
	}

	// Write to a temp file whose basename matches the historical remote name
	// (the boot-file basename, default xpf.conf) so an archive-site directory
	// destination keeps the same archived filename as before this fix.
	base := filepath.Base(d.opts.ConfigFile)
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "xpf.conf"
	}
	tmpDir, err := os.MkdirTemp("", "xpf-archive-")
	if err != nil {
		slog.Warn("config archival failed: create temp dir", "err", err)
		return
	}
	srcPath := filepath.Join(tmpDir, base)
	// AtomicGeneratedConfig (#1894/#1916): the staged snapshot is a
	// regenerated config file, not durable state — it is deleted after the
	// SCP uploads finish, so power-loss durability (fsync) is neither
	// needed nor wanted on this transient copy. WriteFileAtomic writes a
	// ".<base>.tmp-*" sibling in tmpDir and renames to srcPath, so the
	// snapshot appears complete-or-not (a lister/reader never observes a
	// torn file) while preserving the historical remote basename.
	// 0600 — the active config may contain encrypted secrets; keep the
	// transient copy owner-only (MkdirTemp already made the dir 0700).
	if err := fsatomic.WriteFileAtomic(srcPath, []byte(active), 0600); err != nil {
		slog.Warn("config archival failed: write temp config", "err", err)
		os.RemoveAll(tmpDir)
		return
	}

	transfer := d.archiveTransfer
	if transfer == nil {
		transfer = scpArchiveTransfer
	}

	var wg sync.WaitGroup
	for _, site := range sites {
		wg.Add(1)
		go func(dest string) {
			defer wg.Done()
			slog.Info("archiving config", "destination", dest)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := transfer(ctx, srcPath, dest); err != nil {
				slog.Warn("config archival failed", "destination", dest, "err", err)
			} else {
				slog.Info("config archived successfully", "destination", dest)
			}
		}(site)
	}

	// Remove the temp file only after every upload finishes reading it.
	go func() {
		wg.Wait()
		os.RemoveAll(tmpDir)
	}()
}

// scpArchiveTransfer is the default transfer-on-commit transport: scp the
// serialized active-config file to one archive site. It is split out of
// archiveConfig behind the Daemon.archiveTransfer seam so tests can inject a
// capturing transfer and assert archiveConfig serializes the CURRENT active
// config rather than the stale boot file (#3867).
func scpArchiveTransfer(ctx context.Context, srcPath, dest string) error {
	// #4589 A7 F-02: `--` end-of-options separator before the positional
	// src/dest. `dest` is an operator-configured `archive-sites` URL taken
	// verbatim (compiler_system.go); without the separator a leading-dash
	// value (`-oProxyCommand=...`) is parsed by scp's getopt as an OPTION,
	// not a destination — CWE-88 argv injection running as the xpfd root
	// user. After `--`, getopt stops scanning so src/dest are always
	// positional. Belt-and-suspenders with the commit-time leading-dash
	// reject in compiler_system.go.
	out, err := exec.CommandContext(ctx, "scp",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"--",
		srcPath, dest,
	).CombinedOutput()
	if err != nil {
		if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
			return fmt.Errorf("%w: %s", err, trimmed)
		}
		return err
	}
	return nil
}

// flowTraceCallback is the single, stable flow-traceoptions handler
// registered on the EventReader exactly ONCE (traceCBOnce). It reads the live
// TraceWriter lock-free from the atomic pointer, so a config commit can swap
// the writer — or clear it to nil on disable — without ever registering a
// second callback. This is the #3932 fix: the previous applyFlowTrace /
// updateFlowTrace called er.AddCallback on every commit touching traceoptions,
// so a long-lived daemon leaked one callback (and one TraceWriter) per commit,
// and every event was then dispatched to all N — a growing per-event cost plus
// a stale-writer drop storm. A nil pointer (traceoptions disabled) makes this a
// no-op.
func (d *Daemon) flowTraceCallback(rec logging.EventRecord, raw []byte) {
	tw := d.traceWriterPtr.Load()
	if tw == nil {
		return
	}
	tw.HandleEvent(rec, raw)
}

// applyFlowTrace sets up the initial flow trace writer from config at boot.
func (d *Daemon) applyFlowTrace(cfg *config.Config, er *logging.EventReader) {
	d.reconcileFlowTrace(cfg, er)
}

// updateFlowTrace reconciles the trace writer when config changes.
func (d *Daemon) updateFlowTrace(cfg *config.Config) {
	d.reconcileFlowTrace(cfg, d.eventReader)
}

// reconcileFlowTrace installs the flow trace writer described by cfg as the
// SINGLE live writer. The stable indirection callback (flowTraceCallback) is
// registered on er exactly once — the first time a writer is installed — and
// every later call only SWAPS the underlying writer, closing the one it
// replaced. So N commits touching traceoptions leave exactly one registered
// callback and one live TraceWriter (#3932). Closing the old writer on swap
// releases its file handle so it can no longer rotate the trace file (no
// double-rotation, no drop storm from a stale closed writer). Disabling
// traceoptions clears the writer to nil; the stable callback stays but becomes
// a no-op. er may be nil (no event reader yet) — then this is a no-op.
func (d *Daemon) reconcileFlowTrace(cfg *config.Config, er *logging.EventReader) {
	if er == nil {
		return
	}

	to := cfg.Security.Flow.Traceoptions
	enabled := to != nil && to.File != ""

	var tw *logging.TraceWriter
	if enabled {
		w, err := logging.NewTraceWriter(to)
		if err != nil {
			// Keep the current writer running rather than dropping tracing on a
			// bad reconcile (mirrors the flowexport #3742 keep-old-on-build-
			// failure posture). Nothing is swapped, so no callback/writer leak.
			slog.Warn("failed to create trace writer", "err", err)
			return
		}
		tw = w
		// Register the single stable callback exactly once, the first time a
		// writer exists. A boot with traceoptions disabled registers nothing;
		// the first enable arms it.
		d.traceCBOnce.Do(func() {
			er.AddCallback(d.flowTraceCallback)
		})
	}

	// Swap the live writer (possibly nil) and close the one it replaced. The
	// callback reads the pointer lock-free; traceReconMu only serializes
	// concurrent reconciles so exactly one writer is closed per swap.
	d.traceReconMu.Lock()
	old := d.traceWriterPtr.Swap(tw)
	if old != nil {
		old.Close()
	}
	d.traceReconMu.Unlock()

	switch {
	case enabled:
		slog.Info("flow traceoptions active",
			"file", to.File,
			"filters", len(to.PacketFilters))
	case old != nil:
		slog.Info("flow traceoptions disabled")
	}
}

// linkStateResubBackoffDefault is the delay between a link-update
// subscription closing (e.g. on a recoverable ENOBUFS) and the
// resubscribe attempt. Matches the neighbor listener's 2s backoff.
const linkStateResubBackoffDefault = 2 * time.Second

// monitorLinkState subscribes to netlink link updates and emits SNMP
// linkUp/linkDown traps on interface state changes.
//
// Resilience (#3950): a netlink multicast receive can fail with ENOBUFS
// when a burst of link events overflows the socket receive buffer — many
// interfaces flapping at once, precisely when link-state monitoring
// matters most for HA (RETH member link-down tracking, DHCP-on-link-up).
// ENOBUFS is RECOVERABLE: the kernel dropped some notifications but the
// socket stays usable. The vishvananda/netlink subscribe goroutine,
// however, treats ANY receive error as terminal — it reports the error to
// the ErrorCallback and closes the update channel. The pre-#3950 loop
// returned on that channel close, so a single transient ENOBUFS
// permanently disabled link-state traps for the daemon's lifetime.
//
// The loop now RESUBSCRIBES on channel close (mirroring the neighbor
// listener's runOneSubscription pattern) and, because messages were
// dropped during the overflow, RE-SYNCS via LinkList to catch up on any
// up/down transitions missed while unsubscribed — feeding the same emit
// path a streamed event would. It exits only on context cancellation.
func (d *Daemon) monitorLinkState(ctx context.Context) {
	// prevOper persists ACROSS resubscribes so the post-ENOBUFS re-sync
	// only emits traps for interfaces whose state genuinely changed.
	prevOper := make(map[int]bool) // ifindex -> up
	seeded := false
	slog.Info("SNMP link state monitor started")

	for {
		if !d.runLinkStateSubscription(ctx, prevOper, &seeded) {
			return // context cancelled — clean exit
		}
		// Subscription closed on a recoverable receive error (ENOBUFS or
		// similar). Back off briefly, then loop to resubscribe. The
		// catch-up re-sync runs inside runLinkStateSubscription right after
		// the fresh subscription is live, so no state-change window is lost.
		backoff := d.linkStateResubBackoff
		if backoff <= 0 {
			backoff = linkStateResubBackoffDefault
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// runLinkStateSubscription owns ONE netlink link-update subscription.
// Returns true when the subscription closed on a recoverable receive
// error (the caller should back off and resubscribe); false when ctx was
// cancelled (the caller should exit). done is closed exactly once on every
// path (no double-close, no leak).
//
// seeded gates the re-sync's emit behavior: the FIRST subscription seeds
// prevOper silently (no traps for interfaces already up at boot); every
// later resubscribe emits catch-up traps for transitions missed during the
// overflow. The re-sync runs after the subscription is established so any
// transition racing the enumeration is also streamed on the live socket.
func (d *Daemon) runLinkStateSubscription(ctx context.Context, prevOper map[int]bool, seeded *bool) bool {
	updates := make(chan netlink.LinkUpdate, 64)
	done := make(chan struct{})

	onErr := func(err error) {
		// Runs on the subscribe goroutine. slog is concurrency-safe; the
		// warning names the recoverable receive error (e.g. ENOBUFS) that is
		// about to close the channel and trigger a resubscribe.
		slog.Warn("SNMP link monitor: netlink receive error, resubscribing", "err", err)
	}

	subscribe := d.linkStateSubscribe
	if subscribe == nil {
		subscribe = defaultLinkStateSubscribe
	}
	if err := subscribe(updates, done, onErr); err != nil {
		slog.Warn("SNMP link monitor: subscribe failed", "err", err)
		// The subscribe may have started its done-watcher goroutine before a
		// ListExisting dump failed; close done to avoid leaking it. Treat as
		// recoverable so the caller backs off and retries.
		close(done)
		return true
	}
	defer close(done)

	// Seed / catch-up now that the subscription is live.
	d.resyncLinkState(prevOper, *seeded)
	*seeded = true

	for {
		select {
		case <-ctx.Done():
			return false
		case update, ok := <-updates:
			if !ok {
				// The netlink subscribe goroutine closes the channel on ANY
				// receive error, including a recoverable ENOBUFS. Resubscribe.
				return true
			}
			attrs := update.Attrs()
			if attrs == nil || attrs.Name == "lo" {
				continue
			}
			d.applyLinkState(prevOper, attrs.Index, attrs.Name,
				attrs.OperState == netlink.OperUp, true)
		}
	}
}

// resyncLinkState enumerates all current links via LinkList and reconciles
// prevOper against ground truth. When emit is true (a post-ENOBUFS
// catch-up) it emits an SNMP trap for every interface whose up/down state
// differs from prevOper — messages were dropped, so the current kernel
// state is authoritative for the transitions we missed. When emit is false
// (the boot seed) it only records current state without emitting.
func (d *Daemon) resyncLinkState(prevOper map[int]bool, emit bool) {
	lister := d.linkStateList
	if lister == nil {
		lister = netlink.LinkList
	}
	links, err := lister()
	if err != nil {
		slog.Warn("SNMP link monitor: link re-sync failed", "err", err)
		return
	}
	for _, l := range links {
		attrs := l.Attrs()
		if attrs.Name == "lo" {
			continue
		}
		d.applyLinkState(prevOper, attrs.Index, attrs.Name,
			attrs.OperState == netlink.OperUp, emit)
	}
}

// applyLinkState records the up/down state for ifindex against prevOper
// and, when the state changed from the last-known value AND emit is true,
// emits an SNMP linkUp/linkDown trap. Shared by the streamed-event path and
// the re-sync catch-up so both dedup identically against prevOper.
func (d *Daemon) applyLinkState(prevOper map[int]bool, index int, name string, up, emit bool) {
	was, known := prevOper[index]
	if known && was == up {
		return // no change
	}
	prevOper[index] = up
	if emit {
		d.emitLinkStateTrap(index, name, up)
	}
}

// emitLinkStateTrap dispatches one link up/down transition. The
// linkStateEmit seam (if set) captures it for tests; otherwise it emits an
// SNMP linkUp/linkDown trap via the snmp agent (a no-op when no agent).
func (d *Daemon) emitLinkStateTrap(index int, name string, up bool) {
	if d.linkStateEmit != nil {
		d.linkStateEmit(index, name, up)
		return
	}
	if d.snmpAgent == nil {
		return
	}
	if up {
		d.snmpAgent.NotifyLinkUp(index, name)
	} else {
		d.snmpAgent.NotifyLinkDown(index, name)
	}
}

// defaultLinkStateSubscribe is the production linkStateSubscribe seam. It
// subscribes to netlink RTNLGRP_LINK updates and wires onErr to the
// subscription's ErrorCallback so a recoverable ENOBUFS is logged before
// the channel closes and the loop resubscribes (#3950).
func defaultLinkStateSubscribe(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error {
	return netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ErrorCallback: onErr,
	})
}
