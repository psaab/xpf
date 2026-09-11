package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

// deferredIPVLAN names one fabric overlay to (re)create: the physical parent,
// the fab* device name, and the addresses it carries. Shared by the deferred
// (OnXSKBound) creation path and the #6791 re-assert loop so both describe the
// work the same way.
type deferredIPVLAN struct {
	parent string
	name   string
	addrs  []string
}

// applyFabricIPVLAN creates the fabric-member IPVLAN overlays (fab0/fab1) for
// cluster heartbeat + VRRP, deferring creation past XSK bind when the userspace
// dataplane is active (an existing IPVLAN breaks zero-copy bind, #128), and
// cleans up stale fabric IPVLAN overlays not in the current config. Extracted
// verbatim from applyConfigLocked (#4407); runs in the same slot, after the
// interface-creation reconcile and before the RETH-MAC pre-check.
func (d *Daemon) applyFabricIPVLAN(cfg *config.Config) error {
	// #6791: accumulates the overlays whose creation is genuinely terminal —
	// retries exhausted and no working fab* device. Joined and returned so the
	// commit fails closed instead of acknowledging a cluster whose heartbeat
	// and session-sync transport does not exist.
	var fabricErrs []error
	// 1.9. Create IPVLAN interfaces for fabric members (fab0, fab1).
	// The physical member (ge-0-0-0) keeps its name; fab0 is IPVLAN L2
	// on top for IP addressing. BPF attaches to the parent.
	// Track which overlays are configured so stale ones can be cleaned up (#128).
	//
	// When the userspace dataplane is active, DEFER IPVLAN creation until
	// after XSK binds complete. The kernel checks for upper devices (like
	// IPVLAN) at XSK bind time — if an IPVLAN exists, zerocopy bind fails
	// and falls back to copy mode (~3 Gbps). Deferring lets the fabric
	// parent bind XSK in zerocopy first, then the IPVLAN is added for
	// sync/heartbeat addressing.
	activeFabricOverlays := make(map[string]bool)
	var deferredOverlays []deferredIPVLAN
	bindingCtrl, isUserspaceDP := d.dataplane().(userspaceXSKBindingController)
	for ifName, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg == nil || ifCfg.LocalFabricMember == "" || !strings.HasPrefix(ifName, "fab") {
			continue
		}
		parentLinux := config.LinuxIfName(ifCfg.LocalFabricMember)
		fabLinux := config.LinuxIfName(ifName)
		activeFabricOverlays[fabLinux] = true
		var addrs []string
		if unit, ok := ifCfg.Units[0]; ok {
			addrs = unit.Addresses
		}
		// When userspace DP is active, remove any existing IPVLAN and
		// defer recreation until after XSK binds in zerocopy. The kernel
		// checks for upper devices at bind time — IPVLAN blocks zerocopy.
		// On subsequent applyConfig calls (config change), the IPVLAN
		// already exists from the OnXSKBound callback and XSK is already
		// bound, so the xskBoundNotified guard prevents re-deletion.
		if isUserspaceDP {
			if bindingCtrl != nil && !bindingCtrl.XSKBoundNotified() {
				// First applyConfig — remove stale IPVLAN so XSK can zerocopy.
				if link, err := netlink.LinkByName(fabLinux); err == nil {
					netlink.LinkDel(link)
					slog.Info("removed fabric IPVLAN for deferred zerocopy XSK bind",
						"name", fabLinux)
				}
				deferredOverlays = append(deferredOverlays, deferredIPVLAN{
					parent: parentLinux, name: fabLinux, addrs: addrs,
				})
				slog.Info("deferring fabric IPVLAN creation until XSK binds complete",
					"parent", parentLinux, "name", fabLinux)
				// continue // DISABLED: deferred IPVLAN broke forwarding
			}
			// XSK already bound — fall through to reconcile.
		}
		if err := fabricEnsureFn(parentLinux, fabLinux, addrs); err != nil {
			// Fabric overlay is critical for cluster heartbeat and VRRP.
			// Retry up to 5 times with 1s delay — the parent interface
			// might not be ready yet after a power cycle.
			var retryErr error
			for retry := 0; retry < 5; retry++ {
				time.Sleep(fabricIPVLANRetryDelay)
				slog.Info("retrying fabric IPVLAN creation",
					"parent", parentLinux, "name", fabLinux, "attempt", retry+2)
				retryErr = fabricEnsureFn(parentLinux, fabLinux, addrs)
				if retryErr == nil {
					break
				}
			}
			if retryErr != nil {
				slog.Error("CRITICAL: fabric IPVLAN creation failed after retries — cluster heartbeat will not work",
					"parent", parentLinux, "name", fabLinux, "err", retryErr)
				// #6791: this log line said the cluster heartbeat will not
				// work and then returned success. ensureFabricIPVLAN only
				// returns an error when there is no usable overlay (address
				// failures are warn-only inside it and AddrReplace is
				// idempotent), so every error reaching here is terminal for
				// fabric function, not a benign already-exists.
				fabricErrs = append(fabricErrs, fmt.Errorf(
					"fabric IPVLAN %s on %s: %w", fabLinux, parentLinux, retryErr))
			}
			continue
		}
	}
	// Register deferred IPVLAN creation callback on the userspace manager.
	if len(deferredOverlays) > 0 && bindingCtrl != nil {
		bindingCtrl.SetOnXSKBound(func() {
			for _, ov := range deferredOverlays {
				slog.Info("XSK bound — creating deferred fabric IPVLAN",
					"parent", ov.parent, "name", ov.name)
				if err := fabricEnsureFn(ov.parent, ov.name, ov.addrs); err != nil {
					slog.Error("deferred fabric IPVLAN creation failed",
						"parent", ov.parent, "name", ov.name, "err", err)
				}
			}
		})
	}
	// Clean up stale fabric IPVLAN overlays not in current config (#128).
	for _, name := range []string{"fab0", "fab1"} {
		if activeFabricOverlays[name] {
			continue
		}
		if link, err := netlink.LinkByName(name); err == nil {
			if _, ok := link.(*netlink.IPVlan); ok {
				netlink.LinkDel(link)
				slog.Info("removed stale fabric IPVLAN", "name", name)
			}
		}
	}
	// The deferred (OnXSKBound) overlays above are created asynchronously after
	// this function has returned, so their failure cannot be reported here at
	// all. fabricIPVLANReassertLoop (#6791) is the retry owner that covers both
	// that window and a transient failure outlasting the in-apply retries.
	return errors.Join(fabricErrs...)
}

// applyVRFReconcile reconciles routing-instance VRFs during a config apply:
// the #2926-C1 context-cancellation boundary check, ReconcileVRFs (create/
// update/orphan-delete vrf-* devices), binding routing-instance member
// interfaces to their VRFs, binding management interfaces (fxp*/fab*/em*) to
// vrf-mgmt when it is managed, and applying the management-VRF routes.
// Extracted verbatim from applyConfigLocked (#4407).
//
// Returns TWO errors (#5700). ctxErr is the #2926-C1 ctx-cancellation check (the
// block's sole early return), which applyConfigLocked propagates unchanged
// through the host-authorization closeout — the C1 abort semantics are
// UNCHANGED. vrfErr is the DEFERRED VRF-device-setup failure: a ReconcileVRFs
// error means the vrf-* device could not be created/reconciled, yet
// reconcileVRFs's partial-failure contract still records the VRF in the
// managed/tracked set (IsManagedVRF returns true below), so the commit used to
// report the VRF configured while it was absent on the kernel — a false
// convergence with no retry owner. vrfErr is threaded into the tail commit-error
// join exactly like the #5310 ifaceErr / #5696 routeLeakErr / #5844
// routingRuleErr deferred errors, so a failed commit fails closed and is the
// retry owner (the next apply re-reconciles). Runs in the same slot, before the
// interface-creation reconcile.
func (d *Daemon) applyVRFReconcile(ctx context.Context, cfg *config.Config) (ctxErr error, vrfErr error) {
	// #2926 boundary C1: before the netlink reconcile phase. Nothing in the
	// kernel / dataplane / FRR has been touched yet (the SNMP swap above is an
	// idempotent in-memory pointer flip), so a cancellation here skips the
	// entire pipeline cleanly. This is the cheapest, safest place to honor a
	// daemon stop.
	if err := ctx.Err(); err != nil {
		return err, nil
	}

	// 0. Reconcile VRF devices (routing-instance VRFs + management VRF).
	// ReconcileVRFs is idempotent: VRFs already present with the correct
	// table ID are preserved (ifindex unchanged). Removed-from-config
	// VRFs are deleted. #847: xpfd claims the entire `vrf-*` kernel
	// namespace — orphan vrf-* devices not in desired and not in
	// m.vrfs (e.g. left over from a routing-instance rename across
	// a daemon restart) are also reaped. Operators MUST NOT
	// pre-create vrf-<name> outside xpfd config.
	//
	// (The original docs/pr/844-vrf-idempotent/plan.md described an
	// earlier design where external VRFs were left alone; the
	// namespace-claim policy in this code supersedes that plan. See
	// the godoc on routing.ReconcileVRFs for the current contract.)
	const mgmtVRFName = config.ManagementVRFInstanceName // #9622: the one definition
	const mgmtTableID = config.ManagementVRFTableID
	mgmtIfaces := managementVRFIfaceSet(cfg)

	if d.routing != nil {
		var desired []routing.VRFSpec
		for _, ri := range cfg.RoutingInstances {
			if ri.InstanceType == "forwarding" {
				slog.Info("forwarding instance, skipping VRF creation",
					"instance", ri.Name)
				continue
			}
			if config.IsReservedRoutingInstanceName(ri.Name) {
				// #9622 belt: pkg/config quarantines this on every compile path;
				// never plan a second VRF of a reserved name if one slips through.
				slog.Warn("routing instance uses a reserved VRF name, skipping VRF creation",
					"instance", ri.Name)
				continue
			}
			desired = append(desired, routing.VRFSpec{
				Name:    ri.Name,
				TableID: ri.TableID,
			})
		}
		if len(mgmtIfaces) > 0 {
			desired = append(desired, routing.VRFSpec{
				Name:    mgmtVRFName,
				TableID: mgmtTableID,
			})
		}
		if err := d.routing.ReconcileVRFs(desired); err != nil {
			// #5700: the VRF DEVICE setup failed (vrf-* could not be created/
			// reconciled). reconcileVRFs still records the VRF as managed on a
			// partial failure, so surface this into commit truth rather than
			// swallowing it at WARN — otherwise the commit reports the VRF
			// configured while it is not on the kernel (false convergence). This is
			// transient-free: VRF device creation depends on no other interface.
			slog.Warn("failed to reconcile VRFs", "err", err)
			vrfErr = errors.Join(vrfErr, fmt.Errorf("reconcile VRFs: %w", err))
		}
	}

	// 0a. Bind routing-instance interfaces to their VRFs.
	// Name normalization is shared with collectAppliedTunnels'
	// RIListMember scan via riMemberLinuxName (#1884) so the tunnel
	// manager's unbind veto can never diverge from what this loop
	// actually binds. Tunnel list members resolve through
	// cfg.TunnelNameMap() (#1904) so a unit>0 entry like gr-0/0/0.1
	// binds the real per-unit device (gr-0-0-0u1), not the literal
	// ".1" name.
	//
	// #5700: deliberately best-effort (WARN, not surfaced). This runs BEFORE
	// applyInterfaceReconcile creates tunnel/xfrmi devices, so a routing-instance
	// member that is a later-created tunnel is legitimately "not found" here — an
	// EXPECTED transient absence that must NOT be promoted into a permanent
	// commit failure.
	//
	// #6805: and because it is legitimately absent here, this pass alone left it
	// UNBOUND. The tunnel manager will not bind a list-only member either — its
	// case-2 arm only OBSERVES, because "0a owns list binds" — so on a FIRST
	// apply the tunnel came up outside its VRF, in the default table, and stayed
	// there until some later apply happened to run this loop while the device
	// existed. rebindRoutingInstanceMembers re-drives the SAME loop after the
	// devices exist; see its comment.
	d.bindRoutingInstanceMembers(cfg)

	// 0b. Bind management interfaces (fxp*/fab*/em*) to vrf-mgmt, but
	// only if ReconcileVRFs actually got vrf-mgmt into the managed set.
	// If reconcile errored out before vrf-mgmt could be created,
	// downstream code (applyMgmtVRFRoutes, HA sync) would otherwise
	// run against a non-existent VRF.
	// Compute the final management-VRF interface set, then publish it with a
	// single atomic Store (#5113) so a lock-free DHCP-callback reader never
	// observes the transient nil the old two-step (= nil then = mgmtIfaces)
	// published. mgmtSet stays nil (readers see the safe empty state) unless
	// reconcile actually got vrf-mgmt into the managed set.
	var mgmtSet map[string]bool
	if d.routing != nil && len(mgmtIfaces) > 0 && d.routing.IsManagedVRF(mgmtVRFName) {
		mgmtSet = mgmtIfaces
		for ifName := range mgmtIfaces {
			// #5700: this PRE-networkd bind is best-effort (WARN, not surfaced).
			// applyNetworkdConfig's `networkctl reconfigure` strips the VRF master
			// binding right after this phase, so the AUTHORITATIVE management-VRF
			// bind is the post-networkd rebindManagementVRFIfaces (whose failure IS
			// surfaced into commit truth). Surfacing this pre-strip bind would report
			// a failure for a binding networkd is about to remove and re-establish.
			if err := d.routing.BindInterfaceToVRF(ifName, mgmtVRFName); err != nil {
				slog.Warn("failed to bind interface to management VRF",
					"interface", ifName, "err", err)
			}
		}
	}
	d.publishMgmtVRFIfaces(mgmtSet)

	// #5867: the DHCP management-VRF route program+reconcile (formerly step 0.6
	// here) now runs in applyConfigLocked immediately after this reconcile
	// returns, so its RouteReplace / cleanup error is threaded into the tail
	// commit-error join (fail-closed but complete) instead of being swallowed at
	// this early phase. Moving it out of applyVRFReconcile also keeps a stale-
	// route-pin failure from aborting the whole apply early (it must NOT skip the
	// dataplane apply). Ordering is unchanged: it still runs after this reconcile
	// (which publishes the mgmt-interface set it reads) and before the interface/
	// dataplane reconciles.
	return nil, vrfErr
}

// rebindManagementVRFIfaces re-binds the published management-VRF interface set
// to vrf-mgmt after applyNetworkdConfig's `networkctl reconfigure` strips the
// VRF master binding (it treats the daemon-created vrf-mgmt device as
// unmanaged). This is the AUTHORITATIVE, load-bearing management-VRF bind:
// #5700 aggregates and RETURNS the per-interface bind failures so the caller can
// join them into commit truth (via networkdErr) instead of swallowing at WARN —
// a genuine bind failure otherwise reports the management VRF configured while
// the interface carries no VRF membership (false convergence, no retry owner).
// The management interfaces exist by this phase, so a failure is genuine, not a
// transient absence. Returns nil when there is nothing to bind or every bind
// succeeds. Extracted so the fail-closed bind can be unit-tested directly,
// mirroring applyInterfaceReconcile (#5310).
func (d *Daemon) rebindManagementVRFIfaces() error {
	mgmtSet := d.mgmtVRFIfaceSet()
	if d.routing == nil || len(mgmtSet) == 0 {
		return nil
	}
	var errs []error
	for ifName := range mgmtSet {
		if err := d.routing.BindInterfaceToVRF(ifName, config.ManagementVRFInstanceName); err != nil {
			slog.Warn("failed to re-bind interface to management VRF",
				"interface", ifName, "err", err)
			errs = append(errs, fmt.Errorf("re-bind %s to management VRF: %w", ifName, err))
		}
	}
	return errors.Join(errs...)
}

// bindRoutingInstanceMembers binds every non-forwarding routing-instance's
// `interface` list members to their VRF.
//
// ONE implementation, deliberately, called from BOTH the pre-networkd step-0a
// pass and the post-device late re-bind (#6805). The two passes must agree on
// exactly which names they bind: the tunnel manager's unbind VETO
// (reconcileVRFClaimLocked case 2) is written against "whatever 0a binds", and a
// second loop that drifted from this one would make that veto guard a different
// set than the one being bound. Name normalization goes through
// riMemberLinuxName (#1884) and cfg.TunnelNameMap() (#1904) so a unit>0 entry
// like gr-0/0/0.1 binds the real per-unit device (gr-0-0-0u1), not the literal
// ".1" name.
//
// Best-effort at WARN in both passes. A routing-instance `interface` list can
// legitimately name an interface that is genuinely absent on this chassis, so
// promoting a bind failure to a commit failure here would reject configs that
// are correct for the fleet — a different defect from the one #6805 fixes.
func (d *Daemon) bindRoutingInstanceMembers(cfg *config.Config) {
	if d.routing == nil || cfg == nil {
		return
	}
	tunMap := cfg.TunnelNameMap()
	for _, ri := range cfg.RoutingInstances {
		if ri.InstanceType == "forwarding" || config.IsReservedRoutingInstanceName(ri.Name) {
			continue
		}
		for _, ifaceName := range ri.Interfaces {
			linuxName := riMemberLinuxName(cfg, tunMap, ifaceName)
			if err := d.routing.BindInterfaceToVRF(linuxName, ri.Name); err != nil {
				slog.Warn("failed to bind interface to VRF",
					"interface", ifaceName, "linux", linuxName,
					"instance", ri.Name, "err", err)
			}
		}
	}
}

// rebindRoutingInstanceMembers is the #6805 late pass: the step-0a bind, re-run
// after the tunnel / xfrmi devices actually exist.
//
// Step 0a is the designated owner of routing-instance list binds — the tunnel
// manager's `reconcileVRFClaimLocked` case 2 refuses to bind a list-only member
// and only OBSERVES whether the link's master is already its VRF, with an
// explicit "0a owns list binds" veto against unbinding. But 0a runs BEFORE
// applyInterfaceReconcile creates those devices, so on a FIRST apply the owner
// ran before the thing it owns existed: 0a warned "not found", the tunnel
// manager observed a link with no master and took no claim, and the tunnel came
// up OUTSIDE its VRF — forwarding in the default table on a commit that reported
// success, until some later apply happened to run 0a while the device existed.
//
// The veto is on UNBIND and stays correct; nothing about it requires the first
// apply to leave the member unbound. The bug was the ordering, so the fix is a
// second pass at the point where the devices are real, not a bind moved into the
// tunnel manager.
//
// Idempotent: BindInterfaceToVRF is LinkByName + LinkSetMaster with no manager
// state, so re-driving it on an already-bound member is a cheap no-op. That is
// why the whole loop is re-run rather than narrowed to "only the tunnels" —
// narrowing would need a second notion of which members are late-created, and
// that is exactly the kind of second list that drifts from the first.
func (d *Daemon) rebindRoutingInstanceMembers(cfg *config.Config) {
	d.bindRoutingInstanceMembers(cfg)
}

// applyInterfaceReconcile creates/reconciles the interface-level network
// devices during a config apply: tunnel interfaces (interface + per-unit),
// xfrmi interfaces for IPsec VPNs (before BPF compilation so compileZones can
// map them to zones), fabric bond/LAG member interfaces, and cleanup of legacy
// RETH bond devices. Extracted verbatim from applyConfigLocked (#4407); all
// steps are idempotent reconciles (unchanged config = no-op). Runs in the same
// slot, after the VRF reconcile and before fabric IPVLAN creation.
//
// Fail-closed (#5310): each sub-stage's GENUINE reconcile failure is
// accumulated with errors.Join and returned so the caller can join it into the
// commit result. Before this the function was void and every sub-stage error
// was swallowed at WARN — a route-based IPsec VPN whose xfrmi failed to be
// created (xfrmManager.Apply used to return nil unconditionally) or a fabric
// bond that could not be realized (#4823) reported a SUCCESSFUL commit while the
// interface carried no traffic. The tolerated idempotent conditions stay
// non-errors inside each manager (an already-exists link is adopted, an
// already-gone delete is a no-op — #4901/#5119/#5261), so a benign re-apply
// still returns nil and keeps succeeding. All steps still run (no early return)
// so a failure in one does not skip the others.
func (d *Daemon) applyInterfaceReconcile(cfg *config.Config) error {
	if d.routing == nil {
		return nil
	}

	var errs []error

	// 1. Create tunnel interfaces (interface-level + per-unit tunnels)
	if err := d.routing.ApplyTunnels(collectAppliedTunnels(cfg)); err != nil {
		slog.Warn("failed to apply tunnels", "err", err)
		errs = append(errs, fmt.Errorf("apply tunnels: %w", err))
	}

	// 1.5. Create xfrmi interfaces for IPsec VPN tunnels.
	// Must happen before BPF compilation so compileZones() can discover
	// the xfrmi interfaces and map them to security zones.
	// Always call ApplyXfrmi so stale xfrmi devices are removed when VPNs
	// are deleted from config.
	if err := d.routing.ApplyXfrmi(cfg.Security.IPsec.VPNs); err != nil {
		slog.Warn("failed to apply xfrmi interfaces", "err", err)
		errs = append(errs, fmt.Errorf("apply xfrmi interfaces: %w", err))
	}

	// 1.7. Create bond (LAG) interfaces for fabric-options member-interfaces.
	// Always call ApplyBonds (even with empty list) so stale bonds from
	// previous configs get cleaned up via ClearBonds().
	var bondIfaces []*config.InterfaceConfig
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if len(ifc.FabricMembers) > 0 {
			bondIfaces = append(bondIfaces, ifc)
		}
	}
	if err := d.routing.ApplyBonds(bondIfaces); err != nil {
		slog.Warn("failed to apply bonds", "err", err)
		errs = append(errs, fmt.Errorf("apply bonds: %w", err))
	}

	// 1.8. Clean up legacy RETH bond devices from previous binary versions.
	// VRRP now runs directly on physical member interfaces — no bonds needed.
	// ClearRethInterfaces returns an error on a netlink LinkList failure OR on
	// any per-bond LinkDel failure (aggregated with errors.Join, #5704); surface
	// it so a stale legacy reth bond left in the kernel fails the commit closed.
	if err := d.routing.ClearRethInterfaces(); err != nil {
		slog.Warn("failed to clean up legacy RETH bonds", "err", err)
		errs = append(errs, fmt.Errorf("clean up legacy RETH bonds: %w", err))
	}

	return errors.Join(errs...)
}

// managementVRFIfaceSet is the set of Linux interface names the daemon binds to
// vrf-mgmt, keyed the way the DHCP-callback readers look them up
// (config.LinuxIfName). Extracted from the apply path so the class rule has a
// callable, testable entry point rather than living inline in a long reconcile.
//
// #7515: the class comes from config.IsManagementIfName, the SSOT shared with
// the networkd `VRF=` emitter and the ip-monitoring next-hop validator. Those
// three answer the same question, and a divergence between them is always a bug:
// the daemon would bind a VRF networkd strips, or the validator would refuse a
// next-hop whose lease FRR actually owns.
func managementVRFIfaceSet(cfg *config.Config) map[string]bool {
	out := make(map[string]bool)
	if cfg == nil {
		return out
	}
	for name := range cfg.Interfaces.Interfaces {
		if config.IsManagementIfName(name) {
			out[config.LinuxIfName(name)] = true
		}
	}
	return out
}
