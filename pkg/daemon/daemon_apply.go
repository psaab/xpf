// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/vrrp"
)

// bootstrapFromFile reads the text Junos config file and imports it as the
// initial active configuration. This is called on first start when the DB
// has no active config yet.
func (d *Daemon) bootstrapFromFile() error {
	data, err := os.ReadFile(d.opts.ConfigFile)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	// Import into the store: enter config mode, load, commit.
	// Commit() handles compilation (including ${node} variable expansion
	// when nodeID is set on the store for cluster mode).
	if err := d.store.EnterConfigure(); err != nil {
		return fmt.Errorf("enter configure: %w", err)
	}
	if err := d.store.LoadOverride(string(data)); err != nil {
		d.store.ExitConfigure()
		return fmt.Errorf("load override: %w", err)
	}
	if _, err := d.store.Commit(); err != nil {
		d.store.ExitConfigure()
		return fmt.Errorf("commit: %w", err)
	}
	d.store.ExitConfigure()
	slog.Info("configuration bootstrapped from file", "file", d.opts.ConfigFile)
	return nil
}

// applyConfig applies a compiled config to the dataplane / kernel.
// Wraps applyConfigLocked under the apply semaphore for non-context
// callers (DHCP callbacks, config-poll, dynamic feeds, event engine,
// in-process CLI commits, CLI auto-rollback, cluster sync recv).
// Always succeeds in acquiring the lock because Background never
// cancels.
//
// #846: HTTP/gRPC commit handlers go through commitAndApply /
// commitConfirmedAndApply instead, which take the same semaphore
// with a request-bound context so a slow lock holder surfaces 503
// to the client rather than hanging the request.
func (d *Daemon) applyConfig(cfg *config.Config) {
	_ = d.applySem.Acquire(context.Background(), 1)
	defer d.applySem.Release(1)
	if err := d.applyConfigLocked(cfg); err != nil {
		slog.Warn("apply config failed", "err", err)
	}
}

// commitAndApply atomically promotes the candidate config and
// applies it. Holds applySem across configstore.Commit and
// applyConfigLocked so two concurrent committers can't interleave
// their commit→apply pairs (which would let kernel state lag store
// state). Optionally syncs to the cluster peer inside the lock.
//
// If ctx is canceled before the semaphore is acquired, returns
// ctx.Err() and NEITHER commit nor apply runs — no divergence. Once
// the semaphore is held, commit and apply run to completion;
// cancellation past that point is ignored (applyConfigLocked is not
// safe to interrupt mid-stream — kernel route writes, FRR reload,
// etc.).
func (d *Daemon) commitAndApply(ctx context.Context, comment string, syncPeer bool) (*config.Config, error) {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer d.applySem.Release(1)

	var compiled *config.Config
	var err error
	if comment != "" {
		compiled, err = d.store.CommitWithDescription(comment)
	} else {
		compiled, err = d.store.Commit()
	}
	if err != nil {
		return nil, err
	}
	if err := d.applyConfigLocked(compiled); err != nil {
		return nil, err
	}
	if syncPeer {
		d.syncConfigToPeer()
	}
	return compiled, nil
}

// syncAndApply is the cluster-sync-recv analogue of commitAndApply.
// Holds applySem across configstore.SyncApply (peer-driven active
// promotion) + applyConfigLocked, so a peer-sync can't interleave
// between a local committer's Commit and applyConfig (which would
// briefly leave store=peer-config but kernel=local-config).
func (d *Daemon) syncAndApply(ctx context.Context, configText string, chassisPreserve func(*config.ConfigTree)) (*config.Config, error) {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer d.applySem.Release(1)

	compiled, err := d.store.SyncApply(configText, chassisPreserve)
	if err != nil {
		return nil, err
	}
	if compiled != nil {
		if err := d.applyConfigLocked(compiled); err != nil {
			return nil, err
		}
	}
	return compiled, nil
}

// commitConfirmedAndApply is the commit-confirmed analogue of
// commitAndApply. Same atomicity guarantees.
func (d *Daemon) commitConfirmedAndApply(ctx context.Context, minutes int, syncPeer bool) (*config.Config, error) {
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer d.applySem.Release(1)

	compiled, err := d.store.CommitConfirmed(minutes)
	if err != nil {
		return nil, err
	}
	if err := d.applyConfigLocked(compiled); err != nil {
		return nil, err
	}
	if syncPeer {
		d.syncConfigToPeer()
	}
	return compiled, nil
}

// applyConfigLocked runs the actual reconcile pipeline. MUST be
// called with d.applySem held.
func (d *Daemon) applyConfigLocked(cfg *config.Config) error {
	if d.applyBodyForTest != nil {
		d.applyBodyForTest(cfg)
		return nil
	}
	// Reset VIP warning suppression so new config gets fresh warnings.
	d.vipWarnedIfaces = nil

	// Log config validation warnings
	for _, w := range cfg.Warnings {
		slog.Warn("config validation", "warning", w)
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
	const mgmtVRFName = "mgmt"
	const mgmtTableID = 999
	mgmtIfaces := make(map[string]bool)
	for name := range cfg.Interfaces.Interfaces {
		if strings.HasPrefix(name, "fxp") || strings.HasPrefix(name, "fab") || strings.HasPrefix(name, "em") {
			mgmtIfaces[config.LinuxIfName(name)] = true
		}
	}

	if d.routing != nil {
		var desired []routing.VRFSpec
		for _, ri := range cfg.RoutingInstances {
			if ri.InstanceType == "forwarding" {
				slog.Info("forwarding instance, skipping VRF creation",
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
			slog.Warn("failed to reconcile VRFs", "err", err)
		}
	}

	// 0a. Bind routing-instance interfaces to their VRFs.
	if d.routing != nil {
		for _, ri := range cfg.RoutingInstances {
			if ri.InstanceType == "forwarding" {
				continue
			}
			for _, ifaceName := range ri.Interfaces {
				// Convert Junos name (gr-0/0/0.0) to Linux name (gr-0-0-0).
				// Strip ".0" unit suffix — unit 0 is the base interface.
				linuxName := config.LinuxIfName(ifaceName)
				if strings.HasSuffix(linuxName, ".0") {
					linuxName = strings.TrimSuffix(linuxName, ".0")
				}
				if err := d.routing.BindInterfaceToVRF(linuxName, ri.Name); err != nil {
					slog.Warn("failed to bind interface to VRF",
						"interface", ifaceName, "linux", linuxName,
						"instance", ri.Name, "err", err)
				}
			}
		}
	}

	// 0b. Bind management interfaces (fxp*/fab*/em*) to vrf-mgmt, but
	// only if ReconcileVRFs actually got vrf-mgmt into the managed set.
	// If reconcile errored out before vrf-mgmt could be created,
	// downstream code (applyMgmtVRFRoutes, HA sync) would otherwise
	// run against a non-existent VRF.
	d.mgmtVRFInterfaces = nil
	if d.routing != nil && len(mgmtIfaces) > 0 && d.routing.IsManagedVRF(mgmtVRFName) {
		d.mgmtVRFInterfaces = mgmtIfaces
		for ifName := range mgmtIfaces {
			if err := d.routing.BindInterfaceToVRF(ifName, mgmtVRFName); err != nil {
				slog.Warn("failed to bind interface to management VRF",
					"interface", ifName, "err", err)
			}
		}
	}

	// 0.6. Program default routes in the management VRF for DHCP leases.
	d.applyMgmtVRFRoutes()

	// 1. Create tunnel interfaces (interface-level + per-unit tunnels)
	if d.routing != nil {
		if err := d.routing.ApplyTunnels(collectAppliedTunnels(cfg)); err != nil {
			slog.Warn("failed to apply tunnels", "err", err)
		}
	}

	// 1.5. Create xfrmi interfaces for IPsec VPN tunnels.
	// Must happen before BPF compilation so compileZones() can discover
	// the xfrmi interfaces and map them to security zones.
	// Always call ApplyXfrmi so stale xfrmi devices are removed when VPNs
	// are deleted from config.
	if d.routing != nil {
		if err := d.routing.ApplyXfrmi(cfg.Security.IPsec.VPNs); err != nil {
			slog.Warn("failed to apply xfrmi interfaces", "err", err)
		}
	}

	// 1.7. Create bond (LAG) interfaces for fabric-options member-interfaces.
	// Always call ApplyBonds (even with empty list) so stale bonds from
	// previous configs get cleaned up via ClearBonds().
	if d.routing != nil {
		var bondIfaces []*config.InterfaceConfig
		for _, ifc := range cfg.Interfaces.Interfaces {
			if len(ifc.FabricMembers) > 0 {
				bondIfaces = append(bondIfaces, ifc)
			}
		}
		if err := d.routing.ApplyBonds(bondIfaces); err != nil {
			slog.Warn("failed to apply bonds", "err", err)
		}
	}

	// 1.8. Clean up legacy RETH bond devices from previous binary versions.
	// VRRP now runs directly on physical member interfaces — no bonds needed.
	if d.routing != nil {
		d.routing.ClearRethInterfaces()
	}

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
	type deferredIPVLAN struct {
		parent string
		name   string
		addrs  []string
	}
	var deferredOverlays []deferredIPVLAN
	_, isUserspaceDP := d.dp.(*dpuserspace.Manager)
	for ifName, ifCfg := range cfg.Interfaces.Interfaces {
		if ifCfg.LocalFabricMember == "" || !strings.HasPrefix(ifName, "fab") {
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
			if um, ok := d.dp.(*dpuserspace.Manager); ok && !um.XSKBoundNotified() {
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
		if err := ensureFabricIPVLAN(parentLinux, fabLinux, addrs); err != nil {
			// Fabric overlay is critical for cluster heartbeat and VRRP.
			// Retry up to 5 times with 1s delay — the parent interface
			// might not be ready yet after a power cycle.
			var retryErr error
			for retry := 0; retry < 5; retry++ {
				time.Sleep(time.Second)
				slog.Info("retrying fabric IPVLAN creation",
					"parent", parentLinux, "name", fabLinux, "attempt", retry+2)
				retryErr = ensureFabricIPVLAN(parentLinux, fabLinux, addrs)
				if retryErr == nil {
					break
				}
			}
			if retryErr != nil {
				slog.Error("CRITICAL: fabric IPVLAN creation failed after retries — cluster heartbeat will not work",
					"parent", parentLinux, "name", fabLinux, "err", retryErr)
			}
			continue
		}
	}
	// Register deferred IPVLAN creation callback on the userspace manager.
	if len(deferredOverlays) > 0 {
		if um, ok := d.dp.(*dpuserspace.Manager); ok {
			um.OnXSKBound = func() {
				for _, ov := range deferredOverlays {
					slog.Info("XSK bound — creating deferred fabric IPVLAN",
						"parent", ov.parent, "name", ov.name)
					if err := ensureFabricIPVLAN(ov.parent, ov.name, ov.addrs); err != nil {
						slog.Error("deferred fabric IPVLAN creation failed",
							"parent", ov.parent, "name", ov.name, "err", err)
					}
				}
			}
		}
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

	// 1.9. Pre-check: will RETH MAC programming require a link cycle?
	// If yes, tell the userspace DP to skip initial worker startup during
	// Compile(). Workers will be started by NotifyLinkCycle() after MAC
	// programming is done. This avoids the double-bind that causes EBUSY
	// on mlx5 zero-copy queues.
	rethMACPending := false
	deferWorkersActive := false
	var clearDeferWorkers func()
	if d.cluster != nil && cfg.Chassis.Cluster != nil && d.dp != nil {
		cc := cfg.Chassis.Cluster
		for rethName, physName := range cfg.RethToPhysical() {
			rethCfg, ok := cfg.Interfaces.Interfaces[rethName]
			if !ok || rethCfg.RedundancyGroup <= 0 {
				continue
			}
			linuxName := config.LinuxIfName(physName)
			link, err := netlink.LinkByName(linuxName)
			if err != nil {
				continue
			}
			mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
			if !bytes.Equal(link.Attrs().HardwareAddr, mac) {
				rethMACPending = true
				break
			}
		}
		if rethMACPending {
			type deferSetter interface{ SetDeferWorkers(bool) }
			if ds, ok := d.dp.(deferSetter); ok {
				ds.SetDeferWorkers(true)
				deferWorkersActive = true
				clearDeferWorkers = func() {
					ds.SetDeferWorkers(false)
				}
				defer func() {
					if deferWorkersActive {
						clearDeferWorkers()
					}
				}()
			}
		}
	}

	policySchedulerActiveState := d.reconcilePolicySchedulerLocked(cfg)
	d.seedPolicySchedulerActiveStateLocked(policySchedulerActiveState)

	// 2. Compile eBPF dataplane
	var compileResult *dataplane.CompileResult
	if d.dp != nil {
		var err error
		if compileResult, err = d.dp.Compile(cfg); err != nil {
			d.recordCompileFailure(err)
			if compileErrorMustAbortApply(err) {
				return err
			}
		} else {
			d.recordCompileSuccess()
		}
	}
	if d.dp != nil && policySchedulerActiveState != nil && compileResult != nil {
		if _, isUserspace := d.dp.(*dpuserspace.Manager); !isUserspace {
			d.dp.UpdatePolicyScheduleState(cfg, policySchedulerActiveState)
		}
	}

	// Clear defer flag after Compile so subsequent recompiles (where MAC
	// is already set) don't skip workers.
	if deferWorkersActive {
		clearDeferWorkers()
		deferWorkersActive = false
	}

	// 2.1. Wire aggressive session aging config to GC.
	if d.gc != nil {
		d.gc.SetAgingConfig(
			cfg.Security.Flow.AgingEarlyAgeout,
			cfg.Security.Flow.AgingHighWatermark,
			cfg.Security.Flow.AgingLowWatermark,
		)

		// Enable per-IP session counting if any screen profile has session limits.
		sessionLimitEnabled := false
		for _, sp := range cfg.Security.Screen {
			if sp.LimitSession.SourceIPBased > 0 || sp.LimitSession.DestinationIPBased > 0 {
				sessionLimitEnabled = true
				break
			}
		}
		d.gc.SetSessionLimitEnabled(sessionLimitEnabled)
	}

	// 2.2. Build zone→RG map for per-RG session sync.
	if d.sessionSync != nil && compileResult != nil {
		d.sessionSync.SetZoneRGMap(buildZoneRGMap(cfg, compileResult.ZoneIDs))
	}

	// 2.5. Write systemd-networkd config for managed interfaces
	if d.networkd != nil && compileResult != nil && len(compileResult.ManagedInterfaces) > 0 {
		if err := d.networkd.Apply(compileResult.ManagedInterfaces); err != nil {
			slog.Warn("failed to apply networkd config", "err", err)
		}
	}

	// 2.6. Program deterministic virtual MACs on RETH member interfaces.
	// Each node gets a per-node MAC (02:bf:72:CC:RR:NN) to avoid FDB conflicts
	// when both nodes' members are on the same L2 domain. VRRP + gratuitous NA
	// handle failover; RA goodbye packets handle IPv6 default gateway transitions.
	// Must run AFTER networkd.Apply() so .link renames are applied first.
	needLinkCycleRecovery := false
	if d.cluster != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		rethToPhys := cfg.RethToPhysical()

		// PrepareLinkCycle is called on-demand after programRethMAC reports
		// an actual link DOWN/UP cycle. Most drivers (mlx5, virtio) support
		// IFF_LIVE_ADDR_CHANGE so no cycle is needed and workers keep running.

		for rethName, physName := range rethToPhys {
			rethCfg, ok := cfg.Interfaces.Interfaces[rethName]
			if !ok || rethCfg.RedundancyGroup <= 0 {
				continue
			}
			linuxName := config.LinuxIfName(physName)
			// If the interface doesn't exist under its config name,
			// find it by RETH virtual MAC and rename it.
			if _, err := netlink.LinkByName(linuxName); err != nil {
				mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
				if oldName := renameRethMember(linuxName, mac); oldName != "" {
					slog.Info("renamed RETH member interface",
						"from", oldName, "to", linuxName)
					fixRethLinkFile(linuxName, oldName)
				}
			}
			// Ensure the .link file uses OriginalName= (not MACAddress=)
			// for stable matching across reboots. The bootstrap .link
			// files may use MACAddress= which breaks after virtual MAC
			// programming — the interface reboots with physical MAC but
			// the MACAddress= line might reference the wrong one.
			ensureRethLinkOriginalName(linuxName)
			// Disable DAD — virtual MAC may still collide with peer on
			// some deployments; disable to avoid DAD failures.
			dadPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", linuxName)
			os.WriteFile(dadPath, []byte("0"), 0644)
			// Suppress auto link-local generation on RETH member interfaces.
			// The virtual MAC triggers a kernel-generated link-local (fe80::...)
			// which causes continuous MLDv2 multicast reports on the L2 segment.
			// VIPs are managed explicitly; auto link-locals are unnecessary.
			addrGenPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/addr_gen_mode", linuxName)
			os.WriteFile(addrGenPath, []byte("1"), 0644)
			mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
			linkCycled, err := programRethMAC(linuxName, mac)
			if err != nil {
				slog.Warn("failed to set RETH MAC", "iface", linuxName, "mac", mac, "err", err)
			}
			if linkCycled && !needLinkCycleRecovery {
				// First link cycle — stop workers NOW (they may have
				// been accessing UMEM during the DOWN/UP). The rebind
				// in NotifyLinkCycle will restart them.
				if d.dp != nil {
					type linkCyclePreparer interface{ PrepareLinkCycle() }
					if preparer, ok := d.dp.(linkCyclePreparer); ok {
						slog.Info("userspace: stopping workers after RETH MAC link cycle")
						preparer.PrepareLinkCycle()
					}
				}
			}
			needLinkCycleRecovery = needLinkCycleRecovery || linkCycled
			clearDadFailed(linuxName)
			removeAutoLinkLocal(linuxName)
			// Re-add link-local if this parent interface has IPv6 on unit 0.
			// NDP Neighbor Solicitation requires a link-local source address.
			if rethUnitHasIPv6(rethCfg, 0) {
				ensureRethLinkLocal(linuxName)
			}

			// Re-disable VLAN RX offload after MAC programming.
			// The iavf VF driver resets ethtool features (including
			// rx-vlan-offload) during the link down/up cycle that
			// programRethMAC requires. Without this, XDP cannot see
			// VLAN tags in the packet data and drops VLAN traffic.
			if out, err := exec.Command("ethtool", "-K", linuxName, "rxvlan", "off").CombinedOutput(); err != nil {
				slog.Warn("failed to re-disable rxvlan after RETH MAC",
					"interface", linuxName, "err", err, "output", strings.TrimSpace(string(out)))
			} else {
				slog.Info("re-disabled VLAN RX offload after RETH MAC", "interface", linuxName)
			}

			// Propagate MAC change to VLAN sub-interfaces.
			// Linux VLAN sub-interfaces don't always inherit the
			// parent's MAC change after link down/up.
			if parentLink, err := netlink.LinkByName(linuxName); err == nil {
				parentIdx := parentLink.Attrs().Index
				links, _ := netlink.LinkList()
				for _, l := range links {
					if l.Attrs().ParentIndex != parentIdx {
						continue
					}
					subName := l.Attrs().Name
					// Suppress auto link-local on VLAN sub-interfaces too.
					subAddrGen := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/addr_gen_mode", subName)
					os.WriteFile(subAddrGen, []byte("1"), 0644)
					if !bytes.Equal(l.Attrs().HardwareAddr, mac) {
						if err := netlink.LinkSetHardwareAddr(l, mac); err != nil {
							slog.Warn("failed to propagate MAC to VLAN sub-interface",
								"iface", subName, "err", err)
						} else {
							slog.Info("propagated RETH MAC to VLAN sub-interface",
								"iface", subName, "mac", mac)
						}
					}
					removeAutoLinkLocal(subName)
					// Re-add link-local if this VLAN sub-interface has IPv6.
					// Extract VLAN ID from sub-interface name (e.g. "ge-7-0-1.100").
					if dotIdx := strings.LastIndex(subName, "."); dotIdx >= 0 {
						if vid, err := strconv.Atoi(subName[dotIdx+1:]); err == nil {
							if rethUnitHasIPv6(rethCfg, vid) {
								ensureRethLinkLocal(subName)
							}
						}
					}
				}
			}
		}
	}

	// 2.6b. Reconcile VRRP VIPs and stable link-locals after RETH MAC
	// programming. Only needed when programRethMAC had to bring the
	// interface DOWN/UP (link cycle), which removes all addresses
	// including VRRP VIPs and stable link-locals.
	if needLinkCycleRecovery && d.isNoRethVRRP() {
		// Direct mode: re-add VIPs + stable link-locals for each RG
		// where we are primary.
		if d.cluster != nil {
			for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
				if d.cluster.IsLocalPrimary(rg.ID) {
					d.directAddVIPs(rg.ID)
					d.addStableRethLinkLocal(rg.ID)
					d.scheduleDirectAnnounce(rg.ID, "link-cycle-recovery")
				}
			}
		}
	} else if needLinkCycleRecovery && d.vrrpMgr != nil {
		d.vrrpMgr.ReconcileVIPs()
		// Re-add stable link-locals for active RGs after MAC bounce.
		if d.cluster != nil && cfg.Chassis.Cluster != nil {
			for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
				s := d.getOrCreateRGState(rg.ID)
				if s.IsActive() {
					d.addStableRethLinkLocal(rg.ID)
				}
			}
		}
	}

	// 2.6b2. Rebind AF_XDP sockets after RETH MAC programming.
	// Only needed when PrepareLinkCycle was called (macChangeNeeded=true
	// or rethMACPending=true). Calling NotifyLinkCycle without a prior
	// PrepareLinkCycle causes a spurious rebind that gets EBUSY on mlx5
	// zero-copy queues because the first bind is still in progress.
	if d.dp != nil && needLinkCycleRecovery {
		// Actual link DOWN/UP occurred — old XSK sockets are dead.
		// Rebind to create fresh sockets on the reinitialized queues.
		d.dp.NotifyLinkCycle()
		if d.ra != nil {
			d.ra.ResendBurst()
		}
	} else if d.dp != nil && rethMACPending && !needLinkCycleRecovery {
		// MAC set live (no link cycle) but workers were deferred.
		// Trigger a re-Compile to start workers with the now-correct MAC.
		// This is cheaper than NotifyLinkCycle (no stop_workers/rebind).
		if _, err := d.dp.Compile(cfg); err != nil {
			slog.Warn("failed to re-compile after deferred MAC", "err", err)
		}
	}

	// NOTE: stable link-local cleanup for secondary RGs is handled by
	// the reconcile loop (reconcileRGState) after election settles,
	// not here — we don't know who's primary during config apply.

	// 2.6c. Reconcile proxy ARP entries for NAT addresses.
	if len(cfg.Security.NAT.ProxyARP) > 0 {
		ifaceMap := make(map[string]int)
		rethToPhys := cfg.RethToPhysical()
		for _, entry := range cfg.Security.NAT.ProxyARP {
			parts := strings.SplitN(entry.Interface, ".", 2)
			baseName := parts[0]
			if phys, ok := rethToPhys[baseName]; ok {
				baseName = phys
			}
			linuxName := config.LinuxIfName(baseName)
			if _, ok := ifaceMap[entry.Interface]; ok {
				continue
			}
			iface, err := net.InterfaceByName(linuxName)
			if err != nil {
				slog.Warn("proxy-arp: interface not found", "iface", entry.Interface, "linux", linuxName, "err", err)
				continue
			}
			ifaceMap[entry.Interface] = iface.Index
		}
		added, err := dataplane.ReconcileProxyARP(cfg, ifaceMap)
		if err != nil {
			slog.Warn("failed to reconcile proxy ARP", "err", err)
		}
		for _, a := range added {
			if a.Iface != "" {
				if err := cluster.SendGratuitousARP(a.Iface, a.IP, 1); err != nil {
					slog.Warn("proxy-arp: GARP failed", "ip", a.IP, "iface", a.Iface, "err", err)
				}
			}
		}
	}

	// 2.7. Re-bind management VRF interfaces after networkd.Apply().
	// networkctl reconfigure strips VRF master bindings because networkd
	// considers the daemon-created vrf-mgmt device "unmanaged" and ignores
	// the VRF= directive. Re-bind here to restore VRF membership.
	if d.routing != nil && d.mgmtVRFInterfaces != nil {
		for ifName := range d.mgmtVRFInterfaces {
			if err := d.routing.BindInterfaceToVRF(ifName, "mgmt"); err != nil {
				slog.Warn("failed to re-bind interface to management VRF",
					"interface", ifName, "err", err)
			}
		}
		// Restart heartbeat after VRF rebind — networkd reconfigure moves
		// the control interface (em0) out of vrf-mgmt temporarily, which
		// invalidates the heartbeat UDP sockets. Without this restart,
		// the recovering node stops receiving peer heartbeats and declares
		// split-brain after the grace period expires.
		if d.cluster != nil {
			d.cluster.RestartHeartbeat()
		}
	}

	// 3. Apply all routes + dynamic protocols via FRR
	if d.frr != nil {
		// Collect interface bandwidths and point-to-point flags for FRR.
		ifaceBandwidths := make(map[string]uint64)
		ifaceP2P := make(map[string]bool)
		for name, ifc := range cfg.Interfaces.Interfaces {
			linuxName := config.LinuxIfName(name)
			if ifc.Bandwidth > 0 {
				ifaceBandwidths[linuxName] = ifc.Bandwidth
			}
			for _, unit := range ifc.Units {
				if unit.PointToPoint {
					ifaceP2P[linuxName] = true
				}
			}
		}

		fc := &frr.FullConfig{
			OSPF:                  cfg.Protocols.OSPF,
			OSPFv3:                cfg.Protocols.OSPFv3,
			BGP:                   cfg.Protocols.BGP,
			RIP:                   cfg.Protocols.RIP,
			ISIS:                  cfg.Protocols.ISIS,
			StaticRoutes:          cfg.RoutingOptions.StaticRoutes,
			Inet6StaticRoutes:     cfg.RoutingOptions.Inet6StaticRoutes,
			GenerateRoutes:        cfg.RoutingOptions.GenerateRoutes,
			DHCPRoutes:            d.collectDHCPRoutes(),
			PolicyOptions:         &cfg.PolicyOptions,
			ForwardingTableExport: cfg.RoutingOptions.ForwardingTableExport,
			BackupRouter:          cfg.System.BackupRouter,
			BackupRouterDst:       cfg.System.BackupRouterDst,
			InterfaceBandwidths:   ifaceBandwidths,
			InterfacePointToPoint: ifaceP2P,
			RethMap:               cfg.RethToPhysical(),
			IPv6NextHopInterfaces: inferIPv6StaticNextHopInterfaces(cfg),
			ClusterMode:           d.cluster != nil,
		}
		for _, ri := range cfg.RoutingInstances {
			vrfName := "vrf-" + ri.Name
			if ri.InstanceType == "forwarding" {
				vrfName = "" // forwarding instances use the default table
			}
			fc.Instances = append(fc.Instances, frr.InstanceConfig{
				VRFName:           vrfName,
				OSPF:              ri.OSPF,
				OSPFv3:            ri.OSPFv3,
				BGP:               ri.BGP,
				RIP:               ri.RIP,
				ISIS:              ri.ISIS,
				StaticRoutes:      ri.StaticRoutes,
				Inet6StaticRoutes: ri.Inet6StaticRoutes,
			})
		}
		if err := d.frr.ApplyFull(fc); err != nil {
			slog.Warn("failed to apply FRR config", "err", err)
		}

		// Set L4 ECMP hash when consistent-hash is configured.
		if fc.ConsistentHash {
			path := "/proc/sys/net/ipv4/fib_multipath_hash_policy"
			current, _ := os.ReadFile(path)
			if strings.TrimSpace(string(current)) != "1" {
				if err := os.WriteFile(path, []byte("1\n"), 0644); err != nil {
					slog.Warn("failed to set fib_multipath_hash_policy", "err", err)
				} else {
					slog.Info("enabled L4 ECMP hashing (consistent-hash)")
				}
			}
		}
	}

	// 3b. Apply next-table policy routing rules (ip rule)
	if d.routing != nil {
		// Collect all static routes from main + per-rib
		allRoutes := append(cfg.RoutingOptions.StaticRoutes, cfg.RoutingOptions.Inet6StaticRoutes...)
		if err := d.routing.ApplyNextTableRules(allRoutes, cfg.RoutingInstances); err != nil {
			slog.Warn("failed to apply next-table rules", "err", err)
		}
	}

	// 3c. Apply rib-group route leaking rules (ip rule)
	if d.routing != nil && len(cfg.RoutingOptions.RibGroups) > 0 {
		if err := d.routing.ApplyRibGroupRules(cfg.RoutingOptions.RibGroups, cfg.RoutingInstances); err != nil {
			slog.Warn("failed to apply rib-group rules", "err", err)
		}
	}

	// 3d. Apply policy-based routing rules (ip rule) for firewall filter routing-instance
	if d.routing != nil {
		pbrRules := routing.BuildPBRRules(&cfg.Firewall, cfg.RoutingInstances)
		if err := d.routing.ApplyPBRRules(pbrRules); err != nil {
			slog.Warn("failed to apply PBR rules", "err", err)
		}
	}

	// 4. Proactive neighbor resolution for all known next-hops/gateways.
	// This ensures bpf_fib_lookup returns SUCCESS (with valid MACs)
	// instead of NO_NEIGH for the first forwarded packet.
	// In cluster mode, skip here — RETH VIPs are not yet installed (VRRP
	// hasn't become MASTER), so RouteGet() for WAN next-hops may fail.
	// resolveNeighbors() is triggered on VRRP MASTER in watchVRRPEvents.
	if cfg.Chassis.Cluster == nil {
		d.resolveNeighbors(cfg)
	}

	// 5. Apply RA config (Router Advertisements)
	// In cluster mode, RA/kea are managed by watchVRRPEvents — only
	// the MASTER runs these services to prevent dual-RA / dual-DHCP.
	// The VRRP event fires shortly after startup and calls applyRethServices().
	isCluster := cfg.Chassis.Cluster != nil
	raConfigs := d.buildRAConfigs(cfg)
	if !isCluster {
		if d.ra != nil && len(raConfigs) > 0 {
			if err := d.ra.Apply(raConfigs); err != nil {
				slog.Warn("failed to apply RA config", "err", err)
			}
		} else if d.ra != nil {
			// No RA configs — clear any previous RA senders.
			if err := d.ra.Clear(); err != nil {
				slog.Warn("failed to clear RA config", "err", err)
			}
		}
	}
	// Cluster startup: goodbye RAs for stale routes are handled by the
	// reconcile loop (reconcileRGState) after VRRP election settles.
	// Each RETH node has a different virtual MAC (hence different
	// link-local), so both nodes appear as separate routers to hosts.
	// Only the primary sends RAs (via applyRethServicesForRG on MASTER);
	// the reconcile loop sends goodbye RAs for inactive RGs.
	//
	// Stable link-local cleanup: handled by reconcile after election.

	// 6. Apply IPsec config
	// Always call Apply so stale swanctl config is removed when VPNs are
	// deleted from config.
	if d.ipsec != nil {
		if err := d.ipsec.Apply(ipsec.PrepareConfig(cfg)); err != nil {
			slog.Warn("failed to apply IPsec config", "err", err)
		}
	}

	// 7. Apply DHCP server config (Kea DHCPv4 + DHCPv6)
	// In cluster mode, deferred to VRRP MASTER transition.
	if !isCluster && d.dhcpServer != nil && (cfg.System.DHCPServer.DHCPLocalServer != nil || cfg.System.DHCPServer.DHCPv6LocalServer != nil) {
		// Resolve RETH interface names for Kea (needs real Linux names)
		resolveDHCPRethInterfaces(&cfg.System.DHCPServer, cfg)
		if err := d.dhcpServer.Apply(&cfg.System.DHCPServer); err != nil {
			slog.Warn("failed to apply DHCP server config", "err", err)
		}
	}

	// 8. Apply VRRP config — merge user VRRP + RETH VRRP instances
	vrrpInstances := vrrp.CollectInstances(cfg)
	if d.cluster != nil {
		localPri := d.cluster.LocalPriorities()
		vrrpInstances = append(vrrpInstances, vrrp.CollectRethInstances(cfg, localPri)...)
	}
	if err := d.vrrpMgr.UpdateInstances(vrrpInstances); err != nil {
		slog.Warn("failed to update VRRP instances", "err", err)
	}

	// 9. Apply system DNS and NTP configuration
	d.applySystemDNS(cfg)
	d.applySystemNTP(cfg)
	d.applyDNSService(cfg)

	// 9.5. Apply system hostname, timezone, and kernel tuning
	d.applyHostname(cfg)
	d.applyTimezone(cfg)
	d.applyKernelTuning(cfg)
	d.applyLo0Filter(cfg)

	// 9.6. Write SSH known hosts file
	d.applySSHKnownHosts(cfg)

	// 10. Apply system syslog forwarding
	d.applySystemSyslog(cfg)

	// 11. Apply system login users (create OS accounts, SSH keys)
	d.applySystemLogin(cfg)

	// 12. Apply SSH service configuration (root-login)
	d.applySSHConfig(cfg)

	// 13. Apply root authentication (encrypted-password + SSH keys)
	d.applyRootAuth(cfg)

	// 14. Apply syslog file destinations (rsyslog configs)
	d.applySyslogFiles(cfg)

	// 14b. Update security log syslog clients + zone name mapping
	if d.eventReader != nil {
		d.applySyslogConfig(d.eventReader, cfg)
	}

	// 15. Archive config to remote sites if transfer-on-commit is enabled
	d.archiveConfig(cfg)

	// 15b. Configure local archival settings for auto-archive on commit
	if cfg.System.Archival != nil {
		dir := cfg.System.Archival.ArchiveDir
		if dir == "" {
			dir = "/var/lib/xpf/archive"
		}
		max := cfg.System.Archival.MaxArchives
		if max <= 0 {
			max = 10
		}
		d.store.SetArchiveConfig(dir, max)
	} else {
		d.store.SetArchiveConfig("", 0)
	}

	// 16. Update flow traceoptions (trace file + filters)
	d.updateFlowTrace(cfg)

	// 17. Update event-options policies (RPM-driven failover)
	if d.eventEngine != nil {
		d.eventEngine.Apply(cfg.EventOptions)
	}

	// 18. Update chassis cluster interface monitors
	if d.routing != nil && cfg.Chassis.Cluster != nil &&
		len(cfg.Chassis.Cluster.RedundancyGroups) > 0 {
		d.routing.ApplyInterfaceMonitors(cfg.Chassis.Cluster.RedundancyGroups)
	}

	// 19. Update chassis cluster state machine
	if d.cluster != nil && cfg.Chassis.Cluster != nil {
		d.cluster.UpdateConfig(cfg.Chassis.Cluster)
		// Feed interface monitor statuses into cluster weight calculation
		if d.routing != nil {
			monStatuses := d.routing.InterfaceMonitorStatuses()
			for rgID, statuses := range monStatuses {
				for _, st := range statuses {
					d.cluster.SetMonitorWeight(rgID, st.Interface, !st.Up, st.Weight)
				}
			}
		}

		// RETH GARP is handled by native VRRP (VRRP-backed RETH).
		// No manual GARP registration needed.
	}

	// 20. Detect cluster transport config changes and restart comms (#87).
	// Only restart if comms were previously started (activeClusterTransport
	// is non-zero) and the new config differs.
	if d.cluster != nil && d.daemonCtx != nil {
		newTransport := clusterTransportFromConfig(cfg)
		if d.activeClusterTransport != (clusterTransportKey{}) && newTransport != d.activeClusterTransport {
			slog.Info("cluster: transport config changed, restarting comms",
				"old_control", d.activeClusterTransport.ControlInterface,
				"new_control", newTransport.ControlInterface,
				"old_peer", d.activeClusterTransport.PeerAddress,
				"new_peer", newTransport.PeerAddress,
				"old_fabric", d.activeClusterTransport.FabricInterface,
				"new_fabric", newTransport.FabricInterface,
				"old_fabric_peer", d.activeClusterTransport.FabricPeerAddress,
				"new_fabric_peer", newTransport.FabricPeerAddress)
			d.stopClusterComms()
			d.startClusterComms(d.daemonCtx)
		}
	}

	// 21. Re-apply D3 RSS indirection on config change (#797 HIGH #2).
	// Worker count can change via commit (e.g. `set system dataplane
	// workers 6`), and the D3 disable knob can flip; either requires
	// re-running the reshape (or restore) against the current HW state.
	// Idempotent: matching tables skip the write. Non-mlx5 interfaces
	// are skipped at the per-interface guard. The allowlist is
	// recomputed from the *new* compiled config so interface-set
	// changes (added/removed zoned mlx5 interfaces, fabric interface
	// changes) take effect on the same commit.
	if !d.opts.NoDataplane {
		rssEnabled := true
		workers := 0
		var rssAllowed []string
		// #801: mirror the startup site so a commit that changes any
		// of the Step-0 knobs takes effect without a restart.
		var (
			governor          string
			netdevBudget      int
			coalesceEnable    bool
			coalesceRX        int
			coalesceTX        int
			userspaceDP       bool
			coalesceExplicit  bool
			claimHostTunables bool
		)
		if cfg.System.DataplaneType == "userspace" && cfg.System.UserspaceDataplane != nil {
			userspaceDP = true
			workers = cfg.System.UserspaceDataplane.Workers
			if cfg.System.UserspaceDataplane.RSSIndirectionDisabled {
				rssEnabled = false
			}
			rssAllowed = dpuserspace.UserspaceBoundLinuxInterfaces(cfg)
			claimHostTunables = cfg.System.UserspaceDataplane.ClaimHostTunables
			governor = cfg.System.UserspaceDataplane.CPUGovernor
			netdevBudget = cfg.System.UserspaceDataplane.NetdevBudget
			coalesceExplicit = cfg.System.UserspaceDataplane.CoalescenceAdaptiveExplicit
			if coalesceExplicit &&
				!cfg.System.UserspaceDataplane.CoalescenceAdaptiveDisabled {
				coalesceEnable = true
			}
			coalesceRX = cfg.System.UserspaceDataplane.CoalescenceRXUsecs
			coalesceTX = cfg.System.UserspaceDataplane.CoalescenceTXUsecs
		}
		reapplyRSSIndirection(rssEnabled, workers, rssAllowed)
		// #801 B1 + B2: opt-in gate + restore-on-disable.
		d.applyStep0Tunables(userspaceDP, claimHostTunables, governor, netdevBudget,
			coalesceExplicit, coalesceEnable, coalesceRX, coalesceTX, rssAllowed)
	}
	return nil
}

func compileErrorMustAbortApply(err error) bool {
	return errors.Is(err, dpuserspace.ErrPolicySchedulerProtocolIncompatible)
}
