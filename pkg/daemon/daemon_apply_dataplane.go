package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// applyDataplaneAndHACore runs the ordering-entangled dataplane-apply and
// RETH-MAC / VRRP-VIP / AF_XDP-worker-rebind critical section of a config
// apply (#4407). Extracted verbatim from applyConfigLocked; the head-produced
// state that the earlier decoupled phases do not touch stays local here —
// rethMACPending and the deferred-worker-startup flag/defer are self-contained
// — and the two values the tail still needs are returned: the ip-monitoring
// commit overlay (fed to applyRoutingRules and the FRR render), the captured
// networkd write error, and the DEFERRED ordinary dataplane-apply error
// (#5679) — both threaded into applyTailReconciles' Join. The three early
// error returns — the two #2926 context-abort boundaries (ctx.Err() before
// ApplyConfig and before the FRR reload) and the compileErrorMustAbortApply
// dataplane abort on an ApplyConfig failure — are preserved; the caller bails
// (via the terminal `err` return) without running the routing / service / tail
// reconciles, exactly as the inline `return err` did.
//
// applyErr (#5679) is DISTINCT from that terminal `err`: an ORDINARY (non-abort
// -class) ApplyConfig failure does NOT disarm the dataplane — the OLD compiled
// config stays live and forwarding — so the tail reconciles MUST still run
// (fail-closed but complete, exactly like networkdErr / ifaceErr). It is
// returned as a deferred error the caller joins at the tail so the commit
// reports FAILURE rather than silently succeeding against the stale policy,
// instead of aborting the rest of the apply. commitOverlay, networkdErr, and
// applyErr are named returns so the pre-networkd boundaries can return them
// (nil) before the networkd / apply phases assign them. Runs in the same slot,
// after the fabric-IPVLAN reconcile and before the routing rules.
func (d *Daemon) applyDataplaneAndHACore(ctx context.Context, cfg *config.Config) (commitOverlay []config.RouteOverlayEntry, networkdErr error, applyErr error, err error) {
	// #6871 (round 8): a link-cycle lease cannot outlive this function.
	//
	// This is the extent that contains BOTH ends of the cycle — step 2.6's
	// rethToPhys loop takes the lease (via programRethMACWithWorkerJoin ->
	// PrepareLinkCycle) and step 2.6b2 releases it (NotifyLinkCycle) — so a
	// defer here is a guarantee no arrangement of the code between them can
	// break: it runs on a panic and on any early return a later change adds.
	//
	// It is what makes the self-renewing lease safe. The lease now re-arms its
	// own deadline on a fixed period (linkCycleLeaseHeartbeat), which is what
	// lets its TTL bound a CONSTANT instead of an interval that scales with
	// reth-count, child-netdev count and netlink latency — but a lease that
	// renews itself is a lease that a leak would suppress the 1 Hz reconcile
	// with FOREVER. The wall-clock backstop cannot fix that without also being
	// able to expire a cycle that is still running; a guaranteed release can.
	//
	// On the normal path this is a no-op: NotifyLinkCycle already released.
	defer d.abandonLinkCycleLease()

	// 1.9. Pre-check: will RETH MAC programming require a link cycle?
	// If yes, tell the userspace DP to skip initial worker startup during
	// ApplyConfig(). Workers will be started by NotifyLinkCycle() after MAC
	// programming is done. This avoids the double-bind that causes EBUSY
	// on mlx5 zero-copy queues.
	rethMACPending := false
	deferWorkersActive := false
	var clearDeferWorkers func()
	if d.cluster != nil && cfg.Chassis.Cluster != nil && d.dataplane() != nil {
		cc := cfg.Chassis.Cluster
		for rethName, physName := range cfg.RethToPhysical() {
			rethCfg, ok := cfg.Interfaces.Interfaces[rethName]
			if !ok || rethCfg == nil || rethCfg.RedundancyGroup <= 0 {
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
			d.setDataplaneDeferWorkers(true)
			deferWorkersActive = true
			clearDeferWorkers = func() {
				d.setDataplaneDeferWorkers(false)
			}
			defer func() {
				if deferWorkersActive {
					clearDeferWorkers()
				}
			}()
		}
	}

	policySchedulerApplyTime := time.Now()
	policySchedulerActiveState := d.policySchedulerActiveStateForApplyLocked(cfg, policySchedulerApplyTime)
	d.seedPolicySchedulerActiveStateLocked(policySchedulerActiveState)

	// 1.95. Refresh the dataplane's ip-monitoring overlay cache from
	// the engine BEFORE the full snapshot build (#1827, AGY r2-2): an
	// operator commit while a policy is FAILED must rebuild routes
	// with the active overlay instead of wiping the injected failover
	// route until the next engine tick. The overlay is filtered
	// against the INCOMING config (Codex PR #1843 HIGH-1) so a commit
	// that removes or edits a policy never republishes the stale
	// entries; the same filtered view feeds the FRR render in step 3.
	commitOverlay = d.commitOverlayForConfig(cfg)
	if setter, ok := d.dataplane().(routeOverlaySetter); ok {
		setter.SetRouteOverlay(commitOverlay)
	}

	// 1.95. Reconcile the running dynamic-address feed-producer set against
	// this config generation BEFORE reading its overlay (#5036). This is what
	// makes a day-2 feed-server add/remove/edit take effect: the feed manager
	// is constructed unconditionally at boot, and this hash-gated Apply starts
	// the replacement producers (and joins removed ones) whenever the
	// feed-server config changes. A feed CONTENT refresh leaves the hash
	// unchanged, so it does not restart the fetchers. Must run before the
	// SetFeedSnapshots overlay push below so the overlay reflects the
	// reconciled generation (the fresh snapshot lands asynchronously and its
	// onUpdate re-applies, exactly as at boot).
	d.reconcileFeeds(cfg)

	// 1.96. Refresh the dataplane's dynamic-address feed overlay from the
	// feed manager BEFORE the full snapshot build (#2049). The feed manager
	// fetches threat-feed/allowlist prefixes and its onUpdate callback
	// re-enters applyConfig against the SAME *config.Config; without this
	// hand-off the address book the helper enforces would never see the
	// feed prefixes (the never-enforced gap #2049 closes). The overlay is
	// joined against the INCOMING config's bindings so a commit that removes
	// a binding stops enforcing its feed. Mirrors SetRouteOverlay above.
	if setter, ok := d.dataplane().(feedSnapshotSetter); ok {
		setter.SetFeedSnapshots(d.feedSnapshotsForConfig(cfg))
	}

	// #2926 boundary C2: before the dataplane apply (the Rust control-socket
	// sync push). The fabric-IPVLAN / VRF / tunnel / bond netlink reconciles
	// above are idempotent and have each run to completion, so bailing here
	// leaves a consistent kernel state with the dataplane untouched. Once
	// the dataplane ApplyConfig and the RETH MAC / VIP / worker-rebind sequence that
	// follows it begin, they run as one unit (no mid-sequence abort) — the
	// next boundary is before the FRR reload.
	if err := ctx.Err(); err != nil {
		return commitOverlay, networkdErr, nil, err
	}

	// #6948: capture the commit-time session-invalidation candidates HERE — the
	// last statement before the dataplane publishes the new policy snapshot.
	// Runtime policy ids are positional, so the new snapshot renumbers them; the
	// invalidation's target set is derived from the OLD numbering and the live
	// rows stop carrying that numbering the moment ApplyConfig returns (new
	// admissions use the new ids, and the helper's #3395 refresh re-stamps
	// established rows to them). Reading the table after the apply therefore
	// sweeps sessions of the policy that INHERITED a deleted policy's id and
	// misses the deleted policy's own. Placement is the design: this is a READ,
	// so it cannot re-admit anything, and moving it any later re-opens the
	// window. See daemon_policy_invalidate_capture.go.
	d.capturePolicyInvalidationLocked(cfg)

	// 2. Apply dataplane config through the runtime config sink.
	var applyResult *dataplane.ApplyResult
	if rt := d.dataplane(); rt != nil {
		var err error
		if applyResult, err = rt.ApplyConfig(context.Background(), cfg); err != nil {
			d.recordCompileFailure(err)
			if compileErrorMustAbortApply(err) {
				return commitOverlay, networkdErr, nil, err
			}
			// #5679: an ORDINARY (non-abort-class) full-apply failure does
			// NOT disarm the dataplane — the dataplane ApplyConfig leaves the OLD
			// compiled policy live and forwarding while store.Commit has
			// already promoted+persisted the NEW config. Left unhandled the
			// commit reported SUCCESS against stale enforcement (a tightening
			// commit — e.g. a new deny — appeared applied while the looser old
			// policy was still on the wire), a fail-open-to-stale on the main
			// config-apply path. Capture the failure as a DEFERRED commit error
			// (threaded into the tail Join, fail-closed but complete like
			// networkdErr / ifaceErr) so the operator sees the commit fail; the
			// applied config never advanced, so an identical re-commit / the
			// feed onUpdate retry (#5646, via applyConfigResult) re-applies and
			// self-heals a transient helper / control-socket error.
			applyErr = err
		} else {
			d.recordCompileSuccess()
		}
	}
	policySchedulerActiveState = d.reconcilePolicySchedulerLockedAt(cfg, policySchedulerApplyTime)
	d.publishInitialPolicySchedulerStateLocked(cfg, policySchedulerActiveState, applyResult)

	// Clear defer flag after ApplyConfig so subsequent applies (where MAC
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
	if ss := d.getSessionSync(); ss != nil && applyResult != nil {
		ss.SetZoneRGMap(buildZoneRGMap(cfg, applyResult.ZoneIDs))
	}

	// 2.45. #1956 V-4: managed->unmapped teardown MUST run BEFORE
	// networkd.Apply so its stale-file sweep has nothing to half-clean.
	// No-op idempotent when nothing transitioned (zero churn on an
	// unrelated commit).
	//
	// A genuine teardown failure (rename-back EBUSY/collision or networkctl
	// reload failure) is now RETURNED and RETAINS the durable .link/.network
	// markers (#5309). It is captured into networkdErr (the interface-management
	// error already threaded into the tail commit join) so the commit fails
	// CLOSED instead of reporting success while the wrong live interface name
	// persists and the retry debt is destroyed. errors.Join preserves any error
	// the later networkd.Apply also records.
	if cfg.Chassis.DeviceMap.Active() {
		if err := teardownUnmappedManaged(cfg.Chassis.DeviceMap, protectedForConfig(cfg)); err != nil {
			slog.Warn("device-map teardown failed; retaining durable state, failing commit closed",
				"err", err)
			networkdErr = errors.Join(networkdErr, err)
		}
	}

	// 2.5. Write systemd-networkd config for managed interfaces.
	//
	// An empty ManagedInterfaces set is NOT a no-op (#2988): when the last
	// xpf-managed interface is removed, networkd.Apply must still run so its
	// stale `10-xpf-*` sweep cleans the now-orphaned .network/.link/.netdev
	// snippets (otherwise the next reload resurrects stale addresses/bonds/
	// renames). The previous `len(...) > 0` guard shadowed the sweep, leaving
	// the library fix dead on the live reconcile path. The lifeline is still
	// protected end-to-end: SetProtectedResolver (daemon_run.go) feeds
	// resolveProtectedInterfaces, which derives the mgmt set from
	// ActiveConfig independently of ManagedInterfaces, so the empty-set sweep
	// preserves the management NIC's files. The `applyResult != nil` guard
	// stays — a nil result (no dataplane) means there is nothing to reconcile
	// and the daemon's own startup/Clear paths own the files.
	//
	// A write failure is captured (not swallowed, #2987) and returned at the
	// tail of applyConfigLocked so the commit reports failure (fail-closed),
	// mirroring dhcpServerErr: every downstream reconcile step still runs so a
	// networkd write error does not skip RETH MAC programming, VRRP VIP
	// reconcile, FRR, RA, IPsec, etc. and leave HA state half-applied.
	if d.networkd != nil && applyResult != nil {
		if err := d.networkd.Apply(applyResult.ManagedInterfaces); err != nil {
			slog.Warn("failed to apply networkd config", "err", err)
			// errors.Join (not assignment) so a device-map teardown failure
			// recorded just above (#5309) is not clobbered — both fail-closed.
			networkdErr = errors.Join(networkdErr, fmt.Errorf("apply networkd config: %w", err))
		}
	}

	// 2.6. Program deterministic virtual MACs on RETH member interfaces.
	// Each node gets a per-node MAC (02:bf:72:CC:RR:NN) to avoid FDB conflicts
	// when both nodes' members are on the same L2 domain. VRRP + gratuitous NA
	// handle failover; RA goodbye packets handle IPv6 default gateway transitions.
	// Must run AFTER networkd.Apply() so .link renames are applied first.
	needLinkCycleRecovery := false
	// #7007: set when an aborted member's in-loop rollback rebound WITHOUT
	// releasing the apply's lease. It is what makes the end-of-apply release
	// below unconditional in effect — 2.6b2 is gated on needLinkCycleRecovery,
	// so an apply where every member ABORTS (nothing cycled) reaches no
	// NotifyLinkCycle at all and would otherwise strand the lease to the
	// deferred abandon, turning that backstop's ERROR into routine noise for
	// exactly the reason the issue rejects a refcount.
	rethRollbackKeptLease := false
	if d.cluster != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		rethToPhys := cfg.RethToPhysical()

		// #5103: the AF_XDP worker join is handed to programRethMAC as a
		// beforeCycle hook rather than run after it returns. Whether a cycle
		// is needed is only knowable by attempting the live MAC set, so the
		// hook is the only place that both KNOWS a cycle is coming and still
		// runs before the link is touched. On the cluster's own NICs (mlx5,
		// virtio) the kernel almost always accepts the live set, so the hook
		// does not fire and the workers keep running — the cost is paid only
		// when it is refused. #6871: "almost always", not "always", and not
		// keyed on IFF_LIVE_ADDR_CHANGE — dev_set_mac_address also refuses a
		// live set on a BUSY device, so these same VFs can take the fallback
		// transiently. programRethMACWithWorkerJoin owns the hook and the
		// rollback of a prepare whose cycle then aborted.

		for rethName, physName := range rethToPhys {
			rethCfg, ok := cfg.Interfaces.Interfaces[rethName]
			if !ok || rethCfg == nil || rethCfg.RedundancyGroup <= 0 {
				continue
			}
			linuxName := config.LinuxIfName(physName)
			// If the interface doesn't exist under its config name,
			// find it by RETH virtual MAC and rename it.
			if _, err := netlink.LinkByName(linuxName); err != nil {
				mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
				// #6911: renameRethMember cycles the link too, so it gets the
				// same worker join programRethMAC has had since #5103. The
				// lease PrepareLinkCycle takes is released by the
				// abandonLinkCycleLease deferred over this whole apply, so the
				// rebind is owned exactly as it is for the MAC-programming
				// cycle — this hook adds a join, not a new lifecycle.
				renameJoin := func() error {
					rt := d.dataplane()
					if rt == nil {
						return nil
					}
					slog.Info("userspace: stopping workers before RETH member rename",
						"iface", linuxName)
					return rt.Link().PrepareLinkCycle()
				}
				if oldName := renameRethMember(linuxName, mac, renameJoin); oldName != "" {
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
			setRethIPv6Knobs(linuxName)
			mac := cluster.RethMAC(cc.ClusterID, rethCfg.RedundancyGroup, cc.NodeID)
			networkdErr, needLinkCycleRecovery, rethRollbackKeptLease =
				d.programRethMemberMAC(linuxName, mac, networkdErr,
					needLinkCycleRecovery, rethRollbackKeptLease)
			if err := d.finishRethMemberLinkTail(linuxName, mac, rethCfg); err != nil {
				networkdErr = errors.Join(networkdErr, err)
			}
		}
	}

	// 2.6b. Reconcile VRRP VIPs and stable link-locals after RETH MAC
	// programming. Only needed when programRethMAC had to bring the
	// interface DOWN/UP (link cycle), which removes all addresses
	// including VRRP VIPs and stable link-locals.
	d.reconcileAfterRethLinkCycle(cfg, needLinkCycleRecovery)

	// 2.6b2. Rebind AF_XDP sockets after RETH MAC programming.
	// Only needed when PrepareLinkCycle was called (macChangeNeeded=true
	// or rethMACPending=true). Calling NotifyLinkCycle without a prior
	// PrepareLinkCycle causes a spurious rebind that gets EBUSY on mlx5
	// zero-copy queues because the first bind is still in progress.
	if rt := d.dataplane(); rt != nil && needLinkCycleRecovery {
		// Actual link DOWN/UP occurred — old XSK sockets are dead.
		// Rebind to create fresh sockets on the reinitialized queues.
		//
		// #6871: fold a failed rebind into the commit. Every member that cycled
		// had its workers joined by PrepareLinkCycle and its ctrl disabled; this
		// is the only call that undoes that. A rebind that does not land leaves
		// the node forwarding nothing, and reporting the commit successful over
		// it is a silent total outage. Same errRethPrepareLinkCycle class as a
		// failed join — the observable state is identical.
		if err := rt.Link().NotifyLinkCycle(); err != nil {
			slog.Error("failed to rebind AF_XDP sockets after the RETH MAC link cycle; "+
				"workers stay stopped", "err", err)
			networkdErr = errors.Join(networkdErr,
				fmt.Errorf("%w: %w", errRethPrepareLinkCycle, err))
		}
		if d.ra != nil {
			d.ra.ResendBurst()
		}
		// #7007: 2.6b2's NotifyLinkCycle above is the RELEASING repair, and it
		// is the last one of the apply, so any lease an aborted member's
		// rollback kept ends here.
		rethRollbackKeptLease = false
	} else if rt != nil && rethMACPending && !needLinkCycleRecovery {
		// MAC set live (no link cycle) but workers were deferred.
		// Trigger a re-apply to start workers with the now-correct MAC.
		// This is cheaper than NotifyLinkCycle (no stop_workers/rebind).
		d.reapplyAfterDeferredMAC(cfg)
	}

	// #7007: the LAST repair of the apply releases, and this is the arm that
	// makes that true when step 2.6b2 did not run.
	//
	// 2.6b2 is gated on needLinkCycleRecovery, which only a member that actually
	// COMPLETED a cycle arms. An apply where every member ABORTS therefore
	// reaches no NotifyLinkCycle at all, and since #7007 the rollbacks no longer
	// release — so without this the lease would survive to the deferred abandon
	// and make its ERROR ("leaving with a RETH link-cycle lease still held")
	// routine on a path that is not a bug. That is precisely the failure mode
	// the issue rejects a refcount for; it would be no better arrived at this
	// way.
	//
	// AbandonLinkCycle rather than NotifyLinkCycle, deliberately: the rollbacks
	// already rebound, and a second rebind here would cost another NIC-settle
	// second and a second worker recreate on a path where the commit is failing
	// anyway. What is owed is the RELEASE, not another repair.
	//
	// Scoped to rethRollbackKeptLease rather than "release whatever is held", so
	// the deferred abandon keeps its teeth for the case it was written for — the
	// rename-join hook, which takes a lease with no release partner at all and
	// SHOULD still be reported.
	if rethRollbackKeptLease {
		if rt := d.dataplane(); rt != nil {
			rt.Link().AbandonLinkCycle()
		}
	}

	// NOTE: stable link-local cleanup for secondary RGs is handled by
	// the reconcile loop (reconcileRGState) after election settles,
	// not here — we don't know who's primary during config apply.

	// 2.6c. Reconcile proxy ARP/NDP entries for NAT addresses. Factored into
	// reconcileProxyARP so the always-on periodic re-assert loop (#2197 item
	// 2) can re-run the identical reconcile after a non-commit link cycle.
	d.reconcileProxyARP(cfg)

	// 2.7. Re-bind management VRF interfaces after networkd.Apply().
	// networkctl reconfigure strips VRF master bindings because networkd
	// considers the daemon-created vrf-mgmt device "unmanaged" and ignores
	// the VRF= directive. Re-bind here to restore VRF membership. This is the
	// AUTHORITATIVE management-VRF bind (post-networkd): #5700 surfaces its
	// failure into commit truth (joined into networkdErr — mirroring the #1956
	// device-map-teardown joins above) instead of swallowing at WARN, so a
	// genuine bind failure fails the commit closed rather than reporting the
	// management VRF configured while the interface carries no VRF membership.
	// The management interfaces (fxp*/fab*/em*) exist by this phase, so the bind
	// is transient-free (unlike the pre-networkd best-effort bind and the
	// routing-instance tunnel-member binds in applyVRFReconcile).
	// #6805: the routing-instance member re-bind belongs at the SAME point and
	// for the same reason — the devices exist by this phase. Step 0a runs before
	// applyInterfaceReconcile creates tunnel/xfrmi devices, so a list-only
	// routing-instance member was legitimately "not found" there and nothing else
	// bound it: the tunnel manager's case-2 arm only observes, because 0a owns
	// list binds. The result was a tunnel forwarding in the DEFAULT table on a
	// first apply that reported success.
	//
	// Unlike the management re-bind below, this one stays best-effort at WARN and
	// is NOT joined into networkdErr: a routing-instance `interface` list can
	// legitimately name an interface that is genuinely absent on this chassis,
	// and failing the commit on that would reject configs that are correct for
	// the fleet. The management set cannot be absent by this phase, which is
	// exactly why that one is surfaced and this one is not.
	d.rebindRoutingInstanceMembers(cfg)

	if mgmtSet := d.mgmtVRFIfaceSet(); d.routing != nil && len(mgmtSet) > 0 {
		if err := d.rebindManagementVRFIfaces(); err != nil {
			networkdErr = errors.Join(networkdErr, err)
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

	// #2926 boundary C3: before the FRR reload. The dataplane apply and the
	// RETH MAC / VIP / worker-rebind sequence above have completed; FRR still
	// holds the previous render. Bailing here skips the FRR reload and the
	// remaining service reconciles (IPsec, DHCP, RA, VRRP, syslog, exporters);
	// on the next boot the boot-time apply re-renders FRR and re-runs every
	// service step against the active config, so the skip converges. (After
	// store.Commit the store already holds the new config, so this is a clean
	// "apply the rest on next start" boundary, not a divergence.)
	if err := ctx.Err(); err != nil {
		return commitOverlay, networkdErr, nil, err
	}

	return commitOverlay, networkdErr, applyErr, nil
}

// errRethPrepareLinkCycle classifies a programRethMAC failure that the #5103
// AF_XDP worker-join hook had already RUN for. It exists so the caller can fail
// the commit closed on exactly that class: an ordinary netlink MAC-set failure
// has always been warn-only and stays so, because it disturbs nothing but the
// member's MAC. Once the hook has run, the member is not merely on the wrong
// MAC — ctrl is being driven to 0 and the workers may already be joined, so it
// is not forwarding.
//
// #6871 (round 6): the message says the HOOK RAN, not "after the worker join", and the
// difference is exactly why this sentinel keys on joinRan. PrepareLinkCycle can
// fail on the DIAL or the WRITE, before the helper ever reaches its stop_workers
// handler, so on that path the workers were NOT joined — and an earlier revision
// of this string asserted they were. What the daemon CAN know is that the hook
// ran, which is what makes the outcome unknown and the fail-closed escalation
// correct. The runtime behaviour was already right; only the diagnosis was
// overstated.
var errRethPrepareLinkCycle = errors.New("reth mac: link cycle failed after the af_xdp worker-join hook ran")

// programRethMemberMAC programs ONE RETH member's virtual MAC through the
// #5103 worker-join wrapper and folds that member's outcome into the two
// accumulators step 2.6 carries across its loop: the commit error (networkdErr,
// the tail-commit channel the device-map teardown (#5309) and the management-VRF
// rebind (#5700) also use) and needLinkCycleRecovery (step 2.6b2's rebind gate).
// It returns both, updated.
//
// Only the class where the worker-join HOOK RAN produces a commit error; an
// ordinary MAC-set failure stays warn-only, as it always has. (#6871: an earlier
// revision said "the failed-worker-join class", which was narrower than the code
// — programRethMACWithWorkerJoin also classifies a post-join setDown, cycled
// MAC-write or link-UP failure as commit-fatal, and deliberately so: the hook has
// already stopped the workers by then. The gate is "the hook ran", and this
// sentence now says the same thing the wrapper does.) errors.Join, not assignment: an
// error already accumulated by an earlier step or an earlier member must not be
// clobbered by this one. The recovery gate is ORed, not assigned: a member that
// needs no cycle must not clear a gate an earlier member armed.
//
// This is a function rather than three inline statements so the fail-closed
// plumbing is BEHAVIOURALLY testable (reth_commit_fold_5103_test.go). Inline it
// was reachable only through applyDataplaneAndHACore, which needs a live cluster
// manager, a wired dataplane, a networkd writer and real netlink members, so the
// only available guard was a structural canary over the AST — and a structural
// canary is satisfied by an assignment that is unreachable, shadowed, or jumped
// over. Here the fold runs against the same fake link seam and fake dataplane the
// wrapper's own tests use.
// #7007 adds the `leaseKept` accumulator alongside `needLinkCycleRecovery`.
// Both are accumulators rather than per-member facts: they are ORed across the
// loop.
//
// Widened in place rather than wrapped, for the same reason as
// programRethMACWithWorkerJoin above: TestDaemonPassesRethBeforeCycleHook_5103
// requires EXACTLY ONE call site of this function in the package, and routing
// the loop through a differently named inner function left this one with zero —
// which reddened that gate correctly, since "reached from nowhere else" is the
// property it pins.
func (d *Daemon) programRethMemberMAC(ifName string, mac net.HardwareAddr,
	commitErr error, needLinkCycleRecovery bool, leaseKept bool) (error, bool, bool) {
	memberKeptLease := false
	linkCycled, prepareErr := d.programRethMACWithWorkerJoin(ifName, mac, &memberKeptLease)
	if prepareErr != nil {
		commitErr = errors.Join(commitErr, prepareErr)
	}
	// #6871 (round 6): renew the link-cycle lease on EVERY member's turn,
	// whether or not this one cycled.
	//
	// Without it the lease's TTL would have to cover the whole of step 2.6's
	// loop, and no constant does. Only a member that actually cycles re-arms the
	// lease (PrepareLinkCycle takes it), so the exposure is the tail of members
	// visited AFTER the last cycling one — while `reth-count` is
	// operator-settable to 128 (pkg/config/schema_chassis.go) and the dominant
	// per-member cost, the `ethtool -K rxvlan off` finishRethMemberLinkTail runs
	// right after this call, has a 20s hard ceiling (externalCommandTimeout + the
	// 5s WaitDelay, exec_timeout.go). Four wedging members in that tail already
	// exceed a 60s TTL. Worse, rethToPhys is a Go MAP, so that tail is a
	// different set on every run: the same config would pass or fail at random,
	// which is the failure shape hardest to reproduce and the one a bigger
	// constant hides rather than fixes.
	//
	// This renewal covers the MAC SET, and only that. It is deliberately NOT the
	// only one, and an earlier revision of this comment claimed otherwise —
	// "renewing here makes the TTL bound the interval between two consecutive
	// members" was false, because this call lands BEFORE that member's ethtool
	// and child-netdev work, so the interval between two consecutive renewals
	// spanned member N's whole tail plus member N+1's MAC set. #6871 round 7
	// added the other two renewal points that make the per-interval claim true:
	// finishRethMemberLinkTail (after the ethtool + child loop) and
	// reconcileAfterRethLinkCycle (after the VIP/link-local reconcile, the span
	// that used to run all the way into NotifyLinkCycle unrenewed). What each
	// interval does and does not bound is stated at linkCycleLeaseTTL
	// (pkg/dataplane/userspace/process_linkcycle.go) rather than restated here.
	//
	// It cannot CREATE a lease: RenewLinkCycle refuses unless one is already
	// live. So the overwhelmingly common apply — every member's MAC set live, no
	// cycle anywhere — is completely unaffected, and this cannot become a way to
	// suppress the 1 Hz reconcile with nothing obliged to release it.
	d.renewLinkCycleLease()
	return commitErr, needLinkCycleRecovery || linkCycled, leaseKept || memberKeptLease
}

// renewLinkCycleLease extends a link-cycle lease that is already held. It is the
// single place step 2.6 touches the lease, so every renewal point below reads
// identically and a new one cannot silently skip the nil guard.
//
// It cannot CREATE a lease (Manager.RenewLinkCycle refuses unless one is live),
// so calling it on an apply that cycled nothing — the overwhelming majority — is
// a no-op, and it can never become a way to suppress the 1 Hz reconcile with
// nothing obliged to release it.
func (d *Daemon) renewLinkCycleLease() {
	rt := d.dataplane()
	if rt == nil {
		return
	}
	rt.Link().RenewLinkCycle()
}

// abandonLinkCycleLease drops a link-cycle lease the apply is leaving behind. It
// is deferred over the whole of applyDataplaneAndHACore, so it is the one
// release that no control-flow arrangement can skip (#6871 round 8).
//
// A true return is a BUG REPORT, not a routine outcome: every path that takes a
// lease reaches NotifyLinkCycle (the cycle completes and step 2.6b2 rebinds, or
// it aborts and programRethMACWithWorkerJoin rolls back with the same call), so
// reaching here with one still held means a path was added that does neither.
// Log it at Error with what it implies about the dataplane, because dropping the
// lease resumes the 1 Hz reconcile but does NOT rebind — the reconcile has to
// re-arm the workers itself, which is exactly master's pre-#6871 behaviour.
func (d *Daemon) abandonLinkCycleLease() {
	rt := d.dataplane()
	if rt == nil {
		return
	}
	if rt.Link().AbandonLinkCycle() {
		slog.Error("userspace: the config apply is leaving with a RETH link-cycle lease " +
			"still held; dropping it so the reconcile loop resumes. The AF_XDP workers " +
			"may still be joined and ctrl disabled — the 1 Hz reconcile is now what has " +
			"to re-arm them. Some path between PrepareLinkCycle and NotifyLinkCycle " +
			"returned or panicked without completing the cycle")
	}
}

// finishRethMemberLinkTail runs the per-member work that follows the MAC set:
// DAD/link-local repair, the ethtool VLAN-RX-offload re-disable, and the MAC
// propagation to this member's VLAN sub-interfaces. It renews the link-cycle
// lease when it is done.
//
// #6871 (round 7): this is an EXTRACTION whose purpose is that renewal, and the
// reason it is a function rather than an inline call is the same reason
// programRethMemberMAC is one — inline, the only reachable guard would have been
// a structural canary over the AST, and a structural canary is satisfied by a
// statement that is unreachable, shadowed, or jumped over.
//
// Why the tail needs its own renewal. programRethMemberMAC renews at the end of
// the MAC set, which is BEFORE any of this: the `ethtool -K rxvlan off` below has
// a 20s hard ceiling (externalCommandTimeout 15s plus the 5s WaitDelay in
// exec_timeout.go), and the child-netdev loop is cardinality-dependent — one
// netlink round trip per VLAN sub-interface of this member, with no bound on how
// many an operator configures. Renewing only at the MAC set therefore left every
// member's tail, plus the next member's whole MAC set, inside ONE TTL window.
// Renewing here splits that in two, so each window holds at most one 20s-ceiling
// command. See linkCycleLeaseTTL (pkg/dataplane/userspace/process_linkcycle.go)
// for what that does and does not let the TTL claim.
//
// The renewal is unconditional on this member's outcome, exactly as
// programRethMemberMAC's is: a member that needed no cycle still spends the
// ethtool ceiling, and the lease it is burning down may have been taken by an
// EARLIER member.
// The returned error joins networkdErr, the "fail-closed but complete"
// accumulator this file already uses (see applyDataplaneAndHACore's header):
// the tail keeps going and the operator still sees the commit fail.
//
// #6980: it used to return nothing, and the VLAN propagation loop below read
// `links, _ := netlink.LinkList()`. On a LinkList failure `links` is nil, the
// loop body never runs, the RETH virtual MAC never reaches any VLAN
// sub-interface -- and there was no log line and no commit error. The apply
// reported success.
//
// On the reference topology the VLAN units are what carry traffic (reth0.50
// transit, reth0.80 the data path), so the silent skip leaves them on the STALE
// MAC while the parent RETH has the new one: peers ARP to an address the box no
// longer answers on, until the entry ages out. A blackhole whose only symptom
// is a successful commit.
//
// Warning alone would not be enough. The per-sub-interface failures below are
// genuinely best-effort and warn, but those are ONE child each; a LinkList
// failure skips EVERY child, so it is a different-sized event and belongs in
// the channel that fails the commit.
func (d *Daemon) finishRethMemberLinkTail(linuxName string, mac net.HardwareAddr, rethCfg *config.InterfaceConfig) error {
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
	if out, err := runCommandTimeout("ethtool", "-K", linuxName, "rxvlan", "off"); err != nil {
		slog.Warn("failed to re-disable rxvlan after RETH MAC",
			"interface", linuxName, "err", err, "output", strings.TrimSpace(string(out)))
	} else {
		slog.Info("re-disabled VLAN RX offload after RETH MAC", "interface", linuxName)
	}

	// Propagate MAC change to VLAN sub-interfaces.
	// Linux VLAN sub-interfaces don't always inherit the
	// parent's MAC change after link down/up.
	if parentLink, err := rethParentLinkByName(linuxName); err == nil {
		parentIdx := parentLink.Attrs().Index
		links, err := rethLinkLister()
		if err != nil {
			slog.Error("failed to enumerate links for RETH VLAN MAC propagation; "+
				"every VLAN sub-interface keeps its STALE MAC while the parent has the new one, "+
				"so peers ARP to an address this node no longer answers on until the entry ages out",
				"parent", linuxName, "mac", mac, "err", err)
			return fmt.Errorf("enumerate links to propagate RETH MAC from %s: %w", linuxName, err)
		}
		for _, l := range links {
			if l.Attrs().ParentIndex != parentIdx {
				continue
			}
			subName := l.Attrs().Name
			// Suppress auto link-local on VLAN sub-interfaces too.
			setVLANSubAddrGenMode(subName)
			if !bytes.Equal(l.Attrs().HardwareAddr, mac) {
				if err := netlink.LinkSetHardwareAddr(l, mac); err != nil {
					slog.Warn("failed to propagate MAC to VLAN sub-interface",
						"iface", subName, "err", err)
				} else {
					slog.Info("propagated RETH MAC to VLAN sub-interface",
						"iface", subName, "mac", mac)
				}
			}
			// Strip any stale auto link-local, then re-add a stable one
			// if this VLAN sub-interface carries IPv6. The kernel suffix
			// is the unit's vlan-id (e.g. "ge-7-0-1.180"), which may
			// differ from the logical unit number rethCfg.Units is keyed
			// by (`unit 80 vlan-id 180`); the repair resolves the vlan-id
			// back to its unit(s) before checking for IPv6 — indexing
			// Units[vid] directly silently skipped the repair (#5107).
			// The whole decision+action lives in rethSubIfaceLinkLocalRepair
			// (spy-tested); this loop only enumerates the child netdevs.
			rethSubIfaceLinkLocalRepair(rethCfg, subName)
		}
	}
	d.renewLinkCycleLease()
	return nil
}

// reconcileAfterRethLinkCycle re-adds the VRRP VIPs and stable link-locals that
// a RETH MAC link cycle removed (the DOWN/UP drops every kernel address on the
// member), then renews the link-cycle lease.
//
// #6871 (round 7): this renewal covers the LAST unrenewed span, and it was the
// worst one. The final member's tail is followed by this reconcile — netlink,
// once per redundancy group — and then by step 2.6b2's NotifyLinkCycle, which is
// what RELEASES the lease. Before this renewal existed, everything from the last
// member's MAC set through this reconcile and into NotifyLinkCycle's own 1s NIC
// settle had to fit in one TTL, with no renewal anywhere in it. After it, the
// span from here to the release contains only that 1s sleep and one control
// round trip.
//
// Renewing unconditionally is safe: RenewLinkCycle cannot create a lease, so an
// apply that cycled nothing is unaffected.
//
// It is not, however, load-bearing, and an earlier revision claimed it was
// (#6871 round 15). That revision said gating on needLinkCycleRecovery "would
// skip exactly the abort path — where the cycle DID take a lease and then
// returned linkCycled=false". The abort path has no lease left to renew by the
// time this runs: programRethMACWithWorkerJoin's rollback calls NotifyLinkCycle,
// whose FIRST act is releaseLinkCycleLease, and that happens inside the
// per-member loop above — so the word is already 0 here and RenewLinkCycle
// refuses to renew from the 0 sentinel. Whenever a lease IS still held at this
// line, needLinkCycleRecovery is true (the only way to take one and return
// linkCycled=false is to fail after the join, which routes through that same
// rollback), so the gate the ungating was defending against would have been
// equivalent. Ungated is still the right shape — it does not depend on an
// accumulator staying in sync with the lease — but the reason is "no gate is
// needed", not "the gate would lose the abort path".
func (d *Daemon) reconcileAfterRethLinkCycle(cfg *config.Config, needLinkCycleRecovery bool) {
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
	d.renewLinkCycleLease()
}

// programRethMACWithWorkerJoin programs a RETH member's virtual MAC with the
// #5103 worker-join hook, and unwinds that join when the rest of the cycle then
// failed. It returns whether the link was cycled and a COMMIT error, non-nil
// only for the class where the hook had already run.
//
// The hook runs only when a cycle is actually required — programRethMAC calls it
// after the live MAC set has been rejected and before setDown, the first
// mutation. The ordinary paths (the live set succeeds, or the member lookup
// fails) never reach it and stay warn-only exactly as they always have. Aborting
// AT the hook leaves the LINK exactly as it was found and the member on its
// previous MAC, which the next apply retries.
//
// The DATAPLANE is not left as it was found, and that is true from the moment
// the hook RUNS, not from the moment it fails. PrepareLinkCycle disables ctrl
// (and attempts to clear the binding rows if that disable could not be verified
// — #6871: clearAllBindingRowsLocked is best-effort, it discards each map Update
// error and no-ops entirely when the bindings map is not loaded, so "cleared" is
// the intent, not a guarantee; the guarantee is that ctrl is being driven to 0)
// before it can fail on stop_workers, so a failed join leaves "the outcome is unknown" —
// but a SUCCEEDED join leaves the workers deliberately stopped, which is the
// same forwarding state. After it returns nil, setDown and the cycled
// setHardwareAddr are both still fallible. So the gate is "did the hook RUN",
// not "did the hook FAIL": keying on the hook's own error let those two escape
// with a nil commit error and no rebind, i.e. a half-applied prepare under a
// green commit.
//
// #6915: only the setDown failure still yields linkCycled=false. A failed CYCLED
// MAC write now reports true — setDown has already succeeded by then, so the
// link really did cycle — and is re-armed by step 2.6b2 rather than by the
// rollback here. Both still fail the commit; the "did the hook RUN" gate is
// unchanged, and the sentence above must not be read as a claim about the value
// both paths return.
//
// A half-applied prepare has no other owner:
//
//   - the post-cycle rebind (step 2.6b2) is gated on linkCycled, which every
//     aborted cycle makes false; and
//   - reapplyAfterDeferredMAC is gated on rethMACPending, which is computed
//     BEFORE networkd.Apply — so it is false for an apply whose only member
//     needing a MAC was renamed into its config name by that same networkd.Apply.
//     (rethMACPending is one bool for the whole apply, not per member: a
//     multi-RETH apply where a DIFFERENT member was already present with the
//     wrong MAC does set it, and that apply does re-apply.)
//
// Before #5103 that triple self-healed for the wrong reason: the cycle ran
// whether or not the workers had been joined, so linkCycled was true and
// NotifyLinkCycle rebound the sockets. Aborting the cycle is the correct
// behaviour, but it must keep the recovery. "rebind" is the documented inverse of
// "stop_workers" (userspace-dp/src/server/handlers/stop_workers.rs: "The
// subsequent rebind request ... recreates workers with fresh sockets"), and
// NotifyLinkCycle is what sends it — so the rollback is that same call, driven by
// the abort instead of by a cycle that never happened. Its 1s NIC-settle sleep is
// paid only here.
//
// A cycle that COMPLETED and then failed only on link-up (linkCycled=true) is the
// one member of the class that fails the commit WITHOUT rolling back here: step
// 2.6b2 already rebinds off linkCycled, so firing NotifyLinkCycle too would be
// the double rebind that call site's own comment warns gets EBUSY on mlx5
// zero-copy queues.
//
// Reachability is narrower than the common case but NOT confined to exotic
// drivers, and an earlier revision of this note said it was. Entering the class
// takes any refused live MAC set plus a control-socket or netlink failure in the
// same window. The first term is not "a driver without IFF_LIVE_ADDR_CHANGE":
// programRethMAC falls back on EVERY error from setHardwareAddr, and
// dev_set_mac_address fails the same way for a busy or absent device or a
// notifier rejection — so a transient refusal on the cluster's own mlx5 VFs
// enters this abort/rollback class too. What stays true is the direction:
// fail-CLOSED throughout, ctrl is off, so transit is dropped, never passed.
// #7007 adds the `leaseKept` out-parameter: when the abort path below rebinds
// WITHOUT releasing, it sets *leaseKept so the caller knows the apply still owns
// a lease no NotifyLinkCycle will end. Nil is accepted, which is what the
// single-member tests pass.
//
// A PARAMETER rather than a renamed wrapper, deliberately.
// TestLinkCycleLeaseHasExactlyOneAcquisitionSite_6871 keys its allowlist on
// `file:receiver.FuncName: expr [form]`, so splitting this into a differently
// named inner function moved the sole production PrepareLinkCycle site and
// reddened that gate — correctly, since a moved acquisition site is exactly what
// it is built to notice. Adding a parameter leaves the key, and therefore the
// gate's containment proof, untouched.
func (d *Daemon) programRethMACWithWorkerJoin(ifName string, mac net.HardwareAddr, leaseKept *bool) (linkCycled bool, commitErr error) {
	// joinRan, not joinFailed: set AFTER the nil-dataplane guard, so it means
	// exactly "the hook ran, and the dataplane may be half torn down". A nil
	// dataplane leaves it false, which keeps the joined.Link() deref below
	// unreachable.
	//
	// #6743: the dataplane is read through d.dataplane() (the atomic cell), not
	// a plain field, so a bootstrap-exit publish can swap or clear it between
	// the join and the rollback below. joined pins the EXACT instance whose
	// workers this hook stopped, so the rollback rebinds the dataplane it
	// actually tore down rather than whichever one is published later.
	joinRan := false
	var joined dataplane.RuntimeDataPlane
	beforeCycle := func() error {
		rt := d.dataplane()
		if rt == nil {
			return nil
		}
		joined = rt
		joinRan = true
		slog.Info("userspace: stopping workers before RETH MAC link cycle", "iface", ifName)
		return rt.Link().PrepareLinkCycle()
	}
	linkCycled, err := programRethMAC(ifName, mac, beforeCycle)
	if err != nil {
		slog.Warn("failed to set RETH MAC", "iface", ifName, "mac", mac, "err", err)
	}
	if err == nil || !joinRan {
		return linkCycled, nil
	}
	if linkCycled {
		// The link went DOWN and back UP. Since #6915 that is TWO outcomes, not
		// one, and they differ in whether anything repairs the member:
		//
		//   - link-up failed: the MAC write SUCCEEDED, so every later apply
		//     early-returns on bytes.Equal(current, mac) and never attempts
		//     setUp again, and the only other nlLinkSetUp on a RETH member runs
		//     at daemon start. The member stays administratively down until a
		//     restart while step 2.6b2 rebinds AF_XDP sockets onto it.
		//   - the CYCLED MAC write failed: the member is back UP (programRethMAC
		//     does a best-effort setUp on that path) and still carries its old
		//     MAC, so the next apply does NOT early-return and retries the whole
		//     sequence. Recoverable, unlike the row above — do not read the
		//     "NOTHING repairs it" sentence as covering both.
		//
		// Both fail the commit, and both reach here rather than the rollback
		// below for the same reason: the cycle happened, so step 2.6b2 owns the
		// rebind and step 2.6b owns re-adding the addresses the DOWN flushed.
		//
		// Leave the rebind to step 2.6b2, which owns it for every cycled
		// member. Note that suppression is per-MEMBER while 2.6b2's gate
		// (needLinkCycleRecovery) is a per-APPLY accumulator, so an apply that
		// mixes a cycled member with an aborted one pays BOTH the aborted
		// member's rollback rebind and 2.6b2's.
		//
		// Which of those two arms the 500ms zero-copy quiesce depends on the
		// order the members are visited in, and that order is a Go map range
		// (rethToPhys, step 2.6) — so state both. tear_down samples
		// had_live_workers = !coord.workers.records.is_empty()
		// (coordinator/reconcile/teardown.rs), and a stop_workers that REACHES
		// ITS HANDLER empties records (handlers/stop_workers.rs -> afxdp.stop()
		// -> stop_inner -> WorkerManager::stop_and_clear, which joins each
		// worker thread and then records.clear()s).
		//
		// "REACHES ITS HANDLER" is load-bearing and an earlier revision of this
		// comment said "every stop_workers" without it (#6871 F3). The prepare
		// can fail on the DIAL or the WRITE, before the helper ever runs the
		// handler — which is precisely the failure class this whole block
		// exists for. In that case records are NOT cleared and stay live, so
		// the had_live_workers sample below is true rather than false and the
		// quiesce is PAID rather than skipped. The two orders below therefore
		// describe the handler-ran case; a pre-handler failure costs an extra
		// 500ms and nothing else. Behaviour is unaffected either way — the
		// rebind is correct with live records or without them — but the
		// sentence was not universally true as written. So:
		//
		//   - aborted member FIRST: its rollback rebind sees an empty records
		//     (its own stop_workers just cleared it) and skips the quiesce, then
		//     recreates the workers. The cycled member's stop_workers then joins
		//     and clears them AGAIN, so 2.6b2's rebind ALSO sees false and ALSO
		//     skips it.
		//   - cycled member FIRST: its stop_workers clears records and nothing
		//     recreates them before the aborted member's own stop_workers, so
		//     the rollback rebind skips the quiesce and recreates the workers —
		//     and 2.6b2's rebind, with nothing clearing them in between, sees
		//     had_live_workers TRUE and DOES arm it.
		//
		// Both are safe, and not because of the quiesce: the quiesce (#1921)
		// covers a rebind that rebuilds the same queue set IMMEDIATELY after a
		// teardown it did not itself wait on. Here every rebind is preceded by a
		// stop_workers that JOINED the worker threads synchronously before
		// returning, and NotifyLinkCycle pays an unconditional 1s NIC settle
		// (pkg/dataplane/userspace/process_linkcycle.go) before it sends the
		// rebind at all — twice the 500ms it may skip.
		return linkCycled, fmt.Errorf("%w: %w", errRethPrepareLinkCycle, err)
	}
	slog.Warn("userspace: RETH MAC link cycle did not complete after the worker join; "+
		"rebinding AF_XDP sockets so the prepare is not left half-applied",
		"iface", ifName, "err", err)
	// THE ADDRESS GAP IS CLOSED (#6915). This block used to record a deliberate
	// carve-out: the "join OK, setDown OK, cycled MAC write refused" member had
	// already taken the link DOWN and back UP by the time it arrived here, the
	// kernel flushes an interface's addresses on the way down, and it
	// nonetheless returned linkCycled=false — so it contributed nothing to
	// needLinkCycleRecovery and step 2.6b's VIP reconcile was skipped for a
	// cycle that genuinely happened. The member came back holding the VRRP role
	// with none of the addresses that role answers for, and nothing re-added
	// them: ReconcileVIPs has exactly ONE production caller (that gated one),
	// the 2s reconcileRGState tick re-adds only the stable link-local in VRRP
	// mode, and sendAdvert swallows its send error at Debug so VRRP never
	// observes the flap and stays MASTER.
	//
	// programRethMAC now returns linkCycled=true on that path, because the value
	// reports whether the link CYCLED and not whether the MAC write succeeded —
	// which is what the link-up-failure row beside it has always meant. That
	// member therefore leaves through the arm ABOVE, not this one: it arms step
	// 2.6b (the VIP re-add) and step 2.6b2 (the rebind), and does NOT fire the
	// local rollback, since doing both would be the double rebind this file
	// warns gets EBUSY on mlx5 zero-copy queues.
	//
	// What still reaches HERE is the class where no cycle happened at all — the
	// join failed, or setDown itself failed. Those flushed nothing, so there are
	// no addresses to reconcile and no sockets a cycle tore down; the rollback
	// below is the only owner of their rebind.

	// NotifyLinkCycle opens with a 1s NIC-settle sleep before it takes the
	// manager lock, and this call site is INSIDE the per-member RETH loop —
	// step 2.6b2 pays that second at most once, outside it. Worst case here is
	// N extra seconds of d.applySem hold when every member aborts (N = RETH
	// count; 2 on the loss cluster). Bounded, and only on a path where this
	// node's forwarding is already down — but do not widen this loop, or move
	// another sleeping call into it, without re-checking that budget.
	//
	// #6871: the rollback's own failure is now visible. NotifyLinkCycle was void
	// and swallowed a failed rebind into a slog.Warn, so "this path owns its own
	// rollback" was a claim the mechanism could not keep — an abort whose recovery
	// ALSO failed produced exactly the same (false) evidence as one that recovered.
	// The commit already fails on this branch either way; the rollback error is
	// JOINED onto the abort cause rather than replacing it, because the abort is
	// the more actionable of the two and must not be lost.
	//
	// #7007: KeepingLease. This rollback is INSIDE the per-member loop, and the
	// lease it would otherwise end is the APPLY's, not this member's — a sibling
	// that already cycled is still depending on it, and every renewal after this
	// point would become a no-op against a zeroed word. The rebind still has to
	// happen (this member's workers are joined and its ctrl is off); what moves
	// is the release, to the apply-wide site outside the loop. See
	// `Manager.NotifyLinkCycleKeepingLease` for why this is not a refcount.
	if leaseKept != nil {
		*leaseKept = true
	}
	if rebindErr := joined.Link().NotifyLinkCycleKeepingLease(); rebindErr != nil {
		slog.Error("userspace: the RETH MAC rollback rebind ALSO failed; this node's "+
			"AF_XDP workers are stopped with nothing left to re-arm them",
			"iface", ifName, "err", rebindErr)
		return linkCycled, fmt.Errorf("%w: %w", errRethPrepareLinkCycle,
			errors.Join(err, rebindErr))
	}
	return linkCycled, fmt.Errorf("%w: %w", errRethPrepareLinkCycle, err)
}

func (d *Daemon) setDataplaneDeferWorkers(deferWorkers bool) {
	rt := d.dataplane()
	if rt == nil {
		return
	}
	type deferSetter interface{ SetDeferWorkers(bool) }
	if setter, ok := rt.(deferSetter); ok {
		setter.SetDeferWorkers(deferWorkers)
		return
	}
	rt.Link().SetDeferWorkers(deferWorkers)
}

// reapplyAfterDeferredMAC runs the MANDATORY dataplane re-apply that arms the
// deferred AF_XDP workers after a live RETH virtual-MAC change with no link
// cycle (#5134). The first apply of this commit published a workerless
// DeferWorkers=true snapshot (worker startup was deferred so the double-bind
// does not EBUSY on mlx5 zero-copy queues); this re-apply — now with the
// correct MAC and DeferWorkers cleared — is what actually starts the workers.
//
// If the re-apply fails, the error MUST NOT be swallowed into a successful
// commit: the userspace manager only advances its snapshot bookkeeping on a
// successful publish, so a failed re-apply leaves the workerless snapshot as
// the published/last state and status reconciliation replays it forever —
// workers never bind and forwarding is silently down on this node. Record
// generation debt so the status reconcile loop retries the DeferWorkers=false
// publish until the workers bind, self-healing a transient helper /
// control-socket error.
func (d *Daemon) reapplyAfterDeferredMAC(cfg *config.Config) {
	rt := d.dataplane()
	if rt == nil {
		return
	}
	if _, err := rt.ApplyConfig(context.Background(), cfg); err != nil {
		slog.Warn("failed to re-apply after deferred MAC; recording worker-arm debt for retry",
			"err", err)
		d.recordDataplaneWorkerArmDebt()
	}
}

// recordDataplaneWorkerArmDebt records the #5134 deferred-MAC worker-arm debt on
// the dataplane so status reconciliation retries the DeferWorkers=false publish.
// Mirrors setDataplaneDeferWorkers: assert the recorder directly on the
// dataplane, else reach it through the link controller.
func (d *Daemon) recordDataplaneWorkerArmDebt() {
	rt := d.dataplane()
	if rt == nil {
		return
	}
	type debtRecorder interface{ RecordDeferredWorkerArmDebt() }
	if r, ok := rt.(debtRecorder); ok {
		r.RecordDeferredWorkerArmDebt()
		return
	}
	if r, ok := rt.Link().(debtRecorder); ok {
		r.RecordDeferredWorkerArmDebt()
	}
}

// #6980 seams. Package-level function variables defaulting to netlink, the same
// shape snmpLinkLister already uses, so the LinkList FAILURE path in
// finishRethMemberLinkTail can be exercised without a privileged netdev.
//
// Two seams rather than one: the LinkList call is only reached when LinkByName
// SUCCEEDS, so a test that stubs only the lister never gets there — every
// existing test in this area names an absent interface, which is exactly why
// this path stayed unbound long enough for the discarded error to survive.
var (
	rethParentLinkByName = netlink.LinkByName
	rethLinkLister       = netlink.LinkList
)
