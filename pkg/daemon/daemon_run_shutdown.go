package daemon

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// applyCloseoutDrainTimeout bounds how long runShutdownSequence waits for an
// in-flight, just-cancelled apply to finish its bounded nft/login host-
// authorization closeout (#5643 / M35) before proceeding to teardown. It must be
// comfortably under the systemd unit's TimeoutStopSec (20s) so a wedged apply
// can never stall the whole stop past the drain budget.
const applyCloseoutDrainTimeout = 5 * time.Second

// controlShutdownBounder is implemented by a dataplane runtime that can bound
// its own control-socket round trips once a stop has begun (#8526). The
// userspace runtime does: it holds its manager mutex across a control round
// trip whose reachable deadline is 67s, which is 3.35x this unit's
// TimeoutStopSec=20.
//
// It is an OPTIONAL interface rather than a method on RuntimeDataPlane because
// the bound is a property of the userspace helper's socket transport, not of
// every backend — but that makes the assertion below silent when it stops
// matching, so pkg/daemon asserts the concrete userspace types against this
// interface at compile time in daemon_control_shutdown_8526_test.go.
type controlShutdownBounder interface{ BeginControlShutdown() }

// runShutdownSequence performs the ordered post-run teardown: abort in-flight
// apply, stop the signal context, wait background goroutines, then tear down
// SNMP/flowexport/feeds/RPM/archive/event-engine/ipmon/natpool-alarm/FRR/LLDP,
// clear HA rg_active (non-hitless), withdraw RA, stop VRRP/cluster/session-sync,
// close/teardown the dataplane, and restore step0 tunables. The ordering is
// load-bearing (see the per-step comments). Extracted verbatim from Run() so
// the 1690-LOC lifecycle stays reviewable (#4662 Increment 1). Returns runErr
// unchanged.
func (d *Daemon) runShutdownSequence(wg *sync.WaitGroup, stop func(), runErr error) error {
	// #8621: stop answering ARP for source-NAT pool addresses FIRST. A node on
	// its way down should stop claiming those addresses before the dataplane is
	// torn out from under them — otherwise an upstream keeps a binding pointing
	// at this node and sends it pool return traffic it can no longer forward.
	// Idempotent, and safe when no responder ever started.
	d.stopProxyARPResponders()

	// #2926: explicitly abort any in-flight commit/remediation apply NOW, at the
	// very start of the shutdown sequence and BEFORE the explicit subsystem
	// teardown below (FRR Stop, HA rg_active clear, dp.Teardown). applyCancelCtx
	// callers (commit/sync/confirmed-commit) then bail at their next coarse
	// boundary instead of completing netlink + an FRR reload + a Rust sync while
	// we tear down. applyCancelContext is a child of the signal context, so a
	// signal-driven stop has already cancelled it; this call also covers the
	// interactive CLI-exit path and is idempotent. The teardown itself performs
	// no applyConfigLocked, so nothing legitimate is aborted here.
	// #6788: fence background applies FIRST — before the cancel below, and
	// before the single drain that follows it. The drain is a drain-and-RELEASE,
	// not a barrier: it acquires applySem to wait out an in-flight apply's
	// closeout and hands the semaphore straight back, so without this fence any
	// background applier that wakes afterwards acquires immediately and runs a
	// FULL apply into a half-torn-down daemon. The DHCP lease-change callback is
	// the one that reaches it on a 2s debounce timer, but the feed publication
	// and config-poll appliers take the same path.
	//
	// Cancellation cannot cover it. applyCancelContext aborts an apply that is
	// already RUNNING; the background appliers deliberately bind
	// context.Background() so they always run to completion, and there is
	// nothing to cancel in an apply that has not started. Refusing before it
	// begins is also strictly better than aborting one midway — no half-finished
	// apply is left behind.
	//
	// Ordering is load-bearing: fence, then cancel, then drain. That makes the
	// drain the LAST apply this process performs, which is what the drain has
	// always been documented to be.
	d.fenceBackgroundApplies()

	// #8526: bound the dataplane control socket FIRST, ahead of everything
	// below, because three separate waits in this function can be blocked by a
	// goroutine holding the userspace manager mutex across a control round
	// trip — and that round trip's reachable deadline is 67s against a 20s
	// TimeoutStopSec:
	//
	//   - the applySem drain below (bounded at 5s, but 5s of the budget spent
	//     waiting on a hold that will outlast the budget anyway);
	//   - wg.Wait(), which is unbounded; and
	//   - d.stopPolicySchedulerLoop(), which ends in an unbounded
	//     d.schedulerWg.Wait() joining the goroutine whose updateFn IS
	//     UpdatePolicyScheduleState — the site #8526 was filed against.
	//
	// Cutting an in-flight publish short here is consistent with what the rest
	// of this prologue already does: applies are fenced and cancelled two
	// lines below, so a publish still in flight belongs to an apply this
	// sequence has already decided to abandon. The #5643 host-authorization
	// closeout the drain protects is nft + local credentials, not dataplane
	// control I/O, so it is unaffected.
	if b, ok := d.dataplane().(controlShutdownBounder); ok {
		b.BeginControlShutdown()
	}

	// #6788: stop the DHCP client's address-change notifications BEFORE the
	// drain, so the drain is not racing a callback that is about to be armed.
	// Quiesce is deliberately NOT StopAll: cancelling the clients would run
	// finishClient -> removeAddress and STRIP the DHCP address from every DHCP
	// interface — including a DHCP-managed management NIC (fxp0) — both during
	// this shutdown and across a graceful restart, which is the exact contract
	// pkg/dhcp's client context comment preserves. Quiesce leaves every lease,
	// address and client goroutine untouched and shuts off only the callback.
	if d.dhcp != nil {
		d.dhcp.Quiesce()
	}

	if d.applyCancel != nil {
		d.applyCancel()

		// #5643 (M35): the cancel above makes an in-flight promoted apply bail at
		// its next #2926 boundary, where applyConfigLocked now runs the bounded
		// nft/login host-authorization closeout so the committed (restrictive)
		// config is still enforced even though the apply is abandoned. Drain
		// applySem so that closeout COMPLETES before we tear down / exit —
		// otherwise the process could stop with the OLD, more-permissive host
		// authorization still live in the kernel nft tables / on-disk credentials.
		// applySem is a weight-1 mutex: acquiring it waits for the in-flight apply
		// (now including its closeout) to release. The closeout is bounded (two
		// atomic nft loads + local credential reconciles, no FRR/netlink reload),
		// so this cannot hang on unbounded work; bound it defensively anyway so a
		// wedged apply cannot block the whole shutdown past the drain budget.
		if d.applySem != nil {
			drainCtx, cancelDrain := context.WithTimeout(context.Background(), applyCloseoutDrainTimeout)
			if err := d.applySem.Acquire(drainCtx, 1); err == nil {
				d.applySem.Release(1)
			} else {
				slog.Warn("shutdown: timed out draining in-flight apply before teardown; "+
					"host-authorization closeout may be incomplete", "err", err)
			}
			cancelDrain()
		}
	}

	// Cancel context to stop background goroutines, then wait for them.
	stop()
	wg.Wait()

	// ── THE FAIL-CLOSED ACTIONS RUN FIRST (#9035) ──────────────────────
	//
	// This block used to sit ~90 lines below, after the telemetry, feeds, RPM,
	// SNMP, FRR and LLDP teardowns. Its own comment already stated the intent
	// exactly — "clear rg_active BEFORE stopping subsystems that may hang" —
	// but it was positioned relative to only the two subsystems anyone had
	// worried about (VRRP, sync), so every teardown added above it silently
	// moved ownership-release later in the budget.
	//
	// WHAT MUST BE TRUE BEFORE THE BUDGET IS GONE. `TimeoutStopSec=20`, and
	// systemd SIGKILLs at that point wherever we are. Exactly two actions must
	// have completed by then, because only they are FAIL-CLOSED — everything
	// else is best-effort cleanup whose loss costs telemetry, not correctness:
	//
	//   1. rg_active cleared, so this node stops forwarding; and
	//   2. the Kea units stopped, so it stops answering DHCP (#6787).
	//
	// Miss either and the peer promotes onto a segment this node is still
	// serving: duplicate OFFERs from two lease databases, which is the exact
	// outcome #6787 exists to prevent.
	//
	// #9035 showed the flow-export drain reaching 22 s on its own (serial,
	// 2 s per collector, uncapped cardinality, untimed join) — over budget
	// before either action ran. Bounding that drain is necessary and is done
	// below, but it is NOT sufficient and never could be: it fixes the one
	// subsystem that was measured, and leaves the next slow one to re-break
	// the same invariant. Ordering makes it STRUCTURAL — no teardown added
	// after this point can push the fail-closed actions past the budget,
	// because they have already happened.
	//
	// WHY HERE AND NOT EARLIER. It must follow `stop(); wg.Wait()` above.
	// `desired = clusterPri || allVrrpMaster` (rg_state.go), and a live
	// reconcile goroutine observing desired=true would re-drive rg_active
	// back to TRUE after this clear — the #6530 retry, doing exactly its job
	// against a clear it cannot distinguish from a spurious revert. The
	// goroutines must be joined first for the clear to stick.
	//
	// RESIDUAL, stated rather than left implicit: `wg.Wait()` above is itself
	// unbounded. Nothing in this issue's evidence points at it, and bounding a
	// join whose goroutines are context-cancelled is a different change with a
	// different risk, so it is recorded here rather than folded in.
	cfg := d.store.ActiveConfig()
	haMode := cfg != nil && cfg.Chassis.Cluster != nil
	hitless := !haMode // standalone = hitless by default
	if haMode && cfg.Chassis.Cluster.HitlessRestart {
		hitless = true // operator explicitly opted in
	}

	// #9686: a fail-closed stop must CLOSE kernel transit before it detaches the
	// dataplane. Teardown below removes every XDP program and pin, and nothing
	// else on this path lowers ip_forward or installs the #7191 barrier. So
	// without this the "fail-closed" branch ended with the kernel routing
	// transit that still reached the node (surviving interface addresses,
	// static/BGP next hops, link-local next hops) with no policy, session or NAT,
	// for the whole downtime and into the next start until re-arm. The
	// not-armed transition is the same one bootstrap and --no-dataplane use: it
	// installs the barrier and writes both sysctls to 0, and nothing on the way
	// out re-opens them.
	//
	// It keys on hitless alone, not on a published runtime: forwarding can be
	// open from an earlier open gate whether or not a dataplane is still
	// published. A hitless stop (standalone, or `hitless-restart`) keeps the
	// dataplane attached and the shim dropping transit, so it leaves forwarding
	// as it is.
	if !hitless {
		d.markDataplaneNotArmed("shutdown", "HA fail-closed stop: closing kernel transit before the dataplane detach")
	}

	// In HA fail-closed mode, clear rg_active and watchdog immediately so
	// BPF stops forwarding traffic even if subsequent cleanup steps hang.
	// #2114: one snapshot for the whole HA-clear block (plan §5.3 rule 5).
	if rt := d.dataplane(); !hitless && rt != nil && cfg.Chassis.Cluster != nil {
		slog.Info("HA shutdown: clearing rg_active for all RGs")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
			err := runHAShutdownUpdate(shutdownCtx, func(ctx context.Context) error {
				return rt.HA().SetRGActive(ctx, rg.ID, false)
			})
			if err != nil {
				slog.Warn("failed to clear rg_active on shutdown", "rg", rg.ID, "err", err)
			}
			err = runHAShutdownUpdate(shutdownCtx, func(ctx context.Context) error {
				return rt.HA().SetHAWatchdog(ctx, rg.ID, 0)
			})
			if err != nil {
				slog.Warn("failed to clear ha_watchdog on shutdown", "rg", rg.ID, "err", err)
			}
		}
	}

	// #6787: STOP THE KEA UNITS BEFORE RELINQUISHING OWNERSHIP.
	//
	// Everything below this point hands the segment to the peer: the RA
	// goodbye, the VIP removal, VRRP's priority-0 burst, and the heartbeat
	// stop. None of them touched the DHCP server, and Kea runs as SEPARATE
	// systemd units that outlive xpfd. So an orderly HA shutdown promoted the
	// peer — which starts ITS Kea on the same segment — while this node's Kea
	// kept answering: duplicate OFFERs, and two lease databases handing out
	// addresses from one pool with neither aware of the other. The units also
	// survived the whole xpfd downtime, so the condition persisted until the
	// operator noticed.
	//
	// Placed BEFORE the withdrawal, not after, so there is never a moment when
	// both nodes serve. #9035 moved it FURTHER forward, to here: it is the
	// second of the two fail-closed actions, so it belongs beside the first
	// and ahead of every best-effort teardown, not merely ahead of the
	// withdrawal. The invariant it protects is unchanged and strictly better
	// served — a stop that systemd SIGKILLs before it runs is a stop that did
	// not happen. Synchronous, because ApplyAsync's mailbox is drained by
	// a worker goroutine and a stop enqueued during shutdown races process exit
	// — a fix that is present and does nothing looks exactly like a fix that
	// works. Manager.Shutdown also LATCHES, so a VRRP MASTER transition racing
	// this window cannot re-arm the units with a newer generation.
	//
	// CLUSTER MODE ONLY. In standalone there is no peer to hand the segment to,
	// and Kea deliberately survives an xpfd restart today; stopping it here
	// would turn every daemon restart into a DHCP outage. haMode is the
	// discriminator, not `hitless`: VRRP sends its priority-0 burst even on a
	// hitless HA restart, so the peer takes over and this node must stop
	// serving either way.
	if haMode && d.dhcpServer != nil {
		if err := d.dhcpServer.Shutdown(); err != nil {
			slog.Warn("shutdown: failed to stop the DHCP server units — this "+
				"node may keep answering DHCP while the peer serves the same "+
				"segment", "err", err)
		} else {
			slog.Info("shutdown: DHCP server stopped before relinquishing ownership")
		}
	}

	// #5308: cancel + join the two long-lived loops that bind to d.daemonCtx
	// (never cancelled in production) rather than the run WaitGroup above, so
	// wg.Wait does NOT cover them. Both call into subsystems torn down further
	// below and therefore MUST be stopped first: the policy scheduler
	// republishes schedule state through the dataplane runtime
	// (UpdatePolicyScheduleState — closed by dp.Close/dp.Teardown), and the RPM
	// probe-pin retry loop runs routing-pin syscalls through the routing/FRR
	// manager (stopped by frr.Stop / routing teardown). Cancelling + joining
	// here guarantees no late scheduler tick runs against a closed runtime and
	// no late pin-retry tick runs a syscall after routing is gone. Both helpers
	// are idempotent / nil-safe (a never-started loop joins cleanly), so this is
	// also the safety-net for the Run()-returns path via the defers in Run.
	d.stopPolicySchedulerLoop()
	d.stopPinRetryLoop()
	// #9166: the flow-export build retry runs reconciles that dial the
	// configured collectors and swap exporter generations, so a late tick must
	// not land after the exporters are torn down below. Idempotent / nil-safe
	// and bounded, like its two neighbours.
	d.stopFlowExportRetryLoop()

	// #5523 C179-093: cancel + join the two remaining background loops that do
	// NOT bind to the run WaitGroup and were previously leaked at shutdown:
	//   - the session-aggregation flush goroutine (binds to context.Background,
	//     cancelled only via aggCancel) — cancelling here triggers its #5313
	//     ctx.Done final flush so the pending window is emitted rather than
	//     dropped, and joins it. Done BEFORE the flow/feeds/event teardown below
	//     so the flush still has a live SetLogFunc -> er.ForwardLogMsg path.
	//   - the IPsec DHCP-rebind retry loop (bound to d.daemonCtx, never
	//     cancelled in production) — stopping it before FRR/IPsec teardown keeps
	//     a late 30s rebind tick from racing a swanctl reapply against a
	//     torn-down subsystem. Both helpers are idempotent / nil-safe.
	d.stopAggregator()
	d.stopIPsecRebindLoop()

	// Stop the SNMP agent + link-state trap monitor (#3967). Their goroutines
	// bind to d.daemonCtx (never cancelled in production) rather than the run
	// WaitGroup, so wg.Wait above does not cover them — teardownSNMP cancels
	// the agent's lifetime context, joins the goroutines, and releases UDP/161.
	d.teardownSNMP()

	// Clean up flow exporters.
	d.stopFlowExporter()
	d.stopIPFIXExporter()

	// Clean up dynamic address feeds.
	if d.feeds != nil {
		d.feeds.StopAll()
	}

	// Clean up RPM probes.
	if d.rpm != nil {
		d.rpm.StopAll()
	}

	// Stop the periodic configuration-archival timer (#4078). Its goroutine
	// binds to a per-generation stop channel (not the run WaitGroup), so this
	// explicit stop is the authoritative shutdown for the boot-armed timer,
	// whose captured daemon-stop context may predate applyCancelContext.
	d.stopArchiveTimer()

	// Stop the event-options action worker (after RPM so no events arrive
	// during teardown). Close drains in-flight lock-retry backoffs (#2157).
	if d.eventEngine != nil {
		d.eventEngine.Close()
	}

	// Stop the ip-monitoring engine (after RPM so no transitions
	// arrive during teardown).
	if d.ipmon != nil {
		d.ipmon.Stop()
	}

	// #2079/#2114: stop the NAT pool-utilization-alarm monitor. Routed
	// through the helper so the atomic pointer is read/cleared the same way
	// as the runtime start/discard paths.
	d.stopAndDiscardNATPoolAlarm()

	// Stop the FRR manager (after ipmon, whose actuator is an FRR
	// writer): cancels the degraded-retry goroutine and kills any
	// in-flight frr-reload.py process group (#1880).
	if d.frr != nil {
		d.frr.Stop()
	}

	// Clean up LLDP.
	if d.lldpMgr != nil {
		d.lldpMgr.Stop()
	}

	// Withdraw RA senders (sends goodbye RAs with lifetime=0) before VRRP
	// stop so hosts immediately stop using this node as a default router.
	if d.ra != nil {
		if err := d.ra.Withdraw(); err != nil {
			slog.Warn("shutdown: failed to withdraw RA senders", "err", err)
		}
	}

	// Direct-mode: remove VIPs before VRRP stop (VRRP won't manage them).
	if d.isNoRethVRRP() && cfg.Chassis.Cluster != nil {
		for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
			d.directRemoveVIPs(rg.ID)
		}
	}

	// Stop VRRP manager (removes VIPs, sends priority-0).
	if d.vrrpMgr != nil {
		d.vrrpMgr.Stop()
	}

	// Stop cluster monitor (heartbeats) immediately after VRRP priority-0.
	// This ensures the peer's heartbeat timeout starts promptly instead of
	// being delayed by the 5s sync Stop timeout below.
	if d.cluster != nil {
		d.cluster.Stop()
	}

	// Stop session sync (5s timeout to avoid blocking teardown).
	if ss := d.getSessionSync(); ss != nil {
		d.stopSyncReadyTimer()
		ss.Stop()
	}

	// #2114: a SECOND snapshot for final-stats + Close/Teardown (plan §5.3
	// rule 5), matching the pre-cell two separate reads.
	if rt := d.dataplane(); rt != nil {
		// logFinalStats now reads through the runtime Telemetry
		// domain (#1519); the dataplaneReadyProbe gate keeps the
		// "no-op when dp not loaded" contract intact for both
		// backends.
		if ready, ok := rt.(dataplaneReadyProbe); ok {
			logFinalStats(ready, rt.Telemetry())
		}
		if hitless {
			// Hitless: close Go handles only — BPF programs keep running.
			//
			// #9725: no gate call here. Close REPORTS the links that survive it —
			// the ones whose pin still names them — and the observer closes the
			// gate when that is zero. That covers the cases this path's premise
			// misses: the pin is best effort (AttachXDP logs a failed Pin at Warn
			// and still returns success), and a stop landing between
			// removeUserspaceShimXDPLinkPins and the re-attach finds live links
			// with no pins, which Close then detaches. A genuine hitless upgrade
			// reports a non-zero surviving count and keeps forwarding, as #9686
			// intends.
			slog.Info("hitless shutdown: preserving BPF state")
			rt.Close()
		} else {
			// Fail-closed: tear down all pinned BPF state.
			slog.Info("HA shutdown: tearing down BPF state")
			rt.Teardown()
		}
	}

	// #801 B2: restore any host-scope tunables xpfd claimed to their
	// pre-xpfd values. No-op if `claim-host-tunables` was never set.
	// Runs on every shutdown (hitless + fail-closed) so stopping xpfd
	// leaves the host as xpfd found it.
	d.restoreStep0TunablesOnShutdown()

	slog.Info("shutdown complete")
	return runErr
}

func runHAShutdownUpdate(ctx context.Context, update func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		done <- update(ctx)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
