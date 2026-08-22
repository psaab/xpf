package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/ra"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/vrrp"
)

// initManagers eagerly constructs the daemon's subsystem managers (routing,
// FRR, IPsec, RPM, ip-monitoring, event-options engine, DHCP, cluster, and
// VRRP), storing each on d.*, BEFORE the first applyConfig and the dataplane
// backend build that follow in Run(). Extracted verbatim from Run()'s PHASE 3
// (#4662 Increment 4); the creation order is load-bearing (e.g. the
// event-options engine registers an RPM callback and must exist before the
// first applyConfig reconciles RPM). configCompileFailed is the #1960
// fail-closed flag threaded from PHASE 1 (read-only here, at
// clearFRRForFailClosedBoot). Returns a non-nil error only on a fatal DHCP
// manager-create failure (the sole early return in the original block), which
// Run propagates unchanged.
// initManagers constructs the routing/FRR/IPsec/RPM/ipmon/event-engine/DHCP/
// cluster/VRRP managers and runs the first applyConfig. Its long-lived runtimes
// (cluster monitor, cluster-event watcher, kernel self-recovery) bind to
// d.daemonCtx — the RAW, signal-uncancelled daemon-lifetime parent — NOT the
// startup-signal context, because the shutdown sequence tears them down
// EXPLICITLY and needs them live during teardown; a startup signal aborts at the
// phase boundary (runStartupPhases), it must not kill these runtimes underneath
// the teardown (#5807).
func (d *Daemon) initManagers(configCompileFailed bool) error {
	// Initialize routing, FRR, and IPsec managers
	if !d.opts.NoDataplane {
		rm, err := routing.New()
		if err != nil {
			slog.Warn("failed to create routing manager", "err", err)
		} else {
			d.routing = rm
			// #1827: flush the reserved probe-pin band (ip rules 50-99 +
			// tables 7000-7049) before anything else runs, so a crashed
			// daemon never leaks stale probe pins across restarts.
			if err := d.routing.ClearProbePins(); err != nil {
				slog.Warn("failed to clear stale probe pins", "err", err)
			}
		}
		d.frr = frr.New()
		// #1993: on a compile-failure boot with NO preserved XDP attachments,
		// the last-good frr.conf managed section is still on disk and FRR (an
		// independent service) will form peerings + re-advertise prefixes for
		// routes this unarmed node cannot forward — a transit blackhole. Clear
		// ONLY the managed section, right after the manager exists and BEFORE
		// the run loop settles, so peers fail over to the HA partner. The
		// predicate PRESERVES the managed section on a hitless restart only when
		// the helper control socket reports forwarding is genuinely live
		// (enabled+armed); pinned XDP links are merely a cheap pre-filter, NOT
		// proof of live forwarding (a graceful stop leaves the pins but disarms
		// forwarding). Freeze-in-last-known-good for management (#1960) is
		// preserved: no .network/.link removal, no link-cycle.
		d.clearFRRForFailClosedBoot(configCompileFailed)
		d.ipsec = ipsec.New()
		d.ra = ra.New()
		d.networkd = networkd.New()
		// #1956 AGY r3 CRITICAL: exempt the #1922 management protected set
		// from networkd.Apply's stale-file sweep so the lifeline's rename +
		// addressing survive a commit that leaves it out of the config.
		d.networkd.SetProtectedResolver(d.resolveProtectedInterfaces)
		d.dhcpServer = dhcpserver.New()
		// #1387 inc-2: construct the DHCP dynamic-DNS manager UNCONDITIONALLY
		// (plan §4.2) — even when DDNS is disabled — so the always-on
		// reconcile loop can withdraw records on an enabled→disabled commit.
		// The nodeID is a node-stable watermark HINT only (never the
		// delete-matching key, Inc-1 ddns.go), so an empty seed in standalone
		// mode is harmless. The live rfc2136 backend is resolved per-Reconcile
		// from the current policy.
		d.ddns = dhcpserver.NewProductionDDNSManager(ddnsNodeIDSeed())
		// #2691 P2: the always-on Surface A manager (router/interface-address
		// publish). Constructed unconditionally for the same reason as the lease
		// manager — a binding removal must have a running loop to withdraw.
		d.surfaceA.mgr = ddns.NewSurfaceAManager()
		// #5748: cross-wire the two DDNS ownership surfaces so each teardown guard
		// can see a wire RR the OTHER surface co-owns and suppress a DELETE that
		// would clobber it (the cross-surface arm of the #5709 co-ownership guard).
		// Each accessor is a LOCK-FREE snapshot read (an atomic.Pointer load in the
		// peer, never taking the peer's mutex), so a teardown holding its own
		// manager's mu can consult the peer with no lock-order cycle / deadlock.
		d.ddns.SetSurfaceACoownerSource(d.surfaceA.mgr.WireRRClaims)
		d.surfaceA.mgr.SetLeaseCoownerSource(d.ddns.WireRRClaims)
	}

	// Create the RPM manager eagerly so the pointer is stable for the
	// CLI/gRPC results closures and so applyConfig's hash-gated
	// reconcileRPM (#1827) can start probes from the very first apply.
	d.rpm = rpm.New()

	// Create the ip-monitoring engine (#1827 PR-1b) before the first
	// applyConfig so reconcileIPMon can install committed policies.
	// The engine drives the routes-only actuator through its own
	// debounce/throttle loop; the RPM transition hook is its sensor.
	d.ipmon = ipmon.New(d.actuateRouteOverlay)
	d.rpm.SetTransitionCallback(d.ipmon.HandleTransition)

	// Construct the event-options engine and register its RPM event callback
	// HERE — BEFORE the first applyConfig runs reconcileRPM and starts the
	// probe goroutines (#3755). runProbeLoop runs its FIRST cycle immediately,
	// so a ping_probe_failed / ping_test_failed / ping_test_completed emitted by
	// that first cycle would be dropped (fireEvent is a no-op while onEvent is
	// nil) if the callback were installed later — a boot-time failover edge the
	// automation exists to handle, lost for long test-interval values. Wiring
	// the callback before probes start closes that gap; rpm additionally buffers
	// any event fired before a callback exists and replays it on registration,
	// as a belt against a future reorder. Idempotent (write-once pointer).
	d.initEventEngine()

	// Create the DHCP manager eagerly, beside the ipmon engine (#1844
	// plan §4.3, AGY r2-1/r2-2): d.dhcp is write-once at boot and
	// read-only thereafter — the engine's run-loop goroutine (via the
	// next-hop resolver) and the CLI/gRPC handlers read the pointer
	// bare, so the previous lazy-create-under-applySem was a Go data
	// race (and the first apply would have built the overlay against a
	// nil resolver target). A dhcp.New failure is FATAL: it means
	// netlink.NewHandle failed, and the daemon cannot manage interfaces
	// without netlink anyway — a silent nil d.dhcp would strand the
	// process DHCP-less for its lifetime with no retry path (SMR plan
	// r3). The gateway-change hook nil-guards d.ipmon so construction
	// order can never regress silently.
	if !d.opts.NoDataplane {
		// State dir for DUID persistence — same directory as config file.
		dm, err := dhcp.New(filepath.Dir(d.opts.ConfigFile), d.onDHCPAddressChange, func() {
			if e := d.ipmon; e != nil {
				e.NotifyNextHopChange()
			}
		})
		if err != nil {
			return fmt.Errorf("create DHCP manager: %w", err)
		}
		d.dhcp = dm
	}

	// Resolver injection MUST precede Start(): the run-loop goroutine
	// reads the resolver field without further synchronization, and the
	// goroutine-creation happens-before edge also publishes d.dhcp.
	d.ipmon.SetNextHopResolver(d.resolveDHCPNextHop)
	d.ipmon.Start()

	// Initialize cluster manager if configured (heartbeat/sync started after applyConfig).
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		d.cluster = cluster.NewManager(cc.NodeID, cc.ClusterID)
		d.cluster.SetSoftwareVersion(d.opts.Version)

		// #1930 INC-2: if THIS boot is a kernel-candidate trial (the kernel
		// journal is ARMED), set the unconditional election hold BEFORE the
		// FIRST election so the candidate can never win it (even isolated) until
		// the promotion gate verifies the dataplane. UpdateConfig() ITSELF runs
		// an election (single-node path when no peer is up yet, which is exactly
		// the candidate-boot case), so the hold MUST precede UpdateConfig — not
		// merely Start() — or the node is already StatePrimary by the time the
		// hold is set and Start()'s heartbeat/VRRP would advertise primary and
		// preempt the healthy peer. ManualFailover is in-memory (lost across the
		// reboot) and peerAlive is still false here, so the unconditional hold —
		// not ForceSecondary — is what keeps an unverified candidate from
		// blackholing traffic (r2 AGY Critical). No-op on an ordinary boot.
		d.holdSecondaryIfKernelCandidateArmed()

		d.cluster.UpdateConfig(cc)
		d.cluster.Start(d.daemonCtx)
		// Wire event-drop callback: on dropped cluster events, trigger
		// immediate reconciliation so the safety net doesn't wait 2s.
		d.cluster.SetOnEventDrop(d.triggerReconcile)
		// Wire dual-active reaffirm-drop callback (#4867): if the
		// "winner stays" event is dropped on a full channel, the generic
		// reconcile above does NOT re-announce for a steady VIP owner, so
		// re-drive the direct-mode GARP/NA refresh directly. Runs off the
		// election goroutine (cluster m.mu held during the callback) — spawn
		// so the announce I/O never blocks election under that lock.
		d.cluster.SetOnDualActiveWinDrop(func(rgID int) {
			go func() {
				if d.isNoRethVRRP() {
					d.scheduleDirectAnnounce(rgID, "dual-active-win-drop")
				}
			}()
		})
		slog.Info("cluster manager initialized",
			"node", cc.NodeID, "cluster", cc.ClusterID)

		// Watch cluster events for state transitions (primary/secondary).
		go d.watchClusterEvents(d.daemonCtx)

		// #1930 INC-2: bounded local self-recovery for the LANE-1 HA kernel
		// channel — auto-rejoin if an external kernel-roll orchestrator crashed
		// while this node was drained+rebooting (no-op unless orphaned-drained).
		d.startKernelSelfRecovery(d.daemonCtx)
	}

	// Enable IP forwarding — required for the firewall to route packets —
	// or, in the two states that never arm, explicitly CLOSE it (#1922
	// suppression + the #5275 gate). See applyBootTransitPolicy.
	d.applyBootTransitPolicy()

	// Create VRRP manager eagerly — must exist before applyConfig runs.
	d.vrrpMgr = vrrp.NewManager()
	// Wire event-drop callback: on dropped VRRP events, trigger
	// immediate reconciliation.
	d.vrrpMgr.SetOnEventDrop(d.triggerReconcile)
	if err := d.vrrpMgr.Start(context.Background()); err != nil {
		slog.Warn("failed to start VRRP manager", "err", err)
	}
	// On fresh cluster daemon start, suppress VRRP preemption until session
	// bulk sync completes (or timeout) to avoid preempt-before-sync outages.
	// Only applies when VRRP is enabled — otherwise no RETH VRRP instances.
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		if cc.FabricInterface != "" && cc.FabricPeerAddress != "" && !cc.NoRethVRRP && !cc.PrivateRGElection {
			d.vrrpMgr.SetSyncHold(30 * time.Second)
		}
		// Private-rg-election mode takes no VRRP sync-hold (the branch
		// above excludes it), so arm the sync-ready timeout instead. Be
		// exact about what that buys (#7102): cluster.Manager.syncReady
		// does NOT gate RG promotion in this mode — takeover readiness
		// here is VIP ownership alone (checkNoRethTakeoverReadiness) and
		// the readiness conjunction has no sync term — so this is a bound
		// on a reported/logged state, not on takeover. It is also not the
		// only arm: the cold-start branch of onSessionSyncPeerConnected
		// re-arms the timer (bumping syncReadyTimerGen, which supersedes
		// this one), and this timer's callback returns early while no sync
		// peer is connected. Whether promotion SHOULD be sync-gated is
		// #110; do not read this call as already doing it.
		if cc.PrivateRGElection && cc.FabricInterface != "" && cc.FabricPeerAddress != "" {
			d.armSyncReadyTimer()
		}
	}
	return nil
}

// loadAndBootstrapConfig loads the persisted configuration (DB, falling back to
// the text config file), enforces the #1917 fatal-on-parse floor, runs
// bootstrapFromFile when required, and derives the boot class + node-id state.
// Extracted verbatim from Run()'s PHASE 1 (#4662 Increment 5). Returns the
// #1960 configCompileFailed fail-closed flag (threaded onward to initManagers)
// and a non-nil error only for the fatal 'DB present but unreadable' floor,
// which Run propagates unchanged (fail closed, never a blind bootstrap).
func (d *Daemon) loadAndBootstrapConfig() (bool, error) {
	// Load persisted configuration from DB, falling back to text config file.
	//
	// Fatal-on-parse floor (#1917 increment B, plan §6.4 / D1): a PRESENT
	// but unreadable active.json (JSON parse error, decrypt failure, or a
	// config compatibility envelope this build cannot read because it was
	// written by a NEWER xpf) must FAIL CLOSED — return the error from Run
	// instead of warning-and-proceeding to a blind bootstrapFromFile() that
	// would OVERWRITE the unreadable DB and silently wipe the operator's
	// config. This is the structural guard that makes a future config-format
	// change safe to roll out: an old reader refuses a too-new DB rather than
	// empty-loading it. A compile error (handled leniently inside Load) or an
	// absent DB (start-fresh) is NOT this case and still degrades gracefully.
	//
	// mgmt-never-stranded (#1922): on the appliance the day-0 + protected-set
	// lifeline keeps mgmt reachable through a fail-closed boot; #1922 hardens
	// the foreign/non-appliance host case (noted in the PR; not implemented
	// here).
	// configCompileFailed records the #1960 fail-closed case: a PRESENT,
	// previously-committed active.json read+parsed fine but no longer
	// compiles. It must NOT fall back to bootstrapFromFile() (which would
	// blind-import the text config file over a broken-but-present committed
	// DB — the same silently-wrong takeover this issue closes) and it forces
	// bootstrap mode below regardless of computeBootClass's other inputs.
	configCompileFailed := false
	switch loadErr := d.store.Load(); classifyLoadError(loadErr) {
	case loadFatalUnreadable:
		// Point recovery at the actual unreadable artifact — the config
		// DB under .configdb/, NOT the text config file (Copilot).
		dbPath := filepath.Join(filepath.Dir(d.opts.ConfigFile), ".configdb", "active.json")
		return false, fmt.Errorf("config DB is present but unreadable; refusing to "+
			"start and overwrite it (fail closed). Inspect/repair %s (the on-disk "+
			"config DB, NOT the text config file) or roll the xpf binary forward "+
			"to a build that can read it: %w",
			dbPath, loadErr)
	case loadCompileFailed:
		// #1960 fail-closed: a previously-committed config no longer
		// compiles. Store.Load set everCommitted=true but left compiled
		// nil, so without this the boot predicate would resolve to NORMAL
		// (ActiveConfig()==nil + everCommitted) and run the positional
		// claim-all interface rename — exactly the safety hole this fixes.
		// Surface it LOUDLY (Error, not the ignored Warn) and route into
		// the #1922 bootstrap/lifeline safe state below.
		configCompileFailed = true
		dbPath := filepath.Join(filepath.Dir(d.opts.ConfigFile), ".configdb", "active.json")
		slog.Error("active config DB is present but no longer compiles; refusing interface "+
			"takeover and entering BOOTSTRAP/lifeline safe state (management preserved, NO "+
			"positional claim-all). Fix the config from the CLI/gRPC and 'commit confirmed', "+
			"or repair/remove the on-disk config DB",
			"db_path", dbPath, "err", loadErr)
	case loadOtherError:
		slog.Warn("failed to load config from db", "err", loadErr)
	case loadOK:
		// nil error: absent DB (start-fresh) or a valid loaded config.
	}

	// If DB had no active config, bootstrap from the text config file.
	//
	// #1960: but NOT when a present committed config failed to compile —
	// importing the text xpf.conf there would silently swap in a different
	// config and then take over interfaces, defeating the fail-closed intent.
	if shouldBootstrapFromFile(d.store.ActiveConfig() != nil, configCompileFailed) {
		if err := d.bootstrapFromFile(); err != nil {
			// #4186 (H-17): a missing text config file is the EXPECTED
			// factory/fresh-boot state, not a failure — log it at Info, not
			// Warn, so operators triaging a real day-0 failure aren't taught
			// to ignore a benign line. Keep Warn for a REAL failure (file
			// present but unreadable/unparseable/uncommittable, incl. the
			// #4183 device-map strand rejection).
			// #4184 (H-11): record the outcome so a failed import is visible
			// on /health + an event, not just here in journald.
			if errors.Is(err, os.ErrNotExist) {
				slog.Info("no text config present to bootstrap from (factory/fresh boot)",
					"file", d.opts.ConfigFile)
				d.recordBootstrapImport(bootstrapImportNoConfig, "")
			} else {
				slog.Warn("failed to bootstrap config from file", "err", err)
				d.recordBootstrapImport(bootstrapImportFailed, err.Error())
			}
		} else {
			d.recordBootstrapImport(bootstrapImportOK, "")
		}
	} else if d.store.ActiveConfig() != nil {
		slog.Info("configuration loaded from db")
		d.recordBootstrapImport(bootstrapImportLoadedDB, "")
	} else {
		// No DB config and bootstrap-from-file suppressed (e.g. a present
		// committed config that failed to compile, #1960). Record no-config
		// so /health reflects that no active config is installed.
		d.recordBootstrapImport(bootstrapImportNoConfig, "")
	}

	// #1922 Item 2: the five-case boot predicate, computed ONCE here after
	// Load + bootstrapFromFile have resolved. Case 4 (corrupt/too-new DB)
	// already exited fatally above (#1917 D1). The remaining cases select
	// bootstrap vs normal. Bootstrap mode suppresses interface/dataplane
	// TAKEOVER actions (but not the management control surfaces or manager
	// construction — C1). Every existing deployment resolves NOT-bootstrap
	// (case 2/3, or case 5 committed-empty) → zero behavior change.
	//
	// #1960: configCompileFailed forces bootstrap here — a previously-committed
	// config that no longer compiles must fail closed (no positional claim-all)
	// regardless of the other inputs, including the HA-node guard.
	nodeIDPresent := hasNodeIDFile()
	bootClass := computeBootClass(d.store.ActiveConfig() != nil, d.store.EverCommitted(), nodeIDPresent, configCompileFailed)
	if bootClass == bootClassBootstrap {
		d.bootstrapMode.Store(true)
		detail := "management control plane (gRPC/REST/CLI) runs normally, but interface " +
			"rename/takeover, dataplane arm, and FRR/VRRP takeover are SUPPRESSED until the " +
			"first 'commit confirmed' (+ confirm) or cluster config sync. This keeps a " +
			"foreign/non-appliance host reachable on its existing management NIC."
		if configCompileFailed {
			// #1960: distinct cause — not "no config", but "committed config no
			// longer compiles". The Error log above already named the DB path.
			slog.Warn("xpf daemon entering BOOTSTRAP mode: committed configuration no longer compiles",
				"detail", detail)
		} else {
			slog.Warn("xpf daemon entering BOOTSTRAP mode: no committed configuration found",
				"detail", detail)
		}
	} else if nodeIDPresent && d.store.ActiveConfig() == nil {
		// HA-node guard (C2/C8): node-id present but NEITHER a DB nor an
		// importable xpf.conf. Resolved to NOT-bootstrap so takeover is not
		// silently suppressed on a normal deploy, but HA availability is NOT
		// promised — this is an operator misconfiguration. Log loudly.
		//
		// #4179: the nil active config carries no cluster stanza, so the boot
		// naming below runs in STANDALONE mode (clusterMode=false → fxp0 +
		// ge-0-0-X, no em0 / FPC). Arm the one-shot re-naming flag so the first
		// non-empty config that arrives (a cluster SyncApply from the primary,
		// or a local commit) re-runs startup naming with the config's real
		// cluster identity. Naming reconciles on config arrival — no daemon
		// restart is required.
		d.emptyHANamingPending.Store(true)
		slog.Error("xpf HA node has /etc/xpf/node-id but no committed config and no importable "+
			"xpf.conf; proceeding with EMPTY config takeover (NOT bootstrap mode) using STANDALONE "+
			"interface names. HA availability is NOT promised until the cluster config is pushed and "+
			"committed; interface naming will reconcile to the node's cluster names (em0, ge-<fpc>-0-X) "+
			"automatically when that config arrives (no restart required)",
			"node_id_file", nodeIDFile)
	}
	return configCompileFailed, nil
}

// setupDataplaneAndInitialConfig builds the runtime dataplane backend (unless
// config-only), seeds the NAT/session-id counters, runs the FIRST applyConfig
// (configures VRFs/interfaces/routing before cluster comms), flips the #1715
// dnsBootDone flag under applySem, and clears stale blackhole routes. Extracted
// verbatim from Run()'s PHASE 3 tail (#4662 Increment 7) — the ordering-
// sensitive dataplane-arming path. The resolver injection in initManagers
// (called before this) precedes the dataplane Start here, and the dataplane is
// loaded before the first applyConfig; order is preserved by calling this in
// the same Run() slot right after initManagers. Returns a non-nil error only
// on a fatal dataplane-create failure (the block's sole early return), which
// Run propagates unchanged.
// setupDataplaneAndInitialConfig loads the dataplane and runs the boot config
// apply. The dataplane runtime (dp.Start) binds to d.daemonCtx — the RAW,
// signal-uncancelled daemon-lifetime parent (mirroring the bootstrap-exit
// dp.Start below) — NOT the startup-signal context: the shutdown sequence needs
// the runtime live for logFinalStats (dp.Telemetry) and the HA rg_active clear
// (dp.HA) during teardown, so a startup signal aborts at the phase boundary
// rather than tearing the runtime out from under the teardown (#5807).
func (d *Daemon) setupDataplaneAndInitialConfig() error {
	// Create dataplane backend (unless in config-only mode)
	if !d.opts.NoDataplane {
		dpType := ""
		if cfg := d.store.ActiveConfig(); cfg != nil {
			dpType = cfg.System.DataplaneType
		}
		dp, err := buildRuntimeDataPlane(dpType)
		if errors.Is(err, dataplane.ErrDPDKBackendRetired) {
			// #1527 Phase 2 of the DPDK retirement (umbrella
			// #1525): the runtime DPDK backend is gone, but a
			// node may still have "set system dataplane-type
			// dpdk" persisted in the active config from before
			// Chain A (#1526) blocked the commit. Treat this
			// the same way as a Start() failure: log a warning
			// and fall through to config-only mode so the
			// daemon stays up and the operator can fix the
			// config from the CLI / gRPC. The hard fatal-at-
			// startup branch is reserved for genuinely unknown
			// dataplane types (the default branch below).
			//
			// Note: Store.Load() now also rewrites persisted
			// `dataplane-type dpdk` to empty before compile, so
			// the typical path through buildRuntimeDataPlane
			// resolves to userspace and never reaches this
			// branch. The branch stays as defence-in-depth for
			// callers (config sync, REST/gRPC candidate apply)
			// that bypass Store.Load() and pass the retired
			// type through explicitly.
			slog.Warn("the DPDK dataplane backend has been retired; running in config-only mode until config is updated",
				"type", dpType,
				"err", err,
				"remediation", "set system dataplane-type userspace",
			)
			d.setDataplane(nil)
			// #5275: a retired backend never arms, so transit must be
			// closed BEFORE the applyConfig below runs.
			d.markDataplaneArmFailed("boot: dpdk backend retired",
				"set system dataplane-type userspace", err)
		} else if errors.Is(err, dataplane.ErrEBPFBackendRetired) {
			// #1476: mechanical source removal of the legacy
			// eBPF dataplane. Behaviour mirrors the DPDK arm
			// above. Store.Load() / Store.SyncApply() both
			// rewrite persisted `dataplane-type ebpf` to
			// empty before compile, so the typical path
			// never reaches this branch — but a candidate
			// apply through REST/gRPC that explicitly passes
			// the retired type will, and the daemon must stay
			// up so the operator can correct the candidate.
			slog.Warn("the legacy eBPF dataplane backend has been retired; running in config-only mode until config is updated",
				"type", dpType,
				"err", err,
				"remediation", "set system dataplane-type userspace",
			)
			d.setDataplane(nil)
			// #5275: as above — a retired backend never arms.
			d.markDataplaneArmFailed("boot: ebpf backend retired",
				"set system dataplane-type userspace", err)
		} else if err != nil {
			slog.Error("failed to create dataplane", "type", dpType, "err", err)
			return fmt.Errorf("create dataplane: %w", err)
		} else {
			d.setDataplane(dp)
		}
		// #2114: snapshot the just-published dataplane ONCE for the rest
		// of this straight-line boot block (plan §5.3 rule 3) — the
		// nil-check, the cold-path mask stamp, Start, and the seeder all
		// share one coherent view.
		rt := d.dataplane()
		// #1620: stamp the cold-path sample mask onto the userspace
		// Manager so the next buildSnapshot includes it. Mask
		// validation already happened in cmd/xpfd/main.go (two-flag
		// scheme, pow-of-2-1, reject u64::MAX). nil pointer ⇒ no
		// operator setting, userspace-dp defaults to 0xff.
		if rt != nil && d.opts.ColdPathSampleMask != nil {
			if adapter, ok := rt.(interface{ Manager() *dpuserspace.Manager }); ok {
				if mgr := adapter.Manager(); mgr != nil {
					mgr.SetColdPathSampleMask(d.opts.ColdPathSampleMask)
				}
			}
		}
		// #1922 Item 2: in bootstrap mode, do NOT arm the dataplane
		// (AF_XDP attach) and do NOT run the boot-time applyConfig
		// (interface/FRR/routing takeover). The backend object stays
		// constructed (rt != nil) so the bootstrap-exit reconcile can
		// arm it on the first confirmed commit (C1: construct always, arm
		// only when not bootstrap). The control plane (gRPC/REST/CLI) is
		// started later regardless.
		if d.inBootstrap() {
			slog.Info("bootstrap mode: dataplane arm and boot-time config apply suppressed")
		} else {
			d.armBootDataplane(rt)
			// Apply current config — needed even in config-only mode so that
			// VRFs, interfaces, and routing are configured before cluster comms.
			//
			// #5275: this runs on the arm-FAILURE path too, which is exactly
			// the fall-through that made an unarmed node an open router. The
			// arm decision above has already driven the transit knobs, so by
			// the time this apply reaches its tail (applyKernelTuning) the
			// gate reads the real arm state instead of re-opening forwarding.
			if cfg := d.store.ActiveConfig(); cfg != nil {
				slog.Info("applying active configuration")
				d.applyConfig(cfg)
			}
		}
	}
	// #1715: the boot-time DNS reconcile (inside the apply above) ran
	// before DHCP clients start, so its empty-merge policy was
	// repair-only. From here on, an empty DNS merge means "clear DNS".
	// Set under applySem so reconcileDNSLocked (which reads it) never
	// races: applyConfig has released the lock by now, and every later
	// reader re-acquires it.
	_ = d.applySem.Acquire(context.Background(), 1)
	d.dnsBootDone = true
	d.applySem.Release(1)

	// Remove stale blackhole routes from previous daemon runs before
	// cluster comms start (which may inject new ones).
	if d.cluster != nil {
		d.reconcileBlackholeRoutes()
	}
	return nil
}

// applyBootTransitPolicy decides, at bring-up, whether the kernel is allowed
// to route transit — the #5275 gate's boot half. Split out of initManagers so
// the decision is drivable in a test against the sysctl seam rather than
// buried behind the manager-construction block.
//
// Three cases, and the two closing ones are the decision this function
// exists to state explicitly:
//
//   - --no-dataplane: there is no dataplane at all. Bring-up already declined
//     to enable forwarding here; closing the knob makes the apply tail agree
//     with bring-up instead of contradicting it.
//   - bootstrap mode: no committed config, so no policy to enforce. #1922
//     already SUPPRESSED enableForwarding — but suppression is not closure,
//     because the sysctls outlive the process: a daemon restart into
//     bootstrap (or into the #1960 compile-failed boot, which forces
//     bootstrap) inherits ip_forward=1 from the previous armed run and routes
//     transit under no policy. pkg/daemon/README.md already asserts transit
//     is fail-closed in this state; this is what makes that true.
//   - otherwise: enable, provisionally. The arm has not happened yet;
//     setupDataplaneAndInitialConfig closes the knobs again if it fails.
func (d *Daemon) applyBootTransitPolicy() {
	switch {
	case d.opts.NoDataplane:
		d.markDataplaneNotArmed("boot", "--no-dataplane config-only mode")
	case d.inBootstrap():
		d.markDataplaneNotArmed("boot", "bootstrap mode: no committed config to enforce")
	default:
		enableForwarding()
	}
}

// armBootDataplane arms the runtime dataplane on the NORMAL (non-bootstrap)
// boot path: it Starts the constructed backend and, on success, seeds the
// NAT port / session-id counters. On failure the cell is CLEARED so nothing
// can acquire the unarmed backend, mirroring armBootstrapExitDataplane.
//
// Split out of setupDataplaneAndInitialConfig (#5275) for the same reason
// #2114 split armBootstrapExitDataplane: the arm/nil-on-failure writer is
// the security boundary, and it must be drivable in a test without building
// a real backend or running the boot applyConfig. The caller passes the
// ONE dataplane snapshot the surrounding boot block shares (#2114 plan
// §5.3 rule 3) rather than re-reading the cell here.
//
// Both outcomes drive the #5275 transit gate: a successful arm leaves
// kernel transit forwarding enabled, a failed arm closes it BEFORE the
// caller's applyConfig runs.
func (d *Daemon) armBootDataplane(rt dataplane.RuntimeDataPlane) {
	if rt == nil {
		return
	}
	if err := rt.Start(d.daemonCtx); err != nil {
		slog.Warn("failed to start dataplane, running in config-only mode",
			"err", err)
		d.setDataplane(nil)
		// #5275: the AF_XDP shim never attached, so nothing adjudicates
		// transit on this node and there is no nftables `hook forward`
		// substitute. Close the kernel transit path before the caller's
		// applyConfig (and its applyKernelTuning tail) runs.
		d.markDataplaneArmFailed("boot: dataplane start failed",
			"check `journalctl -u xpfd` for the shim/AF_XDP attach error, then "+
				"correct the config and re-commit, or restart xpfd", err)
		return
	}
	d.markDataplaneArmed("boot")
	// natSeeder is satisfied by both *dataplane.Manager
	// (legacy eBPF — SeedNATPortCounters in maps_nat.go,
	// SeedSessionIDCounter in maps_session.go) and the userspace
	// *LegacyDataPlaneAdapter (via embedded bpfShim). The
	// seed methods are no-ops on the userspace fast path
	// but harmless to invoke. The legacyDP() round-trip is
	// no longer required (#1519).
	if seeder, ok := rt.(natSeeder); ok {
		seeder.SeedNATPortCounters()
		nodeID := 0
		if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Chassis.Cluster != nil {
			nodeID = cfg.Chassis.Cluster.NodeID
		}
		seeder.SeedSessionIDCounter(nodeID)
	}
}

// isInteractive returns true if stdin is a real terminal (not /dev/null or a pipe).
// enableForwarding enables IPv4 and IPv6 forwarding via sysctl
// and disables RA acceptance on all interfaces.
// A firewall must forward packets between interfaces; without this,
// the kernel drops all transit traffic. A firewall must not accept
// RAs — it uses its own configured routes exclusively.
func enableForwarding() {
	// #5275: the two TRANSIT knobs are owned by the arm gate
	// (daemon_transit_gate.go) so bring-up and the apply tail cannot drift
	// into disagreeing about which sysctls admit transit. The rest of this
	// bundle is host posture that does not admit transit on its own and
	// stays unconditional.
	writeTransitForwardSysctls(true)
	sysctls := map[string]string{
		"/proc/sys/net/ipv6/conf/all/accept_ra":     "0",
		"/proc/sys/net/ipv6/conf/default/accept_ra": "0",
		// l3mdev_accept: allow accepting TCP/UDP connections on management VRF
		// interfaces from sockets not bound to the VRF (needed for SSH).
		"/proc/sys/net/ipv4/tcp_l3mdev_accept": "1",
		"/proc/sys/net/ipv4/udp_l3mdev_accept": "1",
		// accept_local: allow packets with a source IP that is local to the
		// machine on a different interface. Required when XDP SNAT rewrites
		// src to a tunnel endpoint IP and XDP_PASS to kernel for routing —
		// kernel would otherwise reject the packet as a martian.
		"/proc/sys/net/ipv4/conf/all/accept_local": "1",
	}
	for path, val := range sysctls {
		if err := os.WriteFile(path, []byte(val), 0644); err != nil {
			slog.Warn("failed to set sysctl", "path", path, "err", err)
		}
	}
	slog.Info("IP forwarding enabled, RA acceptance disabled")
}
