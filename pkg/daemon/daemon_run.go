// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/cli"
	"github.com/psaab/xpf/pkg/coalesce"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/dhcprelay"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/fwdstatus"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/osident"
	"github.com/psaab/xpf/pkg/rpm"
)

// buildRuntimeDataPlane selects the userspace-native Boot() path for the
// default and explicit userspace selections, and falls through to
// dataplane.NewRuntimeDataPlane for every other type. After #1476
// (legacy eBPF retirement) and #1527 (DPDK Phase 2), the only
// operator-facing cases on the fall-through branch are the two
// retirement-error sentinels: explicit "dataplane-type ebpf" →
// ErrEBPFBackendRetired, and "dataplane-type dpdk" →
// ErrDPDKBackendRetired. Unknown/custom types and any future
// registry-backed types also flow through the same default branch
// and surface the legacy factory's error (including "unknown
// dataplane type") verbatim.
//
// Keeping the legacy branch routed through the dataplane factory
// preserves both retirement sentinel handlings unchanged AND
// preserves the existing AST canary in
// pkg/dataplane/retirement_boundary_canary_test.go
// (TestDaemonRuntimeEntryPointUsesRuntimeDataPlane) that requires
// daemon_run.go to reference dataplane.NewRuntimeDataPlane.
//
// This helper MUST stay in daemon_run.go for the canary above. Do not
// split into a separate file in pkg/daemon/ without updating the canary.
//
// #1520 (sub-#1451 S5): userspace daemon construction no longer detours
// through the runtime backend registry. The registry entry is retained
// as a compatibility / test seam (see pkg/dataplane/userspace/manager.go
// init()).
func buildRuntimeDataPlane(dpType string) (dataplane.RuntimeDataPlane, error) {
	switch dataplane.EffectiveType(dpType) {
	case dataplane.TypeUserspace:
		return dpuserspace.Boot(), nil
	default:
		return dataplane.NewRuntimeDataPlane(dpType)
	}
}

// Run starts the daemon and blocks until shutdown.
func (d *Daemon) Run(ctx context.Context) error {
	// d.daemonCtx is the RAW parent (production: context.Background) for the
	// long-lived background goroutines and the dataplane/cluster runtimes. The
	// shutdown sequence tears those down EXPLICITLY and needs them LIVE during
	// teardown (logFinalStats via dp.Telemetry, the HA rg_active clear via
	// dp.HA()), so it is deliberately kept SEPARATE from — and never replaced by
	// — the shutdown-signal context below (#5807).
	d.daemonCtx = ctx

	// #5807: capture the shutdown signals BEFORE the mutating startup phases
	// (config load / interface naming / manager init / dataplane setup). A
	// SIGTERM — or a daemon-mode SIGINT — that arrives DURING startup then
	// cancels this context instead of the process taking its default action
	// (immediate kill, no deferred cleanup): runStartupOrAbort below aborts the
	// remaining phases and runs the ordered teardown for whatever was already
	// initialized, so a signal mid-startup no longer strands partially-applied
	// links / routes / FRR / IPsec / DHCP / HA / dataplane state with none of
	// the fencing steady-state shutdown performs. The signal set matches the
	// pre-#5807 late install: interactive mode catches only SIGTERM (the CLI
	// keeps SIGINT for Ctrl-C command cancellation), daemon mode catches both.
	// `ctx` is reassigned to this signal context and carries through every later
	// phase, the apply-cancel context, and the main wait exactly as the old
	// PHASE 4 install did.
	ctx, stop := startupSignalContext(ctx)
	defer stop()

	// #5308: guarantee the two daemonCtx-bound background loops (policy
	// scheduler + RPM probe-pin retry) are cancelled + joined even when Run
	// returns WITHOUT reaching runShutdownSequence — an early-error return
	// (config load / manager init / dataplane setup) or an embedded library
	// caller whose ctx cancels. On the normal path runShutdownSequence has
	// already stopped both (idempotent / nil-safe), so these defers are no-ops
	// there; they only do real work on the return paths that skip it. Both loops
	// may be started during initManagers' boot apply below, so registering the
	// defers here covers every subsequent return.
	defer d.stopPinRetryLoop()
	defer d.stopPolicySchedulerLoop()
	// #5523 C179-093: the aggregator flush goroutine and the IPsec DHCP-rebind
	// retry loop are also started during the boot apply below and are NOT
	// covered by the run WaitGroup, so guarantee they are cancelled + joined on
	// every Run return — including the early-error / embedded-caller paths that
	// skip runShutdownSequence. On the normal path runShutdownSequence stops
	// both first (idempotent / nil-safe), so these defers are no-ops there. A
	// persistent stall is the only case where both the runShutdownSequence call
	// and this defer do real work — each bounded join (#6395/#6397) waits its
	// budget once, but the fence-starvation that matters is the PRE-fence call in
	// runShutdownSequence; this POST-fence re-wait runs after the HA fence has
	// already completed, so its extra budget is harmless.
	defer d.stopIPsecRebindLoop()
	defer d.stopFlowExportRetryLoop() // #9166
	defer d.stopAggregator()
	d.startPolicySchedulerLoopLocked()

	// WaitGroup for coordinated shutdown of background goroutines. Declared here
	// (before the mutating phases) so the #5807 startup-abort path can hand it to
	// runShutdownSequence; no goroutine is added until PHASE 5, so an early-abort
	// wg.Wait() is a no-op.
	var wg sync.WaitGroup

	// Wrap the default slog handler to support system syslog forwarding.
	// Syslog clients are added later when config is applied.
	d.slogHandler = logging.NewSyslogSlogHandler(slog.Default().Handler())
	slog.SetDefault(slog.New(d.slogHandler))

	slog.Info("starting xpf daemon",
		"config", d.opts.ConfigFile,
		"pid", os.Getpid())

	// Register the daemon-owned commit-confirmed timeout rollback executor
	// (#1922 Item 1a). Wiring it here — at daemon init, before any commit can
	// be issued — covers ALL commit-confirmed paths (gRPC/REST/remote-cli
	// service mode as well as the interactive in-process CLI), not just the
	// interactive shell. The executor acquires d.applySem then runs store
	// promotion + dataplane re-apply atomically; see executeConfirmedRollback.
	d.store.SetRollbackExecutor(d.executeConfirmedRollback)

	// Register the #1922 Item 4 protected-set resolver so the dataplane
	// reconcile (compileZones unmanaged strip) never brings down the
	// management lifeline / fxp0, even on an empty/absent/rolled-back
	// config. The resolver lives in the reconcile path (config-independent);
	// it reads the persisted PCI-keyed lifeline record + the (optional)
	// `system management-interface` leaf. Set even in NoDataplane mode is
	// harmless (the compiler is not exercised there).
	dataplane.SetProtectedInterfaceResolver(d.resolveProtectedInterfaces)

	// ===== PHASES 1-4: mutating startup, cancellable via the signal ctx (#5807) =====
	// Each phase mutates real host / manager / dataplane state. runStartupOrAbort
	// checks the shutdown-signal context BEFORE each phase, so a SIGTERM (or
	// daemon-mode SIGINT) that arrives partway through skips the remaining phases
	// and runs the ordered teardown for whatever was already initialized (every
	// runShutdownSequence step nil-guards its manager, so a partial init tears
	// down cleanly) — then Run returns the non-nil abort error rather than
	// proceeding into steady state. A PLAIN phase error keeps the historical
	// path: return the error and let the deferred loop stops (#5308) run.
	var configCompileFailed bool
	phases := []startupPhase{
		{"config-load-bootstrap", func(context.Context) error {
			var e error
			configCompileFailed, e = d.loadAndBootstrapConfig()
			return e
		}},
		{"interface-naming", func(context.Context) error {
			d.setupInterfaceNaming()
			return nil
		}},
		{"manager-init", func(context.Context) error {
			return d.initManagers(configCompileFailed)
		}},
		// #9615: after manager-init so the feed manager exists; an alarm only,
		// never a refusal to keep the recovered window armed.
		{"recovered-confirm-preflight", func(context.Context) error {
			d.checkRecoveredConfirmTarget()
			return nil
		}},
		{"dataplane-setup", func(context.Context) error {
			return d.setupDataplaneAndInitialConfig()
		}},
	}
	if err := d.runStartupOrAbort(ctx, phases, func(abortErr error) error {
		return d.runShutdownSequence(&wg, stop, abortErr)
	}); err != nil {
		return err
	}

	// #2926: dedicated apply-abort context. A child of the signal context
	// captured at the top of Run, so a real daemon stop (SIGTERM, plus SIGINT in
	// daemon mode)
	// cancels an in-flight commit/remediation apply at its next coarse
	// boundary (applyConfigLocked C1/C2/C3) instead of blocking termination
	// behind netlink + an FRR reload + a Rust control-socket sync. It is kept
	// SEPARATE from d.daemonCtx: d.daemonCtx stays the (production-uncancelled,
	// context.Background) parent of the long-lived background goroutines —
	// flow-export/IPFIX relays, RPM probe-pin retry, the policy scheduler,
	// cluster comms, and the dp.Start dataplane runtime — which the shutdown
	// sequence below tears down EXPLICITLY and which the orderly teardown
	// (logFinalStats through dp.Telemetry, the HA rg_active clear through
	// dp.HA()) still needs live. applyCancelCtx() returns this context; only
	// the commit/sync/confirmed-commit applies route through it. The boot /
	// DHCP / feed applies and executeConfirmedRollback still pass
	// context.Background() unconditionally so they always run to completion.
	d.applyCancelContext, d.applyCancel = context.WithCancel(ctx)
	defer d.applyCancel()

	// Create event buffer (shared between event reader and CLI)
	eventBuf := logging.NewEventBuffer(1000)
	d.eventBuf = eventBuf

	// (wg is declared at the top of Run so the #5807 startup-abort path can pass
	// it to runShutdownSequence.)

	// NOTE: session sync dp wiring + sweep start moved into startClusterComms
	// goroutine to avoid race: d.sessionSync is created asynchronously.

	// ===== PHASE 5: Background-service starts + HTTP/gRPC API =====
	// Start background services if dataplane is loaded
	var er *logging.EventReader
	if rt := d.dataplane(); rt != nil {
		// StartFIBSync is a no-op on every in-tree backend: eBPF
		// resolves FIB queries via bpf_fib_lookup in-kernel and the
		// userspace AF_XDP runtime wraps that no-op through the
		// legacy adapter.  Call site retained for backends that
		// need a userspace route populator (DPDK had one; retired
		// in #1527 / #1525).
		// fibSyncStarter is a no-op on both in-tree backends
		// (kernel bpf_fib_lookup handles FIB resolution); the probe
		// is retained for forward compatibility (a future backend
		// may need a userspace route populator).
		if starter, ok := rt.(fibSyncStarter); ok {
			starter.StartFIBSync(ctx)
		}

		gc := d.newConntrackGC(rt, 10*time.Second)
		d.gc = gc

		// When the userspace dataplane is active, skip BPF session map
		// GC entirely — sessions are managed in user-space. Without
		// this, BatchLookup burns ~19% CPU scanning maps not used for
		// forwarding decisions.
		//
		// The helper still mirrors sessions to BPF conntrack for display
		// and periodically refreshes last_seen (~10s) so IterateSessions
		// callers see accurate idle times.  See #333.
		if _, ok := rt.(userspaceSessionDeltaDrainer); ok {
			gc.SkipSweep = func() bool { return true }
		}

		// In cluster mode, GC should only expire sessions when this node
		// is primary.  The peer primary ages sessions and syncs deletes.
		if d.cluster != nil {
			gc.IsLocalPrimary = d.cluster.IsLocalPrimaryAny
		}

		// Wire GC delete callbacks for incremental session sync.
		// Deletes are synced if this node is primary for any RG — the peer
		// ignores deletes for sessions it doesn't have.
		gc.OnDeleteV4 = func(key dataplane.SessionKey) {
			// Always sync deletes. Dropping deletes leaves stale sessions
			// on the peer indefinitely.
			if ss := d.getSessionSync(); d.cluster != nil && d.cluster.IsLocalPrimaryAny() && ss != nil {
				ss.QueueDeleteV4(key)
			}
		}
		gc.OnDeleteV6 = func(key dataplane.SessionKeyV6) {
			if ss := d.getSessionSync(); d.cluster != nil && d.cluster.IsLocalPrimaryAny() && ss != nil {
				ss.QueueDeleteV6(key)
			}
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			gc.Run(ctx)
		}()

		// #8607: keep the persistent-NAT SHOW table populated.
		//
		// It is started HERE, beside the GC whose SkipSweep above is the
		// reason it is needed, and NOT from cluster-comms wiring where the
		// #8121 lease PUSH loop lives. That loop is gated on being RG master,
		// which is right for a peer push and wrong for an operator table: a
		// standalone box with a persistent-NAT pool would keep the empty table
		// this exists to fix. The refresher is a no-op on any backend that
		// cannot export leases, so binding it to the run path costs nothing on
		// the others.
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.runPersistentNatShowRefreshLoop(ctx)
		}()

		evSrc, evErr := rt.Telemetry().NewEventSource()
		if evErr != nil {
			slog.Warn("failed to create event source", "err", evErr)
		}
		if evSrc != nil {
			er = logging.NewEventReader(evSrc, eventBuf)
			d.eventReader = er
			wg.Add(1)
			go func() {
				defer wg.Done()
				er.Run(ctx)
			}()

			// Wire ring buffer callback for near-real-time session sync.
			if d.getSessionSync() != nil {
				er.AddCallback(func(rec logging.EventRecord, raw []byte) {
					if rec.Type != "SESSION_OPEN" {
						return
					}
					if d.cluster == nil || !d.cluster.IsLocalPrimaryAny() {
						return
					}
					// Snapshot the session-sync object once per event (#4958)
					// so the connection check and both queue calls operate on
					// the same instance a concurrent comms restart cannot nil
					// between reads.
					ss := d.getSessionSync()
					if ss == nil || !ss.IsConnected() {
						return
					}
					if len(raw) < 56 {
						return
					}
					// #2114: one dataplane snapshot per event (plan §5.3
					// rule 7) — the closure runs on the event-reader
					// goroutine long after this block published it.
					rt := d.dataplane()
					if rt == nil {
						return
					}
					proto := raw[53]
					af := raw[55]
					if af == dataplane.AFInet6 {
						var key dataplane.SessionKeyV6
						copy(key.SrcIP[:], raw[8:24])
						copy(key.DstIP[:], raw[24:40])
						key.SrcPort = binary.BigEndian.Uint16(raw[40:42])
						key.DstPort = binary.BigEndian.Uint16(raw[42:44])
						key.Protocol = proto
						if val, err := rt.Sessions().GetV6(key); err == nil && val.IsReverse == 0 {
							if ss.ShouldSyncZone(val.IngressZone) {
								ss.QueueSessionV6(key, val)
							}
						}
					} else {
						var key dataplane.SessionKey
						copy(key.SrcIP[:], raw[8:12])
						copy(key.DstIP[:], raw[24:28])
						key.SrcPort = binary.BigEndian.Uint16(raw[40:42])
						key.DstPort = binary.BigEndian.Uint16(raw[42:44])
						key.Protocol = proto
						if val, err := rt.Sessions().GetV4(key); err == nil && val.IsReverse == 0 {
							if ss.ShouldSyncZone(val.IngressZone) {
								ss.QueueSessionV4(key, val)
							}
						}
					}
				})
			}

			// Set up syslog clients from active config
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.applySyslogConfig(er, cfg)
			}

			// Start NetFlow v9 + IPFIX exporters if configured (#2075).
			// This post-EventReader block is load-bearing: the earlier
			// boot applyConfig ran before d.eventReader existed, so the
			// apply-path reconcileFlowExporters no-op'd. This call is
			// what first starts the exporters at boot; later commits go
			// through the apply path.
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.reconcileFlowExporters(cfg)
			}

			// Set up flow traceoptions if configured
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.applyFlowTrace(cfg, er)
			}
		}
		if er == nil {
			if _, ok := rt.(userspaceEventStreamProvider); ok {
				er = logging.NewEventReader(nil, eventBuf)
				d.eventReader = er
				if cfg := d.store.ActiveConfig(); cfg != nil {
					d.applySyslogConfig(er, cfg)
					d.reconcileFlowExporters(cfg)
					d.applyFlowTrace(cfg, er)
				}
			}
		}

		if _, ok := rt.(userspaceEventStreamProvider); ok && d.cluster == nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.runUserspaceEventStream(ctx)
			}()
		}

		// #2079: start the NAT source pool-utilization-alarm monitor HERE —
		// after the dataplane cell and d.eventReader are both fully assigned above — so the
		// monitor goroutine's sampler (reads the cell) and emitter (reads
		// d.eventReader) never race with their initialization. Slow (10s) loop
		// over the helper's last-applied NAT pool snapshot; raises/clears
		// `show security alarms` entries with hysteresis and emits one
		// structured RT_NAT syslog line per transition. (The whole block is
		// gated on a non-NoDataplane dataplane being present.)
		//
		// #2114: route through maybeStartNATPoolAlarm, which gates on
		// !inBootstrap() in addition to a constructed dataplane. In bootstrap
		// mode the dataplane object exists (published) but is not armed, and
		// the bootstrap-exit path may clear the cell on an arm failure;
		// launching the sampler here would race that write. The monitor is
		// instead started in runBootstrapExitStartup once the dataplane is
		// armed. On a normal (non-bootstrap) boot the gate passes and the
		// monitor starts here exactly as before.
		d.maybeStartNATPoolAlarm()
	}

	// Start cluster heartbeat + sync after event fanout is initialized.
	// This avoids an HA startup race where runUserspaceEventStream wires a
	// decode-only fallback callback before d.eventReader exists.
	if d.cluster != nil {
		d.startClusterComms(ctx)
	}

	// Reconcile DHCP clients for interfaces configured with dhcp/dhcpv6.
	// The startup applyConfig above already reconciled them (#1793), so
	// this is normally a no-op; it is kept as a safety net to preserve
	// the documented ordering guarantee: clients run only after BPF load
	// + config compile, so HOST_INBOUND_DHCP flags are active before
	// DHCP packets start flowing.
	if !d.opts.NoDataplane {
		if cfg := d.store.ActiveConfig(); cfg != nil {
			d.reconcileDHCPClients(cfg)
		}
	}

	// Construct the dynamic-address feed manager UNCONDITIONALLY (#5036) — even
	// when no feed servers are configured at boot — and reconcile it against
	// the active config. Before this the manager was built only if boot-time
	// feed servers existed and Apply was never re-invoked, so a feed server
	// added (or removed/edited) on a later commit was silently ignored until
	// restart: a deny policy bound to the new feed armed with zero prefixes
	// (fail-open). ensureFeedManager makes d.feeds non-nil so the day-2
	// reconcile path (reconcileFeeds, wired into applyConfigLocked) can start
	// the producers; reconcileFeeds here does the initial hash-gated Apply for
	// a config that already declares feed servers.
	if cfg := d.store.ActiveConfig(); cfg != nil {
		d.ensureFeedManager()
		d.reconcileFeeds(cfg)
	}

	// RPM probes are started by the hash-gated reconcileRPM step inside
	// the startup applyConfig above (#1827); this safety net covers the
	// no-dataplane path where the startup apply may have run before
	// d.daemonCtx-dependent wiring settled.
	if cfg := d.store.ActiveConfig(); cfg != nil {
		d.reconcileRPM(cfg)
	}

	// Start LLDP if configured. The Manager is always created here (not gated
	// on a non-nil/enabled LLDP config), mirroring d.dhcpRelay above: the
	// d.lldpMgr pointer is then written exactly once, at boot, so the lock-free
	// reads on the gRPC / CLI `show lldp neighbors` handler goroutines never
	// race a day-2 commit (#2372 finding 3 — a lazy day-2 reassignment would be
	// a data race on the pointer). reconcileLLDP is the single source of truth
	// for LLDP start/stop/reconfigure: it runs here at boot and again on every
	// day-2 commit from applyConfigLocked, so a config change to `protocols
	// lldp` takes effect without a daemon restart, and it only ever calls
	// Apply()/Stop() on this already-constructed manager.
	d.lldpMgr = lldp.New()
	if cfg := d.store.ActiveConfig(); cfg != nil {
		d.reconcileLLDP(cfg)
	}

	// Event-options engine safety net. The engine was already constructed and
	// its RPM callback registered earlier (initEventEngine, before probes
	// started, #3755), and the boot applyConfig reconciled the policy set via
	// applyConfigLocked step 17. This mirrors the reconcileRPM/reconcileLLDP
	// boot safety nets above: it covers the bootstrap-mode path where the boot
	// applyConfig was suppressed, so a bootstrap-exit still loads any policies.
	// reconcileEventOptions is idempotent (Apply reconciles state), so a repeat
	// on the normal path is harmless (#3752).
	if cfg := d.store.ActiveConfig(); cfg != nil {
		d.reconcileEventOptions(cfg)
	}

	// Start DHCP relay. The Manager is always created (not gated on a
	// non-nil relay config) so the apply pipeline (reconcileDHCPRelay,
	// #2348) can start a relay added on a day-2 commit and stop one
	// removed — Apply diffs desired-vs-running and a nil config stops all
	// relays. The relay goroutines bind to d.daemonCtx (== ctx here) so
	// they outlive each apply call and are torn down only at daemon stop.
	d.dhcpRelay = dhcprelay.NewManager()
	// #2456: gate the upstream relay-forward on this node's VRRP/cluster MASTER
	// state for the relay interface's redundancy group. On a shared client
	// segment both the master and the backup receive the client broadcast;
	// without this gate BOTH relay it upstream (duplicate relayed requests with
	// different per-node giaddrs). The gate is read per packet, so a backup that
	// becomes master starts relaying immediately. Standalone / non-RG-owned
	// interfaces always relay (the gate returns true).
	d.dhcpRelay.SetMasterGate(d.relayMasterGateOpen)
	// Boot goes through the SAME reconcile the day-2 commit path uses (#9406)
	// rather than calling Apply directly. Apply needs an interface-name
	// resolver wired for the config being applied, and two call sites is two
	// places to forget it — the boot one being the one that matters, since a
	// box that boots with a relay configured never sees a commit. d.daemonCtx
	// is already set (line 72) and is the ctx this call passed anyway.
	if cfg := d.store.ActiveConfig(); cfg != nil {
		d.reconcileDHCPRelay(cfg)
	}

	// Port mirroring
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.ForwardingOptions.PortMirroring != nil {
		for name, inst := range cfg.ForwardingOptions.PortMirroring.Instances {
			slog.Info("Port mirroring configured", "instance", name, "input", inst.Input, "output", inst.Output)
		}
	}

	// Start the SNMP agent if configured (#3967). This is the FIRST start; it
	// runs regardless of config-only / bootstrap mode (unlike the boot
	// applyConfig, which is gated on !NoDataplane and suppressed in bootstrap)
	// so the agent serves even in degraded modes, matching pre-#3967 behavior.
	// The agent + link-state monitor are bound to a lifetime context derived
	// from d.daemonCtx (via startSNMPLocked) and torn down explicitly at
	// shutdown (teardownSNMP), NOT on this run WaitGroup. Setting snmpBootReady
	// hands day-2 lifecycle changes over to reconcileSNMP (applyConfigLocked):
	// an earlier boot apply left the start gated on snmpBootReady==false so the
	// boot apply and this block never double-start.
	d.snmpReconMu.Lock()
	if cfg := d.store.ActiveConfig(); snmpEnabled(cfg) {
		// Record the running-config hash only if the listener actually bound.
		// A discarded bind failure would otherwise leave SNMP down while state
		// says "applied", so a later identical commit no-ops forever (#5110);
		// leaving the hash unrecorded lets the next commit retry the bind.
		if err := d.startSNMPLocked(cfg); err != nil {
			slog.Error("SNMP agent failed to start at boot; a later commit will retry", "err", err)
		} else {
			d.snmpHash, d.snmpHashSet = snmpConfigHash(cfg), true
		}
	}
	d.snmpBootReady = true
	d.snmpReconMu.Unlock()

	// Start periodic neighbor resolution to keep ARP entries warm for
	// known forwarding targets (DNAT pools, gateways, address-book hosts).
	// Without this, bpf_fib_lookup returns NO_NEIGH when ARP expires,
	// causing cold-start delays or connection failures for return traffic.
	if !d.opts.NoDataplane {
		if cfg := d.store.ActiveConfig(); cfg != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.runPeriodicNeighborResolution(ctx)
			}()
			// #1197: kernel-as-authority neighbor listener.
			// Subscribes to RTM_NEWNEIGH/DELNEIGH and triggers
			// snapshot regen on forwarding-relevant changes.
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.neighborListener(ctx)
			}()
			// #7437: kernel route listener. Closes the learned-route
			// staleness window #7409 left — the helper FIB was only
			// republished on a commit or an ipmon actuation, so a route
			// the kernel learned in between still resolved NoRoute and
			// took the unadjudicated reinject. Marks only; the bounded
			// republish is pkg/coalesce's, because a per-event full
			// snapshot replace under BGP churn would starve session
			// installs on the shared control socket.
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.routeListener(ctx, coalesce.New(d.actuateLearnedRouteRefresh))
			}()
		}
		// #2197 item 2: always-on proxy-ARP/NDP re-assert. Started
		// unconditionally (independent of ActiveConfig at start, which it
		// re-reads each tick) so a non-commit link cycle that re-defaults
		// the per-interface proxy_arp/proxy_ndp sysctl self-heals within
		// proxyARPReassertInterval. The reconcile is a no-op when no
		// proxy-arp entries are configured, so the loop is cheap on configs
		// that do not use proxy-arp. It covers BOTH standalone and cluster
		// modes (reconcileRGStateLoop is cluster-only; monitorLinkState is
		// SNMP-gated).
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.proxyARPReassertLoop(ctx)
		}()
	}

	// #6793: the always-on retry owner for an RA sender whose ASYNCHRONOUS conn
	// open failed. Started unconditionally, alongside the proxy-ARP re-assert
	// and for the same reason: standalone applies RA only from a config apply
	// and reconcileRGStateLoop is cluster-only, so a boot-time bind failure
	// otherwise left the interface silent until an operator happened to commit.
	// The loop is free when every sender opened (its gate is a map walk over
	// live senders), so it costs nothing on configs that do not use RA.
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.raDeadSenderReassertLoop(ctx)
	}()

	// #6802: the always-on retry owner for a FAILED host-inbound conntrack
	// revocation. Started unconditionally, alongside the proxy-ARP and RA
	// re-assert loops and for the same reason: no ticker under pkg/daemon
	// re-runs applyConfig / applyHostInboundFilter / the flush, so before this
	// the only re-attempt was the next externally-triggered apply. The gate is a
	// single atomic pointer load, so the loop is free on a node whose
	// revocations have all succeeded.
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.hostInboundConntrackReassertLoop(ctx)
	}()

	// #6803: the always-on retry owner for a management listener whose serve
	// loop exited unexpectedly. Started unconditionally, alongside the proxy-ARP
	// and RA re-assert loops and for the same reason: the ONLY caller of
	// reconcileWebManagement is applyConfigLocked, so before this the endpoint
	// came back only when an operator happened to commit — on a box whose
	// management API had just died, which is the box they can no longer reach to
	// commit from. The gate is a state read on the reconciler, so the loop is
	// free on a node whose listeners are healthy and a no-op with no reconciler
	// at all.
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.mgmtListenerReassertLoop(ctx)
	}()

	// #6791: the always-on retry owner for a fabric IPVLAN overlay whose
	// creation failed. Started unconditionally, alongside the proxy-ARP and RA
	// re-asserts and for the same reason: BOTH standalone and cluster nodes
	// create fab0/fab1 only from a config apply, whose in-line retry gives up
	// after five seconds, so a boot-time netlink failure (a parent NIC still
	// being renamed after a power cycle) otherwise left the node with no
	// cluster heartbeat and no session-sync transport until an operator
	// happened to commit. It also covers the deferred (OnXSKBound) overlays,
	// which are created after the apply has returned and so cannot report
	// failure to the commit at all. The gate is one netlink name lookup per
	// configured fab device, so it costs nothing on a healthy node and nothing
	// at all on a config with no fabric interfaces.
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.fabricIPVLANReassertLoop(ctx)
	}()

	// #6800: the always-on retry owner for an xpf-managed service
	// configuration file whose RUNTIME reload failed after the file itself
	// converged (rsyslog drop-ins, chrony sources/threshold). Started
	// unconditionally, alongside the three re-asserts above and for the same
	// reason: both appliers run only from a config apply and gate their reload
	// on "did the on-disk file set change", so a failed reload was erased by
	// the convergence that preceded it and never retried — the daemon kept
	// serving the previous ruleset until an unrelated syslog/NTP edit or a
	// reboot. The gate is three booleans under one mutex, so the loop costs
	// nothing on a node that owes nothing.
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.serviceReloadDebtReassertLoop(ctx)
	}()

	// #1387 inc-2: start the always-on DHCP dynamic-DNS reconcile loop. It
	// is constructed UNCONDITIONALLY (idle when disabled) so an
	// enabled→disabled commit can still withdraw published records; the loop
	// is file-I/O + DNS only (no control-socket contention) and is gated to
	// the HA-active node (MASTER for >=1 RG; always-open standalone).
	if !d.opts.NoDataplane && d.ddns != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.runDDNSReconcileLoop(ctx)
		}()
	}

	// #2691 P2: start the always-on Surface A (router/interface-address) DDNS
	// reconcile loop. Same lifecycle + control-socket-free + per-RG-gated
	// discipline as the lease loop above; it reads netlink + the DHCP client
	// lease set and publishes the firewall's own addresses.
	if !d.opts.NoDataplane && d.surfaceA.mgr != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.runSurfaceADDNSReconcileLoop(ctx)
		}()
	}

	// Start VRRP event watcher (manager was created earlier, before applyConfig).
	// Uses context.Background() — the watcher must outlive daemon ctx cancel
	// so it can process VRRP BACKUP events during shutdown (rg_active cleanup).
	// The watcher exits when eventCh is closed by vrrpMgr.Stop().
	go d.watchVRRPEvents(context.Background())

	// Start reconciliation loop — periodic safety net that corrects
	// rg_active and blackhole route drift from dropped events.
	if d.cluster != nil {
		d.startReconcileRGStateLoop(ctx, &wg)
	}

	// Start HTTP API server if configured.
	if d.opts.APIAddr != "" {
		d.startHTTPServer(ctx, &wg, eventBuf)
	}

	// #881: forwarding-daemon CPU sampler (5s/1m/5m windows for
	// `show chassis forwarding`).  Shared between the gRPC server
	// and the local CLI; both paths call Snapshot() at query time.
	// Started here so the ring is populated before the first CLI.
	fwdSampler := fwdstatus.NewSampler(d.forwardingStatusDataplane(), fwdstatus.OSProcReader{})
	fwdSampler.Start(ctx)

	// Start gRPC API server.
	d.startGRPCServer(ctx, &wg, eventBuf, fwdSampler)

	// ===== PHASE 6: Main block / wait (interactive CLI or daemon-mode signal wait) =====
	// Start interactive CLI or block in daemon mode
	var runErr error
	if isInteractive() {
		// #2114 (r4): the LIVE indirection — cli.New stores dp on the CLI for
		// the console session's lifetime, so a startup snapshot outlived every
		// setDataplane(nil) and the console kept clearing counters on a
		// disowned backend. liveDataPlane (daemon_dp_live.go) re-reads the cell
		// per call and satisfies the local cliDataPlane probe
		// (runtime_probes.go) — structurally identical to pkg/cli's
		// package-private cliRuntime (pkg/cli/runtime.go, #1517). Go duck-types
		// the assignment to cli.New's dp parameter at this site; signature
		// drift surfaces as a compile error.
		var cliDP cliDataPlane
		if live, ok := d.liveDataplane(); ok {
			cliDP = live
		}
		shell := cli.New(d.store, cliDP, eventBuf, er, d.routing, d.frr, d.ipsec, d.dhcp, d.dhcpRelay, d.cluster)
		shell.SetVersion(d.opts.Version)
		shell.SetForwardingSampler(fwdSampler)
		// #797 H2 / #846: route in-process CLI commits through the
		// daemon's atomic commit+apply so they serialize against
		// HTTP/gRPC/event-engine commits under d.applySem.
		// applyConfigFn stays wired for non-commit paths (rollback,
		// confirm) that still need the full reconcile.
		shell.SetApplyConfigFn(d.applyConfig)
		// #5054: in-process CLI commits sync to the peer on the SAME
		// RG0-ownership policy as gRPC/REST — peer convergence is
		// transport-independent, decided in commitAndApplyOperator, not
		// by which API committed. Wiring lives in the shellCommitFn /
		// shellCommitConfirmedFn seams so it is fail-on-revert covered
		// (#5961, configsync_transport_5054_test.go).
		shell.SetCommitFns(d.shellCommitFn(), d.shellCommitConfirmedFn())
		// #5871: route the in-process `request system zeroize` through the
		// daemon's coordinated factory-reset transaction — the SAME function wired
		// into the gRPC server as grpcapi.Config.ZeroizeFn. factoryReset takes
		// d.applySem (draining any in-flight apply) and enters the terminal reset
		// generation BEFORE the wipe, so a console zeroize can no longer erase
		// state out-of-band while a concurrent commit / HA-sync / reconcile
		// re-creates the just-erased .configdb SSOT or re-renders the wiped secrets.
		shell.SetFactoryResetFn(d.factoryReset)
		// #6495: the #1930 kernel-channel state on the console. Before this,
		// an operator mid-roll had to leave the CLI for a root shell running
		// `xpfd upgrade kernel status`, or read journald — while the
		// xpf-deploy roll orchestrator polled that same verb over node_exec.
		// Automation had a path; the human did not.
		shell.SetKernelUpgradeStatusFn(d.kernelUpgradeStatus)
		// #6496: the day-0 config-import verdict for `show system
		// bootstrap-import` on the console. Same recorded snapshot /health and
		// the gRPC ShowText renderer read, so an operator standing at a fresh
		// box can answer "why didn't my day-0 config apply?" from the CLI they
		// are already in instead of leaving it to curl the loopback REST API.
		shell.SetBootstrapImportFn(d.bootstrapShowSnapshot)
		shell.SetRPMResultsFn(func() []*rpm.ProbeResult {
			if d.rpm != nil {
				return d.rpm.Results()
			}
			return nil
		})
		shell.SetIPMonStatusFn(func() []ipmon.PolicyStatus {
			if d.ipmon != nil {
				return d.ipmon.Status()
			}
			return nil
		})
		// #2079: active NAT pool-utilization alarms for `show security alarms`.
		shell.SetNATPoolAlarmsFn(d.natPoolAlarms)
		shell.SetFeedsFn(func() map[string]feeds.FeedInfo {
			if d.feeds != nil {
				return d.feeds.AllFeeds()
			}
			return nil
		})
		// #3105: live feed-prefix overlay so the in-process CLI's
		// `show security match-policies` / `test policy` simulators resolve
		// feed-backed address-names to their live CIDRs, matching the REST/gRPC
		// simulators (same FeedOverlayFn) and what the AF_XDP helper enforces.
		// Reads daemon-local state (feedSnapshotsForConfig -> the feed
		// manager's in-memory snapshots) — no control-socket call.
		shell.SetFeedOverlayFn(func() map[string][]string {
			return d.feedSnapshotsForConfig(d.store.ActiveConfig())
		})
		shell.SetLLDPNeighborsFn(func() []*lldp.Neighbor {
			if d.lldpMgr != nil {
				return d.lldpMgr.Neighbors()
			}
			return nil
		})
		// #1387 inc-2: DHCP dynamic-DNS status hooks for the in-process CLI.
		shell.SetDDNSStatsFn(d.DDNSStats)
		shell.SetDDNSOwnedRecordsFn(d.OwnedDDNSRecords)
		shell.SetSurfaceADDNSStatsFn(d.SurfaceAStats)
		shell.SetSurfaceADDNSStatusFn(d.SurfaceAStatus)
		shell.SetSurfaceADDNSForceFn(d.ForceDDNSUpdate)
		shell.SetFlowCollectorHealthFn(d.FlowCollectorHealth)
		// #6385: the local console `show system services` renderer reports the
		// EFFECTIVE post-bind listener addresses from the SAME daemon-owned
		// snapshot the remote gRPC renderer reads (grpcapi.Config.ListenersFn), so
		// local and remote never disagree.
		shell.SetListenersFn(d.effectiveListeners)
		shell.SetVRRPManager(d.vrrpMgr)
		shell.SetFabricPeer(func() []string {
			var addrs []string
			if d.syncPeerAddr != "" {
				addrs = append(addrs, d.syncPeerAddr)
			} else {
				d.fabricMu.RLock()
				if d.fabricPeerIP != nil {
					addrs = append(addrs, d.fabricPeerIP.String())
				}
				d.fabricMu.RUnlock()
			}
			if d.syncPeerAddr1 != "" {
				addrs = append(addrs, d.syncPeerAddr1)
			} else {
				d.fabricMu.RLock()
				if d.fabricPeerIP1 != nil {
					addrs = append(addrs, d.fabricPeerIP1.String())
				}
				d.fabricMu.RUnlock()
			}
			return addrs
		}, func() string {
			if c := d.store.ActiveConfig(); c != nil && c.Chassis.Cluster != nil {
				cc := c.Chassis.Cluster
				if cc.ControlInterface != "" || cc.FabricInterface != "" {
					return config.ManagementVRFDeviceName
				}
			}
			return ""
		}())

		// Set the RBAC login class for the in-process console shell (#6701).
		// See applyCLILoginClass (cli_rbac.go) for why identity comes from the
		// kernel, and for the THREE outcomes — an earlier revision of this
		// comment said "the default is the restrictive class, not super-user",
		// which is only two of them (#6706 review r11): a caller RBAC cannot
		// place gets the restrictive class, uid 0 keeps the Junos super-user
		// default, and a config with no `system login` at all leaves the class
		// UNSET, which is pkg/cli's legacy allow-everything mode. An earlier
		// revision called that "more permissive than super-user"; measured, the
		// two are BEHAVIOURALLY EQUIVALENT — checkPermission returns nil for
		// every command under both (`userClass == ""` short-circuits;
		// super-user holds PermAll) and showConfigRedacted is false for both,
		// so secrets render in cleartext either way (permissions.go).
		applyCLILoginClass(shell, d.store.ActiveConfig(), osident.Current())

		// Run CLI in a goroutine so we can still handle signals
		errCh := make(chan error, 1)
		go func() {
			errCh <- shell.Run()
		}()

		select {
		case err := <-errCh:
			if err != nil {
				runErr = fmt.Errorf("CLI: %w", err)
			}
		case err := <-d.fatalCh:
			// #8233: shut down and carry the reason out as the process exit
			// status, rather than the zero a signal produces.
			slog.Error("fatal condition; shutting down", "err", err)
			runErr = err
		case <-ctx.Done():
			slog.Info("signal received, shutting down")
		}
	} else {
		slog.Info("daemon mode (non-interactive), waiting for signals")
		select {
		case err := <-d.fatalCh:
			// #8233: the only non-signal way out of the daemon-mode wait. Run
			// returns this, so cmd/xpfd exits NON-ZERO and the operator sees
			// which condition ended the daemon instead of a clean stop.
			slog.Error("fatal condition; shutting down", "err", err)
			runErr = err
		case <-ctx.Done():
			slog.Info("signal received, shutting down")
		}
	}

	// ===== PHASE 7: Shutdown sequence (extracted to runShutdownSequence, #4662) =====
	return d.runShutdownSequence(&wg, stop, runErr)
}

// startupSignalContext returns a child of parent that is cancelled when the
// daemon receives a shutdown signal, captured at the TOP of Run so a signal
// during the mutating startup phases aborts startup instead of the process
// default-terminating (#5807). The signal set is mode-dependent and matches the
// historical late install: interactive mode catches only SIGTERM so the CLI
// keeps SIGINT for Ctrl-C command cancellation; daemon (non-interactive) mode
// catches SIGTERM and SIGINT. Extracted as a named seam so a test can assert the
// returned context is a cancellable child (not context.Background, whose Done()
// is nil) without delivering a real OS signal.
func startupSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	if isInteractive() {
		return signal.NotifyContext(parent, syscall.SIGTERM)
	}
	return signal.NotifyContext(parent, syscall.SIGTERM, syscall.SIGINT)
}

// startupPhase is one ordered, MUTATING startup step run under the
// shutdown-signal context (#5807). name is used only for the abort log/error.
type startupPhase struct {
	name string
	run  func(context.Context) error
}

// runStartupPhases executes the mutating startup phases in order, checking the
// shutdown-signal context for cancellation BEFORE each phase and once more after
// the last (#5807). A SIGTERM / daemon-SIGINT that arrives mid-startup therefore
// stops the sequence at the next phase boundary — the remaining phases do NOT
// run and their mutations never happen — and the wrapped context error is
// returned. A phase's own error is returned as-is (unwrapped). It returns nil
// only when every phase ran and the context was never cancelled.
//
// Cancellation is observed BETWEEN phases (a phase already in flight runs to
// completion): the mutating phases use context.Background()-equivalent
// long-lived wiring internally, so this coarse, boundary-level cancellation is
// the abort granularity — matched to the coarse boot mutations it guards.
func (d *Daemon) runStartupPhases(ctx context.Context, phases []startupPhase) error {
	for _, p := range phases {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("startup aborted by shutdown signal before phase %q: %w", p.name, err)
		}
		if err := p.run(ctx); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("startup aborted by shutdown signal after the final phase: %w", err)
	}
	return nil
}

// runStartupOrAbort runs the mutating startup phases (runStartupPhases) and,
// when a shutdown signal cancelled startup mid-way, runs the ordered teardown
// for whatever was initialized before returning the non-nil abort error (#5807).
// teardown is injected (Run passes runShutdownSequence) so the abort→cleanup
// wiring is unit-testable without executing the real subsystem teardown.
//
// A PLAIN phase error (ctx NOT cancelled) is returned WITHOUT running teardown:
// that preserves the pre-#5807 early-error path, where Run's deferred
// stopPolicySchedulerLoop / stopPinRetryLoop (#5308) are the intended cleanup
// and running the full ordered teardown was deliberately not done. The
// distinguishing test is ctx.Err() (was the SIGNAL context cancelled), never the
// returned error's identity, so a phase error that merely wraps a context error
// is not mistaken for a signal abort.
func (d *Daemon) runStartupOrAbort(ctx context.Context, phases []startupPhase, teardown func(error) error) error {
	err := d.runStartupPhases(ctx, phases)
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		slog.Warn("xpf daemon: shutdown signal during startup — running teardown for the "+
			"initialized subset before exit (partial-init safe)", "err", err)
		return teardown(err)
	}
	return err
}

// startReconcileRGStateLoop launches the RG-state reconcile safety-net loop and
// registers it on the run WaitGroup so runShutdownSequence's wg.Wait() JOINS it
// BEFORE the HA ownership-relinquish steps (rg_active clear, RA withdraw,
// direct-mode VIP removal, VRRP Stop). #5681 / M23: as a bare goroutine the loop
// was never joined — stop() cancelled its ctx, but a tick already past the
// ctx.Done() select (or blocked mid-pass on a control-socket update) could
// complete AFTER wg.Wait() during ownership cleanup and re-assert mastership
// (re-enable forwarding / re-add VIPs), opening a transient dual-master /
// blackhole window on planned shutdown or failover. Quiescing it early removes
// no needed shutdown behavior: the VRRP BACKUP transition during shutdown is
// driven by watchVRRPEvents (deliberately on context.Background()), not this
// safety-net loop. Mirrors the sibling reconcile loops (DDNS/proxy-ARP/Surface
// A) that were already wg-registered.
func (d *Daemon) startReconcileRGStateLoop(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.reconcileRGStateLoop(ctx)
	}()
}
