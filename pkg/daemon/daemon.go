// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcprelay"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/eventengine"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/flowexport"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/grpcapi"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/natpoolalarm"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/ra"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/scheduler"
	"github.com/psaab/xpf/pkg/snmp"
	"github.com/psaab/xpf/pkg/upgrade"
	"github.com/psaab/xpf/pkg/vrrp"
)

// Options configures the daemon.
type Options struct {
	ConfigFile  string
	NoDataplane bool   // set to true to run without a dataplane (config-only mode)
	APIAddr     string // HTTP API listen address (empty = disabled)
	GRPCAddr    string // gRPC API listen address (empty = disabled)
	Version     string // software version string
	// #1620: cold-path latency histogram sample mask. nil pointer ⇒
	// userspace-dp uses default 0xff (1-in-256). Non-nil pointer ⇒
	// the operator explicitly set --cold-path-sample-mask (and, if
	// the value is 0, also --enable-cold-path-1-in-1-sampling). The
	// daemon forwards this verbatim to userspace-dp via the
	// `cold_path_sample_mask` field on ConfigSnapshot.
	ColdPathSampleMask *uint64
}

// nodeIDFile is the path to the cluster node ID file.
// If this file exists and contains a valid integer (0 or 1), the daemon
// runs in cluster mode with ${node} variable expansion. If the file does
// not exist, the daemon runs in standalone mode.
const nodeIDFile = "/etc/xpf/node-id"

// dpSlot is the immutable publication payload for Daemon.dpCell (#2114):
// the runtime dataplane interface value, frozen at Store time so a reader
// observes either no dataplane or the full (type, data) pair — never a
// torn multiword interface read.
type dpSlot struct{ v dataplane.RuntimeDataPlane }

// Daemon is the main xpf daemon.
type Daemon struct {
	opts  Options
	store *configstore.Store
	// dpCell is the #2114 single synchronized publication point for the
	// runtime dataplane. A nil cell means no dataplane (NoDataplane mode,
	// a retired-backend construction failure, or an arm-failure
	// teardown). Every ACQUISITION goes through dataplane() /
	// setDataplane(); the same atomic.Pointer publication idiom as
	// natPoolAlarm (#2116) below. The plain interface field this replaces
	// raced the bootstrap-exit `d.dp = nil` writer against the
	// forwarding-status sampler, the HA watcher chain, and the recovered
	// commit-confirmed rollback timer (#2114).
	//
	// The cell is a PUBLICATION protocol, not a LIFETIME one. It does not
	// stop an acquired handle from outliving its publication, and it does
	// not un-publish a backend that Teardown() has detached (the
	// commit-confirmed rollback deliberately keeps the torn-down object
	// here so a corrected commit re-arms it — #6741 owns that window).
	// The three operator-facing management servers therefore receive
	// liveDataPlane (daemon_dp_live.go), which re-reads this cell per
	// call, instead of a startup snapshot of the handle; the conntrack
	// GC, cluster SessionSync, and the userspace event-stream loop stay
	// deliberate capture-once consumers (rationale in daemon_dp_live.go
	// and pkg/daemon/README.md).
	dpCell atomic.Pointer[dpSlot]

	// dataplaneArmed is the #5275 arm state: true ONLY while the runtime
	// dataplane has been proven to have STARTED (rt.Start /
	// LoadUserspaceShim returned nil) in this daemon's lifetime. It is the
	// predicate the kernel transit-forwarding gate keys off — see
	// daemon_transit_gate.go for the full contract, the two knobs it owns,
	// and why an unarmed node must not route transit.
	//
	// Deliberately SEPARATE from dpCell: the cell answers "is a backend
	// published", which is not the same question. A backend is published
	// before Start is attempted, and the commit-confirmed rollback keeps a
	// torn-down backend published on purpose (#6741), so a non-nil cell is
	// not proof of an armed forwarding path.
	dataplaneArmed atomic.Bool

	networkd *networkd.Manager
	routing  *routing.Manager
	frr      *frr.Manager
	ipsec    *ipsec.Manager
	ra       *ra.Manager
	dhcp     *dhcp.Manager
	// dnsBootDone gates the #1715 DNS boot policy. It is false during the
	// single boot-time applyConfig (which runs before DHCP clients start,
	// so the lease set is empty) and set true immediately after. While
	// false, an empty DNS merge only repairs a dangling/stub/missing
	// /etc/resolv.conf and never clobbers a pre-existing good file; once
	// true, an empty merge is a declarative "clear DNS" (deleting all
	// `name-server` / expiring the last lease clears the file). Written
	// once after the boot apply and read only under applySem in
	// reconcileDNSLocked.
	dnsBootDone bool
	dhcpServer  *dhcpserver.Manager
	// ddns is the always-on DHCP dynamic-DNS manager (#1387 inc-2). It is
	// constructed UNCONDITIONALLY at daemon start (plan §4.2) — even when
	// DDNS is disabled — so an enabled→disabled commit always has a running
	// loop to withdraw the records it published. The reconcile loop is
	// file-I/O + DNS-network only (no control-socket calls), gated to the
	// HA-active node, and nudged on commit + MASTER transition.
	ddns *dhcpserver.DDNSManager
	// ddnsReconcileNowCh nudges the DDNS reconcile loop for an immediate
	// pass (config commit / VRRP MASTER takeover). Buffered depth 1 +
	// non-blocking send: coalesces a burst into one pending wakeup.
	ddnsReconcileNowCh chan struct{}
	// ddnsReconcileInFlight is the no-freeze guard for the DDNS loop: a
	// reconcile pass runs in a guarded goroutine (mirrors the neighbor
	// loop) so a hung DNS server can never wedge the loop or starve the
	// nudge channel.
	ddnsReconcileInFlight atomic.Bool
	// surfaceA groups the always-on Surface A (router/interface-address) DDNS
	// manager plus its reconcile-supervision + per-warning-dedup state. This is
	// increment 5 of the #4407 Daemon god-struct decomposition — pure field
	// grouping, no behavior/locking change; every field keeps its exact type and
	// access contract and is reached as d.surfaceA.<field>. See surfaceAState in
	// daemon_ddns_surface_a.go (the file that owns the reconcile loop). Surface B
	// — the DHCP-lease ddns* manager above — stays a set of flat Daemon fields:
	// it is a DIFFERENT DDNS mechanism, exactly the two-mechanism split increment
	// 1's note anticipated when it kept the mirrored ddnsReconcile* fields flat.
	surfaceA surfaceAState
	// #2239 HA DHCP-server lease sync (PATH C). These fields were grouped
	// into dhcpLeaseSyncState (see daemon_dhcp_lease_sync.go) as increment 1
	// of the #4407 Daemon god-struct decomposition — grouping only, no
	// behavior change. The mirrored ddnsReconcile* fields above remain flat.
	dhcpLeaseSync  dhcpLeaseSyncState
	ipsecSANudgeCh chan struct{} // nudge: peer (re)connect -> IPsec SA re-advertise (#4385)
	// #4899 DHCP-lease-change IPsec rebind recovery state. When a DHCP
	// renewal moves the kernel address an IPsec gateway is dynamically bound
	// to (external-interface, no explicit local-address), the management-only
	// lease callback re-renders swanctl local_addrs best-effort
	// (reapplyIPsecForLeaseChange). Before #4899 a swanctl reload failure on
	// that path was dropped as a slog.Warn: strongSwan kept binding the STALE
	// lease address, the tunnel could not re-establish, and the operator had
	// no signal and no recovery. These fields make the failure RECOVERABLE
	// (a single-flight retry loop mirroring probePinRetryLoop, #1895) and
	// VISIBLE (the ipsecRebindPending gauge). All mutations of the two flags
	// happen under ipsecRebindMu; ipsecRebindPending is atomic so the metrics
	// collector reads it lock-free.
	ipsecRebindMu          sync.Mutex
	ipsecRebindPending     atomic.Bool // health signal: local_addrs stale, rebind not yet reconverged
	ipsecRebindRetryActive bool        // single-flight guard for the retry loop (guarded by ipsecRebindMu)
	// #5523 C179-093: cancel + join for the retry loop at shutdown. The loop
	// used to bind directly to d.daemonCtx (the RAW background context that is
	// NEVER cancelled in production, #5807), so it leaked past shutdown and a
	// 30s rebind tick could run a swanctl reapply while teardown was in flight.
	// It now binds to a cancellable child (ipsecRebindCancel) and is tracked on
	// ipsecRebindWg so stopIPsecRebindLoop can cancel + join it, mirroring the
	// #5308 stopPinRetryLoop. ipsecRebindStopped latches the stop so a late
	// armIPsecRebind after shutdown never starts a new loop (that Add would race
	// ipsecRebindWg.Wait). All three are guarded by ipsecRebindMu.
	ipsecRebindCancel  context.CancelFunc
	ipsecRebindWg      sync.WaitGroup
	ipsecRebindStopped bool
	// ipsecRebindRetryEvery overrides the retry cadence (tests); 0 =
	// ipsecRebindRetryInterval.
	ipsecRebindRetryEvery time.Duration
	// ipsecApply is the test seam for the swanctl re-render+reload on the
	// lease-change path; nil = d.ipsec.Apply(ipsec.PrepareConfig(cfg)).
	ipsecApply func(*config.Config) error
	// ipsecRebindActiveCfg is the test seam for the config the retry loop
	// re-renders against; nil = d.store.ActiveConfig (so a commit that
	// removes the VPN naturally converges the loop instead of resurrecting
	// deleted config).
	ipsecRebindActiveCfg func() *config.Config
	feeds                *feeds.Manager
	// feedsMu serializes reconcileFeeds callers and guards activeFeedsHash
	// (#5036). d.feeds itself is constructed once at boot (unconditionally,
	// even with no feed servers) and never reassigned, so its pointer is
	// race-free; only the day-2 reconcile bookkeeping needs the lock.
	feedsMu sync.Mutex
	// activeFeedsHash is the config-hash gate for the day-2 feed reconcile
	// (#5036): d.feeds.Apply (producer swap; persisted feeds carry their
	// last-good snapshot forward, #5282) runs only when the feed-server
	// configuration actually changes, so a feed CONTENT update (which re-enters
	// applyConfig via onUpdate) does not thrash the refresh goroutines.
	activeFeedsHash [32]byte
	rpm             *rpm.Manager
	rpmMu           sync.Mutex // serializes reconcileRPM callers (#1827)
	activeRPMHash   [32]byte   // config-hash gate for RPM re-apply (#1827)
	// rpmPinsFailed records that the last probe-pin install left at
	// least one pin unprogrammed (#1895): the install is retried
	// (without restarting probes) on hash-gated reconcileRPM calls AND
	// by the slow periodic probePinRetryLoop until it succeeds.
	// Guarded by rpmMu.
	rpmPinsFailed bool
	// rpmPinRetryActive is true while a probePinRetryLoop goroutine is
	// running (#1895 AGY fold — autonomous recovery of boot-time pin
	// failures on a quiet box, no commit required). Guarded by rpmMu.
	rpmPinRetryActive bool
	// rpmEffective/rpmRethMap are the last-applied effective RPM
	// config + RETH map, kept for the periodic pin retry (which has no
	// fresh cfg in hand). Guarded by rpmMu.
	rpmEffective *config.RPMConfig
	rpmRethMap   map[string]string
	// probePinRetryEvery overrides the periodic pin-retry cadence
	// (tests); 0 = probePinRetryInterval.
	probePinRetryEvery time.Duration
	// probePinApply is the test seam for probe-pin programming; nil =
	// d.routing.ApplyProbePins (#1895).
	probePinApply func([]routing.ProbePin) map[string]error
	// pinRetryCancel/pinRetryWg/pinRetryStopped scope the probePinRetryLoop
	// lifecycle so daemon shutdown can cancel + join it BEFORE FRR/routing
	// teardown (#5308). The loop used to bind to d.daemonCtx (never cancelled
	// in production), so a late retry tick could run routing-pin syscalls
	// after the routing manager was gone — and it leaked outright for library
	// callers where Run() returns. maybeStartPinRetryLoopLocked now derives a
	// cancellable child of d.daemonCtx and tracks the goroutine on pinRetryWg;
	// stopPinRetryLoop cancels + joins. All three are guarded by rpmMu;
	// pinRetryStopped latches on shutdown so no new loop can be started after
	// the join (which would race pinRetryWg.Wait).
	pinRetryCancel  context.CancelFunc
	pinRetryWg      sync.WaitGroup
	pinRetryStopped bool
	ipmon           *ipmon.Engine
	// natPoolAlarm is the #2079 NAT source pool-utilization-alarm monitor:
	// a slow (10s) loop over the helper's last-applied NAT pool snapshot
	// that raises/clears `show security alarms` entries with hysteresis and
	// emits one structured RT_NAT syslog line per transition. Nil in
	// NoDataplane mode (no helper to sample).
	//
	// #2114: atomic.Pointer because the monitor is now started/stopped at
	// RUNTIME (bootstrap exit arms it; bootstrap rollback stops+discards
	// it) concurrently with the `show security alarms` render reader
	// (natPoolAlarms, wired into the gRPC/CLI callbacks). All access goes
	// through maybeStartNATPoolAlarm / stopAndDiscardNATPoolAlarm /
	// natPoolAlarms so the pointer is never read or written unsynchronized.
	natPoolAlarm atomic.Pointer[natpoolalarm.Monitor]
	// natPoolAlarmTestTick overrides the monitor's sampler cadence at
	// construction time (#2114 race tests only). Zero in production (default
	// 10s). Read once in maybeStartNATPoolAlarm before Start.
	natPoolAlarmTestTick time.Duration
	// pendingFIBBump records an UNCONFIRMED FIB-generation bump after a
	// successful route-overlay publish (#1844, Codex plan r2-1): the
	// bump_fib_generation control message failed, so the next actuation
	// must retry the bump even when its publish is a duplicate-skip —
	// otherwise cached flow routes stay pinned to pre-failover paths.
	// Mutated only in actuateRouteOverlayLocked under applySem.
	pendingFIBBump bool
	// #2461: one exporter per per-flow-server template group, so a
	// collector receives the template it referenced (was a single exporter
	// using the first map-iteration template for every collector).
	flowExporters []*flowexport.Exporter
	flowCancel    context.CancelFunc
	// #3742: flowWg/ipfixWg are POINTERS so a build-before-swap reconcile
	// can start the new generation on a FRESH WaitGroup while the old
	// generation is waited on separately during teardown. A value field
	// cannot be handed off (a WaitGroup must not be copied). nil == no
	// generation running.
	flowWg         *sync.WaitGroup
	ipfixExporters []*flowexport.IPFIXExporter
	ipfixCancel    context.CancelFunc
	ipfixWg        *sync.WaitGroup
	// #2075 flowexport reconcile state. The bundle pointers carry the
	// live (exporter, resolved-config) pair read lock-free by the
	// once-registered session-close callbacks; reconcile swaps them
	// atomically. The per-family hashes gate the reconcile so an
	// unrelated commit never bounces a healthy exporter; the *HashSet
	// bools distinguish "never reconciled" from "reconciled to the
	// nil sentinel". The *ReconMu serialize the reconcile swap against
	// shutdown's stopFlow/IPFIXExporter (both touch the cancel/wg).
	flowBundle  atomic.Pointer[exporterBundle]
	flowHash    [32]byte
	flowHashSet bool
	flowCBOnce  sync.Once
	flowReconMu sync.Mutex
	// #3742: last NetFlow v9 exporter build error. Set (under flowReconMu)
	// when a reconcile's NewExporter build failed and the OLD exporters were
	// kept running so export stayed up; cleared on the next successful
	// reconcile. Surfaced via FlowExportError().
	flowExportErr error
	// #4963 fixed-cardinality handoff-drop totals. Each exporter of a family
	// is injected (SetHandoffCounter) with a pointer to the matching counter
	// here, so a session-close record rejected because it reached an exporter
	// that was already retired during a reconcile (loaded the pre-swap bundle
	// too late) is counted at ONE stable location per family regardless of how
	// many exporter generations have come and gone — the record is no longer
	// silently stranded. Surfaced via FlowExportHandoffDropped().
	flowHandoffDropped  atomic.Uint64
	ipfixHandoffDropped atomic.Uint64
	ipfixBundlePtr      atomic.Pointer[ipfixBundle]
	ipfixHash           [32]byte
	ipfixHashSet        bool
	ipfixCBOnce         sync.Once
	ipfixReconMu        sync.Mutex
	ipfixExportErr      error
	dhcpRelay           *dhcprelay.Manager
	// mgmt owns the HTTP/HTTPS management-listener lifecycle (#5866): it starts
	// the listener at boot and, on every day-2 commit, reconciles the live
	// listener + authentication snapshot against the committed web-management
	// config (make-before-break rebind on an endpoint change; live auth swap on
	// an unchanged bind). nil when the API is not enabled (--api-addr empty).
	mgmt *managementReconciler
	// staleCertMu guards staleCertPending and staleCertGen, and publishes the
	// mgmt pointer the stale-cert delivery path reads (#6827 round 5) — so that
	// read is memory-model safe rather than a benign-looking data race.
	//
	// ONLY that read. `mgmt` is still read unguarded elsewhere (daemon_run_servers.go
	// and reconcileWebManagement), exactly as it was before #6827 — the publish
	// was unsynchronised on every path then, and this PR narrowed the problem to
	// the path it touched rather than solving it. Do not read this as "mgmt is
	// guarded"; it is not, and the remaining readers are tracked separately.
	staleCertMu sync.Mutex
	// staleCertPending records that a `set system host-name` moved the kernel
	// name and the management-TLS staleness diagnostic has NOT yet been
	// delivered (#6827). It is a FLAG, not a stored name: the host name is read
	// from the kernel at delivery time, so a deferred diagnosis can never
	// report a name that is no longer current.
	//
	// It stays set until a delivery actually reaches a served certificate. The
	// boot config apply runs in startup phase 4 while startHTTPServer builds
	// mgmt much later in Run, and HTTPS may be off or fail to bind for far
	// longer than that — but the certificate is DURABLE on disk, so the
	// staleness outlives every one of those gaps. Clearing the flag on a
	// delivery that reached nothing would lose the diagnosis permanently: the
	// next boot's applyHostname sees the name already applied and returns
	// early, and the load path's inferred heuristic declines cross-shape drift
	// by design (see hostNameLikelyAccessIdentity's residual note).
	//
	// It is process-local: a debt still owed when the daemon stops is
	// discarded, which is one of the two states that residual note covers.
	//
	// Guarded by staleCertMu.
	staleCertPending bool
	// staleCertGen advances on every rename. A delivery claims a generation and
	// clears the debt only if it is still current, so a rename landing while an
	// in-flight delivery is unlocked is not settled by that older delivery
	// (#6827 round 5).
	//
	// Guarded by staleCertMu.
	staleCertGen uint64
	snmpAgent    *snmp.Agent

	// --- SNMP subsystem reconcile-on-commit state (#3967) ---
	// The SNMP agent is a start-once-at-boot subsystem: the boot block in
	// daemon_run.go performs the first start (respecting config-only /
	// bootstrap modes), and every later commit reconciles through
	// reconcileSNMP (called from applyConfigLocked). snmpReconMu serializes
	// the reconcile against itself; the agent's own cfgMu still guards the
	// live authorization/community swap done by UpdateConfig.
	snmpReconMu        sync.Mutex
	snmpCtx            context.Context    // lifetime context for the agent + monitor goroutines
	snmpCancel         context.CancelFunc // cancels snmpCtx (day-2 disable / shutdown)
	snmpWg             *sync.WaitGroup    // joins the listener + link-state monitor goroutines
	snmpHash           uint64             // FxHash-free FNV of the live SNMP stanza (idempotence gate)
	snmpHashSet        bool               // true once snmpHash reflects a running agent
	snmpMonitorRunning bool               // true while the link-state trap monitor goroutine is live
	snmpBootReady      bool               // set true after the boot block; gates the reconcile START path
	// snmpServe binds the agent's UDP/161 listener and then serves for the
	// lifetime of ctx. It reports the bind outcome on `ready` exactly once —
	// nil once bound (before serving), or the bind error — so startSNMPLocked
	// can publish the running-config hash ONLY on a confirmed bind (#5110). nil
	// ⇒ the default Agent.Bind + Agent.Serve split (binds UDP/161, needs
	// CAP_NET_BIND_SERVICE). The reconcile unit test injects a seam so it can
	// drive enable/disable — and simulate a bind failure — without binding a
	// privileged socket (#3967, #5110).
	snmpServe func(ctx context.Context, agent *snmp.Agent, ready chan<- error)
	// snmpBootsPath overrides the SNMPv3 engineBoots persistence path passed
	// to snmp.NewAgentWithPaths. Empty ⇒ the package default. Tests inject
	// a temp path so a reconcile-triggered start does not touch /var/lib/xpf
	// (#3967).
	snmpBootsPath string
	// snmpEngineIDPath overrides the per-device EngineID component persistence
	// path (#5283). Empty ⇒ the package default. Tests inject a temp path so a
	// reconcile-triggered start does not touch /var/lib/xpf.
	snmpEngineIDPath string
	lldpMgr          *lldp.Manager
	lldpApplied      *lldp.LLDPConfig // last effective LLDP config Apply()'d (#2372 diff-guard); nil = stopped
	lldpApplyInit    bool             // true once reconcileLLDP has run at least once
	// scheduler is the live policy-window scheduler. It is an atomic.Pointer so
	// the metrics collector can read it lock-free for the
	// xpf_scheduler_republish_fail_closed SSOT gauge
	// (SchedulerRepublishFailClosed → scheduler.RepublishFailClosed) while a
	// commit-time reconcile swaps it under applySem. All mutations still happen
	// under applySem (the "Locked" reconcile convention); the atomic only makes
	// the concurrent lock-free read of the pointer word race-clean (#5669).
	scheduler       atomic.Pointer[scheduler.Scheduler]
	schedulerCancel context.CancelFunc
	// schedulerWg tracks every policy-scheduler Run() goroutine generation so
	// daemon shutdown can join it after cancelling, and schedulerStopped
	// latches on shutdown so no new generation is started after the join
	// (#5308). Before this the scheduler goroutine was cancelled only on a
	// config-replace, so at shutdown a late tick could republish policy
	// schedule state through an already-torn-down runtime, and it leaked for
	// library callers where Run() returns. schedulerCancel/schedulerWg/
	// schedulerStopped are all mutated under applySem (the "Locked" convention
	// for the scheduler start/reconcile path).
	schedulerWg               sync.WaitGroup
	schedulerStopped          bool
	policySchedulerConfigHash [32]byte
	policySchedulerEpoch      atomic.Uint64
	// #3780: scheduler republish-failure observability.
	// schedulerRepublishFailing is 1 while the most recent
	// scheduler-driven policy republish failed and has not yet
	// converged (stale enforcement past a schedule window);
	// schedulerRepublishFirstFailNanos is the wall-clock start of the
	// current failure streak (0 when healthy) for the stale-age gauge.
	// Set in publishPolicyScheduleState, cleared on recovery or
	// scheduler teardown; read lock-free by the metrics collector.
	schedulerRepublishFailing        atomic.Bool
	schedulerRepublishFirstFailNanos atomic.Int64
	cluster                          *cluster.Manager
	// kernelUpgradeHoldFailClosed records that the kernel-upgrade election hold
	// was set FAIL-CLOSED because the kernel-upgrade journal was UNREADABLE at
	// boot (I/O error / corruption / parse failure — NOT a clean ENOENT), rather
	// than because a candidate was affirmatively ARMED (#5682 / codex-review-182
	// M24). It distinguishes the two holds for reconcileKernelUpgradeHold: a
	// normal armed hold releases ONLY on the durable promotion marker (so the
	// revert window can't transiently promote an unverified candidate), whereas a
	// fail-closed hold ALSO self-heals — a later SUCCESSFUL journal read that
	// shows the node is not armed releases it, so a transient I/O blip does not
	// strand the node SECONDARY forever. Written once at boot (before the
	// self-recovery goroutine starts) and read/written only from that goroutine's
	// reconcile tick thereafter, so no lock is needed.
	kernelUpgradeHoldFailClosed bool
	// kernelRunnerFn / kernelSystemFn are test seams for the kernel-upgrade
	// election-hold path (#5682). nil in production: the real KernelRunner (over
	// the /var/lib/xpf journal) and the real KernelSystem are used. Tests inject a
	// runner pointed at a temp journal + a stub system to drive the
	// armed/not-armed/unreadable branches without a live UEFI host.
	kernelRunnerFn             func() (*upgrade.KernelRunner, error)
	kernelSystemFn             func() upgrade.KernelSystem
	sessionSync                *cluster.SessionSync
	syncBulkPrimed             atomic.Bool
	syncPeerBulkPrimed         atomic.Bool
	syncPeerConnected          atomic.Bool
	lastStandbyNeighborRefresh atomic.Int64
	// neighborGuards groups the #1780 Path A per-phase supervision state for
	// runPeriodicNeighborResolution (in-flight overlap guards, last-success
	// timestamps, loop-started gate, plus the warmNeighborCache warmup guard).
	// See neighborPeriodicGuards in daemon_neighbor.go. This is increment 2 of
	// the #4407 Daemon god-struct decomposition — pure field grouping, no
	// behavior/locking change; the fields keep their exact atomic types and are
	// reached as d.neighborGuards.<field>. lastStandbyNeighborRefresh (above)
	// stays a flat Daemon field: it is the standby-side refresh rate limit read
	// in daemon_health.go, a different mechanism from the periodic-resolution
	// supervision grouped here.
	neighborGuards neighborPeriodicGuards
	// neighborWarmDialer is the socket factory warmNeighborCache uses to trigger
	// kernel neighbor (ARP/ND) resolution on failover. Nil in production (the
	// default udpNeighborWarmDialer is used); tests inject a fake to count
	// sockets and capture probed destinations without touching the network
	// (#5451).
	neighborWarmDialer neighborWarmDialer
	hbSuppressStart    atomic.Int64 // CLOCK_MONOTONIC nanos of first heartbeat suppression; 0 = inactive (#1792)
	syncPrimeRetryGen  atomic.Uint64
	syncReadyTimerGen  atomic.Uint64
	syncReadyTimerMu   sync.Mutex
	syncReadyTimer     *time.Timer
	syncReadyTimeout   time.Duration

	// #5863: config-sync to a reconnecting peer is level-triggered, not a
	// one-shot connect edge. syncPeerConnEpoch is bumped on every peer sync
	// (re)connect so the reconciler can tell one live connection from the
	// next. The config-sync marker (configSyncMu-guarded) records the
	// (peer-connection-epoch × config-generation) that has already been
	// pushed, so the reconciler pushes AT MOST ONCE per epoch/generation and
	// is a no-op once the desired state is satisfied. This keeps the shared
	// userspace control socket safe: a later RG0 promotion or the crossing of
	// the stability threshold re-evaluates the invariant and pushes exactly
	// once, instead of leaving the peer indefinitely divergent (the connect
	// edge could have skipped the only push) OR re-pushing on every tick.
	syncPeerConnEpoch     atomic.Uint64
	configSyncMu          sync.Mutex
	configSyncHasPushed   bool
	configSyncPushedEpoch uint64
	configSyncPushedGen   uint64
	configSyncStable      time.Duration // stability threshold; 0 → default 30s (test override)
	// configSyncPushForTest, when non-nil, replaces the reconciler's real
	// SessionSync.QueueConfig push so a unit test can count pushes without a
	// live TCP sync transport (mirrors syncPeerForTest for the commit path).
	configSyncPushForTest func()

	slogHandler *logging.SyslogSlogHandler
	// #3932: the flow-traceoptions writer is published through an atomic
	// pointer read lock-free by a SINGLE stable EventReader callback that
	// traceCBOnce registers exactly once. Each commit that changes
	// traceoptions SWAPS the underlying writer (closing the old one) instead
	// of registering a new callback, so a long-lived daemon that re-commits
	// traceoptions repeatedly leaves exactly one callback and one live
	// TraceWriter regardless of commit count. traceReconMu serializes the
	// build+swap on the commit path; the callback reads the pointer lock-free.
	traceWriterPtr atomic.Pointer[logging.TraceWriter]
	traceCBOnce    sync.Once
	traceReconMu   sync.Mutex
	eventBuf       *logging.EventBuffer
	eventReader    *logging.EventReader
	eventEngine    *eventengine.Engine
	// #4964: the session-aggregation reporter is published through an atomic
	// pointer read lock-free by a SINGLE stable EventReader callback that
	// aggCBOnce registers exactly once. Each report-enabled commit SWAPS the
	// active aggregator (nil-ing the pointer before cancelling the old Run
	// goroutine) instead of registering a new callback, so a long-lived daemon
	// that re-commits with reporting enabled leaves exactly one callback and
	// one live aggregator regardless of commit count. Before #4964
	// applyAggregator called er.AddCallback on every report-enabled reconcile:
	// the callback list is append-only (ringbuf.go: only ClearCallbacks
	// removes, and it is all-or-nothing), so N commits leaked N callbacks each
	// feeding a stale never-flushed 20k-key Space-Saving aggregator, and every
	// event was then dispatched to all N — growing per-event cost and memory
	// even after reporting was disabled. Disabling reporting stores nil; the
	// stable callback stays but becomes a no-op. aggReconMu serializes the
	// swap on the commit path; the callback reads the pointer lock-free.
	aggregatorPtr atomic.Pointer[logging.SessionAggregator]
	aggCancel     context.CancelFunc
	// aggSig is the derived-config signature of the live aggregator generation
	// (#5313). applyAggregator retires+rebuilds the running aggregator ONLY when
	// the newly-derived signature differs; an unchanged signature keeps the live
	// aggregator — and its pending flush window — running instead of discarding
	// ~5 min of SESSION_CLOSE counters on every report-enabled commit.
	aggSig     aggregatorSig
	aggCBOnce  sync.Once
	aggReconMu sync.Mutex
	// #5523 C179-093: the aggregator's Run goroutine binds to context.Background
	// (cancelled only via aggCancel), so shutdown used to leak it and skip its
	// #5313 ctx.Done final flush — up to a full ~5 min window of SESSION_CLOSE
	// counters was dropped on every daemon stop. aggWg tracks every started
	// generation (current + any still-flushing retired one) so stopAggregator
	// can cancel + JOIN them at shutdown; aggStopped latches the stop so a late
	// applyAggregator after shutdown never starts a new generation (that Add
	// would race aggWg.Wait). Both guarded by aggReconMu.
	aggWg      sync.WaitGroup
	aggStopped bool
	vrrpMgr    *vrrp.Manager
	gc         *conntrack.GC
	startTime  time.Time // daemon start time; used to suppress stale config sync

	// #846: applySem (capacity 1) serializes applyConfig + the
	// commit→apply pair across all entry points (HTTP/gRPC commits,
	// cluster sync recv, DHCP callbacks, config-poll, dynamic feeds,
	// event engine, in-process CLI commits, CLI auto-rollback).
	// Without this, two concurrent callers can interleave across
	// VRF/tunnel/FRR-reload steps, or one caller's commit can
	// interleave between another's commit and apply, leaving
	// configstore/kernel divergent. Used as a semaphore (not a
	// sync.Mutex) so handlers can Acquire(ctx, 1) and surface a 503
	// to the client when the lock holder is slow, instead of
	// hanging the request indefinitely.
	applySem *semaphore.Weighted
	// resetting enters the TERMINAL factory-reset (zeroize) generation
	// (#5281). A gRPC-initiated zeroize (factoryReset) sets it true while it
	// holds applySem and erases on-disk state, and — on a successful wipe —
	// leaves it set for the daemon's remaining lifetime (the daemon is stopped
	// moments later). Once set, every config writer that acquires applySem
	// (commitAndApply / commitConfirmedAndApply / syncAndApply /
	// executeConfirmedRollback, the applyConfigLocked reconcile, and the
	// periodic DHCP-lease IPsec rebind) short-circuits, so nothing re-persists
	// the just-erased .configdb SSOT or re-renders the wiped secrets
	// (frr.conf/swanctl PSKs/Kea/login accounts) in the window between the wipe
	// and the daemon stop. Read/written only via isResetting / enterReset...
	// exitResetGeneration (sync/atomic), so the zeroize goroutine and any
	// concurrent apply goroutine race safely. A failed wipe clears it again so
	// the box stays recoverable (fail-closed, see factoryReset).
	resetting atomic.Bool
	// applyBodyForTest, when non-nil, replaces applyConfigLocked's
	// body. Test-only seam used by apply_serialize_test.go to
	// exercise the semaphore contract through the real applyConfig
	// / commitAndApply paths without standing up the full dataplane.
	applyBodyForTest func(*config.Config)

	// bootstrapTeardownForTest, when non-nil, replaces the real per-step
	// teardown executed inside enterBootstrapMode (#5868). Test-only seam:
	// it lets bootstrap_rollback_report_test.go inject synthetic teardown
	// step outcomes (including failures for the FRR-clear / dataplane-teardown
	// steps) to exercise the failure-aggregation and honest DEGRADED/complete
	// reporting without faking the concrete netlink/FRR/dataplane owners.
	bootstrapTeardownForTest func() []bootstrapTeardownStep

	// applyErrForTest is the error the applyBodyForTest seam returns from
	// applyConfigLocked (default nil = success). Test-only: lets a test drive
	// commitAndApply / commitConfirmedAndApply through the real apply→sync
	// error-classification (#4034) with an injected FATAL protocol-gate error,
	// a non-fatal best-effort subsystem error, or a context abort, without
	// standing up the full dataplane. Only consulted when applyBodyForTest is
	// set, so a test that does not touch it is byte-identical to before.
	applyErrForTest error

	// syncPeerForTest, when non-nil, replaces the real d.syncConfigToPeer()
	// push to the cluster peer on BOTH the commit-apply path (commitAndApply /
	// commitConfirmedAndApply via applyAndSyncCommitted, #4034) AND the
	// commit-confirmed timeout rollback re-sync (resyncRolledBackConfigToPeer,
	// #3868). Test-only seam: the production push (syncConfigToPeer ->
	// pushConfigToPeer -> SessionSync.QueueConfig) needs a live TCP transport,
	// so tests inject this to observe that the committed/rolled-back config is
	// pushed (and what text it would carry via d.store.ShowActive()).
	syncPeerForTest func()

	// hostInboundFailOpen groups the three previous-apply host-inbound
	// fail-open / ambiguity sets (#3698 addressless zones, #3710 addressless
	// {zone,iface,family} windows, #3718 order-dependent ambiguous addresses).
	// applyHostInboundFilter diffs the current sets against these to emit
	// state-transition logs only, keeping the warnings low-noise across
	// repeated commits / DHCP renewals. All three are written and read only
	// under applySem in applyHostInboundFilter. See hostInboundFailOpenState in
	// daemon_nft.go (the file that owns the diff/log functions). This is
	// increment 4 of the #4407 Daemon god-struct decomposition — pure field
	// grouping, no behavior/locking change; the fields keep their exact
	// map[string]bool types and are reached as d.hostInboundFailOpen.<field>.
	hostInboundFailOpen hostInboundFailOpenState

	// hostInboundEnforced is the process-local historical gate for the #5644
	// cold-boot fallback. Successful real loads Store true, including program-only
	// generations; successful fallbacks Store true only when their exact rendered
	// snapshot contains an address-scoped DROP. A successful zero-drop fallback
	// leaves false so a later failed real invocation can try another snapshot. A
	// successful no-enforcement TEARDOWN (the table is deleted because nothing is
	// enforceable) Stores false: with no table installed the "a protecting table
	// exists" premise no longer holds, so a later enforceable generation whose
	// first real load fails must take the cold-boot fence path rather than assume a
	// retained table (#5790). A teardown FAILURE (a table may still be installed)
	// does NOT clear it. True proves neither current xpf_hostinbound table presence
	// nor coverage of every current local address — the day-2 COVERAGE gap is
	// tracked separately by hostInboundCoveredAddrs (#5789, #5790). Production
	// access is serialized under applySem; atomic.Bool preserves the existing type,
	// not a current readiness reader. nft success and the following Store are
	// ordered operations in separate state domains, not one atomic publication.
	hostInboundEnforced atomic.Bool

	// hostInboundCoveredAddrs is the set of firewall-local DESTINATION addresses
	// (keyed "<fam>|<addr>", fam '4'/'6') that the currently-RETAINED host-inbound
	// enforcement (the last successfully-loaded real table OR address-scoped
	// cold-boot fence) installs a catch-all DROP for. It is the #5789 coverage
	// discriminator: hostInboundEnforced only proves SOME protecting table loaded
	// at SOME earlier generation, NOT that the retained generation covers the
	// CURRENT desired destination set. When a new static/DHCP/SLAAC address appears
	// and the next real render fails, atomic nft retention keeps the OLD generation
	// — which has no deny for the new address (fail-open). Comparing this covered
	// set against the current desired drop set detects those uncovered destinations
	// so an ADDITIVE gap fence (inet xpf_hostinbound_gap, a separate input-hook
	// table that preserves the retained table's accepts) can deny only them.
	// Updated to the desired set on a successful real load / address-scoped fence;
	// CLEARED on a successful teardown (#5790, no table covers nothing); left
	// UNCHANGED on any failure (atomic retention keeps the old generation, so its
	// coverage claim also stands). Serialized under applySem, like the
	// hostInboundFailOpen maps; a nil/empty map means "nothing retained is known to
	// be covered" (cold boot).
	hostInboundCoveredAddrs map[string]struct{}

	// lo0Enforced records whether the currently-loaded xpf_lo0 table is a REAL
	// operator filter (the #6476 lo0 cold-boot fence gate). It means EXACTLY that:
	// it is set true ONLY by a successful real InstallLo0. A cold-boot FENCE
	// deliberately does NOT set it — a fence is NOT a real filter (its chain is
	// `policy accept` and drops only the firewall-local addresses present in the
	// snapshot it was rendered from, so a later-appearing address is not covered), so
	// lo0Enforced stays false across a fence. A successful no-filter TEARDOWN Stores
	// false (the table is deleted); a teardown FAILURE (a table may still be
	// installed) does NOT clear it.
	//
	// It gates the day-2 fence-skip in applyLo0Filter: a failed InstallLo0 installs
	// a fence UNLESS a real filter is currently loaded. This must key on real-filter-
	// loaded, NOT "any protecting table exists" (#6489). The earlier design set a
	// single flag true on BOTH a real load AND a scoped fence, conflating the two —
	// so a fence -> new-address -> real-install-fails sequence SKIPPED re-fencing and
	// left the newly-appeared address reachable through the stale fence's
	// `policy accept` (fail-open). Because a fence no longer sets lo0Enforced, the
	// gate stays open after a fence and RE-RENDERS the whole-table fence from the
	// current snapshot on every day-2 failure while no real filter is loaded
	// (covering the new address); a retained REAL filter (true) is trusted to govern
	// every local address so no fence is installed — the intended divergence from the
	// host-inbound per-address gap fence (#5789), which lo0 does not need because the
	// operator's hand-authored filter is not per-destination-address scoped.
	//
	// Residuals (pre-existing, NOT introduced or addressed here — tracked in #6492):
	// a retained REAL lo0 filter with no catch-all term (a valid config,
	// compiler_filter_nocatchall_3295_test) need not itself cover a new day-2 address
	// (the lo0 filter's own coverage semantics, independent of this boot fence); and
	// the shared BuildZoneHostInboundViews / fence body carries a management-IP-on-
	// non-lifeline and a zone-less-router behaviour that affect the host-inbound
	// #5644 fence identically. Production access is serialized under applySem (via
	// applyLo0Filter); atomic.Bool matches the hostInboundEnforced type.
	lo0Enforced atomic.Bool

	// mgmtVRFInterfaces tracks interfaces bound to the management VRF (vrf-mgmt).
	// Used by collectDHCPRoutes to exclude management routes from FRR.
	//
	// Concurrency (#5113): the apply path publishes a fresh map on each commit
	// under applySem, but the DHCP-manager lease-change callback
	// (onDHCPAddressChange) reads it WITHOUT applySem — an unsynchronized
	// concurrent map-pointer read/write (a real Go data race). The published
	// maps are immutable (replaced wholesale, never mutated in place), so the
	// field is an atomic.Pointer: apply publishes with a single Store (see
	// publishMgmtVRFIfaces) and every reader Loads a consistent snapshot
	// lock-free (see mgmtVRFIfaceSet). Load may return nil before the first
	// publish — readers treat that as "no mgmt VRF interfaces yet".
	mgmtVRFInterfaces atomic.Pointer[map[string]bool]

	// rgStates tracks the unified cluster + VRRP state for each
	// redundancy group. Both watchClusterEvents and watchVRRPEvents
	// funnel transitions through rgStateMachine, which determines the
	// desired rg_active value and provides an epoch counter for
	// stale-update detection.
	rgStatesMu sync.RWMutex
	rgStates   map[int]*rgStateMachine

	// blackholeRoutes tracks blackhole routes injected for inactive RG subnets.
	// When an RG goes BACKUP, we inject blackhole routes for its RETH subnets
	// to prevent FIB from routing return traffic via the default route (which
	// would escape via WAN). Instead, bpf_fib_lookup returns BLACKHOLE and
	// the FIB failure handler triggers fabric redirect to the peer.
	blackholeMu     sync.Mutex
	blackholeRoutes map[int][]netlink.Route

	// reconcileNowCh triggers an immediate RG state reconciliation pass.
	// Sent on event channel drops (cluster or VRRP) so recovery does not
	// wait for the 2-second periodic ticker.
	reconcileNowCh chan struct{}

	// reconcileTickHook, when non-nil, REPLACES the per-pass reconcile action
	// (reconcileRGState) in reconcileRGStateLoop. Test-only seam (#5681 / M23):
	// it lets the shutdown-ordering regression test make a reconcile pass
	// observably in-flight so it can prove the loop is joined by the run
	// WaitGroup BEFORE HA ownership-relinquish cleanup runs. Always nil in
	// production; reconcileRGStatePass calls the real reconcileRGState.
	reconcileTickHook func()

	// Fabric cross-chassis forwarding state for periodic refresh.
	fabricMu         sync.RWMutex
	fabricIface      string // physical parent (XDP attachment point)
	fabricOverlay    string // IPVLAN overlay for neighbor resolution (#129)
	fabricPeerIP     net.IP
	fabricIface1     string // secondary fabric parent
	fabricOverlay1   string // secondary fabric overlay (#129)
	fabricPeerIP1    net.IP // secondary fabric peer IP
	fabricPopulated  bool   // true after first successful fab0 write
	fabric1Populated bool   // true after first successful fab1 write
	// fabricPeerMAC / fabricPeerMAC1 cache the last peer MAC that was learned
	// from an ADDRESS-MATCHED neighbour entry for the configured fabric peer
	// (#6554). They are the identity the IPv6-NDP link-local fallback is
	// constrained to: only a neighbour bearing this MAC may be accepted when
	// the peer's fabric address itself does not resolve. Written only by an
	// address-matched resolution (never by the fallback itself, which would
	// let a bad guess self-confirm) and cleared when the configured peer
	// address changes, so a re-pointed fabric cannot be pinned to the old
	// peer's MAC.
	fabricPeerMAC    net.HardwareAddr
	fabricPeerMAC1   net.HardwareAddr
	fabricRefreshCh  chan struct{} // wakes the fab0 populateFabricFwd loop
	fabricRefreshCh1 chan struct{} // wakes the fab1 populateFabricFwd1 loop (#4038)
	lastFabricProbe  time.Time     // rate-limit active fab0 neighbor probes
	lastFabricProbe1 time.Time     // rate-limit active fab1 neighbor probes
	lastFabricLog0   time.Time     // rate-limit fab0 refresh failure logs
	lastFabricLog1   time.Time     // rate-limit fab1 refresh failure logs

	// vipWarnedIfaces tracks interfaces that already emitted a
	// "directAddVIPs: interface not found" warning to avoid log spam
	// from the reconcile ticker. Reset on config commit.
	vipWarnedIfaces map[string]bool

	// syncPeerAddr is the primary peer address used for gRPC peer dialing
	// (session queries, config sync). Set to control link or fabric
	// peer depending on sync transport mode.
	syncPeerAddr string
	// syncPeerAddr1 is the secondary fabric peer address (fab1) for
	// gRPC peer dialing failover. Empty if no dual-fabric is configured.
	syncPeerAddr1 string

	// gRPC server reference for starting fabric listener in cluster mode.
	grpcSrv *grpcapi.Server

	// daemonCtx is the parent context from Run(), used to derive
	// independently-cancellable sub-contexts for the daemon-lifetime
	// background goroutines (cluster comms, flow-export/IPFIX relays, RPM
	// probe-pin retry, the policy scheduler, and the dataplane runtime
	// dp.Start). In production cmd/xpfd passes context.Background() into Run,
	// so daemonCtx is NEVER cancelled — those goroutines are torn down
	// EXPLICITLY in the shutdown sequence (stopFlowExporter, rpm.StopAll,
	// cluster.Stop, dp.Teardown, ...), and the orderly teardown (logFinalStats
	// through dp.Telemetry, the HA rg_active clear through dp.HA()) still needs
	// the dataplane runtime live while it runs. daemonCtx is therefore NOT the
	// apply-abort signal; see applyCancelContext / applyCancelCtx (#2926).
	daemonCtx context.Context

	// applyCancelContext is the daemon-lifetime context whose cancellation
	// aborts an in-flight applyConfigLocked at its coarse boundaries
	// (C1/C2/C3) on daemon stop (#2926). Run creates it as a child of the
	// SIGTERM/SIGINT signal context, so a real `systemctl stop xpfd` cancels
	// it. It is kept SEPARATE from daemonCtx so the apply-abort signal does
	// not disturb the lifetimes of the other daemonCtx-derived background
	// goroutines (which the shutdown sequence tears down explicitly and which
	// the orderly teardown still needs live). applyCancelCtx() returns it; a
	// nil value (early boot / unit tests with no wiring) falls back to a
	// non-cancellable context so an apply never aborts spuriously.
	applyCancelContext context.Context

	// applyCancel cancels applyCancelContext. Run defers it and also calls it
	// explicitly at the start of the shutdown sequence so an in-flight apply
	// bails before the explicit subsystem teardown runs.
	applyCancel context.CancelFunc

	// clusterCommsCancel cancels the sub-context used by startClusterComms
	// goroutines. Set when cluster comms are started, called to restart them
	// on config change (#87).
	clusterCommsCancel context.CancelFunc

	// clusterCommsCtx is the currently-live cluster comms sub-context (the
	// context clusterCommsCancel cancels). Held so runtime knob toggles can
	// (re)launch comms-scoped loops — e.g. the #2239 DHCP lease-sync push loop
	// started on a `dhcp-lease-synchronization` commit (#4647) — against the
	// same lifetime as the connect-time launch. Nil when comms are stopped.
	clusterCommsCtx context.Context

	// activeClusterTransport stores the transport config used by the
	// currently running cluster comms. Compared on each applyConfig to
	// detect changes that require a comms restart (#87).
	activeClusterTransport clusterTransportKey

	// clusterCommsMu guards the cluster-comms epoch state that is published
	// asynchronously by the startClusterComms constructor goroutine and torn
	// down by stopClusterComms: sessionSync, fabricRefreshCh/fabricRefreshCh1,
	// clusterCommsCtx/clusterCommsCancel, and clusterCommsGen (#4958). Before
	// #4958 the constructor wrote sessionSync (and re-dereferenced it) and the
	// fabric channels from an untracked goroutine with no lock, so a
	// stop→start restart could nil-deref (stop nils sessionSync between the
	// goroutine's write and its next read) or let a stale constructor overwrite
	// a newer epoch's session/endpoints. The mutex makes every read/write of
	// these fields race-free; clusterCommsGen provides publish-if-current.
	clusterCommsMu sync.Mutex

	// clusterCommsGen is the cluster-comms epoch counter (#4958). Both
	// startClusterComms and stopClusterComms bump it under clusterCommsMu;
	// startClusterComms captures the post-bump value and hands it to its
	// constructor goroutine, which publishes sessionSync/fabric channels ONLY
	// while the counter still matches (publishSessionSyncIfCurrent). A late
	// constructor whose epoch was superseded by a restart drops its publish
	// instead of clobbering the live epoch's state.
	clusterCommsGen uint64

	// clusterCommsWG tracks the in-flight startClusterComms constructor
	// goroutine(s) so stopClusterComms can join them before nilling the shared
	// comms state (#4958). Without the join a cancelled constructor could still
	// be mid-publish while stop tore the epoch down.
	clusterCommsWG sync.WaitGroup

	// startupGoodbyeRA tracks whether the one-shot goodbye RA has been
	// sent for each inactive RG on startup. Prevents stale RA routes
	// from a previous primary run keeping hosts dual-pathing traffic.
	// It is set only AFTER the goodbye provably went out (#5093): a
	// bind/write failure leaves it unset so the reconcile ticker retries.
	// startupGoodbyeMu guards it plus startupGoodbyeInflight, which are now
	// written from the async WithdrawOnce goroutine as well as the reconcile
	// loop. startupGoodbyeInflight marks RGs whose goodbye goroutine is still
	// running so a later reconcile tick does not launch a duplicate (which
	// would self-skip on the held tombstone and falsely record success).
	startupGoodbyeMu       sync.Mutex
	startupGoodbyeRA       map[int]bool
	startupGoodbyeInflight map[int]bool
	// startupGoodbyeWithdrawFn is the WithdrawOnce entry the cold-boot goodbye
	// goroutine calls; overridable in tests to force per-interface outcomes
	// (#5093). Nil means use d.ra.WithdrawOnce.
	startupGoodbyeWithdrawFn func([]*config.RAInterfaceConfig) []ra.GoodbyeResult

	// Cluster RA convergence (#5861). In cluster mode RA senders run ONLY on
	// the RG that is the current active owner; the desired RA set is the union
	// of buildRAConfigs filtered to the currently-active RGs. reconcileClusterRA
	// funnels EVERY cluster RA transition — a day-2 config commit, a VRRP
	// MASTER/BACKUP transition, and a periodic dropped-event safety pass —
	// through one owner-gated + serialized applier so a config edit on a
	// stable-active RG (no ownership transition) actually re-applies RA instead
	// of stranding stale prefixes/lifetimes/options until the next failover.
	//
	// raReconcileMu serializes the ownership snapshot and the ra.Apply so a
	// config apply cannot race a demotion and re-arm/transmit RA on a node that
	// just became inactive (the demotion-race guard): the VRRP demote path
	// updates rg-state BEFORE taking this lock to withdraw, so under the lock
	// the snapshot always reflects the true current owner at apply time.
	//
	// lastRAReconcileHash is the digest of the last successfully applied desired
	// set (empty = no senders). A matching hash short-circuits the periodic pass
	// so it costs nothing when nothing changed; a mismatch (config edit, PD
	// prefix change, or ownership move) drives ra.Apply, which diffs safely.
	//
	// raApplyFn is the ra.Apply entry point; overridable in tests to spy on the
	// applied desired set. Nil means use d.ra.Apply.
	raReconcileMu       sync.Mutex
	lastRAReconcileHash string
	raApplyFn           func([]*config.RAInterfaceConfig) error

	// startupActiveAnnounce tracks whether the one-shot active-side
	// neighbor refresh has been sent for each RG on this daemon run.
	// This covers restart/redeploy of an already-active direct-mode RG,
	// where VIP ownership does not transition and the normal failover
	// GARP/NA path would not fire.
	startupActiveAnnounce map[int]bool
	// directAnnounceSeq cancels and supersedes scheduled direct-mode
	// post-failover re-announcement bursts per RG. A new schedule bumps
	// the sequence; in-flight goroutines exit when their generation is
	// no longer current or the RG is no longer active locally.
	directAnnounceMu       sync.Mutex
	directAnnounceSeq      map[int]uint64
	directAnnounceSchedule []time.Duration
	directSendGARPsFn      func(int)
	// directVIPOwned tracks the last direct-mode ownership state applied
	// for each RG so reconciliation can trigger one-shot side effects
	// (service start/stop, announce bursts) while still reasserting
	// VIP presence/removal idempotently every pass.
	directVIPMu    sync.Mutex
	directVIPOwned map[int]bool
	// garpClampWarned dedups the #5695 per-RG "gratuitous-arp-count clamped"
	// warning so directSendGARPs (per-failover path) logs it at most once per
	// RG, not per send. Guarded by garpClampWarnMu.
	garpClampWarnMu sync.Mutex
	garpClampWarned map[int]bool
	// localFailoverCommitReady tracks whether this node has already
	// applied the local side of a freshly committed transfer request for
	// each RG. The cluster manager waits on this before telling the peer
	// to finalize demotion, so the old owner does not stand down before
	// the target daemon has processed the promotion edge.
	localFailoverCommitMu      sync.Mutex
	localFailoverCommitReady   map[int]bool
	localFailoverCommitTimeout time.Duration
	// localFailoverCommitDelay adds one short post-ready dwell after the
	// readiness bit flips so the VRRP/direct-ownership side effects that set
	// the bit have a chance to propagate before the peer finalizes demotion.
	localFailoverCommitDelay time.Duration
	// failoverActuateMu guards failoverActuateWait. The map holds, per RG, a
	// barrier that watchClusterEvents resolves once it has finished ACTUATING
	// a demotion (VRRP resign to priority-0 / rg_active clear).
	// armFailoverActuation registers a fresh barrier BEFORE ManualFailover
	// enqueues the demotion event, so the resolution can never be missed;
	// waitFailoverActuated blocks the remote-failover applied-ack on it. This
	// closes the #5640 two-owner window where the peer promoted off an ack
	// sent before this (old-owner) node had actually resigned. The barrier
	// carries a verdict, not just a completion: a demotion whose rg_active
	// clear was REJECTED by the dataplane resolves with that error so the ack
	// is downgraded rather than reported applied (#6371).
	failoverActuateMu sync.Mutex
	// The map is keyed by (RG, peer request id) so a stale request's disarm
	// or expired wait can never evict a newer request's barrier (#6177).
	failoverActuateWait map[failoverActuationKey]*failoverActuation
	// failoverActuateTimeout bounds waitFailoverActuated so a demotion event
	// that is never actuated (superseded reset, event-channel drop) downgrades
	// the ack to failed instead of hanging the peer's failover request.
	failoverActuateTimeout time.Duration
	// Test hooks for direct-mode VIP ownership reconciliation.
	directAddVIPsFn        func(int) int
	directRemoveVIPsFn     func(int) int
	directAddStableLLFn    func(int)
	directRemoveStableLLFn func(int)

	// linkByNameFn resolves a network interface by name. Defaults to
	// netlink.LinkByName; overridden in tests.
	linkByNameFn func(string) (netlink.Link, error)

	// neighListFn dumps the kernel neighbour table for an (ifindex, family).
	// Defaults to netlink.NeighList; overridden in tests (#6554) so the
	// fabric peer-MAC resolution can be driven against a synthetic
	// neighbour table.
	neighListFn func(int, int) ([]netlink.Neigh, error)

	// userspaceSessionIDs allocates synthetic session IDs for sessions
	// learned from the userspace dataplane helper before they enter the
	// existing HA/session-sync transport.
	userspaceSessionIDs atomic.Uint64

	// eventStreamConnected is set when the helper's binary event stream
	// is live. The polling fallback loop uses this to decide its cadence:
	// 5s reconciliation when connected, 100ms fast-poll when disconnected.
	eventStreamConnected atomic.Bool

	// userspaceDeltaSyncMu serializes helper delta draining between the
	// event-stream fallback loop and the background polling loop.
	userspaceDeltaSyncMu sync.Mutex
	// userspaceDemotionPrepUntil suppresses duplicate demotion prep for the
	// same RG during a single failover transition. Manual failover can now
	// stage prep before ownership changes; the later cluster/VRRP edges must
	// not rerun the same barrier sequence immediately afterward.
	userspaceDemotionPrepMu    sync.Mutex
	userspaceDemotionPrepUntil map[int]time.Time

	// Compile health (#758). If dataplane compile fails and never
	// succeeds, the daemon is in a degraded state: config is accepted
	// but the forwarding path may be partial or absent. Track this so
	// /health can surface it and operators aren't left staring at a
	// single pre-existing WARN line with no other signal.
	compileHealthMu         sync.Mutex
	compileFailureCount     uint64 // total failed compiles since daemon start
	compileEverSucceeded    bool   // true once any compile completed cleanly
	compileLastError        string // text of the most recent compile error
	compileLastErrorUnixSec int64  // timestamp of the most recent compile error

	// #4184: the day-0 / bootstrap config-import outcome, recorded once at
	// boot so a FAILED import is visible beyond a single journald WARN.
	// Surfaced via /health (bootstrap_import_status) and an event. See
	// recordBootstrapImport / BootstrapImportSnapshot (daemon_health.go).
	bootstrapMu            sync.Mutex
	bootstrapImportStatus  string // "" until recorded; then a bootstrapImport* constant
	bootstrapImportError   string // error detail when status == bootstrapImportFailed
	bootstrapImportUnixSec int64  // Unix seconds the outcome was recorded

	// priorTunables stores the pre-xpfd values of every host-scope
	// tunable xpfd has touched, so that restore-on-disable (B2) can
	// revert to what the operator had before xpfd claimed the host.
	// Populated lazily on first apply. Restored when claim-host-tunables
	// transitions from true → false, or on daemon shutdown. See
	// pkg/daemon/host_tunables.go for capture/restore implementation.
	priorTunablesMu     sync.Mutex
	priorTunables       *priorHostTunables
	priorTunablesActive bool // true once the current config has applied host tunables

	// bootstrapMode is the #1922 explicit bootstrap-mode flag. When set, the
	// daemon runs gRPC/REST/CLI as normal but suppresses ALL interface
	// takeover ACTIONS (rename loop beyond the lifeline path, link cycles,
	// networkd takeover writes beyond the lifeline .network, dataplane arm,
	// FRR managed-section, boot-time applyConfig, VRRP instance creation).
	// Set once at startup from the five-case boot predicate (computeBootClass)
	// and cleared one-way on the first non-empty config apply (local confirmed
	// commit or cluster SyncApply). Read on every commit gate / reconcile, so
	// an atomic avoids a lock on the hot read path. Managers are still
	// constructed unconditionally (C1) so the bootstrap-exit reconcile wires
	// every subsystem.
	bootstrapMode atomic.Bool

	// emptyHANamingPending is the #4179 one-shot flag for the HA-guard
	// EMPTY-config takeover. A node with /etc/xpf/node-id but no committed
	// config resolves NOT-bootstrap (computeBootClass HA-node guard) and names
	// its NICs with STANDALONE names at boot because the nil active config
	// carries no cluster stanza (clusterMode=false). Set here so the FIRST
	// non-empty config that arrives (a cluster SyncApply from the primary, or a
	// local commit) re-runs startup naming with the config's real cluster
	// identity — em0 + ge-<fpc>-0-X — instead of stranding the interfaces on
	// standalone names until a daemon restart. Consumed once, then never again
	// (a normal day-2 commit does not re-name).
	emptyHANamingPending atomic.Bool

	// proxyARPEnabled tracks the (interface name → enabled families) set the
	// proxy-ARP/NDP responder sysctl was last enabled for (#2475). On each
	// reconcile the daemon diffs the new desired set against this remembered
	// set and disables net.ipv4.conf.<if>.proxy_arp /
	// net.ipv6.conf.<if>.proxy_ndp on any (interface, family) that dropped out
	// — a day-2 commit removing proxy-arp must drive the leaked sysctl back to
	// 0 (the dataplane reconcile is stateless across commits, so the daemon
	// owns this teardown state). Guarded by proxyARPEnabledMu; both callers of
	// the reconcile run under applySem — the apply path directly, and the
	// always-on re-assert loop via reassertProxyARPOnce (#4001) — so a re-assert
	// can never interleave with a commit reconcile and re-add a removed
	// responder from a stale config snapshot.
	proxyARPEnabledMu sync.Mutex
	proxyARPEnabled   map[string]map[int]struct{}

	// archiveTransfer performs the transfer-on-commit upload of one
	// serialized active-config file to an archive site. nil ⇒ the default
	// scp transport (scpArchiveTransfer). Overridable so tests can capture
	// the uploaded file's bytes and assert archiveConfig serializes the
	// CURRENT active config (Store.ShowActive), not the stale boot file
	// d.opts.ConfigFile (#3867).
	archiveTransfer func(ctx context.Context, srcPath, dest string) error

	// --- periodic configuration-archival timer (#4078) ---
	// archiveTimer groups the periodic-archival timer supervision state: the
	// (interval|sites) hash-gate key, the per-generation stop channel, their
	// guarding mutex, and the tick-source seam. See archiveTimerState in
	// daemon_archive_timer.go, the file that owns the reconcile/run/stop
	// lifecycle. This is increment 3 of the #4407 Daemon god-struct
	// decomposition — pure field grouping, no behavior/locking change; the
	// fields keep their exact types and are reached as d.archiveTimer.<field>.
	// A named sub-field (not an embed) matches increments 1 and 2: every access
	// site is bounded to daemon_archive_timer.go (plus its test), and the
	// d.archiveTimer.key qualifier also removes the prior confusing collision
	// with the package-level archiveTimerKey(interval, sites) helper function.
	// The transfer-on-commit archiveTransfer seam above stays a flat Daemon
	// field — it is the one-shot upload transport (used by archiveConfig in
	// daemon_flow.go), a different mechanism from the periodic timer grouped
	// here (mirroring how increments 1 and 2 kept ipsecSANudgeCh /
	// lastStandbyNeighborRefresh flat).
	archiveTimer archiveTimerState

	// --- SNMP link-state monitor seams (#3950) ---
	// linkStateSubscribe starts a netlink link-update subscription for the
	// SNMP link-state monitor. It MUST stream updates to ch and close ch when
	// the subscription ends (a receive error — including a recoverable
	// ENOBUFS receive-buffer overflow — or done being closed), invoking onErr
	// with the terminating receive error first (mirroring the
	// netlink.LinkSubscribeOptions.ErrorCallback contract). nil ⇒ the real
	// netlink subscription (defaultLinkStateSubscribe). Overridable so tests
	// can drive the resilient resubscribe/re-sync loop with an injected
	// ENOBUFS (#3950).
	linkStateSubscribe func(ch chan<- netlink.LinkUpdate, done <-chan struct{}, onErr func(error)) error
	// linkStateList enumerates current links for the boot seed and the
	// post-ENOBUFS catch-up re-sync. nil ⇒ netlink.LinkList (#3950).
	linkStateList func() ([]netlink.Link, error)
	// linkStateEmit is invoked for every observed up/down transition (from a
	// streamed event OR a post-resubscribe catch-up re-sync). nil ⇒ an SNMP
	// linkUp/linkDown trap via d.snmpAgent. Overridable so tests can capture
	// transitions without wiring an SNMP agent (#3950).
	linkStateEmit func(index int, name string, up bool)
	// linkStateResubBackoff is the delay between a subscription close and the
	// resubscribe attempt. Zero ⇒ linkStateResubBackoffDefault (#3950).
	linkStateResubBackoff time.Duration

	// --- fabric-state monitor seams (#4031) ---
	// fabricLinkSubscribe starts the netlink link-update subscription for the
	// fabric-state monitor (monitorFabricState). It MUST stream updates to ch
	// and close ch when the subscription ends (a receive error — including a
	// recoverable ENOBUFS receive-buffer overflow — or done being closed). nil
	// ⇒ the real netlink subscription (defaultFabricLinkSubscribe). Overridable
	// so tests can drive the resilient resubscribe loop with an injected close.
	fabricLinkSubscribe func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error
	// fabricNeighSubscribe starts the netlink neighbor-update subscription for
	// the fabric-state monitor. Same close/leak contract as fabricLinkSubscribe.
	// nil ⇒ netlink.NeighSubscribe (defaultFabricNeighSubscribe) (#4031).
	fabricNeighSubscribe func(ch chan<- netlink.NeighUpdate, done <-chan struct{}) error
	// fabricStateResubBackoff is the delay between a fabric subscription close
	// and the resubscribe attempt. Zero ⇒ fabricStateResubBackoffDefault (#4031).
	fabricStateResubBackoff time.Duration
}

// dataplane returns the currently published runtime dataplane, or nil.
// One atomic load; safe from any goroutine. Callers that nil-check AND use
// the value must load ONCE into a local (the #2114 plan's §5.3 snapshot
// boundaries) — a second load may observe a different publication.
func (d *Daemon) dataplane() dataplane.RuntimeDataPlane {
	if s := d.dpCell.Load(); s != nil {
		return s.v
	}
	return nil
}

// setDataplane publishes dp; a nil argument clears the cell. The
// kind-gated typed-nil check keeps a non-nil interface wrapping a nil
// value out of the cell WITHOUT panicking on non-nillable kinds
// (reflect.Value.IsNil panics on struct values) and WITHOUT missing
// non-pointer nillable kinds (named Chan/Func/Map/Slice types can carry
// methods — in-repo precedent:
// pkg/dataplane/userspace/wire_uint8list.go). RuntimeDataPlane has no
// pointer-only constraint and the backend registry
// (pkg/dataplane/dataplane.go) returns arbitrary constructor results
// unchecked, so the guard covers every nillable kind.
func (d *Daemon) setDataplane(dp dataplane.RuntimeDataPlane) {
	if dp == nil {
		d.dpCell.Store(nil)
		return
	}
	v := reflect.ValueOf(dp)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map,
		reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		if v.IsNil() {
			d.dpCell.Store(nil)
			return
		}
	}
	d.dpCell.Store(&dpSlot{v: dp})
}

func (d *Daemon) applyResult() *dataplane.ApplyResult {
	if d == nil {
		return nil
	}
	return dataplane.LastApplyResultOf(d.dataplane())
}

// CompileHealth is a snapshot of dataplane compile health (#758).
// Consumed by /health to surface a degraded state instead of returning
// OK when the dataplane never compiled successfully.
type CompileHealth struct {
	EverSucceeded    bool
	FailureCount     uint64
	LastError        string
	LastErrorUnixSec int64
}

const standbyNeighborRefreshMinInterval = time.Second

// parseNodeIDFileContent parses /etc/xpf/node-id content to the SAME strict
// contract every other node-id consumer enforces (#4185): a trimmed, whole
// integer restricted to 0|1. It returns ok=false for empty, non-integer,
// trailing-garbage ("1garbage"), or out-of-range ("2", "-1") input — all
// forms the historical fmt.Sscanf("%d") silently accepted (it would parse
// "1garbage" as 1). The `-node-id` flag on `xpfd check-config` and the day-0
// loader already enforce 0|1|-1; this brings the daemon's file reader in line.
func parseNodeIDFileContent(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 || n > 1 {
		return 0, false
	}
	return n, true
}

// New creates a new Daemon. It fails when the config store cannot be
// constructed (#1893 — the store is fail-closed on an unusable
// .configdb): a daemon that cannot persist configuration must not
// boot pretending otherwise.
func New(opts Options) (*Daemon, error) {
	if opts.ConfigFile == "" {
		opts.ConfigFile = "/etc/xpf/xpf.conf"
	}

	store, err := configstore.New(opts.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("config store: %w", err)
	}

	// Stamp the build version into the config-DB compatibility envelope on
	// write (#1917 increment B, plan §6.4 / D1). The envelope's magic header
	// makes a future format bump fail closed on an old reader instead of
	// silently empty-loading.
	store.SetConfigDBWriterVersion(opts.Version)

	// Read cluster node ID from file. If the file exists and contains a
	// valid integer, the daemon runs in cluster mode with ${node} variable
	// expansion in apply-groups. If the file does not exist, standalone mode.
	if data, err := os.ReadFile(nodeIDFile); err == nil {
		// #4185: parse to the SAME strict contract every other node-id
		// consumer enforces — a trimmed, whole-string Atoi restricted to
		// 0|1. The historical fmt.Sscanf("%d") accepted "1garbage" and any
		// integer, laxer than `xpfd check-config -node-id` (0|1|-1) and the
		// day-0 loader. A present-but-unparseable/out-of-range file leaves
		// the store at nodeID=-1 while hasNodeIDFile() (stat-only) still
		// forces the HA boot class, so ${node} silently expands with the
		// node-0 fallback — log LOUDLY instead of going half-standalone.
		s := strings.TrimSpace(string(data))
		if nodeID, ok := parseNodeIDFileContent(s); ok {
			store.SetNodeID(nodeID)
			slog.Info("cluster node ID loaded from file", "node", nodeID, "file", nodeIDFile)
		} else {
			slog.Error("cluster node-id file is present but not a valid node id (must be exactly "+
				"0 or 1); the node will boot in the HA class but ${node} expansion falls back to "+
				"node0 and heartbeat/FPC identity may diverge — FIX the file",
				"file", nodeIDFile, "content", s)
		}
	}

	return &Daemon{
		opts:                       opts,
		startTime:                  time.Now(),
		store:                      store,
		rgStates:                   make(map[int]*rgStateMachine),
		blackholeRoutes:            make(map[int][]netlink.Route),
		reconcileNowCh:             make(chan struct{}, 1),
		ddnsReconcileNowCh:         make(chan struct{}, 1),
		surfaceA:                   surfaceAState{reconcileNowCh: make(chan struct{}, 1)},
		dhcpLeaseSync:              dhcpLeaseSyncState{nowCh: make(chan struct{}, 1)},
		ipsecSANudgeCh:             make(chan struct{}, 1),
		syncReadyTimeout:           5 * time.Second,
		linkByNameFn:               netlink.LinkByName,
		neighListFn:                netlink.NeighList,
		directAnnounceSchedule:     []time.Duration{0, 250 * time.Millisecond, 1 * time.Second, 2 * time.Second, 4 * time.Second, 6 * time.Second},
		directVIPOwned:             make(map[int]bool),
		localFailoverCommitReady:   make(map[int]bool),
		localFailoverCommitTimeout: 3 * time.Second,
		localFailoverCommitDelay:   200 * time.Millisecond,
		failoverActuateWait:        make(map[failoverActuationKey]*failoverActuation),
		failoverActuateTimeout:     3 * time.Second,
		userspaceDemotionPrepUntil: make(map[int]time.Time),
		applySem:                   semaphore.NewWeighted(1),
	}, nil
}

// NOTE (#1519, sub-#1451 S4): the (*Daemon).legacyDP() escape hatch
// previously declared here was removed when every daemon-internal
// consumer migrated to a narrow typed probe in runtime_probes.go.
// A regression-guard AST canary in legacy_dataplane_canary_test.go
// keeps the symbol from being reintroduced without explicit review.
