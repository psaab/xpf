package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/ddns"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/eventengine"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/flowexport"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/fsatomic"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/vrrp"

	"github.com/psaab/xpf/pkg/sysservices"
)

// ClusterSessionService is the HA-aware session surface the REST session
// handlers delegate to so REST and gRPC share ONE cross-node session path
// (#3423). The daemon wires the live *grpcapi.Server, which clears/queries
// the LOCAL node AND fans out to the cluster peer over the fabric gRPC
// link (clearPeerSessions / fetchPeerSessions). All three methods already
// exist on the gRPC server; REST builds the protobuf request and maps the
// response back to its JSON types. A nil service (standalone build, or a
// unit test that does not wire it) makes the REST handlers fall back to
// LOCAL-ONLY behavior — the pre-#3423 contract.
type ClusterSessionService interface {
	// ClearSessions clears all sessions on the local node and, in a
	// cluster, forwards the clear to the peer, returning per-family counts
	// plus a partial-failure summary (peer unreachable / peer clear failed).
	ClearSessions(context.Context, *pb.ClearSessionsRequest) (*pb.ClearSessionsResponse, error)
	// GetSessions returns the HA-aware session list; with IncludePeer set it
	// stamps the peer node's sessions onto the response's Peer field.
	GetSessions(context.Context, *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error)
	// GetSessionSummary returns the HA-aware summary; with IncludePeer set it
	// stamps the peer node's summary onto the response's Peer field.
	GetSessionSummary(context.Context, *pb.GetSessionSummaryRequest) (*pb.GetSessionSummaryResponse, error)
	// GetZonePairSummary returns the HA-aware zone-pair breakdown; with
	// IncludePeer set it stamps the peer node's breakdown onto the response's
	// Peer field (#3592).
	GetZonePairSummary(context.Context, *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error)

	// PeerSessions / PeerSessionSummary / PeerZonePairSummary return ONLY the
	// cluster peer's view, with NO local table walk (#5968).
	//
	// The three handlers above already walked the local table themselves before
	// delegating for include_peer, and then discarded the delegate's local
	// result — keeping only its Peer field. That was a second full-table
	// traversal per request, contending with the live session-sync path for the
	// same per-bucket map locks. #5880 fixed the double-ACQUIRE on this path;
	// this is the double-WALK, which survived it.
	//
	// These are in-process only, so they cost no protobuf or wire change, and
	// they acquire through the SAME lease-aware limiter the full methods use —
	// slot accounting is identical before and after, so the #5880 lease
	// guarantee is preserved rather than quietly retired.
	PeerSessions(context.Context, *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error)
	PeerSessionSummary(context.Context) (*pb.GetSessionSummaryResponse, error)
	PeerZonePairSummary(context.Context) (*pb.GetZonePairSummaryResponse, error)
}

// CompileHealthSnapshot mirrors daemon.CompileHealth without the import.
// Keeping pkg/api -> pkg/daemon free of a back-edge preserves the layered
// build shape; the daemon injects a callback that returns this struct.
type CompileHealthSnapshot struct {
	EverSucceeded    bool
	FailureCount     uint64
	LastError        string
	LastErrorUnixSec int64
}

// BootstrapImportSnapshot mirrors daemon.BootstrapImport without the import,
// so pkg/api -> pkg/daemon stays a one-way edge (#4184). The daemon injects a
// callback returning this; /health surfaces the day-0 config-import outcome so
// a failed bootstrap import is visible beyond a single journald WARN.
// HostInboundAppliedSnapshot mirrors daemon.HostInboundAppliedState without the
// import, keeping pkg/api -> pkg/daemon a one-way edge (#4184).
//
// #7181: every zone projection until now rendered host-inbound from CONFIG --
// the DESIRED state -- with no way to say whether the kernel surface enforcing
// it is in place. Established is STICKY (a later failed render does not clear
// it), so it must never be rendered alone as "enforcement is in force"; paired
// with LastApplyFailed it separates never-established / current / stale.
type HostInboundAppliedSnapshot struct {
	Known              bool // false = the daemon could not be asked; claims NOTHING
	Established        bool
	Generation         uint64
	LastApplyFailed    bool
	LastFailureUnixSec int64
	GapFenceActive     bool
}

type BootstrapImportSnapshot struct {
	Status  string // "ok" | "loaded-from-db" | "no-config" | "import-failed" | ""
	Error   string // detail when Status == "import-failed"
	UnixSec int64
	Failed  bool // true only for a real import failure (not the factory no-config state)
}

// Config configures the API server.
type Config struct {
	Addr      string
	HTTPSAddr string      // HTTPS listen address (empty = no HTTPS)
	TLS       bool        // enable HTTPS with auto-generated certificate
	Auth      *AuthConfig // nil = no authentication
	// ListenFunc is the listener factory the server binds through (#5866).
	// nil defaults to net.Listen; a test injects a fake so the
	// make-before-break listener reconcile is exercised without real ports.
	ListenFunc func(network, address string) (net.Listener, error)
	// PeerLookupFn resolves the identity of the peer end of an accepted
	// connection, for the #5561 server-side authorization gate. `client` is
	// the connection's remote address and `server` its local address. nil
	// defaults to authz.LookupPeer, the kernel socket-table lookup.
	//
	// It is a seam, not a mock: a test injects a chosen identity so the route
	// table and the class evaluation are exercised for a principal the test
	// picks, instead of only for whichever account happens to run the suite.
	// The kernel lookup itself is covered against real sockets in pkg/authz,
	// and the REST gate is covered end-to-end with no injection at all by
	// TestProductionServerEnforcesRealPeerIdentity_5561.
	PeerLookupFn func(client, server net.Addr) authz.PeerIdentity
	// PeerLocalityFn re-derives, at the moment an api-auth credential is about
	// to speak for a caller, whether that caller is on THIS host (#5561). nil
	// defaults to authz.PeerCouldBeLocalNow, a fresh interface enumeration.
	//
	// It is a second seam rather than a re-use of PeerLookupFn because the two
	// answer different questions at different moments: PeerLookupFn is the
	// accept-time identity, this is the authoritative locality re-check the
	// credential row performs. A test that fabricates an off-box peer over a
	// real LOOPBACK listener must state that premise here too — the production
	// re-check would otherwise, correctly, call 127.0.0.1 one of ours and deny.
	PeerLocalityFn func(client, server net.Addr) bool
	Store          *configstore.Store
	DP             apiRuntimeDataPlane
	EventBuf       *logging.EventBuffer
	GC             *conntrack.GC
	Routing        *routing.Manager
	FRR            *frr.Manager
	IPsec          *ipsec.Manager
	DHCP           *dhcp.Manager
	VRRPMgr        *vrrp.Manager // native VRRP manager
	// #846: atomic commit+apply callbacks. The daemon holds its
	// apply semaphore across configstore.Commit and applyConfig, so
	// two concurrent committers can't interleave their commit→apply
	// pairs. Returns ctx.Err() if the request is canceled before the
	// semaphore is acquired (handlers translate to 408/503).
	CommitFn          func(ctx context.Context, authority configstore.CommitAuthority, comment string) (*config.Config, error)
	CommitConfirmedFn func(ctx context.Context, authority configstore.CommitAuthority, minutes int) (*config.Config, error)
	// CompileHealthFn surfaces dataplane compile state via /health (#758).
	// Returning a snapshot with EverSucceeded=false and FailureCount>0
	// makes /health return 503 so operators see the degraded state
	// instead of reading "status: ok" alongside a one-shot WARN in the
	// journal. Optional; if nil, /health keeps the pre-#758 behaviour.
	CompileHealthFn func() CompileHealthSnapshot
	// BootstrapImportFn surfaces the day-0 / bootstrap config-import outcome
	// via /health (#4184, mirrors CompileHealthFn). It is reported as a
	// non-fatal field (like rollback_history_degraded): a failed import means
	// the box is in the lifeline-safe bootstrap state, so surfacing the cause
	// is the goal — not pulling a still-reachable box from a probe-gated
	// rotation. Optional; if nil, the field is omitted.
	BootstrapImportFn func() BootstrapImportSnapshot

	// HostInboundAppliedFn returns the #7181 APPLIED state of the host-inbound
	// nftables surface. nil renders desired-only, exactly as before #7181 -- an
	// unwired callback must never be reported as healthy.
	HostInboundAppliedFn func() HostInboundAppliedSnapshot
	// ConfigPersistDegradedFn surfaces the configstore's persist-degraded
	// state via /health and the xpf_daemon_config_persist_degraded gauge
	// (#1799, mirrors the CompileHealthFn pattern). Returning true means
	// config persistence is degraded, which now covers three causes: the
	// RUNNING active config failed to persist to disk (HA SyncApply or
	// commit-confirmed auto-rollback hit a write error) and the background
	// retry has not yet succeeded — a daemon restart would load a stale
	// config (#1799); a RESOLVED commit-confirmed record's removal is not
	// yet durable, so a restart could resurrect its rollback (#5835); or
	// boot recovery could not READ confirm.json, so the pending rollback
	// window is already lost and an UNCONFIRMED config is standing with no
	// timer (#8566). The last one is not self-healing — the window cannot
	// be recovered — and clears only when a later arm or removal of a
	// confirm record succeeds. /health returns 503 while degraded.
	// Optional; if nil, the check and gauge are omitted.
	ConfigPersistDegradedFn func() bool
	// VRRPLocalPrioritiesFn returns this node's per-redundancy-group VRRP
	// priorities (cluster.Manager.LocalPriorities), so the /vrrp handler can
	// build the RETH instances the same way every other surface does (#8321
	// finding 15). Without it the REST endpoint reported only the generic
	// per-interface `vrrp-group` instances and returned an EMPTY set on a
	// chassis cluster, where the VIPs live on RETH instances — a parity gap
	// with the gRPC GetVRRPStatus, which has appended CollectRethInstances
	// all along. Optional; if nil, only the generic instances are reported,
	// which is the pre-#8321 behaviour and the right answer for a
	// non-clustered node.
	VRRPLocalPrioritiesFn func() map[int]int
	// RollbackHistoryDegradedFn surfaces the configstore's
	// rollback-history-degraded state via /health and the
	// xpf_config_rollback_persist_degraded gauge (#3441, mirrors the
	// ConfigPersistDegradedFn pattern). Returning true means the most
	// recent commit failed to durably write its text rollback-history
	// files. UNLIKE ConfigPersistDegradedFn this does NOT make /health
	// return 503: the commit succeeded and the active config is durable
	// (the rollback files are a best-effort recovery aid), so it is
	// reported as a non-fatal field plus the gauge for alerting. Optional;
	// if nil, the field and gauge are omitted.
	RollbackHistoryDegradedFn func() bool
	// ConfigApplyDebtFn surfaces the daemon's #9811 config-apply debt: the
	// dataplane is known to be enforcing something OTHER than the active
	// configuration, because an apply on a path with no caller to report to
	// failed and the retry owner has not yet converged. Today that path is the
	// commit-confirmed auto-rollback, where the store is promoted BEFORE the
	// apply.
	//
	// This DOES make /health return 503, and the distinction from
	// RollbackHistoryDegradedFn is the one that decides it: a degraded rollback
	// history is a recovery AID failing on a node that forwards exactly what it
	// reports, and a perfectly forwarding firewall must not be pulled from
	// rotation over one. Here the node forwards something it does NOT report —
	// the store, `show configuration`, the peer resync and the rest of this
	// payload all name a configuration the dataplane is not enforcing. That is
	// the same class as ConfigPersistDegradedFn ("a restart would load a stale
	// config"): a divergence between the reported state and the real one, which
	// an orchestrator scanning a probe must be able to act on. It is transient
	// by construction — the retry owner re-applies every 30s until it
	// converges. Optional; if nil, the check is omitted.
	ConfigApplyDebtFn func() (owed bool, failures uint64, lastErr string)
	// NeighborPhaseAgeFn surfaces the age (seconds) since each Go
	// periodic neighbor-maintenance phase last completed (#1780 Path A).
	// Keys: resolve/force_probe/clean_failed/warm. A monotonically
	// climbing age for any phase means that phase's guarded goroutine
	// is wedged (a stuck netlink/probe syscall), which is the signature
	// of the idle/overnight cold-connect hang. Optional; if nil, the
	// neighbor_periodic_last_success_age_seconds gauge is not emitted.
	NeighborPhaseAgeFn func() map[string]float64
	// IPMonStatusFn surfaces services ip-monitoring policy state for
	// the xpf_ipmon_* metrics (#1827). Optional; if nil, the family is
	// omitted.
	IPMonStatusFn func() []ipmon.PolicyStatus
	// IPMonActuationFailuresFn surfaces the cumulative count of
	// ip-monitoring route-overlay actuations that did not converge, for
	// the xpf_ipmon_actuation_failures_total counter (#4423 L). Optional;
	// if nil the metric is omitted.
	IPMonActuationFailuresFn func() uint64
	// RouteListenerMarksFn / RouteListenerRepublishesFn surface the #7437
	// kernel-route-listener pair. Optional; nil leaves both metrics unemitted.
	RouteListenerMarksFn       func() uint64
	RouteListenerRepublishesFn func() uint64
	// EventActionStatsFn surfaces event-options remediation action
	// counters for the xpf_event_actions_* / xpf_event_action_queue_depth
	// metrics (#2157). Optional; if nil, the family is omitted.
	EventActionStatsFn func() eventengine.Stats
	// RPMPinFailedFn surfaces the count of RPM next-hop probe pins
	// whose kernel install (fwmark rule + pinned route) is currently
	// failed — the affected tests hold state instead of probing the
	// default path, so a nonzero value means those uplinks are not
	// being health-checked (#1895). Backs the
	// xpf_rpm_probe_pin_install_failures gauge. Optional; if nil, the
	// gauge is not emitted.
	RPMPinFailedFn func() float64
	// FRRReloadDegradedFn reports whether the last applied FRR reload
	// fell back to the additive vtysh -f path (full frr-reload.py diff
	// failed) and the in-manager retry has not yet converged —
	// stale-config removal is deferred while set (#1880). Backs the
	// xpf_frr_reload_degraded gauge (0/1, no labels). Optional; if nil,
	// the gauge is not emitted.
	FRRReloadDegradedFn func() bool

	// FRRQuarantinedRouteMapsFn returns the route-map names the last rendered
	// FRR managed section replaced with the #6807 bounded explicit deny. Its
	// LENGTH feeds the xpf_frr_route_maps_quarantined gauge. Optional; if nil
	// the gauge is not published.
	FRRQuarantinedRouteMapsFn func() []string

	// FRRNarrowedPolicyChainsFn returns the BGP policy-chain attachments whose
	// applied chain is narrower than authored in the last rendered FRR managed
	// section (#8363). Its LENGTH feeds xpf_frr_policy_chains_narrowed.
	// FRRNarrowedPolicyChainsDenySafeFn returns the subset whose undefined
	// members form a suffix. Optional; if nil the gauges are not published.
	FRRNarrowedPolicyChainsFn         func() []string
	FRRNarrowedPolicyChainsDenySafeFn func() []string

	// NATLenientTerminalActionRulesFn returns the identities of NAT rules in
	// the ACTIVE config that the tolerant path admitted despite the strict
	// terminal-action cardinality gate (#7640). Its LENGTH feeds the
	// xpf_nat_rules_lenient_terminal_action gauge. Optional; if nil the gauge
	// is not published.
	NATLenientTerminalActionRulesFn func() []string
	// IPsecRebindPendingFn reports whether the last DHCP-lease-change IPsec
	// rebind failed and has not yet reconverged — swanctl local_addrs are
	// bound to a stale lease address while set, so the tunnel cannot
	// re-establish and the daemon's retry loop is still running (#4899).
	// Backs the xpf_ipsec_rebind_pending gauge (0/1, no labels). Optional;
	// if nil, the gauge is not emitted.
	IPsecRebindPendingFn func() bool
	// HostInboundConntrackRevocationOwedFn reports whether a host-inbound
	// kernel-conntrack revocation failed and has not yet been re-driven
	// (#6802). While true, an established direct-kernel connection to a
	// now-REMOVED host service may still be authorized by the host-inbound
	// chain's leading established/related accept. Backs the
	// xpf_host_inbound_conntrack_revocation_pending gauge (0/1, no labels).
	// Optional; if nil, the gauge is not emitted.
	HostInboundConntrackRevocationOwedFn func() bool
	// HostInboundConntrackFlushFailuresFn reports the monotonic count of
	// host-inbound conntrack revocation failures (#6802), retries included.
	// Backs the xpf_host_inbound_conntrack_revocation_failures_total counter.
	// Optional; if nil, the counter is not emitted.
	HostInboundConntrackFlushFailuresFn func() uint64
	// ManagedServiceReloadOwedFn reports, per xpf-managed service, whether a
	// runtime reload is still owed because the on-disk configuration converged
	// but the reload that would load it failed (#6800). Nil on a server that
	// does not wire it, in which case the series is OMITTED rather than
	// published as an authoritative 0.
	ManagedServiceReloadOwedFn func() map[string]bool
	// ManagedServiceReloadFailuresFn reports the monotonic per-service count of
	// failed reload attempts, retries included (#6800). Same nil contract.
	ManagedServiceReloadFailuresFn func() map[string]uint64
	// #7615: the remaining debt-driven retry owners, on the same surface as the
	// two above. Each reports whether its loop currently owes a repair; nil on
	// a server that does not wire it, in which case the series is OMITTED
	// rather than published as an authoritative 0.
	RADeadSenderPendingFn func() bool
	// ProxyARPUnresolvedFn reports whether a configured proxy-arp interface
	// failed to resolve on the most recent reconcile (#7685). Same nil contract.
	ProxyARPUnresolvedFn     func() bool
	FabricOverlayMissingFn   func() bool
	ManagementListenerDownFn func() bool
	// ManagementListenersFn returns the effective state of BOTH management
	// listeners (#8195). It is the same sysservices.Listeners snapshot
	// `show system services` renders, so the metric and the CLI cannot
	// disagree — deliberately the same source rather than a parallel one.
	ManagementListenersFn func() sysservices.Listeners
	// SchedulerRepublishFailedFn reports whether the most recent
	// scheduler-driven policy republish failed and has not yet converged
	// (#3780). A scheduler window transition republishes enforcement; a
	// swallowed failure leaves stale enforcement live past the window (a
	// permit still forwarding, or a scheduled block that never engaged).
	// Backs the xpf_scheduler_republish_failed gauge (0/1, no labels).
	// Optional; if nil, the gauge is not emitted.
	SchedulerRepublishFailedFn func() bool

	// HelperCrashEpisodesFn returns the #8397 count of userspace-dataplane
	// helper crash episodes this daemon has recovered from, feeding
	// xpf_dataplane_helper_crash_episodes_total. Wired independently of the
	// dataplane accessor chain because the metric must stay readable when the
	// dataplane is NOT loaded -- "has this helper been crashing?" is most worth
	// answering exactly then. nil disables the metric.
	HelperCrashEpisodesFn func() int

	// ForwardingSupportedFn reports whether the userspace dataplane is
	// forwarding transit, feeding xpf_dataplane_forwarding_supported (#8447).
	// nil disables the metric -- deliberately, so a daemon that cannot see the
	// dataplane emits no series rather than a fabricated 1.
	ForwardingSupportedFn func() bool
	// SchedulerRepublishStaleSecondsFn returns how long the current
	// scheduler-republish failure streak has gone unconverged, in
	// seconds (0 when healthy) (#3780). Backs the
	// xpf_scheduler_republish_stale_seconds gauge. Optional; if nil, the
	// gauge is not emitted.
	SchedulerRepublishStaleSecondsFn func() float64
	// SchedulerRepublishFailClosedFn reports whether the scheduler-republish
	// failure streak has persisted past the bounded age and the scheduler has
	// escalated to fail-closed — forcing scheduled policies inactive (deny) so
	// a permit stops forwarding past its window close (#5669). Backs the
	// xpf_scheduler_republish_fail_closed gauge (0/1, no labels). Optional; if
	// nil, the gauge is not emitted.
	SchedulerRepublishFailClosedFn func() bool
	// FeedsFn surfaces live dynamic-address feed status for the
	// xpf_feed_seconds_since_last_success / xpf_feed_stale gauges (#2050).
	// A feed that has never fetched successfully, or whose last-good
	// snapshot is being retained as stale, is the operator's signal that an
	// enforced address set is frozen (retain-forever default). Optional; if
	// nil, the feed gauges are omitted.
	FeedsFn func() map[string]feeds.FeedInfo
	// SyslogDropsFn surfaces per-collector remote-syslog drop counters for the
	// xpf_syslog_messages_dropped_total family (#9165). Before it, all three
	// SyslogClient drop accessors had ZERO production readers: a counted drop
	// reached an operator only through the package's own ≤1/s slog.Warn, so a
	// rate-limited warning left no trace at all. Syslog is where an operator
	// looks AFTER an incident, and a dead collector means that record does not
	// exist — while a `show` still renders the collector as configured.
	// Optional; if nil, the family is omitted.
	SyslogDropsFn func() []logging.SyslogDropStat
	// DDNSStatsFn surfaces the DHCP dynamic-DNS counter snapshot for the
	// xpf_dhcp_ddns_* metric family (#1387 inc-2). The daemon owns the
	// always-on DDNS manager; the API reads it through this function so the
	// api package does not import the manager type. Optional; if nil (or it
	// returns nil), the family is omitted.
	DDNSStatsFn func() *dhcpserver.DDNSStats
	// SurfaceAStatsFn surfaces the Surface A (router/interface-address) DDNS
	// counter snapshot for the xpf_ddns_surface_a_* metric family (#2691 P2).
	// Optional; if nil (or it returns nil), the family is omitted.
	SurfaceAStatsFn func() *ddns.SurfaceAStats
	// FlowCollectorHealthFn surfaces per-collector NetFlow v9 / IPFIX
	// write-health for the xpf_flow_export_collector_* metric family and
	// the /flow-exporters status endpoint (#2464). Flow export is
	// forensics/compliance data; a collector going silently unreachable
	// (every failed UDP write was debug-logged and dropped) is a
	// production concern, so the per-collector attempt/failure counters and
	// last-error/last-success state are surfaced here. Optional; if nil (or
	// it returns nil), the family is omitted.
	FlowCollectorHealthFn func() []flowexport.ExporterCollectorHealth
	// FlowExportBuildStateFn surfaces per-family flow-export BUILD health for
	// the xpf_flowexport_configured_groups / xpf_flowexport_build_failed gauges
	// (#9166). FlowCollectorHealthFn above cannot answer this: its family is
	// omitted when the health slice is empty, which is exactly what a failed
	// build produces, so a dead exporter and an unconfigured box read the same.
	// Optional; if nil, the build-health gauges are omitted.
	FlowExportBuildStateFn func() []flowexport.BuildState
	// FlowExportBatchStatsFn surfaces the per-exporter pending-batch queue
	// stats (current depth, high-water depth, dropped-at-capacity count) for
	// the xpf_flow_export_batch_* metric family (#3747). The export batch used
	// to be unbounded: a stalled/overrun drain grew memory without bound and
	// with no depth or drop visibility. Optional; if nil (or it returns nil),
	// the family is omitted.
	FlowExportBatchStatsFn func() []flowexport.ExporterBatchStats
	// FeedOverlayFn returns the live dynamic-address feed-prefix overlay
	// (#2049): an address-name -> union-of-feed-CIDRs map for the active
	// config, the same view the AF_XDP helper enforces. It is consulted by
	// the `match-policies` simulator (#3042) so a feed-backed policy address
	// token resolves to its live feed prefixes. Optional; if nil the
	// simulator resolves feed-backed names to their static content only.
	FeedOverlayFn func() map[string][]string
	// PolicySchedulerActiveStateFn returns the live daemon-local per-scheduler
	// active-state map (the same view Manager.PolicySchedulerActiveState
	// exposes to the CLI/gRPC show surfaces) plus whether it could be queried
	// (#3104). The `match-policies` simulator consults it so a scheduler-inactive
	// policy is skipped exactly like the runtime (policy.rs try_match_rule),
	// instead of reporting a definitive verdict the dataplane disagrees with.
	// Optional; if nil or it returns ok=false the simulator fails closed and
	// treats scheduled policies as inactive (#3414) — matching the snapshot
	// builder (nil scheduler state => dropped) rather than certifying an
	// as-if-active verdict the dataplane is skipping.
	PolicySchedulerActiveStateFn func() (map[string]bool, bool)
	// HAActiveFn reports whether THIS node is the active cluster member for
	// the default resource group, surfaced as the session ha_active field
	// (#3419 M6), mirroring the gRPC contract (server_sessions.go
	// IsLocalPrimary(0)). Optional; if nil the session view reports
	// ha_active=true (the standalone default).
	HAActiveFn func() bool
	// NodeIDFn returns this node's cluster id (0 standalone), stamped on the
	// REST session list/summary/clear responses so an operator knows WHICH
	// node a result came from (#3423 M5). Optional; if nil node_id reports 0.
	NodeIDFn func() int
	// ClusterSessionFn returns the HA-aware session service (the live gRPC
	// server) so the REST clear/list/summary handlers share the gRPC peer
	// fan-out path (#3423). It is resolved lazily, at request time, so the
	// daemon can wire a gRPC server constructed AFTER the REST server.
	// Optional; if nil (or it returns nil) the handlers stay local-only.
	ClusterSessionFn func() ClusterSessionService
}

// Server is the HTTP API server.
type Server struct {
	httpServer  *http.Server
	httpsServer *http.Server
	// auth is the LIVE authentication snapshot, read atomically on EVERY request
	// by the middleware so a day-2 web-management commit that tightens or revokes
	// credentials takes effect on the very next request WITHOUT rebinding the
	// listener or restarting the daemon (#5866). nil = no authentication (the
	// #4047/#5127 loopback clamp guarantees a nil-auth listener is loopback-only).
	// ReplaceAuth swaps it; a bind-address/port/TLS change instead goes through a
	// make-before-break listener rebuild (managementReconciler).
	auth atomic.Pointer[AuthConfig]
	// #5866 per-listener lifecycle: the HTTP and HTTPS listeners are managed
	// INDEPENDENTLY so a day-2 TLS enable/disable or HTTPS-bind change rebinds
	// ONLY the HTTPS leg while the live HTTP listener keeps serving (and an HTTP
	// bind change rebinds only the HTTP leg). Rebinding the whole server would
	// re-bind a socket the retiring server still holds (EADDRINUSE), so a same-
	// port change could never converge — the bug this replaces. sharedBase is the
	// pre-auth mux+collector+CSRF handler both legs wrap (per-listener auth gate
	// via listenerHandler), so the #4162 shared scrape limiter / session cache is
	// preserved across a rebind. certGen resolves the HTTPS cert for a (re)bind:
	// the self-signed cert is DURABLE (#1916 D6), so an existing on-disk pair is
	// LOADED AS-IS and a fresh cert is minted ONLY when no on-disk pair exists —
	// a rebind does not re-mint (that would churn remote clients' TOFU pins).
	// bindHost is the listener's host (net.SplitHostPort of the bind addr); at
	// FIRST mint it lands a non-loopback management IP in the cert SANs (#5719).
	// A later bind change is NOT re-minted — a loaded cert whose SANs miss the
	// new bind host is warned about (generateSelfSignedCertAt), not re-served
	// silently.
	// ifindexByName resolves a netdev name to its kernel ifindex when building
	// the session {ifindex, VLAN} -> interface-name table. nil means the real
	// kernel lookup; tests inject a fixed table so the session-identity paths
	// are exercisable without real netdevs (mirrors grpcapi).
	ifindexByName func(string) (int, error)
	sharedBase    http.Handler
	certGen       func(bindHost string) (tls.Certificate, error)
	lifeMu        sync.Mutex      // guards httpLeg/httpsLeg/rootCtx across reconciles
	rootCtx       context.Context // daemon lifetime; every leg drains on its cancel
	wg            sync.WaitGroup  // joins EVERY serve goroutine (live + retiring legs)
	httpLeg       *listenerLeg    // live HTTP listener leg (nil = not started / HTTP off)
	httpsLeg      *listenerLeg    // live HTTPS listener leg (nil = HTTPS off)
	// httpSlot / httpsSlot are the credential slots of the legs Start launches
	// from the construction-time servers (#5561 round 14). Every leg gets one;
	// a live slot follows s.auth, a retired one is pinned. See authSlot.
	httpSlot  *authSlot
	httpsSlot *authSlot
	// retiring holds the legs that have been asked to stop but have not finished
	// draining. Their slots are pinned, and ReplaceAuth keeps tightening them so
	// a revocation still reaches a listener on its way out. Guarded by retireMu
	// — NOT lifeMu, which Server.Wait holds across the whole drain.
	retireMu sync.Mutex
	retiring []*listenerLeg
	// listen is the listener factory (#5866): Config.ListenFunc or net.Listen. A
	// test injects a fake so the make-before-break reconcile is exercised without
	// binding real ports.
	listen func(network, address string) (net.Listener, error)
	// peerLookupFn is Config.PeerLookupFn; nil means authz.LookupPeer (#5561).
	peerLookupFn func(client, server net.Addr) authz.PeerIdentity
	// peerLocalityFn is Config.PeerLocalityFn; nil means
	// authz.PeerCouldBeLocalNow (#5561).
	peerLocalityFn func(client, server net.Addr) bool
	store          *configstore.Store
	dp             apiRuntimeDataPlane
	eventBuf       *logging.EventBuffer
	gc             *conntrack.GC
	routing        *routing.Manager
	frr            *frr.Manager
	ipsec          *ipsec.Manager
	dhcp           *dhcp.Manager
	vrrpMgr        *vrrp.Manager
	// #8321 finding 15: see Config.VRRPLocalPrioritiesFn.
	vrrpLocalPrioritiesFn func() map[int]int
	commitFn              func(ctx context.Context, authority configstore.CommitAuthority, comment string) (*config.Config, error)
	commitConfirmedFn     func(ctx context.Context, authority configstore.CommitAuthority, minutes int) (*config.Config, error)
	compileHealthFn       func() CompileHealthSnapshot
	bootstrapImportFn     func() BootstrapImportSnapshot
	// #7181: applied state of the host-inbound nft surface; nil = unwired.
	hostInboundAppliedFn                 func() HostInboundAppliedSnapshot
	configPersistDegradedFn              func() bool
	configApplyDebtFn                    func() (bool, uint64, string)
	rollbackHistoryDegradedFn            func() bool
	neighborPhaseAgeFn                   func() map[string]float64
	frrReloadDegradedFn                  func() bool
	frrQuarantinedRouteMapsFn            func() []string
	frrNarrowedPolicyChainsFn            func() []string
	frrNarrowedPolicyChainsDenySafeFn    func() []string
	natLenientTerminalActionRulesFn      func() []string
	ipsecRebindPendingFn                 func() bool
	hostInboundConntrackRevocationOwedFn func() bool
	hostInboundConntrackFlushFailuresFn  func() uint64
	managedServiceReloadOwedFn           func() map[string]bool
	managedServiceReloadFailuresFn       func() map[string]uint64
	raDeadSenderPendingFn                func() bool
	proxyARPUnresolvedFn                 func() bool
	fabricOverlayMissingFn               func() bool
	managementListenerDownFn             func() bool
	managementListenersFn                func() sysservices.Listeners
	schedulerRepublishFailedFn           func() bool
	helperCrashEpisodesFn                func() int
	forwardingSupportedFn                func() bool
	schedulerRepublishStaleSecondsFn     func() float64
	schedulerRepublishFailClosedFn       func() bool
	ipmonStatusFn                        func() []ipmon.PolicyStatus
	ipmonActuationFailuresFn             func() uint64
	routeListenerMarksFn                 func() uint64
	routeListenerRepublishesFn           func() uint64
	eventActionStatsFn                   func() eventengine.Stats
	rpmPinFailedFn                       func() float64
	feedsFn                              func() map[string]feeds.FeedInfo
	syslogDropsFn                        func() []logging.SyslogDropStat
	ddnsStatsFn                          func() *dhcpserver.DDNSStats
	surfaceAStatsFn                      func() *ddns.SurfaceAStats
	flowCollectorHealthFn                func() []flowexport.ExporterCollectorHealth
	flowExportBuildStateFn               func() []flowexport.BuildState
	flowExportBatchStatsFn               func() []flowexport.ExporterBatchStats
	feedOverlayFn                        func() map[string][]string
	policySchedActiveFn                  func() (map[string]bool, bool)
	haActiveFn                           func() bool
	nodeIDFn                             func() int
	clusterSessionFn                     func() ClusterSessionService
	startTime                            time.Time
}

// Management HTTP/HTTPS server timeouts (M-6). Both http.Server literals used
// to set only Addr/Handler(/TLSConfig), leaving every timeout field zero (no
// limit). Header reads happen BEFORE authMiddleware, so a pre-auth slowloris —
// N connections dribbling request headers or a request body one byte at a time
// — could pin a goroutine/socket per connection indefinitely and wedge the
// control-plane API once web-management binds a non-loopback interface (gosec
// G112/G114). The read-side timeouts below are the slowloris-critical defense.
//
// WriteTimeout is deliberately left UNSET (0 = unlimited): the SSE event/log
// streams (GET /api/v1/events/stream, /api/v1/logs/stream) are long-lived, and
// a full metrics or session-table scrape is a large, legitimately slow
// response. A WriteTimeout would sever those.
//
// #6809 CORRECTION. This block used to add "the response side is bounded by
// per-handler context deadlines instead", and that is not true in the way it
// reads. A context deadline bounds the handler's own WORK; it does not
// interrupt a write already blocked in the kernel because the peer stopped
// reading. Cancelling a context frees whatever the handler owns downstream — a
// child process, a map lock — but the goroutine stays parked in Write until a
// SOCKET write deadline fires. Only http.ResponseController.SetWriteDeadline
// (or a global WriteTimeout, which is what SSE rules out) does that.
//
// So an endpoint that streams to a client which stays CONNECTED but stops
// reading needs its own per-write deadline. /api/routing/bgp?type=routes
// carries one (bgpStreamWriteDeadline, routing.go) because it also pins a
// vtysh child behind the blocked write. Any future streaming endpoint has to
// make the same arrangement explicitly; leaving WriteTimeout unset is a
// deliberate trade that moves the bound to the handler, not a bound that
// happens automatically.
const (
	// apiReadHeaderTimeout bounds the time to read the request headers — the
	// slow-header slowloris defense, and the pre-auth guard since header read
	// precedes authMiddleware.
	apiReadHeaderTimeout = 10 * time.Second
	// apiReadTimeout bounds the time to read the ENTIRE request (headers +
	// body) — the slow-body slowloris defense. 30s is generous for any
	// legitimate mutation body (bodies are small; capped by
	// maxRequestBodyBytes) while cutting off a dribbled body.
	apiReadTimeout = 30 * time.Second
	// apiIdleTimeout caps how long an idle keep-alive connection is held open
	// awaiting the next request.
	apiIdleTimeout = 120 * time.Second
	// apiMaxHeaderBytes bounds total request header size so an attacker cannot
	// buffer unbounded header data before the timeouts fire.
	apiMaxHeaderBytes = 1 << 20 // 1 MiB

	// metricsScrapeTimeout bounds a single /metrics scrape (#4162). promhttp
	// aborts the handler and returns 503 if a scrape runs longer than this,
	// so a scrape that stalls inside a slow dataplane read cannot pin a
	// goroutine indefinitely. Generous relative to a healthy scrape (the
	// session walk is now cached) but a hard ceiling on a wedged one.
	metricsScrapeTimeout = 10 * time.Second
	// metricsMaxInFlight bounds concurrent /metrics scrapes (#4162). promhttp
	// returns 503 to scrapes beyond this many in flight, so a burst of parallel
	// scrapers cannot each spin up a collector pass at once. The session walk
	// is coalesced by the TTL cache, but this is the belt-and-suspenders limit
	// on the rest of the collector's per-scrape work.
	metricsMaxInFlight = 3
)

// NewServer creates a new API server.
func NewServer(cfg Config) *Server {
	s := &Server{
		store:                                cfg.Store,
		dp:                                   cfg.DP,
		eventBuf:                             cfg.EventBuf,
		gc:                                   cfg.GC,
		routing:                              cfg.Routing,
		frr:                                  cfg.FRR,
		ipsec:                                cfg.IPsec,
		dhcp:                                 cfg.DHCP,
		vrrpMgr:                              cfg.VRRPMgr,
		vrrpLocalPrioritiesFn:                cfg.VRRPLocalPrioritiesFn,
		commitFn:                             cfg.CommitFn,
		commitConfirmedFn:                    cfg.CommitConfirmedFn,
		compileHealthFn:                      cfg.CompileHealthFn,
		bootstrapImportFn:                    cfg.BootstrapImportFn,
		hostInboundAppliedFn:                 cfg.HostInboundAppliedFn,
		configPersistDegradedFn:              cfg.ConfigPersistDegradedFn,
		rollbackHistoryDegradedFn:            cfg.RollbackHistoryDegradedFn,
		configApplyDebtFn:                    cfg.ConfigApplyDebtFn,
		neighborPhaseAgeFn:                   cfg.NeighborPhaseAgeFn,
		frrReloadDegradedFn:                  cfg.FRRReloadDegradedFn,
		frrQuarantinedRouteMapsFn:            cfg.FRRQuarantinedRouteMapsFn,
		frrNarrowedPolicyChainsFn:            cfg.FRRNarrowedPolicyChainsFn,
		frrNarrowedPolicyChainsDenySafeFn:    cfg.FRRNarrowedPolicyChainsDenySafeFn,
		natLenientTerminalActionRulesFn:      cfg.NATLenientTerminalActionRulesFn,
		ipsecRebindPendingFn:                 cfg.IPsecRebindPendingFn,
		hostInboundConntrackRevocationOwedFn: cfg.HostInboundConntrackRevocationOwedFn,
		hostInboundConntrackFlushFailuresFn:  cfg.HostInboundConntrackFlushFailuresFn,
		managedServiceReloadOwedFn:           cfg.ManagedServiceReloadOwedFn,
		managedServiceReloadFailuresFn:       cfg.ManagedServiceReloadFailuresFn,
		raDeadSenderPendingFn:                cfg.RADeadSenderPendingFn,
		proxyARPUnresolvedFn:                 cfg.ProxyARPUnresolvedFn,
		fabricOverlayMissingFn:               cfg.FabricOverlayMissingFn,
		managementListenerDownFn:             cfg.ManagementListenerDownFn,
		managementListenersFn:                cfg.ManagementListenersFn,
		schedulerRepublishFailedFn:           cfg.SchedulerRepublishFailedFn,
		helperCrashEpisodesFn:                cfg.HelperCrashEpisodesFn,
		forwardingSupportedFn:                cfg.ForwardingSupportedFn,
		schedulerRepublishStaleSecondsFn:     cfg.SchedulerRepublishStaleSecondsFn,
		schedulerRepublishFailClosedFn:       cfg.SchedulerRepublishFailClosedFn,
		ipmonStatusFn:                        cfg.IPMonStatusFn,
		ipmonActuationFailuresFn:             cfg.IPMonActuationFailuresFn,
		routeListenerMarksFn:                 cfg.RouteListenerMarksFn,
		routeListenerRepublishesFn:           cfg.RouteListenerRepublishesFn,
		eventActionStatsFn:                   cfg.EventActionStatsFn,
		rpmPinFailedFn:                       cfg.RPMPinFailedFn,
		feedsFn:                              cfg.FeedsFn,
		syslogDropsFn:                        cfg.SyslogDropsFn,
		ddnsStatsFn:                          cfg.DDNSStatsFn,
		surfaceAStatsFn:                      cfg.SurfaceAStatsFn,
		flowCollectorHealthFn:                cfg.FlowCollectorHealthFn,
		flowExportBuildStateFn:               cfg.FlowExportBuildStateFn,
		flowExportBatchStatsFn:               cfg.FlowExportBatchStatsFn,
		feedOverlayFn:                        cfg.FeedOverlayFn,
		policySchedActiveFn:                  cfg.PolicySchedulerActiveStateFn,
		haActiveFn:                           cfg.HAActiveFn,
		nodeIDFn:                             cfg.NodeIDFn,
		clusterSessionFn:                     cfg.ClusterSessionFn,
		startTime:                            time.Now(),
	}
	// #5866: seed the live auth snapshot; the middleware reads it atomically per
	// request so ReplaceAuth can swap credentials without rebinding the listener.
	s.auth.Store(cfg.Auth)
	// #5866: the listener factory (Config.ListenFunc or net.Listen).
	s.listen = cfg.ListenFunc
	if s.listen == nil {
		s.listen = net.Listen
	}
	// #5561: the peer-identity resolver behind the authorization gate. nil
	// means the real kernel socket-table lookup (authz.LookupPeer), and nil
	// PeerLocalityFn means the real fresh enumeration
	// (authz.PeerCouldBeLocalNow) the credential row re-derives locality with.
	s.peerLookupFn = cfg.PeerLookupFn
	s.peerLocalityFn = cfg.PeerLocalityFn

	mux := http.NewServeMux()

	// Health + metrics
	mux.HandleFunc("GET /health", s.healthHandler)

	// Prometheus metrics with isolated registry
	registry := prometheus.NewRegistry()
	registry.MustRegister(newCollector(s))
	mux.Handle("GET /metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		// #4162: bound slow / concurrent scrapes. Empty opts left both zero
		// (no timeout, unlimited concurrency), so a stalled or bursty scraper
		// could pile up collector passes over the dataplane.
		Timeout:             metricsScrapeTimeout,
		MaxRequestsInFlight: metricsMaxInFlight,
	}))

	// REST API v1
	mux.HandleFunc("GET /api/v1/status", s.statusHandler)
	mux.HandleFunc("GET /api/v1/statistics/global", s.globalStatsHandler)
	mux.HandleFunc("GET /api/v1/statistics/interfaces", s.ifaceStatsHandler)
	mux.HandleFunc("GET /api/v1/statistics/zones", s.zoneStatsHandler)
	mux.HandleFunc("GET /api/v1/security/zones", s.zonesHandler)
	mux.HandleFunc("GET /api/v1/security/policies", s.policiesHandler)
	mux.HandleFunc("GET /api/v1/security/sessions", s.sessionsHandler)
	mux.HandleFunc("GET /api/v1/security/sessions/summary", s.sessionSummaryHandler)
	mux.HandleFunc("GET /api/v1/security/nat/source", s.natSourceHandler)
	mux.HandleFunc("GET /api/v1/security/nat/destination", s.natDestHandler)
	mux.HandleFunc("GET /api/v1/security/nat/deterministic", s.natDeterministicHandler)
	mux.HandleFunc("GET /api/v1/security/screen", s.screenHandler)
	mux.HandleFunc("GET /api/v1/security/events", s.eventsHandler)
	mux.HandleFunc("GET /api/v1/interfaces", s.interfacesHandler)
	mux.HandleFunc("GET /api/v1/dhcp/leases", s.dhcpLeasesHandler)
	mux.HandleFunc("GET /api/v1/dhcp/identifiers", s.dhcpIdentifiersHandler)
	mux.HandleFunc("GET /api/v1/routes", s.routesHandler)
	mux.HandleFunc("GET /api/v1/config", s.configHandler)

	// Routing protocols
	mux.HandleFunc("GET /api/v1/routing/ospf", s.ospfHandler)
	mux.HandleFunc("GET /api/v1/routing/bgp", s.bgpHandler)

	// IPsec
	mux.HandleFunc("GET /api/v1/security/ipsec/sa", s.ipsecSAHandler)

	// NAT stats
	mux.HandleFunc("GET /api/v1/security/nat/pools", s.natPoolStatsHandler)
	mux.HandleFunc("GET /api/v1/security/nat/rules", s.natRuleStatsHandler)

	// VRRP
	mux.HandleFunc("GET /api/v1/security/vrrp", s.vrrpHandler)

	// Policy match
	mux.HandleFunc("GET /api/v1/security/match", s.matchPoliciesHandler)

	// Interfaces detail
	mux.HandleFunc("GET /api/v1/interfaces/detail", s.interfacesDetailHandler)

	// Session zone-pair summary
	mux.HandleFunc("GET /api/v1/security/sessions/summary/zone-pairs", s.sessionZonePairHandler)

	// Flow-export collector health (#2464)
	mux.HandleFunc("GET /api/v1/services/flow-exporters", s.flowExportersHandler)

	// System info
	mux.HandleFunc("GET /api/v1/system/info", s.systemInfoHandler)
	mux.HandleFunc("GET /api/v1/system/buffers", s.systemBuffersHandler)

	// Mutations
	mux.HandleFunc("POST /api/v1/security/sessions/clear", s.clearSessionsHandler)
	mux.HandleFunc("POST /api/v1/security/counters/clear", s.clearCountersHandler)

	// Diagnostics
	mux.HandleFunc("POST /api/v1/diagnostics/ping", s.pingHandler)
	mux.HandleFunc("POST /api/v1/diagnostics/traceroute", s.tracerouteHandler)

	// Config management
	mux.HandleFunc("POST /api/v1/config/enter", s.configEnterHandler)
	mux.HandleFunc("POST /api/v1/config/exit", s.configExitHandler)
	mux.HandleFunc("GET /api/v1/config/status", s.configStatusHandler)
	mux.HandleFunc("POST /api/v1/config/set", s.configSetHandler)
	mux.HandleFunc("POST /api/v1/config/delete", s.configDeleteHandler)
	mux.HandleFunc("POST /api/v1/config/deactivate", s.configDeactivateHandler)
	mux.HandleFunc("POST /api/v1/config/activate", s.configActivateHandler)
	mux.HandleFunc("POST /api/v1/config/load", s.configLoadHandler)
	mux.HandleFunc("POST /api/v1/config/commit", s.configCommitHandler)
	mux.HandleFunc("POST /api/v1/config/commit-check", s.configCommitCheckHandler)
	mux.HandleFunc("POST /api/v1/config/commit-confirmed", s.configCommitConfirmedHandler)
	mux.HandleFunc("POST /api/v1/config/confirm", s.configConfirmHandler)
	mux.HandleFunc("POST /api/v1/config/rollback", s.configRollbackHandler)
	mux.HandleFunc("GET /api/v1/config/show", s.configShowHandler)
	mux.HandleFunc("GET /api/v1/config/export", s.configExportHandler)
	mux.HandleFunc("GET /api/v1/config/show-rollback", s.configShowRollbackHandler)
	mux.HandleFunc("GET /api/v1/config/compare", s.configCompareHandler)
	mux.HandleFunc("GET /api/v1/config/history", s.configHistoryHandler)
	mux.HandleFunc("GET /api/v1/config/search", s.configSearchHandler)
	mux.HandleFunc("POST /api/v1/config/annotate", s.configAnnotateHandler)

	// DHCP mutations
	mux.HandleFunc("POST /api/v1/dhcp/identifiers/clear", s.clearDHCPIdentifiersHandler)

	// SSE streaming
	mux.HandleFunc("GET /api/v1/events/stream", s.eventStreamHandler)
	mux.HandleFunc("GET /api/v1/logs/stream", s.logStreamHandler)

	// Generic text show
	mux.HandleFunc("GET /api/v1/show-text", s.showTextHandler)

	// System actions
	mux.HandleFunc("POST /api/v1/system/action", s.systemActionHandler)

	// #5055: guard the mutation surface against cross-site credentialed requests
	// (CSRF via browser-ambient Basic auth). This wraps the mux BEFORE auth so it
	// applies to every mutation route whether or not auth is configured; a
	// request that clears auth then hits this guard, so an attacker holding
	// ambient Basic credentials is still blocked from driving a state change from
	// a cross-site page. Safe methods and header-key/Bearer clients are unaffected.
	// #5561: enforce per-principal authorization on every state-changing route
	// INSIDE the cross-site guard, so the order a mutation is evaluated in is
	// (1) does the listener's api-auth policy admit it, (2) is this request of
	// cross-site provenance, (3) is the CALLER allowed to perform this action.
	// Steps 1 and 2 are properties of the request; step 3 is the first one that
	// asks who is making it. (The enumeration listed 1 and 2 the other way round
	// until #6645; the wrapping below is the authority — listenerHandler applies
	// the auth middleware OUTSIDE this handler, so auth runs first. No runtime
	// effect, but a reader reconstructing the order from the comment got it
	// backwards.) It sits inside the auth middleware
	// (applied per listener in listenerHandler) because a valid api-auth
	// credential is one of the identities it considers.
	sharedBase := mutationCrossSiteGuard(s.mutationAuthzGuard(mux))
	// #4162: auth policy belongs to the listener that accepted the request.
	// Keep one mux/collector/CSRF base so HTTP and HTTPS share the scrape
	// limiter and session-gauge cache, then derive an auth wrapper from each
	// listener's configured bind independently. Never infer this from r.Host
	// or the sibling listener: only a literal loopback bind leaves /metrics
	// open when auth is configured. /health remains exempt in authMiddleware.
	// #5866: wrap with a middleware that reads the LIVE auth snapshot (s.auth)
	// atomically per request, so ReplaceAuth takes effect on the next request
	// without rebinding. metricsRequireAuth is fixed per listener (its bind
	// address never changes for a given Server; a bind change goes through the
	// make-before-break rebuild, not this swap).
	// #5866: retain the pre-auth base handler + the cert generator so a per-leg
	// rebind (ReconcileHTTP/ReconcileHTTPS) can rebuild a single listener's
	// http.Server for a new bind address without disturbing the sibling leg.
	s.sharedBase = sharedBase
	s.certGen = generateSelfSignedCert

	if cfg.Addr != "" {
		plan := s.planHTTPLeg(cfg.Addr)
		s.httpSlot, s.httpServer = plan.slot, plan.srv
	}

	// Set up HTTPS server with auto-generated self-signed certificate
	if cfg.TLS && cfg.HTTPSAddr != "" {
		if plan, err := s.planHTTPSLeg(cfg.HTTPSAddr); err != nil {
			slog.Warn("failed to generate self-signed certificate", "err", err)
		} else {
			s.httpsSlot, s.httpsServer = plan.slot, plan.srv
		}
	}

	return s
}

// authSlot is one listener leg's view of the credential policy (#5561 round 14).
//
// While the leg is LIVE the slot follows the server-wide snapshot: load() reads
// s.auth, so a ReplaceAuth is enforced on that leg's very next request with no
// per-leg bookkeeping — byte-for-byte the pre-round-14 behavior, and the reason
// the plain day-2 credential swap is untouched by this.
//
// When the leg is RETIRED the slot is PINNED to what that address was serving at
// the moment of retirement, and from then on it can only tighten. That is the
// ordering fix: retirement is asynchronous (stopLegLocked only wakes the serve
// goroutine, which closes the socket and drains later), so between
// ReconcileHTTP returning and the retired listener actually going away there is
// an interval in which the reconciler publishes the credential set the commit
// authorized for the NEW address. Following s.auth through that interval handed
// that credential to the address the commit had just retired.
type authSlot struct {
	srv    *Server
	pinned atomic.Pointer[AuthConfig]
	// isPinned is separate from a nil `pinned` because nil is a MEANINGFUL
	// policy (no authentication at all), not "unset".
	isPinned atomic.Bool
}

// newAuthSlot allocates a live (following) slot for a new leg.
func (s *Server) newAuthSlot() *authSlot { return &authSlot{srv: s} }

// load returns the policy this leg must enforce for the request in hand.
// listenerHandler guarantees every middleware has a slot, so there is no nil
// receiver here — and deliberately no nil-receiver fallback, because the only
// plausible one (return nil) is dynamicAuthMiddleware's PASS-THROUGH.
func (a *authSlot) load() *AuthConfig {
	if a.isPinned.Load() {
		return a.pinned.Load()
	}
	return a.srv.auth.Load()
}

// pin freezes the slot at cur. Ordered so the pinned value is visible before the
// slot stops following: a request racing this sees either the server-wide
// snapshot or cur, and at the pin instant those are the same value.
func (a *authSlot) pin(cur *AuthConfig) {
	a.pinned.Store(cur)
	a.isPinned.Store(true)
}

// tighten intersects a PINNED slot with next, so a revocation still reaches a
// listener that is draining while no grant does. A nil next (remove-all-api-auth)
// is NOT applied: that direction removes a requirement, and its justification is
// the #4047/#5127 clamp on the address the COMMITTED config binds — never the
// address this leg is being retired from.
func (a *authSlot) tighten(next *AuthConfig) {
	if next == nil || !a.isPinned.Load() {
		return
	}
	a.pinned.Store(AuthForRetainedListener(a.pinned.Load(), next))
}

// listenerHandler wraps the shared pre-auth base with the per-listener auth gate
// for a bind address (#4162/#5866): only a literal loopback bind leaves /metrics
// open when auth is configured. The dynamic middleware reads the leg's own slot
// per request — which follows the live snapshot until the leg is retired — so
// ReplaceAuth needs no rebind.
func (s *Server) listenerHandler(addr string, slot *authSlot) http.Handler {
	if slot == nil {
		// Never let a missing slot become a pass-through: substitute a FOLLOWING
		// slot, which is what a live leg has anyway.
		//
		// #6734: this is now UNREACHABLE from any leg — legPlan allocates the
		// slot and hands the same pointer to this handler and to the leg, and
		// serveLegLocked no longer has a slot parameter to substitute for. It
		// is kept as the single fail-closed fallback for a direct
		// listenerHandler caller (tests build handlers this way), and it is
		// safe to keep precisely BECAUSE it is now the only substitution in the
		// package: one substitution cannot diverge from another.
		slot = s.newAuthSlot()
	}
	return s.dynamicAuthMiddleware(!isLoopbackBindAddr(addr), slot, s.sharedBase)
}

// buildHTTPServer constructs a fresh HTTP *http.Server bound-for addr with the
// per-listener handler (#5866). Used at construction and by a per-leg HTTP
// rebind.
// legPlan is an http.Server together with the authSlot its handler closes
// over (#6734). They are allocated together and travel together, so no caller
// can hand the handler one slot and the leg a different one.
//
// The divergence this makes unrepresentable was latent, not live: every
// production site threaded ONE slot through both layers. But it was reachable
// by construction — listenerHandler substituted a fresh slot for a nil, and
// serveLegLocked substituted again, so a future call site passing nil to both
// would have pinned the leg to slot Y while every request on it was judged by
// slot X. authSlot.pin / tighten would then operate on an object nothing reads
// and a retired listener would keep following the server-wide snapshot —
// exactly the #5561 round-14 defect the pin exists to prevent, silently.
//
// Pairing them is what removes the possibility. serveLegLocked no longer takes
// a slot at all, so there is nothing left for it to substitute; the only
// remaining allocation is the one inside these constructors.
type legPlan struct {
	srv  *http.Server
	slot *authSlot
}

// planHTTPLeg builds the HTTP leg's server and the slot its handler reads.
func (s *Server) planHTTPLeg(addr string) legPlan {
	slot := s.newAuthSlot()
	return legPlan{srv: s.buildHTTPServer(addr, slot), slot: slot}
}

// planHTTPSLeg is planHTTPLeg for the TLS leg; it can fail on cert generation.
func (s *Server) planHTTPSLeg(addr string) (legPlan, error) {
	slot := s.newAuthSlot()
	srv, err := s.buildHTTPSServer(addr, slot)
	if err != nil {
		return legPlan{}, err
	}
	return legPlan{srv: srv, slot: slot}, nil
}

// httpLegPlan / httpsLegPlan re-pair the fields NewServer wrote from one
// legPlan, for Start — which serves the servers built at construction rather
// than planning fresh ones. Callers hold lifeMu.
//
// THEY ADOPT A MISSING SLOT RATHER THAN ASSUMING ONE, and the first draft of
// this comment was wrong about why that is needed. It claimed each pair "has
// exactly ONE writer: the two assignments in NewServer", so a server could
// never exist without its slot. A caller that sets s.httpsServer DIRECTLY
// falsifies that — TestReconcileHTTPSReplacesADeadLeg_6827's fixture does
// exactly that and then calls Start, which produced a nil-slot leg and a nil
// dereference the moment stopLegLocked tried to pin it.
//
// So the slot is allocated here if absent AND STORED BACK. Storing back is the
// whole difference between this and the #6734 defect: the two substitutions
// this issue is about were INDEPENDENT — each allocated a slot the other could
// not see — whereas this one writes the very field it read, so the field, the
// plan and the leg are the same object afterwards and a second call returns it
// unchanged. One self-consistent adoption cannot diverge from itself.
func (s *Server) httpLegPlan() legPlan {
	if s.httpSlot == nil {
		s.httpSlot = s.newAuthSlot()
	}
	return legPlan{srv: s.httpServer, slot: s.httpSlot}
}

func (s *Server) httpsLegPlan() legPlan {
	if s.httpsSlot == nil {
		s.httpsSlot = s.newAuthSlot()
	}
	return legPlan{srv: s.httpsServer, slot: s.httpsSlot}
}

func (s *Server) buildHTTPServer(addr string, slot *authSlot) *http.Server {
	// #7011: trackHijackedConns installs the ConnState hook, so a connection a
	// handler hijacks is still closed by this leg's drain. Every leg
	// constructor must wrap, or that leg's hijacked connections outlive its
	// drain silently.
	return trackHijackedConns(&http.Server{
		Addr:              addr,
		Handler:           s.listenerHandler(addr, slot),
		ReadHeaderTimeout: apiReadHeaderTimeout,
		ReadTimeout:       apiReadTimeout,
		IdleTimeout:       apiIdleTimeout,
		MaxHeaderBytes:    apiMaxHeaderBytes,
		// #5561: resolve the peer's identity at ACCEPT and carry it into every
		// request on the connection. Deferring it would let the caller choose
		// the moment of the lookup — and choose to make it fail.
		ConnContext: s.connContext,
		// WriteTimeout intentionally unset — see the const block above (SSE
		// streams + large scrapes must not be severed).
	})
}

// buildHTTPSServer constructs a fresh HTTPS *http.Server bound-for addr with
// its durable self-signed certificate (#5866): certGen LOADS the existing
// on-disk pair AS-IS and mints a fresh cert ONLY when no on-disk pair exists (a
// rebind does not re-mint — #1916 D6). A cert-resolution failure is returned so
// the caller retains the previous leg (fail-closed).
func (s *Server) buildHTTPSServer(addr string, slot *authSlot) (*http.Server, error) {
	// Thread the listener's host into cert generation so a non-loopback
	// management bind IP (e.g. `web-management https interface 10.0.0.1`)
	// lands in the cert's SANs and a remote client verifies under strict
	// hostname checking (#5719 C001 residual). A wildcard/empty host
	// (":8443") yields "" and is ignored by the SAN builder.
	bindHost := ""
	if h, _, err := net.SplitHostPort(addr); err == nil {
		bindHost = h
	}
	tlsCert, err := s.certGen(bindHost)
	if err != nil {
		return nil, err
	}
	// #7011: same hijack tracking as the HTTP leg — see trackHijackedConns.
	return trackHijackedConns(&http.Server{
		Addr:              addr,
		Handler:           s.listenerHandler(addr, slot),
		ReadHeaderTimeout: apiReadHeaderTimeout,
		ReadTimeout:       apiReadTimeout,
		IdleTimeout:       apiIdleTimeout,
		MaxHeaderBytes:    apiMaxHeaderBytes,
		// #5561: same peer-identity plumbing as the HTTP leg.
		ConnContext: s.connContext,
		// WriteTimeout intentionally unset — see the const block above.
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
	}), nil
}

// Run starts the HTTP (and optionally HTTPS) server and blocks until ctx is
// cancelled or a listener terminates with an error.
//
// #5058: the HTTP and HTTPS listeners form ONE server lifecycle — startup is
// all-or-nothing and any terminal child error tears down every sibling. Both
// listeners are bound synchronously up front (a bind failure on either closes
// whichever already bound and returns before anything serves), then served
// under shared cancellation. On any serve error OR ctx cancellation both
// servers are shut down and both serve goroutines are joined before Run
// returns, so no surviving listener, socket, or goroutine is ever leaked.
// Before this change a bind/serve failure of one listener returned immediately
// and left the other serving forever — an orphaned management socket that the
// daemon wrapper could never reach to shut down.
func (s *Server) Run(ctx context.Context) error {
	httpLn, httpsLn, err := s.bindListeners()
	if err != nil {
		return err
	}
	return s.serveBound(ctx, httpLn, httpsLn)
}

// bindListeners binds the HTTP (and optional HTTPS) listeners SYNCHRONOUSLY, in
// a fixed order (HTTP first), ALL-OR-NOTHING: a bind failure on either closes
// whichever already bound and returns an error, so no orphaned socket is left
// (#5058). It is the make-before-break primitive (#5866) — the caller learns the
// endpoint is bindable before it retires the previous listener. Binds via
// s.listen (Config.ListenFunc, default net.Listen) so a test injects a fake
// factory instead of racing on real ports.
func (s *Server) bindListeners() (httpLn, httpsLn net.Listener, err error) {
	httpLn, err = s.listen("tcp", s.httpServer.Addr)
	if err != nil {
		return nil, nil, fmt.Errorf("api: bind HTTP listener %q: %w", s.httpServer.Addr, err)
	}
	if s.httpsServer != nil {
		httpsLn, err = s.listen("tcp", s.httpsServer.Addr)
		if err != nil {
			// The HTTP listener already bound — close it so a failed startup
			// leaves no orphaned socket behind (#5058).
			httpLn.Close()
			return nil, nil, fmt.Errorf("api: bind HTTPS listener %q: %w", s.httpsServer.Addr, err)
		}
	}
	return httpLn, httpsLn, nil
}

// Start / Wait / ReconcileHTTP / ReconcileHTTPS (the per-listener make-before-
// break lifecycle) live in listener.go (#5866).

// ReplaceAuth atomically swaps the live authentication snapshot (#5866). A day-2
// web-management commit that enables, tightens, or REVOKES credentials on an
// UNCHANGED bind calls this: the middleware reads the new snapshot on the next
// request, so a revoked credential is rejected immediately — no listener bounce,
// no restart, no window. a==nil disables auth (only reached on a loopback bind;
// the #4047/#5127 clamp forces a non-loopback no-auth bind through a rebuild).
//
// The swap reaches every LIVE leg at once (they read s.auth through their slots)
// and reaches each RETIRING leg only as a TIGHTENING (#5561 round 14). A leg
// that a reconcile replaced is still accepting and serving for the width of its
// drain (whose width is not a fixed bound — see legDrainTimeout), and the
// address it is serving is one the committed config asked
// to leave: a revocation must still land there, a grant must not, and a nil must
// not — the clamp that licenses a nil was evaluated against the address the
// commit BOUND, not the one it retired.
func (s *Server) ReplaceAuth(a *AuthConfig) {
	s.auth.Store(a)
	s.retireMu.Lock()
	defer s.retireMu.Unlock()
	for _, leg := range s.pruneRetiredLocked() {
		leg.slot.tighten(a)
	}
}

// LiveAuth returns the credential snapshot the listeners are currently
// enforcing (#5866). The management reconciler reads it to compute what a
// listener RETAINED by a failed rebind is allowed to keep accepting (#5561
// round 12, AuthForRetainedListener); tests read it to assert what a reconcile
// published. It is the same atomic pointer the middleware reads per request, so
// it never drifts from what is actually enforced.
func (s *Server) LiveAuth() *AuthConfig { return s.auth.Load() }

// HTTPHandlerForTest returns the http.Handler the LIVE HTTP leg is serving, or
// nil when no HTTP leg exists. Test-only, and specifically a CROSS-PACKAGE one
// (#5561 round 16).
//
// LiveAuth reports the SERVER-WIDE snapshot, which is not what a retired leg
// enforces: that leg's handler closes over its own authSlot, pinned at
// retirement and only ever tightened afterwards. A pkg/daemon test that wants to
// assert what the listener a reconcile RETIRED still admits therefore has to
// hold the handler across the reconcile — the leg itself is unexported,
// ReconcileHTTP has already replaced s.httpLeg by the time the reconcile
// returns, and s.retiring holds the old leg only until it finishes draining (any
// later ReplaceAuth prunes it), so reading it afterwards is a race. Taking the
// handler BEFORE the reconcile is deterministic and observes exactly what a
// caller arriving on that still-draining socket would be judged by.
func (s *Server) HTTPHandlerForTest() http.Handler {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	if s.httpLeg == nil || s.httpLeg.srv == nil {
		return nil
	}
	return s.httpLeg.srv.Handler
}

// HTTPSLegDrainedForTest reports whether the installed HTTPS leg has finished
// its EXIT PATH AND ITS DRAIN — the listener is gone and every connection it
// accepted has been finished or severed, hijacked connections excepted (Go
// excludes those from both Shutdown and Close; see drainLeg). False when no leg is installed.
// Test-only, and specifically a CROSS-PACKAGE precondition helper (#6827 round
// 7).
//
// It does NOT report that the serve goroutine has returned (#6827 round 8). The
// goroutine's defers run LIFO, so `drained` is stored BEFORE `wg.Done`, and a
// caller can observe true inside that window. That is the right granularity for
// a precondition — the drain is what the caller is waiting on — but a test that
// needs the goroutine itself to be gone must use Server.Wait.
//
// It exists because a test that arranges a dead leg needs to know the exit path
// has run, and the obvious way to ask — polling HTTPSServing() until it goes
// false — reads `dead`, which is the flag such a test is usually there to bind.
// A mutation that stops `dead` being stored then hangs the poll until its
// deadline and the cell reds at the SETUP rather than at its own assertion:
// evidence that the precondition is load-bearing, not that the property is
// bound. `drained` is stored unconditionally by the goroutine's defer on every
// exit path, so it answers "has the exit happened" without consulting anything
// under test.
//
// Server.Wait is the better barrier where it applies (it joins deterministically
// rather than polling), but it joins EVERY leg, so a caller whose server also
// has a live HTTP leg — the shape the daemon reconciler always has — cannot use
// it and needs this.
func (s *Server) HTTPSLegDrainedForTest() bool {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	return s.httpsLeg != nil && s.httpsLeg.drained.Load()
}

// HTTPSCertForTest returns the served TLS leaf certificate, or nil when the
// server is HTTP-only (#5866). Test-only: lets a cross-package test read the cert
// the LIVE HTTPS leg is serving after a reconcile, to assert that the durable
// self-signed pair is reloaded AS-IS across a rebind (#1916 D6 / #6381) rather
// than re-minted.
func (s *Server) HTTPSCertForTest() *tls.Certificate {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	// Read the LIVE HTTPS leg (post-reconcile), not the construction template, so
	// the cert the rebound listener actually serves is observed (#5866).
	srv := s.httpsServer
	if s.httpsLeg != nil {
		srv = s.httpsLeg.srv
	}
	if srv == nil || srv.TLSConfig == nil || len(srv.TLSConfig.Certificates) == 0 {
		return nil
	}
	return &srv.TLSConfig.Certificates[0]
}

// SetTLSCertDirForTest points the server's HTTPS certificate generator at dir
// instead of the production /etc/xpf/tls paths (#6381). Test-only: it lets a
// cross-package test (pkg/daemon managementReconciler) exercise the DURABLE
// self-signed-cert path (#1916 D6) against a WRITABLE temp dir, so an HTTPS
// rebind LOADS the persisted pair AS-IS (the shipping behavior) instead of
// failing to persist and re-minting a fresh in-memory cert on every reconcile
// (the CI-only artifact — an unwritable /etc/xpf/tls — that the old
// TestMgmtReconcileTLSChange_5866 assertion silently depended on). It routes
// through the real production generateSelfSignedCertAt, so the durable
// load-as-is path is genuinely bound.
func (s *Server) SetTLSCertDirForTest(dir string) {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	s.certGen = func(bindHost string) (tls.Certificate, error) {
		return generateSelfSignedCertAt(dir, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), bindHost)
	}
}

// dynamicAuthMiddleware wraps next with the auth snapshot of the LEG that
// accepted the request (#5866; per-leg since #5561 round 14): a live leg's slot
// reads s.auth atomically per request so a ReplaceAuth swap takes effect
// immediately, and a retired leg's slot reads the policy it was pinned to.
// A nil snapshot passes through (no auth) — the loopback clamp guarantees such a
// listener is loopback-only. It enforces byte-for-byte the same checks as the
// static authMiddleware via the shared authCheck.
func (s *Server) dynamicAuthMiddleware(metricsRequireAuth bool, slot *authSlot, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := slot.load()
		if a == nil {
			next.ServeHTTP(w, r)
			return
		}
		if authCheck(*a, metricsRequireAuth, r) {
			next.ServeHTTP(w, r)
			return
		}
		writeAuthChallenge(w)
	})
}

// serveBound serves already-bound listeners until ctx is cancelled or a listener
// terminates with an error, then DRAINS both (drainLeg: graceful Shutdown, then
// force-close what the deadline did not finish) and joins both serve goroutines
// before returning (#5058 lifecycle, extracted for the #5866 Start/Run split).
//
// It goes through drainLeg rather than calling Shutdown itself (#6827 round 10).
// It used to hold the exact shape drainLeg exists to fix — a bare Shutdown that
// returns at its deadline and LEAVES an in-flight response streaming — which
// made pkg/api/README.md's package-wide drain invariant false about this
// function and left the shape here for the next reader to copy. This path is
// test-only today (Server.Run has no production caller; the daemon uses
// NewServer + Start), so the change is cheap, but "no caller today" is not a
// reason to ship the defect.
//
// One behavioural consequence worth stating: this path now drains the way the
// rest of the package does, and that shape has NO wall-clock ceiling. The old
// code ran a bare Shutdown on each server under ONE shared 5s context and never
// reached a Close phase at all; each server now gets its own legDrainTimeout
// AND the severing Close behind it. That is not "5s for both" becoming "5s
// each": legDrainTimeout is a POLL deadline, and each phase puts serial
// per-connection closes ahead of any deadline being consulted — inside
// Shutdown, ahead of the poll deadline itself; after it, ahead of nothing at
// all, since http.Server.Close takes no context.
//
// The five seconds is the HTTPS leg's ALONE, not "each server" (#7047).
// s.httpsServer runs through ServeTLS, so each connection is a *tls.Conn whose
// Close sends close_notify under a five-second write deadline of its own; one
// stalled peer costs up to five seconds, then the next, in both of that leg's
// phases. s.httpServer runs through plain Serve, so its c.rwc is a *net.TCPConn
// whose Close sends no TLS alert and carries no such deadline — the HTTP leg is
// unbounded for other reasons (serial closes, no ceiling), but not by this
// five-second one.
//
// Either way the worst case grows with the number of stalled connections and
// has no fixed ceiling; legDrainTimeout's comment is the authority on why, and
// states the two phases separately rather than collapsing them as this summary
// once did. legDrainTimeout is also the knob a test can shorten.
func (s *Server) serveBound(ctx context.Context, httpLn, httpsLn net.Listener) error {
	// Both listeners are bound. Serve each in its own goroutine; a fatal
	// Serve error is reported once on the buffered channel.
	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("HTTP API server listening", "addr", s.httpServer.Addr)
		if err := s.httpServer.Serve(httpLn); err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	if s.httpsServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Info("HTTPS API server listening", "addr", s.httpsServer.Addr)
			// TLSConfig.Certificates is already populated in NewServer, so
			// ServeTLS with empty cert/key file paths uses those certs
			// (identical to the previous ListenAndServeTLS("", "")).
			if err := s.httpsServer.ServeTLS(httpsLn, "", ""); err != http.ErrServerClosed {
				errCh <- err
			}
		}()
	}

	var serveErr error
	select {
	case serveErr = <-errCh:
	case <-ctx.Done():
	}

	// Drain BOTH servers regardless of which path woke us. Shutdown closes the
	// listener and unblocks the matching Serve goroutine with
	// http.ErrServerClosed; join both so no goroutine outlives Run. The
	// Shutdown error is still what gets reported — a drain that had to sever is
	// visible as a deadline error here, exactly as before.
	var shutErr error
	if s.httpsServer != nil {
		shutErr = drainLeg(s.httpsServer)
	}
	if err := drainLeg(s.httpServer); err != nil && shutErr == nil {
		shutErr = err
	}
	wg.Wait()

	// A serve error is the real cause of the exit; surface it ahead of any
	// shutdown error (which, on the serve-error path, is usually just the
	// already-stopped sibling).
	if serveErr != nil {
		return serveErr
	}
	return shutErr
}

const (
	tlsDir   = "/etc/xpf/tls"
	certPath = "/etc/xpf/tls/cert.pem"
	keyPath  = "/etc/xpf/tls/key.pem"
)

// TLS persistence test seams (#1916 injected-failure tests). Production
// code must never mutate these. tlsHostname is the SAN-source seam (#5719):
// tests drive the non-ASCII / IP-shaped hostname branches deterministically
// without mutating the machine's real hostname.
var (
	tlsMkdirAllDurable  = fsatomic.MkdirAllDurable
	tlsRemove           = os.Remove
	tlsSyncDir          = fsatomic.SyncDir
	tlsWriteFileDurable = fsatomic.WriteFileDurable
	tlsHostname         = os.Hostname
)

// isDNSSANSafeHostname reports whether h is safe to place in a certificate DNS
// SAN. It must be non-empty, contain only ASCII letters, digits, hyphen, and
// dot (the characters x509 can encode as an IA5String and that make a
// well-formed DNS name), and not be an IP literal (an IP-shaped hostname
// belongs in IPAddresses, not DNSNames). A hostname that fails this check is
// dropped from the SAN set rather than fed to x509.CreateCertificate, which
// HARD-FAILS on a non-ASCII DNS name and — under the #5058 all-or-nothing
// management-server lifecycle — would abort cert generation and tear down the
// entire HTTP+HTTPS server.
func isDNSSANSafeHostname(h string) bool {
	if h == "" {
		return false
	}
	if net.ParseIP(h) != nil {
		return false // IP literal → belongs in IPAddresses
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}

// generateSelfSignedCert creates or loads a self-signed TLS certificate
// using the production /etc/xpf/tls paths. See generateSelfSignedCertAt.
func generateSelfSignedCert(bindHost string) (tls.Certificate, error) {
	return generateSelfSignedCertAt(tlsDir, certPath, keyPath, bindHost)
}

// ipSANsContain reports whether ip is already present in sans. net.IP.Equal
// normalizes the 4-byte / 16-byte-mapped forms so a v4 SAN never duplicates.
func ipSANsContain(sans []net.IP, ip net.IP) bool {
	for _, s := range sans {
		if s.Equal(ip) {
			return true
		}
	}
	return false
}

// dnsSANsContain reports whether name is already present in names. DNS names
// are case-insensitive (RFC 4343), so a comparison uses strings.EqualFold —
// "MGMT.example.com" and "mgmt.example.com" name the same host and must not be
// double-encoded as distinct SANs.
func dnsSANsContain(names []string, name string) bool {
	for _, n := range names {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// bindHostWarnable reports whether bindHost is a concrete management host worth
// warning about when a loaded on-disk cert does not cover it. An empty host, a
// wildcard bind (0.0.0.0/::), a loopback host, or "localhost" is NOT warnable:
// the durable cert always carries the loopback SANs, and a wildcard bind names
// no single host. Only a non-loopback, non-unspecified management bind can be
// left uncovered by an older cert.
func bindHostWarnable(bindHost string) bool {
	if bindHost == "" || bindHost == "localhost" {
		return false
	}
	if ip := net.ParseIP(bindHost); ip != nil {
		return !ip.IsLoopback() && !ip.IsUnspecified()
	}
	return true
}

// bindIsLoopbackOnly reports whether the HTTPS management listener can be
// reached ONLY from this host, so no REMOTE client exists to verify anything by
// host name (#7039).
//
// NOT `!bindHostWarnable(bindHost)`. That is the obvious drop-in and it is
// wrong, because the two functions answer different questions and disagree on
// the most remote-reachable bind there is:
//
//	bindHost        bindHostWarnable   bindIsLoopbackOnly
//	""              false              false
//	"localhost"     false              TRUE
//	"127.0.0.1"     false              TRUE
//	"::1"           false              TRUE
//	"0.0.0.0"       false              false   <-- reachable from everywhere
//	"::"            false              false   <-- reachable from everywhere
//	"10.0.0.1"      TRUE               false
//
// `bindHostWarnable` asks "is there a single concrete host here worth warning
// about if the cert misses it" — a WILDCARD bind answers no, because it names no
// one host, not because it is unreachable. Suppressing the host-name diagnostic
// on `!bindHostWarnable` would therefore silence it on `0.0.0.0`, where remote
// clients certainly do exist and the host name certainly is an access identity.
// That is over-suppression of exactly the case the diagnostic is FOR.
// `TestLoopbackOnlyIsNotTheComplementOfBindHostWarnable_7039` pins the divergence.
//
// An empty bindHost is NOT treated as loopback, and the reason is stronger than
// "suppressing on unknown state fails the wrong way". `":8443"` — the bare-port
// form, an ordinary way to spell a listener on every interface — splits to an
// EMPTY host, so `""` most often means WILDCARD rather than unparseable. This
// module's own README already records that reading for the bind-host half:
// "wildcard (`:8443` → empty) / non-encodable bind host is skipped". Treating
// `""` as loopback would therefore suppress the diagnostic on a maximally
// reachable listener — the same error as the `!bindHostWarnable` drop-in,
// reached from a different direction.
// `TestWarnStaleMgmtCertForHostName_6827/wildcard_bind_host_still_diagnoses_the_name`
// binds that shape; it uses exactly a `":8443"` listener.
func bindIsLoopbackOnly(bindHost string) bool {
	if bindHost == "localhost" {
		return true
	}
	if ip := net.ParseIP(bindHost); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// hostnameSANWarnable reports whether the CURRENT kernel host name is an
// identity worth warning about when a loaded on-disk cert does not cover it.
//
// It layers one extra condition on bindHostWarnable: the host name must be one
// a re-mint COULD actually put in the SANs. generateSelfSignedCertAt
// deliberately DROPS a non-ASCII / malformed host name from DNSNames rather
// than hard-failing x509.CreateCertificate (see isDNSSANSafeHostname), so such
// a name is uncoverable BY DESIGN — warning about it every reload would be
// permanent noise advising a re-mint that cannot fix anything. An IP-literal
// host name is warnable because it lands in IPAddresses.
func hostnameSANWarnable(h string) bool {
	if !bindHostWarnable(h) {
		return false
	}
	if net.ParseIP(h) != nil {
		return true // IP-literal host name → IPAddresses SAN
	}
	return isDNSSANSafeHostname(h)
}

// certCoversHost reports whether leaf's SANs cover host under the SAME strict
// hostname check a remote TLS client applies: an IP-literal host must appear in
// the cert's IPAddresses SANs, any other host in its DNSNames SANs (a CN-only
// or SAN-mismatched cert is not covered). x509.Certificate.VerifyHostname
// implements exactly that classification, so a false result means a client
// verifying the connection by host will reject the served cert.
func certCoversHost(leaf *x509.Certificate, host string) bool {
	return leaf.VerifyHostname(host) == nil
}

// certHasNoSANs reports whether leaf carries NO subjectAltName usable for
// hostname verification — neither a DNS name nor an IP address. Such a
// certificate covers NOTHING: every modern client (Go since 1.15, browsers,
// curl) refuses to fall back to the legacy CommonName, so BOTH
// `https://localhost` and `https://127.0.0.1` fail against a CN-only cert.
//
// The per-identity checks below cannot see this: their warnable predicates gate
// out loopback and "localhost" on the assumption that the durable cert always
// carries the loopback SANs. That assumption holds for a cert THIS mint path
// produced, but the load path accepts whatever is on disk — a pair persisted by
// an older build, or placed by an operator, can have no SAN extension at all,
// and then the whole diagnostic goes silent on the most broken cert possible
// (#6827). Other SAN forms (email, URI) are irrelevant here: VerifyHostname
// consults only DNSNames and IPAddresses.
func certHasNoSANs(leaf *x509.Certificate) bool {
	return len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0
}

// hostNameEvidence tells the host-name diagnostic HOW the caller learned the
// kernel host name, which decides how much benefit of the doubt that name gets
// as a management ACCESS identity (#6827).
type hostNameEvidence int

const (
	// hostNameInferred — a certificate (re)load read the kernel host name off
	// the running system (boot, or an HTTPS enable/rebind). Nothing there proves
	// an operator ever connects by that name, so hostNameLikelyAccessIdentity's
	// heuristic applies.
	hostNameInferred hostNameEvidence = iota
	// hostNameOperatorSet — the operator's own `set system host-name` commit
	// JUST moved the kernel host name (Daemon.applyHostname →
	// Server.WarnStaleMgmtCertForHostName). The name is the identity they
	// deliberately chose for this device, reported at the moment they chose it,
	// so it is diagnosed unconditionally: this is the one call site where "is
	// this an access identity?" has a real answer rather than a heuristic.
	hostNameOperatorSet
)

// hostNameLikelyAccessIdentity reports whether the kernel host name is PLAUSIBLY
// a management access identity, judged from the SANs the loaded cert already
// carries. It exists so the diagnostic stops crying wolf (#6827): a box named
// `fw` whose cert covers `mgmt.example.com` and its management IP is reachable
// and strictly verifiable at every URL actually in use, and telling that
// operator to re-mint churns remote clients' TOFU pins to fix nothing. A
// diagnostic that fires on a healthy box gets muted, and the true positive dies
// with it.
//
// THE RULE, and why the cert's own SANs are the best evidence available: this
// package's mint path is the ONLY thing that puts a bare, UNQUALIFIED name into
// a generated cert, and what it puts there is the kernel host name of the day
// (the bind host is the other source, and a management bind is an address or a
// domain-qualified name). So the qualification SHAPE of the cert's DNS SANs
// tells us which naming scheme this device's TLS identity follows:
//
//   - an unqualified DNS SAN (`old-fw`) next to an unqualified kernel host name
//     means the TLS identity IS the kernel name, and it has drifted — diagnose;
//   - a qualified DNS SAN (`mgmt.example.com`) next to an unqualified kernel
//     host name means the TLS identity is domain-scoped and INDEPENDENT of the
//     short kernel name, which was therefore never an access identity — silent;
//   - a cert with no non-loopback DNS SAN at all was never minted for name-based
//     access — silent.
//
// An IP-literal kernel host name is judged the same way against IP SANs:
// address-based access is evidenced by a non-loopback IP SAN.
//
// The heuristic is deliberately NOT applied to hostNameOperatorSet. It is a
// heuristic precisely because a cert load has no way to know what an operator
// types; a rename does know, and it is also the one moment the operator is
// watching the commit output.
//
// KNOWN RESIDUAL, weighed and accepted rather than missed. A rename that also
// CHANGES the naming shape (`old-fw` → `newfw.example.com`, or the reverse) is
// diagnosed at the commit — the rename path skips this function — but never on
// a later boot, because from then on the load path sees a shape mismatch and
// stays quiet. Two states reach that boot with no commit-time diagnosis behind
// them, and only the first is about old boxes:
//
//   - a box ALREADY drifted before this diagnostic shipped never had a commit
//     to catch it;
//   - on a box RUNNING this build, the commit's diagnosis is a PROCESS-LOCAL
//     debt (Daemon.staleCertPending, pkg/daemon), and a restart discards
//     whatever is still owed. A cross-shape rename reaches that restart
//     undelivered whenever no delivery between the rename and the shutdown
//     found a served certificate. The ways in are more than the obvious one and
//     worth naming, because each is an ordinary configuration rather than a
//     fault: HTTPS disabled; its bind failed; the HTTPS serve loop terminated
//     and no later commit rebuilt it (the rebuild itself is #6827 round 6 — the
//     dead leg used to be unrecoverable, so this was permanent rather than
//     merely pending); the API disabled entirely (--api-addr empty, so there is
//     no reconciler to deliver through); the boot HTTP start failed; the kernel
//     name could not be read at any delivery; or startup aborted on a signal
//     (#5807) after the phase-4 config apply but before the management server
//     was built. Enabling `web-management https` after the restart then reaches
//     only the load path, which declines the shape.
//
// So the gap needs a rename that crossed the qualified/unqualified boundary AND
// either pre-dating drift or a debt that did not survive a restart. It is the
// rename path, not this function, that catches the ordinary case, and
// shape-PRESERVING drift — unqualified → unqualified, including the worked
// `old-fw` → `new-fw` — is still caught on every boot by this one.
//
// Closing either half costs the same mechanism and is declined for the same
// reason: a boot-after-upgrade sweep needs upgrade-scoped persistent state (a
// marker file or version stamp), and a debt that outlives a restart needs the
// pending flag persisted plus an invalidation story for a name that changed
// again while the daemon was down. Both then fire on exactly the boxes where
// this function cannot tell whether the name is in use, reintroducing the false
// positive at the least convenient moment. Not worth the mechanism; recorded
// here so the next reader knows the choice was made deliberately.
func hostNameLikelyAccessIdentity(leaf *x509.Certificate, hostName string) bool {
	if net.ParseIP(hostName) != nil {
		for _, ip := range leaf.IPAddresses {
			if !ip.IsLoopback() && !ip.IsUnspecified() {
				return true
			}
		}
		return false
	}
	qualified := strings.Contains(hostName, ".")
	for _, n := range leaf.DNSNames {
		if strings.EqualFold(n, "localhost") {
			continue // always minted; carries no evidence either way
		}
		if strings.Contains(n, ".") == qualified {
			return true
		}
	}
	return false
}

// warnStaleLoadedCert emits a diagnostic for every management identity the
// LOADED durable cert fails to cover. The cert is served AS-IS (#1916 D6: a
// re-mint would churn remote clients' TOFU pins), so this is the ONLY signal an
// operator gets that strict remote verification will fail (#5719 C001).
//
// TWO identities are baked into the cert at first generation and BOTH can go
// stale independently:
//
//   - the HTTPS listener bind host — stale after an A→B `web-management https
//     interface` rebind;
//   - the kernel host name — stale after `set system host-name`, which the
//     durable cert does NOT re-mint for. Before this check that half was
//     entirely SILENT: an operator connecting by the new host name got a bare
//     "certificate is not valid for any names" with nothing in the log, even
//     though the bind host was still covered so the bind-host warning never
//     fired.
//
// The leaf is parsed ONCE and every check shares it. A parse failure or an empty
// chain is not reported here — the caller still serves the pair it loaded, and
// this function's contract is diagnostics only, never a serving decision.
//
// This is only ONE of the two entry points. A `set system host-name` commit does
// NOT reload the certificate (the HTTPS leg rebinds only on a TLS/bind change),
// so the rename half of the diagnostic reaches the operator through
// Server.WarnStaleMgmtCertForHostName instead (#6827).
func warnStaleLoadedCert(cert tls.Certificate, bindHost string) {
	if len(cert.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	hostName, _ := tlsHostname()
	if warnCertNoSANs(leaf, bindHost, hostName) {
		return
	}
	warnStaleBindHost(leaf, bindHost)
	warnStaleHostName(leaf, hostName, bindHost, hostNameInferred)
}

// warnCertNoSANs emits the terminal "this certificate covers nothing"
// diagnostic and reports whether it fired. It is terminal by design: when the
// leaf has no SANs at all, the per-identity warnings below would each report
// "does not cover X" for a cert that covers no X whatsoever, which buries the
// actual finding under a list of symptoms.
func warnCertNoSANs(leaf *x509.Certificate, bindHost, hostName string) bool {
	if !certHasNoSANs(leaf) {
		return false
	}
	slog.Warn("loaded management TLS cert carries NO subjectAltName, so it covers NOTHING — every modern client rejects it for every host name and address (CommonName is not consulted) — remove /etc/xpf/tls to re-mint",
		"cert_common_name", leaf.Subject.CommonName,
		"bind_host", bindHost,
		"host_name", hostName)
	return true
}

// warnStaleBindHost warns when the loaded cert does not cover the HTTPS
// listener's own bind host. The bind host needs no plausibility test: the
// operator configured the listener to answer there, so it is an access identity
// by construction.
func warnStaleBindHost(leaf *x509.Certificate, bindHost string) {
	if !bindHostWarnable(bindHost) || certCoversHost(leaf, bindHost) {
		return
	}
	slog.Warn("loaded management TLS cert does not cover bind host; remote clients verifying by it will fail — remove /etc/xpf/tls to re-mint",
		"bind_host", bindHost,
		"cert_dns_sans", leaf.DNSNames,
		"cert_ip_sans", leaf.IPAddresses)
}

// warnStaleHostName warns when the loaded cert does not cover the kernel host
// name. Unlike the bind host, the kernel name is only SOMETIMES an access
// identity, so ev + hostNameLikelyAccessIdentity gate it (#6827) and the message
// is conditional rather than a bare instruction to re-mint: the SANs it prints
// are exactly the identities the cert DOES cover, so an operator who reaches the
// box by one of those can dismiss it in a single read.
func warnStaleHostName(leaf *x509.Certificate, hostName, bindHost string, ev hostNameEvidence) {
	if !hostnameSANWarnable(hostName) || hostName == bindHost {
		return // uncoverable by any re-mint, or already reported as the bind host
	}
	// #7039: a loopback-only listener has no remote client, so nothing can
	// verify by host name and a re-mint would fix nothing. The bind-host half of
	// this same diagnostic already declines here — bindHostWarnable("127.0.0.1")
	// is false — and the host-name half had no equivalent gate, so every
	// `set system host-name` on a loopback-bound management plane warned about
	// clients that cannot exist. That is the failure mode
	// hostNameLikelyAccessIdentity's own doc block exists to prevent: a
	// diagnostic that fires on a healthy box gets muted, and the true positive
	// dies with it.
	//
	// Placed BEFORE the evidence gate on purpose. This is a property of the
	// BIND, not of the name, so it composes with hostNameOperatorSet rather than
	// contradicting it: an operator who deliberately renames a loopback-only
	// device still has no remote client to break.
	if bindIsLoopbackOnly(bindHost) {
		return
	}
	if ev == hostNameInferred && !hostNameLikelyAccessIdentity(leaf, hostName) {
		return
	}
	if certCoversHost(leaf, hostName) {
		return
	}
	slog.Warn("loaded management TLS cert does not cover the current host-name; clients verifying by host-name will fail — if this device is reached by host-name, remove /etc/xpf/tls to re-mint (the SANs below are the identities it does cover)",
		"host_name", hostName,
		"cert_dns_sans", leaf.DNSNames,
		"cert_ip_sans", leaf.IPAddresses)
}

// WarnStaleMgmtCertForHostName re-runs the stale-certificate diagnostic against
// the certificate the LIVE HTTPS leg is serving, for an EXPLICITLY supplied
// kernel host name (#6827).
//
// A `set system host-name` commit reaches it through the daemon, but NOT
// synchronously: Daemon.applyHostname records a debt and the daemon's delivery
// path (renameHostNotingStaleMgmtCert → deliverStaleMgmtCertDiagnosis) makes the
// call — at the rename when a certificate is already being served, and
// otherwise at whichever later retry point first finds one. The name it passes
// is read from the kernel at that moment, so this function is handed a live
// identity rather than one captured at commit time.
//
// It exists because the load-path diagnostic could never see a rename. Two
// independent reasons, and a fix for either alone is not enough:
//
//  1. REACHABILITY. warnStaleLoadedCert runs only while a certificate is being
//     loaded, and the HTTPS leg is rebuilt only when the TLS flag or the HTTPS
//     bind address changes (managementReconciler.reconcileTo). A plain
//     `set system host-name new-fw` on an unchanged bind reloads nothing, so the
//     appliance stayed silent until the next restart or HTTPS rebind — the exact
//     case the host-name check was written for.
//  2. ORDERING. The management reconcile runs EARLY in applyConfigLocked (before
//     the dataplane apply, so a credential revocation lands even on an aborting
//     commit) while the kernel host name is set late, in the apply tail. So even
//     a commit that DID change the HTTPS bind would have diagnosed the OLD
//     kernel name. Taking the name as a PARAMETER moves the read out of this
//     function, which has no idea where in an apply it is running, and into the
//     daemon, which does: it reads the kernel only after Sethostname has
//     returned, and a delivery whose rename has since been superseded abandons
//     before it gets here (pkg/daemon deliverStaleMgmtCertDiagnosis).
//
// It returns whether it actually reached a certificate — false means no live
// HTTPS leg was serving, so the question could not be answered and the CALLER
// still owes the diagnosis (#6827). Returning false is NOT "nothing was wrong":
// the durable certificate on disk outlives the listener, so a host name that
// went stale while HTTPS was down is still stale when HTTPS comes back.
//
// It deliberately reads the LIVE leg only, never the s.httpsServer construction
// template, which survives a TLS disable and would otherwise produce warnings
// about a certificate nobody serves.
//
// "Live" is listenerLeg.serving(), not a non-nil pointer (#6827). A leg whose
// serve loop exited unexpectedly stays INSTALLED in s.httpsLeg with only its
// `dead` flag set, and a leg retiring under a requested shutdown is still
// installed while it drains — diagnosing either would report a certificate that
// no socket is presenting, which is the same false positive the construction
// template was rejected for.
func (s *Server) WarnStaleMgmtCertForHostName(hostName string) bool {
	s.lifeMu.Lock()
	var srv *http.Server
	if s.httpsLeg.serving() {
		srv = s.httpsLeg.srv
	}
	s.lifeMu.Unlock()
	if srv == nil || srv.TLSConfig == nil || len(srv.TLSConfig.Certificates) == 0 {
		return false
	}
	cert := srv.TLSConfig.Certificates[0]
	if len(cert.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		// A live leg is serving a certificate we cannot parse. The question WAS
		// reached; re-parsing it later will fail identically, so report it
		// answered rather than making the caller retry forever.
		return true
	}
	bindHost := ""
	if h, _, err := net.SplitHostPort(srv.Addr); err == nil {
		bindHost = h
	}
	if warnCertNoSANs(leaf, bindHost, hostName) {
		return true
	}
	// Only the host name is diagnosed here: the bind host did not change, so a
	// stale one was already reported when the leg last bound, and repeating it on
	// every rename is noise.
	warnStaleHostName(leaf, hostName, bindHost, hostNameOperatorSet)
	return true
}

// generateSelfSignedCertAt creates or loads a self-signed TLS certificate
// at the given paths.
//
// If a usable cert/key pair already exists on disk it is loaded and
// returned. Otherwise a new ECDSA P-256 certificate is generated and
// persisted (both cert and key are DurableState per #1916 D6: the HTTPS
// API can bind a non-loopback `web-management https interface` address,
// so cert churn after a power-cut loss would break remote clients' TOFU
// pins — the cert must survive power loss).
//
// Persistence follows the #1916 D5 STRICT sequence so a crash can never
// leave a MISMATCHED cert/key pair on disk:
//  1. MkdirAllDurable(dir).
//  2. Strict-remove any stale cert AND key (ignore ONLY os.IsNotExist;
//     ANY other remove error OR a SyncDir error aborts the write — the
//     {neither} start state is proven, not assumed), then SyncDir.
//  3. WriteFileDurable(key, 0600).
//  4. WriteFileDurable(cert, 0644).
//
// On ANY persistence error (steps 1-4) the function logs and returns the
// in-memory generated pair with a NIL error: the cert is usable this boot,
// only the disk write failed, so HTTPS still installs (the caller binds
// httpsServer on the nil-error path). A non-nil error is returned ONLY for
// a true generation failure (no usable cert at all).
func generateSelfSignedCertAt(dir, certPath, keyPath, bindHost string) (tls.Certificate, error) {
	// Try loading an existing on-disk pair. LoadX509KeyPair reads the cert
	// first and errors on a key-only / mismatched state → falls through to
	// regen, which restores a matching pair.
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		// The on-disk cert is DURABLE (#1916 D6) and served AS-IS: neither the
		// bind host NOR the kernel host name is re-baked on a reload, so an A→B
		// management-IP rebind or a later `set system host-name` keeps the
		// original cert rather than churning remote clients' TOFU pins. But a
		// SAN the cert no longer covers makes strict remote verification fail
		// silently — warn loudly (naming the uncovered identity and the cert's
		// SANs) so an operator can re-mint (remove /etc/xpf/tls) instead of
		// chasing a bare handshake failure. Re-minting here would violate the
		// durable contract, so this is diagnostic only (#5719 C001 residual).
		warnStaleLoadedCert(cert, bindHost)
		return cert, nil
	}

	// Generate new ECDSA key + self-signed cert (true generation failures
	// below return a non-nil error: there is no usable cert at all).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	hostname, _ := tlsHostname()
	cn := hostname
	if cn == "" {
		cn = "xpf"
	}

	// Subject Alternative Names. A cert that carries only a CommonName and no
	// SANs is rejected for hostname verification by every modern TLS client
	// (Go's own client since 1.15, browsers, curl) — "x509: certificate is
	// not valid for any names". Always include the loopback names/addresses:
	// the HTTPS API binds loopback (127.0.0.1/::1) by default and these can
	// never fail to encode (codex-review-182 C-API TLS hygiene). This covers
	// a loopback-bound API and local hostname/localhost verification; the
	// configured management-interface bind IP is added below from bindHost so
	// remote verification by management IP also succeeds (#5719 C001 residual).
	dnsNames := []string{"localhost"}
	ipSANs := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}

	// Add the kernel hostname as a SAN only when it is safe to encode. A valid
	// ASCII DNS hostname goes in DNSNames; an IP-literal hostname goes in
	// IPAddresses (a DNS SAN of an IP never verifies as an IP). A non-ASCII or
	// otherwise malformed hostname is DROPPED, not appended: x509.Create-
	// Certificate marshals DNSNames as an IA5String and HARD-FAILS on a
	// non-ASCII name (e.g. a "café" kernel hostname). Under the #5058 all-or-
	// nothing management-server lifecycle that abort would tear down the whole
	// HTTP+HTTPS server, so degrade to loopback-only SANs instead of failing
	// cert generation.
	if ip := net.ParseIP(hostname); ip != nil {
		if !ip.IsLoopback() { // loopback IPs already present above
			ipSANs = append(ipSANs, ip)
		}
	} else if hostname != "localhost" && isDNSSANSafeHostname(hostname) {
		dnsNames = append(dnsNames, hostname)
	}

	// Thread the HTTPS listener's bind host into the SANs so a non-loopback
	// management bind (e.g. `web-management https interface 10.0.0.1`) verifies
	// under strict hostname checking from a remote client (#5719 C001 residual).
	// An IP-literal bind host goes in IPAddresses; a DNS-safe hostname goes in
	// DNSNames. A loopback, unspecified (0.0.0.0/::), empty, or non-encodable
	// bind host is skipped (loopback SANs are already present, and a wildcard
	// bind names no single host); a value already added above is coalesced.
	// Like the hostname path this can only ADD an encodable SAN, so it never
	// aborts generation under the #5058 all-or-nothing management lifecycle.
	//
	// The bind IP is baked at FIRST generation only: the cert is durable
	// (#1916 D6) and deliberately NOT re-minted when the bind address later
	// changes — auto-regenerating would churn remote clients' TOFU pins. That
	// re-mint-on-change concern is a separate tracked #5719 C001 residual.
	if bindHost != "" {
		if ip := net.ParseIP(bindHost); ip != nil {
			if !ip.IsLoopback() && !ip.IsUnspecified() && !ipSANsContain(ipSANs, ip) {
				ipSANs = append(ipSANs, ip)
			}
		} else if bindHost != "localhost" && isDNSSANSafeHostname(bindHost) && !dnsSANsContain(dnsNames, bindHost) {
			dnsNames = append(dnsNames, bindHost)
		}
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"xpf"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipSANs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	inMemory, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		// The just-generated PEM does not parse — a true generation
		// failure, not a persistence one.
		return tls.Certificate{}, err
	}

	// From here, any failure is a PERSISTENCE failure: log it and return
	// the usable in-memory pair with a nil error so HTTPS still installs.
	if err := persistSelfSignedCert(dir, certPath, keyPath, certPEM, keyPEM); err != nil {
		slog.Error("failed to persist self-signed TLS certificate; serving in-memory cert this boot (will regenerate next boot)",
			"dir", dir, "err", err)
	}
	return inMemory, nil
}

// persistSelfSignedCert implements the #1916 D5 STRICT write sequence. Any
// returned error means the disk state is clean: either the directory could
// not be created, a strict-remove could not establish a provable {neither}
// start state (so no new write was attempted), a SyncDir failed to make the
// removes durable, or a durable write itself failed — in every case no
// mismatched pair is left visible on disk.
func persistSelfSignedCert(dir, certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := tlsMkdirAllDurable(dir, 0700); err != nil {
		return err
	}
	// Strict-remove the stale pair so the start state is provably {neither}.
	// Ignore ONLY os.IsNotExist; any other remove error aborts (do NOT
	// write) so we never leave a stale cert beside a fresh key.
	if err := tlsRemove(certPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := tlsRemove(keyPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	// Make the unlinks durable before writing the new pair; a SyncDir
	// failure also aborts (the {neither} start is not proven).
	if err := tlsSyncDir(dir); err != nil {
		return err
	}
	// Ordered durable writes: key first (DurableState 0600), then cert
	// (DurableState 0644). The only crash-visible states are {neither},
	// {key-only}, {both-matching}; LoadX509KeyPair rejects {key-only}.
	if err := tlsWriteFileDurable(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	if err := tlsWriteFileDurable(certPath, certPEM, 0644); err != nil {
		return err
	}
	return nil
}
