// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
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
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/lldp"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/ra"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/scheduler"
	"github.com/psaab/xpf/pkg/snmp"
	"github.com/psaab/xpf/pkg/vrrp"
)

// Options configures the daemon.
type Options struct {
	ConfigFile  string
	NoDataplane bool   // set to true to run without eBPF (config-only mode)
	APIAddr     string // HTTP API listen address (empty = disabled)
	GRPCAddr    string // gRPC API listen address (empty = disabled)
	Version     string // software version string
}

// nodeIDFile is the path to the cluster node ID file.
// If this file exists and contains a valid integer (0 or 1), the daemon
// runs in cluster mode with ${node} variable expansion. If the file does
// not exist, the daemon runs in standalone mode.
const nodeIDFile = "/etc/xpf/node-id"

// Daemon is the main xpf daemon.
type Daemon struct {
	opts                       Options
	store                      *configstore.Store
	dp                         dataplane.DataPlane
	networkd                   *networkd.Manager
	routing                    *routing.Manager
	frr                        *frr.Manager
	ipsec                      *ipsec.Manager
	ra                         *ra.Manager
	dhcp                       *dhcp.Manager
	dhcpServer                 *dhcpserver.Manager
	feeds                      *feeds.Manager
	rpm                        *rpm.Manager
	flowExporter               *flowexport.Exporter
	flowCancel                 context.CancelFunc
	flowWg                     sync.WaitGroup
	ipfixExporter              *flowexport.IPFIXExporter
	ipfixCancel                context.CancelFunc
	ipfixWg                    sync.WaitGroup
	dhcpRelay                  *dhcprelay.Manager
	snmpAgent                  *snmp.Agent
	lldpMgr                    *lldp.Manager
	scheduler                  *scheduler.Scheduler
	schedulerCancel            context.CancelFunc
	policySchedulerEpoch       atomic.Uint64
	cluster                    *cluster.Manager
	sessionSync                *cluster.SessionSync
	syncBulkPrimed             atomic.Bool
	syncPeerBulkPrimed         atomic.Bool
	syncPeerConnected          atomic.Bool
	lastStandbyNeighborRefresh atomic.Int64
	neighborWarmupInFlight     atomic.Bool
	hbSuppressStart            atomic.Int64 // UnixNano of first heartbeat suppression; 0 = inactive
	syncPrimeRetryGen          atomic.Uint64
	syncReadyTimerGen          atomic.Uint64
	syncReadyTimerMu           sync.Mutex
	syncReadyTimer             *time.Timer
	syncReadyTimeout           time.Duration
	slogHandler                *logging.SyslogSlogHandler
	traceWriter                *logging.TraceWriter
	eventBuf                   *logging.EventBuffer
	eventReader                *logging.EventReader
	eventEngine                *eventengine.Engine
	aggregator                 *logging.SessionAggregator
	aggCancel                  context.CancelFunc
	vrrpMgr                    *vrrp.Manager
	gc                         *conntrack.GC
	startTime                  time.Time // daemon start time; used to suppress stale config sync

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
	// applyBodyForTest, when non-nil, replaces applyConfigLocked's
	// body. Test-only seam used by apply_serialize_test.go to
	// exercise the semaphore contract through the real applyConfig
	// / commitAndApply paths without standing up the full dataplane.
	applyBodyForTest func(*config.Config)

	// mgmtVRFInterfaces tracks interfaces bound to the management VRF (vrf-mgmt).
	// Used by collectDHCPRoutes to exclude management routes from FRR.
	mgmtVRFInterfaces map[string]bool

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

	// Fabric cross-chassis forwarding state for periodic refresh.
	fabricMu         sync.RWMutex
	fabricIface      string // physical parent (XDP attachment point)
	fabricOverlay    string // IPVLAN overlay for neighbor resolution (#129)
	fabricPeerIP     net.IP
	fabricIface1     string        // secondary fabric parent
	fabricOverlay1   string        // secondary fabric overlay (#129)
	fabricPeerIP1    net.IP        // secondary fabric peer IP
	fabricPopulated  bool          // true after first successful fab0 write
	fabric1Populated bool          // true after first successful fab1 write
	fabricRefreshCh  chan struct{} // triggers immediate fabric_fwd refresh
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
	// independently-cancellable sub-contexts for cluster comms.
	daemonCtx context.Context

	// clusterCommsCancel cancels the sub-context used by startClusterComms
	// goroutines. Set when cluster comms are started, called to restart them
	// on config change (#87).
	clusterCommsCancel context.CancelFunc

	// activeClusterTransport stores the transport config used by the
	// currently running cluster comms. Compared on each applyConfig to
	// detect changes that require a comms restart (#87).
	activeClusterTransport clusterTransportKey

	// startupGoodbyeRA tracks whether the one-shot goodbye RA has been
	// sent for each inactive RG on startup. Prevents stale RA routes
	// from a previous primary run keeping hosts dual-pathing traffic.
	startupGoodbyeRA map[int]bool

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
	// Test hooks for direct-mode VIP ownership reconciliation.
	directAddVIPsFn        func(int) int
	directRemoveVIPsFn     func(int) int
	directAddStableLLFn    func(int)
	directRemoveStableLLFn func(int)

	// linkByNameFn resolves a network interface by name. Defaults to
	// netlink.LinkByName; overridden in tests.
	linkByNameFn func(string) (netlink.Link, error)

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

	// priorTunables stores the pre-xpfd values of every host-scope
	// tunable xpfd has touched, so that restore-on-disable (B2) can
	// revert to what the operator had before xpfd claimed the host.
	// Populated lazily on first apply. Restored when claim-host-tunables
	// transitions from true → false, or on daemon shutdown. See
	// pkg/daemon/host_tunables.go for capture/restore implementation.
	priorTunablesMu     sync.Mutex
	priorTunables       *priorHostTunables
	priorTunablesActive bool // true once the current config has applied host tunables
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

// New creates a new Daemon.
func New(opts Options) *Daemon {
	if opts.ConfigFile == "" {
		opts.ConfigFile = "/etc/xpf/xpf.conf"
	}

	store := configstore.New(opts.ConfigFile)

	// Read cluster node ID from file. If the file exists and contains a
	// valid integer, the daemon runs in cluster mode with ${node} variable
	// expansion in apply-groups. If the file does not exist, standalone mode.
	if data, err := os.ReadFile(nodeIDFile); err == nil {
		s := strings.TrimSpace(string(data))
		var nodeID int
		if _, err := fmt.Sscanf(s, "%d", &nodeID); err == nil {
			store.SetNodeID(nodeID)
			slog.Info("cluster node ID loaded from file", "node", nodeID, "file", nodeIDFile)
		}
	}

	return &Daemon{
		opts:                       opts,
		startTime:                  time.Now(),
		store:                      store,
		rgStates:                   make(map[int]*rgStateMachine),
		blackholeRoutes:            make(map[int][]netlink.Route),
		reconcileNowCh:             make(chan struct{}, 1),
		syncReadyTimeout:           5 * time.Second,
		linkByNameFn:               netlink.LinkByName,
		directAnnounceSchedule:     []time.Duration{0, 250 * time.Millisecond, 1 * time.Second, 2 * time.Second, 4 * time.Second, 6 * time.Second},
		directVIPOwned:             make(map[int]bool),
		localFailoverCommitReady:   make(map[int]bool),
		localFailoverCommitTimeout: 3 * time.Second,
		localFailoverCommitDelay:   200 * time.Millisecond,
		userspaceDemotionPrepUntil: make(map[int]time.Time),
		applySem:                   semaphore.NewWeighted(1),
	}
}
