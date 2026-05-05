// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/cli"
	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/dhcprelay"
	"github.com/psaab/xpf/pkg/dhcpserver"
	"github.com/psaab/xpf/pkg/eventengine"
	"github.com/psaab/xpf/pkg/feeds"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/fwdstatus"
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

func collectAppliedTunnels(cfg *config.Config) []*config.TunnelConfig {
	if cfg == nil {
		return nil
	}
	anchorOnly := cfg.System.DataplaneType == dataplane.TypeUserspace
	var tunnels []*config.TunnelConfig
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if ifc.Tunnel != nil && ifc.Tunnel.Source != "" {
			tc := *ifc.Tunnel
			tc.AnchorOnly = anchorOnly
			tunnels = append(tunnels, &tc)
		}
		for _, unit := range ifc.Units {
			if unit == nil || unit.Tunnel == nil {
				continue
			}
			tc := *unit.Tunnel
			tc.AnchorOnly = anchorOnly
			tunnels = append(tunnels, &tc)
		}
	}
	return tunnels
}

// Run starts the daemon and blocks until shutdown.
func (d *Daemon) Run(ctx context.Context) error {
	d.daemonCtx = ctx

	// Wrap the default slog handler to support system syslog forwarding.
	// Syslog clients are added later when config is applied.
	d.slogHandler = logging.NewSyslogSlogHandler(slog.Default().Handler())
	slog.SetDefault(slog.New(d.slogHandler))

	slog.Info("starting xpf daemon",
		"config", d.opts.ConfigFile,
		"pid", os.Getpid())

	// Load persisted configuration from DB, falling back to text config file
	if err := d.store.Load(); err != nil {
		slog.Warn("failed to load config from db", "err", err)
	}

	// If DB had no active config, bootstrap from the text config file
	if d.store.ActiveConfig() == nil {
		if err := d.bootstrapFromFile(); err != nil {
			slog.Warn("failed to bootstrap config from file", "err", err)
		}
	} else {
		slog.Info("configuration loaded from db")
	}

	// Enumerate PCI NICs and assign vSRX-style names (fxp0, em0, ge-X-0-Y)
	// before any manager creation or BPF load.
	if !d.opts.NoDataplane {
		clusterMode := false
		nodeID := 0
		userspaceWorkers := 0
		// D3 (#797): default enabled. Operators opt out via
		// `set system dataplane rss-indirection disable`.
		rssEnabled := true
		var rssAllowed []string
		// #801 Phase-B Step-0 tunables: host-scope governor + netdev
		// budget; per-iface mlx5 coalescence. Host-scope knobs are
		// GATED by `claim-host-tunables true` (B1). Per-iface knobs
		// (rx-usecs/tx-usecs) follow the D3 allowlist and are applied
		// whenever coalescence is configured.
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
		if cfg := d.store.ActiveConfig(); cfg != nil {
			if cfg.Chassis.Cluster != nil {
				clusterMode = true
				nodeID = cfg.Chassis.Cluster.NodeID
			}
			// D3 (#785): pass userspace-dp worker count so linksetup can
			// reshape mlx5 RSS indirection before any AF_XDP bind. Zero
			// when userspace dataplane is not in use — applyRSSIndirection
			// treats that as a no-op.
			if cfg.System.DataplaneType == "userspace" && cfg.System.UserspaceDataplane != nil {
				userspaceDP = true
				userspaceWorkers = cfg.System.UserspaceDataplane.Workers
				if cfg.System.UserspaceDataplane.RSSIndirectionDisabled {
					rssEnabled = false
				}
				// Codex H1: scope D3 to only interfaces that
				// userspace-dp actually binds AF_XDP sockets on.
				rssAllowed = dpuserspace.UserspaceBoundLinuxInterfaces(cfg)
				// #801 knobs.
				claimHostTunables = cfg.System.UserspaceDataplane.ClaimHostTunables
				governor = cfg.System.UserspaceDataplane.CPUGovernor
				netdevBudget = cfg.System.UserspaceDataplane.NetdevBudget
				coalesceExplicit = cfg.System.UserspaceDataplane.CoalescenceAdaptiveExplicit
				// coalesceEnable stays false by default — the Step-0
				// finding is "adaptive=on causes pp99 latency jitter",
				// so default-off is what the issue asks for. An
				// explicit `adaptive enable` inverts this.
				if coalesceExplicit &&
					!cfg.System.UserspaceDataplane.CoalescenceAdaptiveDisabled {
					coalesceEnable = true
				}
				coalesceRX = cfg.System.UserspaceDataplane.CoalescenceRXUsecs
				coalesceTX = cfg.System.UserspaceDataplane.CoalescenceTXUsecs
			}
		}
		if err := enumerateAndRenameInterfaces(nodeID, clusterMode, userspaceWorkers, rssEnabled, rssAllowed); err != nil {
			slog.Warn("interface naming failed", "err", err)
		}
		// #801: host tunables + coalescence. Runs after the interface
		// rename but still before the dataplane is loaded — matches
		// the D3 "before any AF_XDP bind" invariant. Best-effort: any
		// failure logs and continues.
		//
		// B1 opt-in gate: host-scope knobs (governor + netdev_budget +
		// adaptive-rx/tx flip) only apply when `claim-host-tunables
		// true` is set. This keeps xpfd from stepping on shared hosts
		// silently. D3 and per-iface rx-usecs/tx-usecs continue to run
		// as before — both are interface-scoped.
		d.applyStep0Tunables(userspaceDP, claimHostTunables, governor, netdevBudget,
			coalesceExplicit, coalesceEnable, coalesceRX, coalesceTX, rssAllowed)
	}

	// Initialize routing, FRR, and IPsec managers
	if !d.opts.NoDataplane {
		rm, err := routing.New()
		if err != nil {
			slog.Warn("failed to create routing manager", "err", err)
		} else {
			d.routing = rm
		}
		d.frr = frr.New()
		d.ipsec = ipsec.New()
		d.ra = ra.New()
		d.networkd = networkd.New()
		d.dhcpServer = dhcpserver.New()
	}

	// Initialize cluster manager if configured (heartbeat/sync started after applyConfig).
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Chassis.Cluster != nil {
		cc := cfg.Chassis.Cluster
		d.cluster = cluster.NewManager(cc.NodeID, cc.ClusterID)
		d.cluster.SetSoftwareVersion(d.opts.Version)
		d.cluster.UpdateConfig(cc)
		d.cluster.Start(ctx)
		// Wire event-drop callback: on dropped cluster events, trigger
		// immediate reconciliation so the safety net doesn't wait 2s.
		d.cluster.SetOnEventDrop(d.triggerReconcile)
		slog.Info("cluster manager initialized",
			"node", cc.NodeID, "cluster", cc.ClusterID)

		// Watch cluster events for state transitions (primary/secondary).
		go d.watchClusterEvents(ctx)
	}

	// Enable IP forwarding — required for the firewall to route packets.
	if !d.opts.NoDataplane {
		enableForwarding()
	}

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
		// Private-rg-election mode: gate RG promotion on session sync
		// readiness with a 30s timeout fallback (mirrors VRRP sync-hold).
		// Without this, standalone nodes or nodes with permanently-down
		// peers would never become primary.
		if cc.PrivateRGElection && cc.FabricInterface != "" && cc.FabricPeerAddress != "" {
			d.armSyncReadyTimer()
		}
	}

	// Create dataplane backend (unless in config-only mode)
	if !d.opts.NoDataplane {
		dpType := ""
		if cfg := d.store.ActiveConfig(); cfg != nil {
			dpType = cfg.System.DataplaneType
		}
		dp, err := dataplane.NewDataPlane(dpType)
		if err != nil {
			slog.Error("failed to create dataplane", "type", dpType, "err", err)
			return fmt.Errorf("create dataplane: %w", err)
		}
		d.dp = dp
		if err := d.dp.Load(); err != nil {
			slog.Warn("failed to load dataplane programs, running in config-only mode",
				"err", err)
			d.dp = nil
		} else {
			d.dp.SeedNATPortCounters()
			nodeID := 0
			if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Chassis.Cluster != nil {
				nodeID = cfg.Chassis.Cluster.NodeID
			}
			d.dp.SeedSessionIDCounter(nodeID)
		}
		// Apply current config — needed even in config-only mode so that
		// VRFs, interfaces, and routing are configured before cluster comms.
		if cfg := d.store.ActiveConfig(); cfg != nil {
			slog.Info("applying active configuration")
			d.applyConfig(cfg)
		}
	}

	// Remove stale blackhole routes from previous daemon runs before
	// cluster comms start (which may inject new ones).
	if d.cluster != nil {
		d.reconcileBlackholeRoutes()
	}

	// Start cluster heartbeat + sync after applyConfig (needs VRF to exist).
	if d.cluster != nil {
		d.startClusterComms(ctx)
	}

	// Handle signals for clean shutdown.
	// In interactive mode, only SIGTERM triggers shutdown — SIGINT is handled
	// by the CLI for command cancellation (Ctrl-C).
	// In daemon mode, both SIGTERM and SIGINT trigger shutdown.
	var stop context.CancelFunc
	if isInteractive() {
		ctx, stop = signal.NotifyContext(ctx, syscall.SIGTERM)
	} else {
		ctx, stop = signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	}
	defer stop()

	// Create event buffer (shared between event reader and CLI)
	eventBuf := logging.NewEventBuffer(1000)

	// WaitGroup for coordinated shutdown of background goroutines
	var wg sync.WaitGroup

	// NOTE: session sync dp wiring + sweep start moved into startClusterComms
	// goroutine to avoid race: d.sessionSync is created asynchronously.

	// Start background services if dataplane is loaded
	var er *logging.EventReader
	if d.dp != nil {
		// Start FIB sync (DPDK: background route populator; eBPF: no-op)
		d.dp.StartFIBSync(ctx)

		gc := conntrack.NewGC(d.dp, 10*time.Second)
		d.gc = gc

		// When the userspace dataplane is active, skip BPF session map
		// GC entirely — sessions are managed in user-space. Without
		// this, BatchLookup burns ~19% CPU scanning maps not used for
		// forwarding decisions.
		//
		// The helper still mirrors sessions to BPF conntrack for display
		// and periodically refreshes last_seen (~10s) so IterateSessions
		// callers see accurate idle times.  See #333.
		if _, ok := d.dp.(userspaceSessionDeltaDrainer); ok {
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
			if d.cluster != nil && d.cluster.IsLocalPrimaryAny() && d.sessionSync != nil {
				d.sessionSync.QueueDeleteV4(key)
			}
		}
		gc.OnDeleteV6 = func(key dataplane.SessionKeyV6) {
			if d.cluster != nil && d.cluster.IsLocalPrimaryAny() && d.sessionSync != nil {
				d.sessionSync.QueueDeleteV6(key)
			}
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			gc.Run(ctx)
		}()

		evSrc, evErr := d.dp.NewEventSource()
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
			if d.sessionSync != nil {
				er.AddCallback(func(rec logging.EventRecord, raw []byte) {
					if rec.Type != "SESSION_OPEN" {
						return
					}
					if d.cluster == nil || !d.cluster.IsLocalPrimaryAny() {
						return
					}
					if !d.sessionSync.IsConnected() {
						return
					}
					if len(raw) < 56 {
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
						if val, err := d.dp.GetSessionV6(key); err == nil && val.IsReverse == 0 {
							if d.sessionSync.ShouldSyncZone(val.IngressZone) {
								d.sessionSync.QueueSessionV6(key, val)
							}
						}
					} else {
						var key dataplane.SessionKey
						copy(key.SrcIP[:], raw[8:12])
						copy(key.DstIP[:], raw[24:28])
						key.SrcPort = binary.BigEndian.Uint16(raw[40:42])
						key.DstPort = binary.BigEndian.Uint16(raw[42:44])
						key.Protocol = proto
						if val, err := d.dp.GetSessionV4(key); err == nil && val.IsReverse == 0 {
							if d.sessionSync.ShouldSyncZone(val.IngressZone) {
								d.sessionSync.QueueSessionV4(key, val)
							}
						}
					}
				})
			}

			// Set up syslog clients from active config
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.applySyslogConfig(er, cfg)
			}

			// Start NetFlow exporter if configured
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.startFlowExporter(ctx, cfg, er)
			}

			// Start IPFIX exporter if configured
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.startIPFIXExporter(ctx, cfg, er)
			}

			// Set up flow traceoptions if configured
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.applyFlowTrace(cfg, er)
			}
		}
	}

	// Start DHCP clients for interfaces configured with dhcp/dhcpv6.
	// This must happen after BPF load + config compile so HOST_INBOUND_DHCP
	// flags are active before DHCP packets start flowing.
	if !d.opts.NoDataplane {
		if cfg := d.store.ActiveConfig(); cfg != nil {
			d.startDHCPClients(ctx, cfg)
		}
	}

	// Start dynamic address feeds if configured.
	if cfg := d.store.ActiveConfig(); cfg != nil && len(cfg.Security.DynamicAddress.FeedServers) > 0 {
		d.feeds = feeds.New(func() {
			slog.Info("dynamic-address feed updated, recompiling dataplane")
			if activeCfg := d.store.ActiveConfig(); activeCfg != nil {
				d.applyConfig(activeCfg)
			}
		})
		d.feeds.Apply(ctx, &cfg.Security.DynamicAddress)
	}

	// Start RPM probes if configured.
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Services.RPM != nil && len(cfg.Services.RPM.Probes) > 0 {
		d.rpm = rpm.New()
		d.rpm.Apply(ctx, cfg.Services.RPM)
	}

	// Start LLDP if configured.
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.Protocols.LLDP != nil && !cfg.Protocols.LLDP.Disable && len(cfg.Protocols.LLDP.Interfaces) > 0 {
		d.lldpMgr = lldp.New()
		var lldpIfaces []lldp.LLDPInterface
		for _, iface := range cfg.Protocols.LLDP.Interfaces {
			lldpIfaces = append(lldpIfaces, lldp.LLDPInterface{
				Name:    iface.Name,
				Disable: iface.Disable,
			})
		}
		d.lldpMgr.Apply(ctx, &lldp.LLDPConfig{
			Interfaces:     lldpIfaces,
			Interval:       cfg.Protocols.LLDP.Interval,
			HoldMultiplier: cfg.Protocols.LLDP.HoldMultiplier,
			SystemName:     cfg.System.HostName,
		})
	}

	// Start event-options engine if configured.
	if cfg := d.store.ActiveConfig(); cfg != nil && len(cfg.EventOptions) > 0 {
		// #846: route through commitAndApply so the engine's commit
		// serializes with HTTP/gRPC commits under d.applySem.
		// Event-options changes don't sync to peer (the engine fires
		// independently on each node based on local RPM events).
		d.eventEngine = eventengine.New(d.store, func(ctx context.Context, comment string) (*config.Config, error) {
			return d.commitAndApply(ctx, comment, false)
		})
		d.eventEngine.Apply(cfg.EventOptions)
		if d.rpm != nil {
			d.rpm.SetEventCallback(d.eventEngine.HandleEvent)
		}
		slog.Info("event-options engine started", "policies", len(cfg.EventOptions))
	}

	// Start DHCP relay if configured.
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.ForwardingOptions.DHCPRelay != nil {
		d.dhcpRelay = dhcprelay.NewManager()
		d.dhcpRelay.Apply(ctx, cfg.ForwardingOptions.DHCPRelay)
	}

	// Port mirroring
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.ForwardingOptions.PortMirroring != nil {
		for name, inst := range cfg.ForwardingOptions.PortMirroring.Instances {
			slog.Info("Port mirroring configured", "instance", name, "input", inst.Input, "output", inst.Output)
		}
	}

	// Start SNMP agent if configured (unless system processes snmp disable).
	if cfg := d.store.ActiveConfig(); cfg != nil && cfg.System.SNMP != nil && (len(cfg.System.SNMP.Communities) > 0 || len(cfg.System.SNMP.V3Users) > 0) && !isProcessDisabled(cfg, "snmpd") {
		d.snmpAgent = snmp.NewAgent(cfg.System.SNMP)
		d.snmpAgent.SetIfDataFn(func() []snmp.IfData {
			links, err := netlink.LinkList()
			if err != nil {
				return nil
			}
			var result []snmp.IfData
			for _, link := range links {
				attrs := link.Attrs()
				if attrs.Name == "lo" {
					continue
				}
				ifType := 6 // ethernetCsmacd
				switch link.Type() {
				case "vrf":
					ifType = 53 // propVirtual
				case "gre", "ip6tnl", "xfrm":
					ifType = 131 // tunnel
				case "veth":
					ifType = 53
				}
				admin := 2 // down
				if attrs.Flags&net.FlagUp != 0 {
					admin = 1
				}
				oper := 2 // down
				if attrs.OperState == netlink.OperUp || attrs.OperState == netlink.OperUnknown {
					oper = 1
				}
				speed := uint32(0)
				if attrs.TxQLen > 0 {
					speed = 1000000000 // default 1Gbps
				}
				var stats *netlink.LinkStatistics
				if attrs.Statistics != nil {
					stats = attrs.Statistics
				}
				entry := snmp.IfData{
					IfIndex:     attrs.Index,
					IfDescr:     attrs.Name,
					IfType:      ifType,
					IfMtu:       attrs.MTU,
					IfSpeed:     speed,
					AdminStatus: admin,
					OperStatus:  oper,
					IfName:      attrs.Name,
					IfHighSpeed: speed / 1_000_000, // bps -> Mbps
				}
				if stats != nil {
					entry.InOctets = uint32(stats.RxBytes)
					entry.OutOctets = uint32(stats.TxBytes)
					entry.HCInOctets = stats.RxBytes
					entry.HCInUcastPkts = stats.RxPackets
					entry.HCOutOctets = stats.TxBytes
					entry.HCOutUcastPkts = stats.TxPackets
					entry.InMulticastPkts = uint32(stats.Multicast)
				}
				result = append(result, entry)
			}
			return result
		})
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.snmpAgent.Start(ctx)
		}()

		// Start link state monitor for SNMP traps.
		if len(cfg.System.SNMP.TrapGroups) > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.monitorLinkState(ctx)
			}()
		}
	}

	// Start policy scheduler if configured.
	if cfg := d.store.ActiveConfig(); cfg != nil && len(cfg.Schedulers) > 0 && d.dp != nil {
		d.scheduler = scheduler.New(cfg.Schedulers, func(activeState map[string]bool) {
			slog.Info("scheduler state changed, updating policy rules")
			if activeCfg := d.store.ActiveConfig(); activeCfg != nil {
				d.dp.UpdatePolicyScheduleState(activeCfg, activeState)
			}
		})
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.scheduler.Run(ctx)
		}()
	}

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
		}
	}

	// Start VRRP event watcher (manager was created earlier, before applyConfig).
	// Uses context.Background() — the watcher must outlive daemon ctx cancel
	// so it can process VRRP BACKUP events during shutdown (rg_active cleanup).
	// The watcher exits when eventCh is closed by vrrpMgr.Stop().
	go d.watchVRRPEvents(context.Background())

	// Start reconciliation loop — periodic safety net that corrects
	// rg_active and blackhole route drift from dropped events.
	if d.cluster != nil {
		go d.reconcileRGStateLoop(ctx)
	}

	// Start HTTP API server if configured.
	if d.opts.APIAddr != "" {
		apiCfg := api.Config{
			Addr:     d.opts.APIAddr,
			Store:    d.store,
			DP:       d.dp,
			EventBuf: eventBuf,
			GC:       d.gc,
			Routing:  d.routing,
			FRR:      d.frr,
			IPsec:    d.ipsec,
			DHCP:     d.dhcp,
			VRRPMgr:  d.vrrpMgr,
			// HTTP commits don't sync to peer (preserves prior
			// behavior; see #846 for follow-up).
			CommitFn: func(ctx context.Context, comment string) (*config.Config, error) {
				return d.commitAndApply(ctx, comment, false)
			},
			CommitConfirmedFn: func(ctx context.Context, minutes int) (*config.Config, error) {
				return d.commitConfirmedAndApply(ctx, minutes, false)
			},
			// #758: surface compile state so /health returns 503
			// when the dataplane has never compiled successfully.
			CompileHealthFn: func() api.CompileHealthSnapshot {
				h := d.CompileHealthSnapshot()
				return api.CompileHealthSnapshot{
					EverSucceeded:    h.EverSucceeded,
					FailureCount:     h.FailureCount,
					LastError:        h.LastError,
					LastErrorUnixSec: h.LastErrorUnixSec,
				}
			},
		}
		// Resolve interface bindings from web-management config
		if cfg := d.store.ActiveConfig(); cfg != nil && cfg.System.Services != nil &&
			cfg.System.Services.WebManagement != nil {
			wm := cfg.System.Services.WebManagement
			// Bind HTTP to configured interface
			if wm.HTTPInterface != "" {
				bindIP := resolveInterfaceAddr(wm.HTTPInterface, "127.0.0.1")
				apiCfg.Addr = bindIP + ":8080"
				slog.Info("HTTP API bound to interface", "interface", wm.HTTPInterface, "addr", apiCfg.Addr)
			}
			// Enable HTTPS if configured
			if wm.HTTPS {
				httpsBindIP := "127.0.0.1"
				if wm.HTTPSInterface != "" {
					httpsBindIP = resolveInterfaceAddr(wm.HTTPSInterface, "127.0.0.1")
					slog.Info("HTTPS API bound to interface", "interface", wm.HTTPSInterface, "addr", httpsBindIP+":8443")
				}
				apiCfg.TLS = true
				apiCfg.HTTPSAddr = httpsBindIP + ":8443"
			}
			// API authentication
			if wm.APIAuth != nil && (len(wm.APIAuth.Users) > 0 || len(wm.APIAuth.APIKeys) > 0) {
				authCfg := &api.AuthConfig{
					Users:   make(map[string]string),
					APIKeys: make(map[string]bool),
				}
				for _, u := range wm.APIAuth.Users {
					authCfg.Users[u.Username] = u.Password
				}
				for _, k := range wm.APIAuth.APIKeys {
					authCfg.APIKeys[k] = true
				}
				apiCfg.Auth = authCfg
				slog.Info("HTTP API authentication enabled", "users", len(wm.APIAuth.Users), "api_keys", len(wm.APIAuth.APIKeys))
			}
		}
		srv := api.NewServer(apiCfg)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Run(ctx); err != nil {
				slog.Error("API server error", "err", err)
			}
		}()
		slog.Info("HTTP API server started", "addr", d.opts.APIAddr)
	}

	// #881: forwarding-daemon CPU sampler (5s/1m/5m windows for
	// `show chassis forwarding`).  Shared between the gRPC server
	// and the local CLI; both paths call Snapshot() at query time.
	// Started here so the ring is populated before the first CLI.
	fwdSampler := fwdstatus.NewSampler(d.dp, fwdstatus.OSProcReader{})
	fwdSampler.Start(ctx)

	// Start gRPC API server.
	{
		grpcSrv := grpcapi.NewServer(d.opts.GRPCAddr, grpcapi.Config{
			Store:      d.store,
			DP:         d.dp,
			EventBuf:   eventBuf,
			GC:         d.gc,
			Routing:    d.routing,
			FRR:        d.frr,
			IPsec:      d.ipsec,
			Cluster:    d.cluster,
			DHCP:       d.dhcp,
			DHCPServer: d.dhcpServer,
			RPMResultsFn: func() []*rpm.ProbeResult {
				if d.rpm != nil {
					return d.rpm.Results()
				}
				return nil
			},
			FeedsFn: func() map[string]feeds.FeedInfo {
				if d.feeds != nil {
					return d.feeds.AllFeeds()
				}
				return nil
			},
			LLDPNeighborsFn: func() []*lldp.Neighbor {
				if d.lldpMgr != nil {
					return d.lldpMgr.Neighbors()
				}
				return nil
			},
			// gRPC commits sync to cluster peer atomically inside
			// the apply lock so the peer can never observe an apply
			// that hasn't yet been propagated.
			CommitFn: func(ctx context.Context, comment string) (*config.Config, error) {
				return d.commitAndApply(ctx, comment, true)
			},
			CommitConfirmedFn: func(ctx context.Context, minutes int) (*config.Config, error) {
				return d.commitConfirmedAndApply(ctx, minutes, true)
			},
			VRRPMgr: d.vrrpMgr,
			RAMgr:   d.ra,
			Version: d.opts.Version,
			FabricPeerAddrFn: func() []string {
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
			},
			FabricVRFDevice: func() string {
				if c := d.store.ActiveConfig(); c != nil && c.Chassis.Cluster != nil {
					cc := c.Chassis.Cluster
					if cc.ControlInterface != "" || cc.FabricInterface != "" {
						return "vrf-mgmt"
					}
				}
				return ""
			}(),
			FwdSampler: fwdSampler,
		})
		d.grpcSrv = grpcSrv
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := grpcSrv.Run(ctx); err != nil {
				slog.Error("gRPC server error", "err", err)
			}
		}()
		slog.Info("gRPC API server started", "addr", d.opts.GRPCAddr)
	}

	// Start interactive CLI or block in daemon mode
	var runErr error
	if isInteractive() {
		shell := cli.New(d.store, d.dp, eventBuf, er, d.routing, d.frr, d.ipsec, d.dhcp, d.dhcpRelay, d.cluster)
		shell.SetVersion(d.opts.Version)
		shell.SetForwardingSampler(fwdSampler)
		// #797 H2 / #846: route in-process CLI commits through the
		// daemon's atomic commit+apply so they serialize against
		// HTTP/gRPC/event-engine commits under d.applySem.
		// applyConfigFn stays wired for non-commit paths (rollback,
		// confirm) that still need the full reconcile.
		shell.SetApplyConfigFn(d.applyConfig)
		shell.SetCommitFns(
			func(ctx context.Context, comment string) (*config.Config, error) {
				// In-process CLI commits don't sync to peer (the
				// CLI is local; preserves prior per-transport
				// behavior, same as HTTP).
				return d.commitAndApply(ctx, comment, false)
			},
			func(ctx context.Context, minutes int) (*config.Config, error) {
				return d.commitConfirmedAndApply(ctx, minutes, false)
			},
		)
		shell.SetRPMResultsFn(func() []*rpm.ProbeResult {
			if d.rpm != nil {
				return d.rpm.Results()
			}
			return nil
		})
		shell.SetFeedsFn(func() map[string]feeds.FeedInfo {
			if d.feeds != nil {
				return d.feeds.AllFeeds()
			}
			return nil
		})
		shell.SetLLDPNeighborsFn(func() []*lldp.Neighbor {
			if d.lldpMgr != nil {
				return d.lldpMgr.Neighbors()
			}
			return nil
		})
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
					return "vrf-mgmt"
				}
			}
			return ""
		}())

		// Set RBAC login class from config (default to super-user if user not found)
		if cfg := d.store.ActiveConfig(); cfg != nil && cfg.System.Login != nil {
			osUser := os.Getenv("USER")
			found := false
			for _, u := range cfg.System.Login.Users {
				if u.Name == osUser {
					shell.SetUserClass(u.Class)
					found = true
					break
				}
			}
			if !found {
				shell.SetUserClass("super-user")
			}
		}

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
		case <-ctx.Done():
			slog.Info("signal received, shutting down")
		}
	} else {
		slog.Info("daemon mode (non-interactive), waiting for signals")
		<-ctx.Done()
		slog.Info("signal received, shutting down")
	}

	// Cancel context to stop background goroutines, then wait for them.
	stop()
	wg.Wait()

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

	// Clean up LLDP.
	if d.lldpMgr != nil {
		d.lldpMgr.Stop()
	}

	// Determine shutdown mode early so we can clear rg_active BEFORE
	// stopping subsystems (VRRP, sync) that may hang.
	cfg := d.store.ActiveConfig()
	haMode := cfg != nil && cfg.Chassis.Cluster != nil
	hitless := !haMode // standalone = hitless by default
	if haMode && cfg.Chassis.Cluster.HitlessRestart {
		hitless = true // operator explicitly opted in
	}

	// In HA fail-closed mode, clear rg_active and watchdog immediately so
	// BPF stops forwarding traffic even if subsequent cleanup steps hang.
	if !hitless && d.dp != nil && cfg.Chassis.Cluster != nil {
		slog.Info("HA shutdown: clearing rg_active for all RGs")
		for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
			if err := d.dp.UpdateRGActive(rg.ID, false); err != nil {
				slog.Warn("failed to clear rg_active on shutdown", "rg", rg.ID, "err", err)
			}
			if err := d.dp.UpdateHAWatchdog(rg.ID, 0); err != nil {
				slog.Warn("failed to clear ha_watchdog on shutdown", "rg", rg.ID, "err", err)
			}
		}
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
	if d.sessionSync != nil {
		d.stopSyncReadyTimer()
		d.sessionSync.Stop()
	}

	if d.dp != nil {
		logFinalStats(d.dp)
		if hitless {
			// Hitless: close Go handles only — BPF programs keep running.
			slog.Info("hitless shutdown: preserving BPF state")
			d.dp.Close()
		} else {
			// Fail-closed: tear down all pinned BPF state.
			slog.Info("HA shutdown: tearing down BPF state")
			d.dp.Teardown()
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

// isInteractive returns true if stdin is a real terminal (not /dev/null or a pipe).
// enableForwarding enables IPv4 and IPv6 forwarding via sysctl
// and disables RA acceptance on all interfaces.
// A firewall must forward packets between interfaces; without this,
// the kernel drops all transit traffic. A firewall must not accept
// RAs — it uses its own configured routes exclusively.
func enableForwarding() {
	sysctls := map[string]string{
		"/proc/sys/net/ipv4/ip_forward":             "1",
		"/proc/sys/net/ipv6/conf/all/forwarding":    "1",
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

func inferIPv6StaticNextHopInterfaces(cfg *config.Config) map[string]map[string]string {
	type connectedPrefix struct {
		net    *net.IPNet
		ifName string
		bits   int
	}

	var connected []connectedPrefix
	connectedByLogical := make(map[string][]connectedPrefix)
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for ifName := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, ifName)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		base := config.LinuxIfName(ifName)
		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum := range ifc.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := ifc.Units[unitNum]
			logical := base
			if unitNum != 0 {
				logical = fmt.Sprintf("%s.%d", base, unitNum)
			}
			for _, addr := range unit.Addresses {
				ip, ipNet, err := net.ParseCIDR(addr)
				if err != nil || ip == nil || ip.To4() != nil {
					continue
				}
				bits, _ := ipNet.Mask.Size()
				prefix := connectedPrefix{
					net:    ipNet,
					ifName: logical,
					bits:   bits,
				}
				connected = append(connected, prefix)
				connectedByLogical[logical] = append(connectedByLogical[logical], prefix)
			}
		}
	}

	resolve := func(candidates []connectedPrefix, addr string) string {
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() != nil {
			return ""
		}
		bestIf := ""
		bestBits := -1
		for _, candidate := range candidates {
			if !candidate.net.Contains(ip) {
				continue
			}
			if candidate.bits > bestBits || (candidate.bits == bestBits && (bestIf == "" || candidate.ifName < bestIf)) {
				bestIf = candidate.ifName
				bestBits = candidate.bits
			}
		}
		return bestIf
	}

	collectPrefixesForInterface := func(ifName string) []connectedPrefix {
		normalized := config.LinuxIfName(ifName)
		var prefixes []connectedPrefix
		if entries, ok := connectedByLogical[normalized]; ok {
			prefixes = append(prefixes, entries...)
		}
		if !strings.Contains(normalized, ".") {
			prefixNames := make([]string, 0, len(connectedByLogical))
			for logical := range connectedByLogical {
				if strings.HasPrefix(logical, normalized+".") {
					prefixNames = append(prefixNames, logical)
				}
			}
			sort.Strings(prefixNames)
			for _, logical := range prefixNames {
				prefixes = append(prefixes, connectedByLogical[logical]...)
			}
		}
		return prefixes
	}

	resolved := make(map[string]map[string]string)
	connectedByVRF := map[string][]connectedPrefix{
		"": append([]connectedPrefix(nil), connected...),
	}
	setResolved := func(vrfName, nextHop, ifName string) {
		if ifName == "" {
			return
		}
		vrfMap, ok := resolved[vrfName]
		if !ok {
			vrfMap = make(map[string]string)
			resolved[vrfName] = vrfMap
		}
		if existing, ok := vrfMap[nextHop]; !ok || ifName < existing {
			vrfMap[nextHop] = ifName
		}
	}
	addRoutes := func(vrfName string, routes []*config.StaticRoute) {
		candidates := connectedByVRF[vrfName]
		for _, sr := range routes {
			for _, nh := range sr.NextHops {
				if nh.Interface != "" || nh.Address == "" || !strings.Contains(nh.Address, ":") {
					continue
				}
				setResolved(vrfName, nh.Address, resolve(candidates, nh.Address))
			}
		}
	}

	claimedByVRF := make(map[string]struct{})
	for _, ri := range cfg.RoutingInstances {
		vrfName := "vrf-" + ri.Name
		if ri.InstanceType == "forwarding" {
			vrfName = ""
		}
		for _, ifName := range ri.Interfaces {
			prefixes := collectPrefixesForInterface(ifName)
			if len(prefixes) == 0 {
				continue
			}
			connectedByVRF[vrfName] = append(connectedByVRF[vrfName], prefixes...)
			if vrfName != "" {
				normalized := config.LinuxIfName(ifName)
				claimedByVRF[normalized] = struct{}{}
			}
		}
	}
	if len(claimedByVRF) > 0 {
		filtered := connectedByVRF[""][:0]
		for _, prefix := range connectedByVRF[""] {
			base := prefix.ifName
			if idx := strings.IndexByte(base, '.'); idx >= 0 {
				base = base[:idx]
			}
			if _, claimed := claimedByVRF[prefix.ifName]; claimed {
				continue
			}
			if _, claimed := claimedByVRF[base]; claimed {
				continue
			}
			filtered = append(filtered, prefix)
		}
		connectedByVRF[""] = filtered
	}

	addRoutes("", cfg.RoutingOptions.StaticRoutes)
	addRoutes("", cfg.RoutingOptions.Inet6StaticRoutes)
	for _, ri := range cfg.RoutingInstances {
		vrfName := "vrf-" + ri.Name
		if ri.InstanceType == "forwarding" {
			vrfName = ""
		}
		addRoutes(vrfName, ri.StaticRoutes)
		addRoutes(vrfName, ri.Inet6StaticRoutes)
	}
	return resolved
}
