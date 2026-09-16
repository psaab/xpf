package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/clusterfailover"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func (s *Server) proxyPeerSystemAction(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
	peerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	peerCtx = metadata.AppendToOutgoingContext(peerCtx, "x-peer-forwarded", "1")
	if s.peerSystemActionFn != nil {
		return s.peerSystemActionFn(peerCtx, req)
	}
	conn, err := s.dialPeer()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return pb.NewBpfrxServiceClient(conn).SystemAction(peerCtx, req)
}

// logSystemAction records a destructive maintenance action to the configstore
// audit journal BEFORE it executes (#4108 F8). The store append is synchronous
// and fsynced, so an attributable record is durable on disk before the action
// runs — the slog.Warn line only reaches journald, which does not survive a
// reboot. For reboot/halt/power-off the on-disk journal record persists across
// the reboot; for zeroize the wipe now deliberately removes .config.journal
// (#4576 — a completed factory reset must not hand its audit log to the next
// tenant), so the durable cross-wipe trail is the pre-execution fsync (an
// interrupted wipe still leaves it) plus any remote syslog collector.
// Best-effort: a journal write failure never blocks a confirmed power/wipe
// action (the store layer warns rather than failing).
func (s *Server) logSystemAction(action string) {
	if s.store == nil {
		return
	}
	s.store.LogSystemAction(action)
}

// schedulePowerAction runs `systemctl <arg>` after a 1s grace so the RPC
// response reaches the client first. It is a package var so a test can drive
// the reboot/halt/power-off SystemAction verbs (to assert the #4108 F8 journal
// wiring) WITHOUT actually taking the host down.
var schedulePowerAction = func(systemctlArg string) {
	go func() {
		time.Sleep(1 * time.Second)
		// context.Background(): a confirmed power action must not be
		// cancelled by client disconnect. Errors ignored as before.
		runTimeout(context.Background(), "systemctl", systemctlArg)
	}()
}

// scheduleStopDaemon stops xpfd after a 1s grace so the zeroize RPC response
// reaches the client before the daemon exits (#5281). A completed factory reset
// MUST stop the daemon: otherwise xpfd keeps running with the pre-wipe
// in-memory ActiveConfig and re-renders the erased secrets on the next reconcile
// / commit / HA-sync — the incomplete-wipe window this closes. It mirrors the
// local `request system zeroize` CLI path (pkg/cli), which likewise runs
// `systemctl stop xpfd` after the wipe. It is a package var so a test can assert
// the stop is scheduled WITHOUT actually stopping a running daemon, and is
// scheduled ONLY on a fully-successful wipe (never on a fail-closed partial
// wipe). The daemon has already entered the terminal reset generation (see
// ZeroizeFn), so the ~1s grace cannot re-render anything.
var scheduleStopDaemon = func() {
	go func() {
		time.Sleep(1 * time.Second)
		// context.Background(): a confirmed factory reset must not be cancelled
		// by client disconnect. Error ignored (mirrors schedulePowerAction).
		runTimeout(context.Background(), "systemctl", "stop", "xpfd")
	}()
}

// zeroizeConfigRoot resolves the CONFIGURED config root the factory-reset wipe
// must erase — the directory and base name of the store's `-config` path
// (configstore.Store.ConfigPath), the SAME path the daemon loads config from and
// persists the .configdb SSOT / rollback slots / journal to (#5280). Deriving it
// from the store (rather than a hardcoded /etc/xpf) guarantees the wipe targets
// exactly the root the running daemon uses: a daemon started with
// `-config /srv/xpf/site.conf` erases /srv/xpf, not /etc/xpf.
//
// Fail CLOSED: if the store is absent or carries no config path we CANNOT know
// which root holds the prior tenant's secrets, so we return an error rather than
// silently wiping the wrong/nothing (which would report a clean reset while
// secrets survive). In production the daemon always wires a store built from a
// non-empty `-config` path (daemon.New / configstore.New), so this guard only
// trips in a degenerate build.
func (s *Server) zeroizeConfigRoot() (configDir, configBase string, err error) {
	if s.store == nil {
		return "", "", fmt.Errorf("zeroize: config store unavailable; cannot determine configured config root to erase")
	}
	p := s.store.ConfigPath()
	if p == "" {
		return "", "", fmt.Errorf("zeroize: config store has no config path; cannot determine configured config root to erase")
	}
	dir := filepath.Dir(p)
	// #5684: refuse if the resolved root is a shared/parent/system directory. A
	// custom -config placed directly in a shared directory (or a directory-shaped
	// -config, where filepath.Dir climbs to the PARENT) would otherwise turn the
	// factory reset into a broad deletion of *.conf / .configdb / tls siblings xpf
	// does not own. Fail CLOSED here, BEFORE runZeroize enters the terminal reset
	// generation or performZeroizeWipe touches any leg.
	// #9897 F-040: validate the RESOLVED root, not just the lexical path — a
	// link into a forbidden directory must be refused at this early gate too.
	// The ORIGINAL path is still returned (the wipe primitive re-resolves
	// authoritatively), so ordinary callers observe byte-identical roots.
	if _, err := configstore.ResolveFactoryResetRoot(dir); err != nil {
		return "", "", err
	}
	return dir, filepath.Base(p), nil
}

// runZeroize erases on-disk state for a factory reset. It routes through the
// daemon-owned apply gate (ZeroizeFn) when wired (#5281): the daemon acquires
// its apply semaphore, enters the terminal reset generation, and runs the
// performZeroizeWipe primitive while quiesced, so no concurrent or subsequent
// commit / HA-sync / reconcile re-creates the erased state. When ZeroizeFn is
// nil (NoDataplane / a bare unit-test Server with no daemon), it falls back to
// an ungated direct wipe — the pre-#5281 behavior — which is acceptable because
// there is no running reconcile loop to race in that build.
//
// The wipe target is the CONFIGURED config root (zeroizeConfigRoot), not a
// hardcoded /etc/xpf (#5280). Resolution happens BEFORE the gate so a root we
// cannot determine fails closed without entering the terminal reset generation.
func (s *Server) runZeroize(ctx context.Context) error {
	configDir, configBase, err := s.zeroizeConfigRoot()
	if err != nil {
		return err
	}
	// #7173: the CONFIGURED archive dir, from the store this server owns.
	// Hardcoding the default here meant a box with a custom
	// `system archival archive-dir` had that archive — and the cleartext PSKs
	// in it — survive a zeroize that reported success. "" means archival is
	// disabled and there is nothing to erase.
	archiveDir := ""
	if s.store != nil {
		archiveDir = s.store.ArchiveDir()
	}
	wipe := func() error { return performZeroizeWipe(configDir, configBase, archiveDir) }
	if s.zeroizeFn != nil {
		return s.zeroizeFn(ctx, wipe)
	}
	return wipe()
}

func (s *Server) SystemAction(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
	switch req.Action {
	case "reboot":
		slog.Warn("system reboot requested via gRPC")
		// Journal BEFORE the box goes down: the fsynced record survives the
		// reboot even though the slog.Warn journald line may not (#4108 F8).
		s.logSystemAction("reboot")
		schedulePowerAction("reboot")
		return &pb.SystemActionResponse{Message: "System going down for reboot NOW!"}, nil

	case "halt":
		slog.Warn("system halt requested via gRPC")
		s.logSystemAction("halt")
		schedulePowerAction("halt")
		return &pb.SystemActionResponse{Message: "System halting NOW!"}, nil

	case "power-off":
		slog.Warn("system power-off requested via gRPC")
		s.logSystemAction("power-off")
		schedulePowerAction("poweroff")
		return &pb.SystemActionResponse{Message: "System powering off NOW!"}, nil

	case "zeroize":
		slog.Warn("system zeroize requested via gRPC")
		// Journal BEFORE the wipe: the fsynced record is durable on disk
		// before any config file is removed, so an interrupted wipe still
		// leaves an attributable trail and a remote syslog collector keeps the
		// cross-wipe record (#4108 F8). The wipe itself now removes
		// .config.journal (a completed factory reset must not hand its audit
		// log to the next tenant — #4576), superseding the earlier
		// journal-survives-zeroize belt-and-braces.
		s.logSystemAction("zeroize")
		// Run the wipe through the daemon apply gate (#5281): ZeroizeFn takes the
		// same apply semaphore commit/sync serialize on and enters a terminal
		// reset generation BEFORE erasing, so a concurrent in-flight apply is
		// drained and no later commit / HA-sync / reconcile re-creates the erased
		// .configdb SSOT or re-renders the wiped secrets. The pre-#5281 handler
		// called performZeroizeWipe directly with no lifecycle coordination.
		if err := s.runZeroize(ctx); err != nil {
			// FAIL-CLOSED: a partial wipe may leave prior-tenant config/secrets
			// on disk (#4576). Surface it instead of reporting a clean factory
			// reset — the operator must know the erasure did not fully complete
			// and the device is NOT safe to re-tenant. Do NOT stop xpfd here: the
			// wipe did not finish, so stopping would strand a half-reset box (the
			// daemon has already left the reset generation, so it keeps running
			// normally until a retried zeroize succeeds).
			slog.Error("system zeroize did not fully erase config state", "err", err)
			return nil, status.Errorf(codes.Internal,
				"zeroize incomplete: config state may remain on disk: %v", err)
		}
		// The wipe fully completed. Stop xpfd so the daemon does not keep running
		// with the pre-wipe in-memory ActiveConfig and re-render the erased
		// secrets on the next reconcile (#5281). Scheduled after a 1s grace so
		// this response reaches the client; the daemon is already in the terminal
		// reset generation, so nothing re-renders in the interim. The reboot
		// completes the factory reset.
		scheduleStopDaemon()
		return &pb.SystemActionResponse{Message: "System zeroized. Configuration erased. Reboot to complete factory reset."}, nil

	case "rescue-save", "rescue-delete":
		// #8597 K47: `request system configuration rescue save|delete`, which
		// the remote dispatcher used to refuse outright.
		return s.rescueAction(req.Action)

	case "clear-config-lock":
		holder, locked := s.store.ConfigHolder()
		if !locked {
			return &pb.SystemActionResponse{Message: "No configuration lock held"}, nil
		}
		s.store.ForceExitConfigure()
		return &pb.SystemActionResponse{Message: fmt.Sprintf("Configuration lock cleared (was held by %s)", holder)}, nil

	case "clear-arp":
		out, err := combinedOutputTimeoutUnlimited(ctx, "ip", "-4", "neigh", "flush", "all")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "flush ARP: %s", strings.TrimSpace(string(out)))
		}
		return &pb.SystemActionResponse{Message: "ARP cache cleared"}, nil

	case "clear-interfaces-statistics":
		return &pb.SystemActionResponse{
			Message: "Interface statistics counters noted\n(kernel counters are cumulative and cannot be reset)",
		}, nil

	case "clear-ipv6-neighbors":
		out, err := combinedOutputTimeoutUnlimited(ctx, "ip", "-6", "neigh", "flush", "all")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "flush IPv6 neighbors: %s", strings.TrimSpace(string(out)))
		}
		return &pb.SystemActionResponse{Message: "IPv6 neighbor cache cleared"}, nil

	case "clear-policy-counters":
		if s.dp == nil || !s.dp.IsLoaded() {
			return nil, status.Error(codes.Unavailable, "dataplane not loaded")
		}
		if err := s.dp.ClearPolicyCounters(); err != nil {
			return nil, dataplaneActionError(err)
		}
		return &pb.SystemActionResponse{Message: "policy hit counters cleared"}, nil

	case "clear-firewall-counters":
		if s.dp == nil || !s.dp.IsLoaded() {
			return nil, status.Error(codes.Unavailable, "dataplane not loaded")
		}
		if err := s.dp.ClearFilterCounters(); err != nil {
			return nil, dataplaneActionError(err)
		}
		return &pb.SystemActionResponse{Message: "Firewall filter counters cleared"}, nil

	case "clear-nat-counters":
		if s.dp == nil || !s.dp.IsLoaded() {
			return nil, status.Error(codes.Unavailable, "dataplane not loaded")
		}
		if err := s.dp.ClearNATRuleCounters(); err != nil {
			return nil, dataplaneActionError(err)
		}
		return &pb.SystemActionResponse{Message: "NAT translation statistics cleared"}, nil

	case "clear-persistent-nat":
		// #2114/#6743-F2: resolve the table ONCE. Under the daemon's live
		// indirection each GetPersistentNAT() is its own cell load, so a
		// check-then-use pair nil-dereferences if the daemon disowns the
		// backend in between.
		var table *dataplane.PersistentNATTable
		if s.dp != nil {
			table = s.dp.GetPersistentNAT()
		}
		if table == nil {
			return &pb.SystemActionResponse{Message: "Persistent NAT table not available"}, nil
		}
		count := table.Len()
		table.Clear()
		return &pb.SystemActionResponse{
			Message: fmt.Sprintf("Cleared %d persistent NAT bindings", count),
		}, nil

	case "ospf-clear":
		if s.frr == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "FRR manager not available")
		}
		if _, err := s.frr.ExecVtysh(ctx, "clear ip ospf process"); err != nil {
			return nil, status.Errorf(codes.Internal, "clear OSPF: %v", err)
		}
		return &pb.SystemActionResponse{Message: "OSPF process cleared"}, nil

	case "bgp-clear":
		if s.frr == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "FRR manager not available")
		}
		if _, err := s.frr.ExecVtysh(ctx, "clear bgp * soft"); err != nil {
			return nil, status.Errorf(codes.Internal, "clear BGP: %v", err)
		}
		return &pb.SystemActionResponse{Message: "BGP sessions cleared (soft reset)"}, nil

	case "ipsec-sa-clear":
		if s.ipsec == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "IPsec manager not available")
		}
		count, err := s.ipsec.TerminateAllSAs()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &pb.SystemActionResponse{
			Message: fmt.Sprintf("Cleared %d IPsec SA(s)", count),
		}, nil

	case "dhcp-renew":
		if s.dhcp == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "DHCP manager not available")
		}
		if req.Target == "" {
			return nil, status.Errorf(codes.InvalidArgument, "dhcp-renew requires target interface")
		}
		if err := s.dhcp.Renew(req.Target); err != nil {
			return nil, status.Errorf(codes.NotFound, "%v", err)
		}
		return &pb.SystemActionResponse{
			Message: fmt.Sprintf("DHCP renewal initiated on %s", req.Target),
		}, nil

	case "in-service-upgrade":
		if s.cluster == nil {
			return nil, status.Error(codes.Unavailable, "cluster not configured")
		}
		if err := s.cluster.ForceSecondary(); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "ISSU: %v", err)
		}
		// Fence the drain-complete message on an OBSERVED peer takeover rather
		// than on ForceSecondary's return, which only sets desired state
		// (#5039). Bounded by the RPC ctx so an operator Ctrl-C returns the
		// honest (unconfirmed) report instead of hanging.
		waitCtx, cancel := context.WithTimeout(ctx, cluster.DefaultUpgradeHandoffTimeout)
		confirmed := s.cluster.WaitForUpgradeHandoff(waitCtx, cluster.DefaultUpgradeHandoffPoll)
		cancel()
		return &pb.SystemActionResponse{
			Message: strings.Join(cluster.UpgradeDrainReport(confirmed), "\n"),
		}, nil

	case "dynamic-dns-update", "dynamic-dns-check":
		// #3276: operator force-now / check-now verb. force=true (update)
		// re-asserts every owned DDNS record now; force=false (check) only
		// re-observes + publishes changed records. The handler honors the
		// per-RG owner gate (no-op + clear message on the backup).
		if s.surfaceADDNSForceFn == nil {
			return nil, status.Error(codes.Unavailable, "dynamic-dns: DDNS engine not running")
		}
		_, msg := s.surfaceADDNSForceFn(req.Action == "dynamic-dns-update")
		return &pb.SystemActionResponse{Message: msg}, nil

	default:
		// All cluster-failover actions (plain RG / targeted RG / data / reset)
		// share ONE strict grammar with the two CLIs and the fabric interceptor
		// (pkg/clusterfailover). Parsing here rejects a malformed selector, an
		// empty/duplicate/trailing node suffix, or an out-of-range node with
		// InvalidArgument BEFORE any cluster call or peer dial — the old
		// per-form ad-hoc parsing let `cluster-failover:1:node` (empty suffix)
		// fall through to an untargeted ManualFailover (#5810, #5851).
		if clusterfailover.IsFailoverAction(req.Action) {
			if s.cluster == nil {
				return nil, status.Error(codes.Unavailable, "cluster not configured")
			}
			op, err := clusterfailover.ParseAction(req.Action)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "%v", err)
			}
			// #8629: converted at the boundary; see rpcStatus.
			resp, err := s.executeClusterFailover(ctx, req, op)
			return resp, rpcStatus(err)
		}
		if strings.HasPrefix(req.Action, "userspace-inject:") {
			provider, err := s.userspaceDataplaneControl()
			if err != nil {
				return nil, status.Error(codes.Unavailable, err.Error())
			}
			rest := strings.TrimPrefix(req.Action, "userspace-inject:")
			parts := strings.SplitN(rest, ":", 2)
			if len(parts) != 2 {
				return nil, status.Error(codes.InvalidArgument, "usage: userspace-inject:<slot>:<mode>")
			}
			slot, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid userspace slot: %s", parts[0])
			}
			mode := parts[1]
			statusNow, err := provider.Status()
			if err != nil {
				return nil, status.Errorf(codes.Unavailable, "userspace status: %v", err)
			}
			extra, err := dpuserspace.DecodeInjectPacketTarget(req.Target)
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
			injectReq, err := dpuserspace.BuildInjectPacketRequest(uint32(slot), mode, extra, statusNow)
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
			statusAfter, err := provider.InjectPacket(injectReq)
			if err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "userspace inject: %v", err)
			}
			msg := dpformat.FormatStatusSummary(statusAfter) + "\n" + dpformat.FormatBindings(statusAfter)
			return &pb.SystemActionResponse{Message: msg}, nil
		}
		if strings.HasPrefix(req.Action, "userspace-forwarding:") {
			provider, err := s.userspaceDataplaneControl()
			if err != nil {
				return nil, status.Error(codes.Unavailable, err.Error())
			}
			armed, err := dpuserspace.ParseForwardingCommand([]string{"forwarding", strings.TrimPrefix(req.Action, "userspace-forwarding:")})
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
			statusAfter, err := provider.SetForwardingArmed(armed)
			if err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "userspace forwarding control: %v", err)
			}
			msg := dpformat.FormatStatusSummary(statusAfter) + "\n" + dpformat.FormatBindings(statusAfter)
			return &pb.SystemActionResponse{Message: msg}, nil
		}
		if strings.HasPrefix(req.Action, "userspace-queue:") {
			provider, err := s.userspaceDataplaneControl()
			if err != nil {
				return nil, status.Error(codes.Unavailable, err.Error())
			}
			rest := strings.TrimPrefix(req.Action, "userspace-queue:")
			parts := strings.SplitN(rest, ":", 2)
			if len(parts) != 2 {
				return nil, status.Error(codes.InvalidArgument, "usage: userspace-queue:<queue>:<register|unregister|arm|disarm>")
			}
			queueID, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid userspace queue: %s", parts[0])
			}
			registered, armed, err := dpuserspace.ParseRegistrationOperation(parts[1])
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
			statusAfter, err := provider.SetQueueState(uint32(queueID), registered, armed)
			if err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "userspace queue control: %v", err)
			}
			msg := dpformat.FormatStatusSummary(statusAfter) + "\n" + dpformat.FormatBindings(statusAfter)
			return &pb.SystemActionResponse{Message: msg}, nil
		}
		if strings.HasPrefix(req.Action, "userspace-binding:") {
			provider, err := s.userspaceDataplaneControl()
			if err != nil {
				return nil, status.Error(codes.Unavailable, err.Error())
			}
			rest := strings.TrimPrefix(req.Action, "userspace-binding:")
			parts := strings.SplitN(rest, ":", 2)
			if len(parts) != 2 {
				return nil, status.Error(codes.InvalidArgument, "usage: userspace-binding:<slot>:<register|unregister|arm|disarm>")
			}
			slot, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid userspace slot: %s", parts[0])
			}
			if slot < 0 || slot >= int(dataplane.BindingSlotMapMaxEntries) {
				return nil, status.Errorf(codes.InvalidArgument,
					"userspace slot %d out of range [0, %d)", slot, dataplane.BindingSlotMapMaxEntries)
			}
			registered, armed, err := dpuserspace.ParseRegistrationOperation(parts[1])
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
			statusAfter, err := provider.SetBindingState(uint32(slot), registered, armed)
			if err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "userspace binding control: %v", err)
			}
			msg := dpformat.FormatStatusSummary(statusAfter) + "\n" + dpformat.FormatBindings(statusAfter)
			return &pb.SystemActionResponse{Message: msg}, nil
		}
		return nil, status.Errorf(codes.InvalidArgument, "unknown action: %s", req.Action)
	}
}

// executeClusterFailover runs a parsed, validated cluster-failover op. The
// shared grammar (pkg/clusterfailover) has already rejected malformed input, an
// out-of-range node, and empty/duplicate/trailing suffixes, so no branch here
// re-validates the action string — they only ROUTE (local execution vs. peer
// proxy). Because both CLIs, this loopback handler, and the fabric interceptor
// share that one parser, any form reaching this method is one all layers agree
// is well-formed; the fabric allowlist may still deny a valid local-only form
// (plain RG failover / reset) by policy, but never by a divergent parse.
func (s *Server) executeClusterFailover(ctx context.Context, req *pb.SystemActionRequest, op clusterfailover.Op) (*pb.SystemActionResponse, error) {
	switch op.Kind {
	case clusterfailover.KindReset:
		if err := s.cluster.ResetFailover(op.RG); err != nil {
			return nil, status.Errorf(codes.NotFound, "%v", err)
		}
		return &pb.SystemActionResponse{
			Message: fmt.Sprintf("Failover reset for redundancy group %d", op.RG),
		}, nil

	case clusterfailover.KindDataFailover:
		targetNode := op.Node
		if targetNode != s.cluster.NodeID() {
			if peerForwardedFromContext(ctx) {
				return nil, status.Errorf(codes.FailedPrecondition, "forwarded cluster failover target node %d is not local", targetNode)
			}
			resp, err := s.proxyPeerSystemAction(ctx, req)
			if err != nil {
				if st, ok := status.FromError(err); ok {
					return nil, st.Err()
				}
				return nil, status.Errorf(codes.Unavailable, "peer cluster failover proxy failed: %v", err)
			}
			return resp, nil
		}
		dataRGs := s.cluster.DataGroupIDs()
		if len(dataRGs) == 0 {
			return nil, status.Error(codes.FailedPrecondition, "no data redundancy groups configured")
		}
		moveRGs := make([]int, 0, len(dataRGs))
		for _, rgID := range dataRGs {
			if !s.cluster.IsLocalPrimary(rgID) {
				moveRGs = append(moveRGs, rgID)
			}
		}
		if len(moveRGs) == 0 {
			return &pb.SystemActionResponse{
				Message: fmt.Sprintf("All data redundancy groups are already primary on node %d", targetNode),
			}, nil
		}
		if len(moveRGs) == 1 {
			if err := s.cluster.RequestPeerFailover(moveRGs[0]); err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
			}
		} else {
			if err := s.cluster.RequestPeerFailoverBatch(moveRGs); err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
			}
		}
		return &pb.SystemActionResponse{
			Message: fmt.Sprintf("Manual failover completed for data redundancy groups %v (transfer committed)", moveRGs),
		}, nil

	case clusterfailover.KindRGFailoverNode:
		targetNode := op.Node
		if targetNode != s.cluster.NodeID() {
			if peerForwardedFromContext(ctx) {
				return nil, status.Errorf(codes.FailedPrecondition, "forwarded cluster failover target node %d is not local", targetNode)
			}
			resp, err := s.proxyPeerSystemAction(ctx, req)
			if err != nil {
				if st, ok := status.FromError(err); ok {
					return nil, st.Err()
				}
				return nil, status.Errorf(codes.Unavailable, "peer cluster failover proxy failed: %v", err)
			}
			return resp, nil
		}
		// Target is local — make us primary.
		if s.cluster.IsLocalPrimary(op.RG) {
			return &pb.SystemActionResponse{
				Message: fmt.Sprintf("Redundancy group %d is already primary on node %d", op.RG, targetNode),
			}, nil
		}
		// Ask peer to transfer out so we can take primary.
		if err := s.cluster.RequestPeerFailover(op.RG); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
		}
		return &pb.SystemActionResponse{
			Message: fmt.Sprintf("Manual failover completed for redundancy group %d (transfer committed)", op.RG),
		}, nil

	case clusterfailover.KindRGFailover:
		outcome, err := s.cluster.ManualFailover(op.RG)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "%v", err)
		}
		// #8000: a supersede is not an error — a concurrent `reset` is the
		// operator's newer intent — but reporting it as "triggered" tells them
		// a failover happened when none did.
		if outcome == cluster.FailoverSuperseded {
			return &pb.SystemActionResponse{
				Message: fmt.Sprintf("Manual failover for redundancy group %d was superseded by a concurrent reset; no failover performed", op.RG),
			}, nil
		}
		return &pb.SystemActionResponse{
			Message: fmt.Sprintf("Manual failover triggered for redundancy group %d", op.RG),
		}, nil
	}
	// ParseAction only yields the four kinds above; defensive fallthrough.
	return nil, status.Errorf(codes.InvalidArgument, "unknown action: %s", req.Action)
}

// dataplaneActionError maps a dataplane clear/mutate failure to a gRPC
// status.
//
// #2114/#6743-F3: the daemon's live indirection answers
// dataplane.ErrNotPublished when its cell is empty AT CALL TIME, which is
// exactly the condition the `dp == nil || !dp.IsLoaded()` pre-check above
// reports as codes.Unavailable. A clear that races a setDataplane(nil)
// passes the pre-check and then fails inside the forwarder, so without
// this mapping the identical operator-visible condition is reported as
// codes.Internal — a server fault — purely because of when the cell
// cleared. Anything else is a genuine backend failure and stays Internal.
//
// Codex PR #6743 r7: that last sentence is about the MAPPING, not about
// backend coverage — it holds for every failure that actually reaches here.
// Some do not: pkg/dataplane/maps_nat.go's ClearNATRuleCounters discards
// every per-entry Update error and returns nil, so a partial clear is
// reported as success and never gets a code at all. That is pre-existing on
// master, is not part of #2114's publication contract, and is deliberately
// out of scope for this PR — recorded here so the sentence above is not
// read as a claim that every backend failure is surfaced.
func dataplaneActionError(err error) error {
	if errors.Is(err, dataplane.ErrNotPublished) {
		return status.Error(codes.Unavailable, "dataplane not loaded")
	}
	return status.Errorf(codes.Internal, "%v", err)
}
