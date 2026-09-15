package grpcapi

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/monitoriface"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var _ monitoriface.RuntimeDataPlane = monitorInterfaceServerDataPlane{}

type monitorInterfaceServerDataPlane struct {
	server *Server
}

func (a monitorInterfaceServerDataPlane) IsLoaded() bool {
	return a.server != nil && a.server.dp != nil && a.server.dp.IsLoaded()
}

func (a monitorInterfaceServerDataPlane) ReadInterfaceCounters(ifindex int) (monitoriface.InterfaceCounters, error) {
	if a.server == nil || a.server.dp == nil {
		return monitoriface.InterfaceCounters{}, fmt.Errorf("dataplane unavailable")
	}
	ctrs, err := a.server.dp.ReadInterfaceCounters(ifindex)
	if err != nil {
		return monitoriface.InterfaceCounters{}, err
	}
	return monitoriface.InterfaceCounters{
		RxPackets: ctrs.RxPackets,
		RxBytes:   ctrs.RxBytes,
		TxPackets: ctrs.TxPackets,
		TxBytes:   ctrs.TxBytes,
	}, nil
}

func (s *Server) monitorInterfaceDataplane() monitoriface.RuntimeDataPlane {
	if s == nil || s.dp == nil {
		return nil
	}
	return monitorInterfaceServerDataPlane{server: s}
}

// monitorInterfaceLimiter bounds concurrent MonitorInterface streams (#9891).
// It aliases the process-wide diagcmd.MonitorInterfaceLimiter so the bound
// holds regardless of how many Server instances serve the RPC. Acquire is
// fail-fast; over-cap streams return codes.ResourceExhausted without creating
// a ticker, a rendering goroutine, or a peer dial. A package var so a test can
// swap in a fresh small-capacity limiter.
var monitorInterfaceLimiter = diagcmd.MonitorInterfaceLimiter

// monitorInterfaceSendTimeout bounds a SINGLE downstream frame write. A client
// that cannot accept one frame within this window is not reading. Per-write,
// not elapsed: an idle-healthy stream (valid in summary mode between ticks)
// is untouched and only a peer that has stopped draining is cut — the same
// axis sseWriteDeadline uses for SSE (#7632). Matches the 30s slow-reader
// budget so one tuning covers both streaming surfaces. A package var so a test
// can compress it without a real slow reader.
var monitorInterfaceSendTimeout = 30 * time.Second

// sendMonitorInterfaceFrame sends one frame with a slow-consumer bound. gRPC
// has no socket write deadline, so Send runs in a short-lived goroutine and
// the handler selects over its completion, the client context, and the
// per-write timeout. On timeout the stream is severed with DeadlineExceeded;
// the handler return then tears the RPC down, which unblocks the helper Send
// so it cannot outlive the stream. The timer is stopped on the fast path so a
// healthy Send leaves no 30s timer behind.
func sendMonitorInterfaceFrame(stream grpc.ServerStreamingServer[pb.MonitorInterfaceResponse], resp *pb.MonitorInterfaceResponse) error {
	ctx := stream.Context()
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	done := make(chan error, 1)
	go func() { done <- stream.Send(resp) }()
	timer := time.NewTimer(monitorInterfaceSendTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return status.Error(codes.DeadlineExceeded, "monitor interface client is not reading; stream severed")
	}
}

// MonitorPacketDrop streams packet drop events matching the request filters.
func (s *Server) MonitorPacketDrop(req *pb.MonitorPacketDropRequest, stream grpc.ServerStreamingServer[pb.MonitorPacketDropResponse]) error {
	if s.eventBuf == nil {
		return status.Error(codes.Unavailable, "event buffer not available")
	}

	// Validate the request before subscribing (#3382). MonitorPacketDrop
	// streams only LOCAL drops; the CLI applies the same guardrails. An
	// unvalidated filter silently produces an empty stream that looks like
	// "no drops" during incident response, so reject impossible inputs up
	// front with InvalidArgument rather than opening a stream that can never
	// match.

	// node: packet-drop is local-only — it does not proxy to the cluster
	// peer the way MonitorInterface does. Honor an empty/local node and
	// reject any value that designates a different (or "all") node so a
	// client cannot believe a peer filter was applied.
	if !s.isLocalNodeRef(req.Node) {
		return status.Errorf(codes.InvalidArgument,
			"node %q: monitor packet-drop is local-only; run it on the target node", req.Node)
	}

	// count: negative is not "unlimited" (the CLI rejects it); enforce the
	// CLI's 1..8192 cap. 0 remains an explicit "unlimited" sentinel.
	if req.Count < 0 {
		return status.Errorf(codes.InvalidArgument, "count must be >= 0 (0 = unlimited), got %d", req.Count)
	}
	if req.Count > 8192 {
		return status.Errorf(codes.InvalidArgument, "count must be 1..8192 (0 = unlimited), got %d", req.Count)
	}

	// ports: the event records carry 16-bit ports; a value > 65535 can
	// never match and would silently empty the stream.
	if req.SourcePort > 65535 {
		return status.Errorf(codes.InvalidArgument, "source-port must be 0..65535, got %d", req.SourcePort)
	}
	if req.DestinationPort > 65535 {
		return status.Errorf(codes.InvalidArgument, "destination-port must be 0..65535, got %d", req.DestinationPort)
	}

	// protocol: validate against the shared catalog (case-insensitive,
	// named or numeric). A typo like "tpc" can never match. Resolve the
	// request to its protocol NUMBER once so the filter loop can compare
	// numerically — the event record renders rec.Protocol as a NAME for the
	// named set, so a numeric request like "6" must not be string-compared
	// against "TCP" (the accepted-but-never-matches bug).
	var reqProtoNum uint8
	if req.Protocol != "" {
		n, ok := appid.ProtocolNumber(req.Protocol)
		if !ok {
			return status.Errorf(codes.InvalidArgument, "unknown protocol %q", req.Protocol)
		}
		reqProtoNum = n
	}

	// zone / interface: validate against the active configuration so a typo
	// (`trsut`, `ge-0/0/99`) is rejected rather than emitting nothing. The
	// interface filter must MATCH on whichever alias the daemon stored, so
	// resolve the full alias set once and reuse it in the loop.
	var reqIfaceAliases map[string]bool
	if req.FromZone != "" || req.Interface != "" {
		cfg := s.store.ActiveConfig()
		if cfg == nil {
			return status.Error(codes.Unavailable, "no active configuration to validate zone/interface filters")
		}
		if req.FromZone != "" {
			if _, ok := cfg.Security.Zones[req.FromZone]; !ok {
				return status.Errorf(codes.InvalidArgument, "unknown from-zone %q", req.FromZone)
			}
		}
		if req.Interface != "" {
			reqIfaceAliases = interfaceAliasSet(cfg, req.Interface)
			if len(reqIfaceAliases) == 0 {
				return status.Errorf(codes.InvalidArgument, "unknown interface %q", req.Interface)
			}
		}
	}

	// Parse filters.
	var srcNet, dstNet *net.IPNet
	if req.SourcePrefix != "" {
		_, cidr, err := net.ParseCIDR(req.SourcePrefix)
		if err != nil {
			ip := net.ParseIP(req.SourcePrefix)
			if ip == nil {
				return status.Errorf(codes.InvalidArgument, "invalid source-prefix: %s", req.SourcePrefix)
			}
			if ip.To4() != nil {
				cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else {
				cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}
		srcNet = cidr
	}
	if req.DestinationPrefix != "" {
		_, cidr, err := net.ParseCIDR(req.DestinationPrefix)
		if err != nil {
			ip := net.ParseIP(req.DestinationPrefix)
			if ip == nil {
				return status.Errorf(codes.InvalidArgument, "invalid destination-prefix: %s", req.DestinationPrefix)
			}
			if ip.To4() != nil {
				cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else {
				cidr = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}
		dstNet = cidr
	}

	count := int(req.Count)
	// #5850: bound concurrent event-stream subscribers. MonitorPacketDrop is a
	// request-created stream on the loopback-but-UNAUTHENTICATED gRPC listener,
	// so it must NOT bypass the admission cap (defaultMaxSubscribers) the way the
	// uncapped Subscribe did. Each live stream adds a buffered channel AND expands
	// the synchronous O(N) per-event fan-out the EventBuffer does for EVERY event,
	// so any local process opening an unbounded number of these streams exhausts
	// memory + event-production CPU (a DoS distinct from #4484 L-2, which capped
	// only the REST SSE surface and wrongly treated gRPC as inherently bounded).
	// TrySubscribe returns nil at the cap; reject with ResourceExhausted,
	// mirroring the REST SSE 503 (pkg/api/sse.go).
	sub := s.eventBuf.TrySubscribe(256)
	if sub == nil {
		return status.Error(codes.ResourceExhausted, "too many concurrent event subscribers")
	}
	defer sub.Close()

	if err := stream.Send(&pb.MonitorPacketDropResponse{Line: "Starting packet drop:"}); err != nil {
		return err
	}

	seen := 0
	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case rec := <-sub.C:
			if rec.Type != "POLICY_DENY" && rec.Type != "SCREEN_DROP" {
				continue
			}
			if srcNet != nil {
				host, _, _ := net.SplitHostPort(rec.SrcAddr)
				if host == "" {
					host = rec.SrcAddr
				}
				if ip := net.ParseIP(host); ip == nil || !srcNet.Contains(ip) {
					continue
				}
			}
			if dstNet != nil {
				host, _, _ := net.SplitHostPort(rec.DstAddr)
				if host == "" {
					host = rec.DstAddr
				}
				if ip := net.ParseIP(host); ip == nil || !dstNet.Contains(ip) {
					continue
				}
			}
			if req.SourcePort != 0 {
				_, portStr, _ := net.SplitHostPort(rec.SrcAddr)
				if p, _ := strconv.ParseUint(portStr, 10, 16); p != uint64(req.SourcePort) {
					continue
				}
			}
			if req.DestinationPort != 0 {
				_, portStr, _ := net.SplitHostPort(rec.DstAddr)
				if p, _ := strconv.ParseUint(portStr, 10, 16); p != uint64(req.DestinationPort) {
					continue
				}
			}
			if req.Protocol != "" && rec.ProtocolNum != reqProtoNum {
				// Compare against the numeric protocol the RECORD carries,
				// not a re-parse of the rendered name. Comparing numerically
				// is robust regardless of the name SSOT: even though #3393
				// closed the ProtocolName↔ProtocolNumber round-trip (proto 41
				// "ipv6" now reverses), the raw number (#3382) keeps the match
				// total for named, numeric-only, and any future render-only
				// protocols alike. reqProtoNum is resolved once in validation
				// via appid.ProtocolNumber (correct for the named/numeric
				// REQUEST side).
				continue
			}
			if req.FromZone != "" && rec.InZoneName != req.FromZone {
				continue
			}
			if req.Interface != "" && !reqIfaceAliases[rec.IngressIface] {
				// rec.IngressIface is the single daemon-resolved name; the
				// request may be any accepted alias (config key, Linux
				// form, or Name override). Match against the full alias set
				// so any accepted form matches (#3382 matcher fix).
				continue
			}

			// Format the drop event.
			ts := rec.Time.Format("15:04:05.000000")
			reason := rec.Action
			if rec.ScreenCheck != "" {
				reason = "Dropped by SCREEN:" + rec.ScreenCheck
			} else if rec.Type == "POLICY_DENY" {
				reason = "Dropped by FLOW:Policy deny"
				if rec.PolicyName != "" {
					reason = "Dropped by FLOW:Policy " + rec.PolicyName
				}
			}
			line := fmt.Sprintf("%s %s-->%s;%s,%s,%s",
				ts, rec.SrcAddr, rec.DstAddr,
				strings.ToLower(rec.Protocol),
				rec.IngressIface, reason)

			if err := stream.Send(&pb.MonitorPacketDropResponse{Line: line}); err != nil {
				return err
			}
			seen++
			if count > 0 && seen >= count {
				return nil
			}
		}
	}
}

// isLocalNodeRef reports whether a request's node reference designates the
// local node (#3382). An empty string or "local" is always local. In a
// cluster the node's numeric id ("0"/"1") or "nodeN" form for THIS node is
// accepted; a standalone daemon (localID 0) accepts "0" or "node0". Anything
// else — the peer id, "all", "primary" — is not local, so a local-only RPC
// must reject it rather than silently filter local data.
func (s *Server) isLocalNodeRef(node string) bool {
	switch strings.ToLower(strings.TrimSpace(node)) {
	case "", "local":
		return true
	}
	ref := strings.ToLower(strings.TrimSpace(node))
	localID := 0
	if s != nil && s.cluster != nil {
		localID = s.cluster.NodeID()
	}
	return ref == strconv.Itoa(localID) || ref == fmt.Sprintf("node%d", localID)
}

// interfaceAliasSet returns the set of equivalent names for the configured
// interface that `name` designates, or nil if it matches none (#3382). The
// packet-drop filter compares against the SINGLE daemon-resolved ingress name
// (resolveIfName), but the operator may pass any accepted alias — the config
// key ("ge-0/0/1"), its Linux-form rendering ("ge-0-0-1"), an explicit Name
// override, or that Name's Linux form. Returning the full alias set lets both
// validation (len > 0) and the matcher (membership test) accept whichever form
// the daemon happened to store, so a validated interface filter cannot
// accept-but-never-match.
func interfaceAliasSet(cfg *config.Config, name string) map[string]bool {
	if cfg == nil {
		return nil
	}
	for key, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil { // #5886: skip present-but-nil InterfaceConfig
			continue
		}
		aliases := map[string]bool{
			key:                     true,
			config.LinuxIfName(key): true,
		}
		if ifc != nil && ifc.Name != "" {
			aliases[ifc.Name] = true
			aliases[config.LinuxIfName(ifc.Name)] = true
		}
		if aliases[name] {
			return aliases
		}
	}
	return nil
}

// monitorNoPeerMarker is the gRPC metadata key stamped on a MonitorInterface
// request that has already been forwarded to the cluster peer. A request
// carrying it is served LOCALLY and never re-proxied — the strict one-hop
// forwarding bound that closes the #5497 A->B->A recursion. It reuses the
// chassis-forwarding proxy's convention (server_show_cluster_text.go).
const monitorNoPeerMarker = "xpf-no-peer"

// monitorRequestForwardedFromPeer reports whether the inbound MonitorInterface
// request already carries the no-peer hop marker (i.e. the peer forwarded it to
// us). The marker only ever SUPPRESSES a second proxy hop, so a client cannot
// spoof it to reach data it could not otherwise reach — the worst it can do is
// force a would-be proxy to serve locally / report not-found.
func monitorRequestForwardedFromPeer(ctx context.Context) bool {
	// #5883: read the unforgeable in-process capability, not the raw header.
	// The comment above is right that spoofing this marker reaches no data the
	// caller could not otherwise reach — but "the worst it can do is force a
	// would-be proxy to serve locally" is still a caller deciding a hop bound
	// the operator did not, and it is the same key the session-clear path
	// trusts. One mechanism for both, so neither can drift.
	return peerMarkersFromContext(ctx).noPeer
}

// monitorClusterState is the slice of the cluster manager the MonitorInterface
// proxy decision needs. *cluster.Manager satisfies it; tests supply a fake so
// the #5497 hop-bound / peer-ownership logic is exercised without a live
// cluster or a network dial.
type monitorClusterState interface {
	IsLocalPrimary(rg int) bool
	IsPeerPrimary(rg int) bool
}

// monitorProxyAction is the outcome of the MonitorInterface single-interface
// proxy decision.
type monitorProxyAction int

const (
	monitorServeLocal  monitorProxyAction = iota // read counters on this node
	monitorProxyToPeer                           // forward one hop to the peer
	monitorNotFound                              // interface exists on neither side
)

// decideMonitorProxy decides how a single-interface MonitorInterface request is
// handled on a cluster node, enforcing the #5497 invariant that one management
// stream consumes O(1) resources with a strict one-hop forwarding bound.
//
//   - alreadyProxied: the request arrived carrying the no-peer hop marker, i.e.
//     the peer forwarded it to us. It is served locally and NEVER re-proxied — a
//     second hop is the A->B->A recursion that storms
//     connections/streams/goroutines.
//   - existsLocally: the resolved kernel interface exists on this node.
//   - isPeerMember: the interface is a peer node's physical member (its FPC slot
//     maps to the peer, or it is only named in the peer's RG monitors) so it can
//     only be read on the peer.
//   - isReth / rg: a locally-present RETH may be MASTER on the peer. It is
//     proxied ONLY when the peer actually OWNS the RG (peer primary) while this
//     node does not (local not primary). During both-secondary / election /
//     sync-hold / disabled / peer-lost NEITHER node is primary, so it is served
//     locally instead of proxied — the old `!IsLocalPrimary` test proxied in all
//     those states and, absent a hop marker, looped (#5497).
func decideMonitorProxy(alreadyProxied, existsLocally, isPeerMember, isReth bool, rg int, cl monitorClusterState) monitorProxyAction {
	if !existsLocally {
		// Interface is not on this node. Forward to the peer only if it owns
		// the physical member AND we were not already forwarded — otherwise do
		// not bounce it back; report not-found so the loop cannot form.
		if isPeerMember && !alreadyProxied {
			return monitorProxyToPeer
		}
		return monitorNotFound
	}
	if isReth && !alreadyProxied && rg > 0 && cl != nil &&
		!cl.IsLocalPrimary(rg) && cl.IsPeerPrimary(rg) {
		return monitorProxyToPeer
	}
	return monitorServeLocal
}

// MonitorInterface streams pre-formatted interface statistics frames.
func (s *Server) MonitorInterface(req *pb.MonitorInterfaceRequest, stream grpc.ServerStreamingServer[pb.MonitorInterfaceResponse]) error {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return status.Error(codes.Unavailable, "no active configuration")
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}

	// resolveToKernel converts a config-level interface name to its kernel name.
	// e.g. "ge-0/0/0" → "ge-0-0-0", "reth0" → physical member's kernel name.
	//
	// This closure captures the OPEN-time cfg deliberately. It feeds the
	// stream-ENTRY decisions below (single-interface resolution, the RETH
	// proxy-to-peer dispatch), which are settled once and must not move
	// mid-stream — see monitorSummaryInterfaces for the per-tick path and
	// the reasoning for the split.
	resolveToKernel := func(cfgName string) string {
		return monitorResolveToKernel(cfg, cfgName)
	}

	// isRethName returns true if the name is a RETH interface (reth0, reth1, etc).
	isRethName := func(name string) bool {
		return strings.HasPrefix(name, "reth")
	}

	// rethRG returns the redundancy group for a RETH interface, or -1.
	rethRG := func(name string) int {
		parts := strings.SplitN(name, ".", 2)
		if ifc, ok := config.LookupInterface(cfg, parts[0]); ok && ifc.RedundancyGroup > 0 {
			return ifc.RedundancyGroup
		}
		return -1
	}

	// isPeerInterface returns true if the named interface is a cluster peer's
	// physical member. Checks FPC slot → node-id mapping first (ge-7/0/X on
	// node0 belongs to node1), then falls back to RG interface monitors.
	isPeerInterface := func(name string) bool {
		if cfg.Chassis.Cluster == nil {
			return false
		}
		// Check FPC slot: slot 0 → node0, slot 7 → node1.
		if s.cluster != nil {
			slot := config.InterfaceSlot(name)
			if slot >= 0 && config.SlotToNodeID(slot) != s.cluster.NodeID() {
				return true
			}
		}
		base := strings.SplitN(name, ".", 2)[0]
		// Check RG interface monitors.
		for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
			for _, mon := range rg.InterfaceMonitors {
				if strings.SplitN(mon.Interface, ".", 2)[0] == base {
					return true
				}
			}
		}
		return false
	}

	isSingle := req.InterfaceName != ""
	var singleDisplayName, singleKernelName string
	proxyToPeer := false
	if isSingle {
		singleDisplayName = req.InterfaceName
		singleKernelName = monitoriface.ResolvePhysicalParent(resolveToKernel(req.InterfaceName))

		// Decide whether to serve locally, proxy one hop to the peer, or report
		// not-found. A request already forwarded from the peer (no-peer marker)
		// is never re-proxied, and a locally-present RETH is proxied only when
		// the peer actually owns the RG — together these bound the forwarding
		// to a single hop and close the #5497 A->B->A recursion.
		// NotFound returns BEFORE admission below so validation failures cost
		// no subscriber slot; the proxy decision is recorded and acted on only
		// once a slot is held, so a refused subscriber dials no peer.
		_, ifErr := net.InterfaceByName(singleKernelName)
		var cl monitorClusterState
		if s.cluster != nil {
			cl = s.cluster
		}
		switch decideMonitorProxy(
			monitorRequestForwardedFromPeer(stream.Context()),
			ifErr == nil,
			isPeerInterface(req.InterfaceName),
			isRethName(req.InterfaceName),
			rethRG(req.InterfaceName),
			cl,
		) {
		case monitorProxyToPeer:
			proxyToPeer = true
		case monitorNotFound:
			return status.Errorf(codes.NotFound, "interface %s not found", req.InterfaceName)
		}
		// monitorServeLocal: fall through and read local counters below.
	}

	// Admission bound (#9891): fail-fast before the ticker, the rendering
	// state, and any peer dial, so a refused subscriber costs no goroutine,
	// no ticker, and no connection. Held across the proxy forwarding loop as
	// well — it still pins a local goroutine plus a peer connection — while
	// the peer charges its own slot for the rendering half.
	release, err := monitorInterfaceLimiter.Acquire()
	if err != nil {
		return status.Error(codes.ResourceExhausted, "too many concurrent monitor interface subscribers")
	}
	defer release()
	if proxyToPeer {
		return s.proxyMonitorInterface(req, stream)
	}

	summaryInterfaces := func() ([]string, map[string]string) {
		return s.monitorSummaryInterfaces(cfg)
	}

	startTime := time.Now()
	ctx := stream.Context()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	summaryMode := monitorSummaryModeFromProto(req.GetSummaryMode())

	// Previous snapshots for rate calculation.
	var prevSingle *monitoriface.Snapshot
	var baselineSingle *monitoriface.Snapshot
	prevAll := make(map[string]*monitoriface.Snapshot)

	// statusReader is the shared, coalescing Status() reader (#5707). Summary
	// mode reads every configured interface each tick and every concurrent stream
	// runs its own ticker, so binding the per-interface, per-stream snapshot read
	// to the raw s.userspaceDataplaneStatus would issue O(interfaces*streams)
	// control-socket queries per tick. The Server-wide cache fans one query out
	// to all callers within a poll window, keeping the load O(1) per tick.
	statusReader := s.monitorStatusReader()
	readSnap := func(name string) *monitoriface.Snapshot {
		snap, err := monitoriface.ReadSnapshot(s.monitorInterfaceDataplane(), statusReader, name)
		if err != nil {
			return nil
		}
		return &snap
	}

	for {
		var buf strings.Builder
		if isSingle {
			snap := readSnap(singleKernelName)
			if snap == nil {
				fmt.Fprintf(&buf, "interface %s: not available\n", singleDisplayName)
			} else {
				if baselineSingle == nil {
					baselineSingle = snap
				}
				monitoriface.RenderSingleInterface(&buf, hostname, singleDisplayName, singleKernelName, snap, prevSingle, baselineSingle, startTime)
				snapCopy := *snap
				prevSingle = &snapCopy
			}
		} else {
			names, kernelNames := summaryInterfaces()
			snaps := make(map[string]*monitoriface.Snapshot, len(names))
			newPrev := make(map[string]*monitoriface.Snapshot, len(names))
			for _, name := range names {
				snap := readSnap(kernelNames[name])
				if snap == nil {
					continue
				}
				newPrev[name] = snap
				snaps[name] = snap
			}
			monitoriface.RenderTrafficSummary(&buf, hostname, names, kernelNames, snaps, prevAll, summaryMode, startTime)
			prevAll = newPrev
		}

		if err := sendMonitorInterfaceFrame(stream, &pb.MonitorInterfaceResponse{Frame: buf.String()}); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// proxyMonitorInterface forwards a MonitorInterface stream to the cluster peer.
// The caller (MonitorInterface) already holds this node's subscriber slot; the
// peer charges its own for the rendering half.
func (s *Server) proxyMonitorInterface(req *pb.MonitorInterfaceRequest, stream grpc.ServerStreamingServer[pb.MonitorInterfaceResponse]) error {
	conn, err := s.dialPeer()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Stamp the no-peer hop marker so the peer serves this request LOCALLY and
	// never proxies it back to us — the strict one-hop bound that closes the
	// #5497 A->B->A recursion (mirrors the chassis-forwarding proxy).
	ctx := metadata.AppendToOutgoingContext(stream.Context(), monitorNoPeerMarker, "1")

	client := pb.NewBpfrxServiceClient(conn)
	peerStream, err := client.MonitorInterface(ctx, req)
	if err != nil {
		return status.Errorf(codes.Unavailable, "peer monitor failed: %v", err)
	}

	for {
		resp, err := peerStream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if err := sendMonitorInterfaceFrame(stream, resp); err != nil {
			return err
		}
	}
}

func monitorSummaryModeFromProto(mode pb.MonitorInterfaceSummaryMode) monitoriface.SummaryMode {
	switch mode {
	case pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_PACKETS:
		return monitoriface.SummaryModePackets
	case pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_BYTES:
		return monitoriface.SummaryModeBytes
	case pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_DELTA:
		return monitoriface.SummaryModeDelta
	case pb.MonitorInterfaceSummaryMode_MONITOR_INTERFACE_SUMMARY_MODE_RATE:
		return monitoriface.SummaryModeRate
	default:
		return monitoriface.SummaryModeCombined
	}
}
