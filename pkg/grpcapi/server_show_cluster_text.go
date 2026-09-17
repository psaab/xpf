// Phase 11 of #1043: extract the chassis-forwarding and
// chassis-cluster-* ShowText case bodies into dedicated methods. Same
// methodology as Phases 1-10: semantic relocation, no behavior change.
// Each case body is moved verbatim apart from `&buf` references
// becoming `buf` (passed-in `*strings.Builder`) and `break`-on-guard
// patterns flattened into early-return form.
//
// `showChassisForwarding` takes `ctx` because the original case used
// `metadata.FromIncomingContext(ctx)` and called the peer-dial helper
// `s.dialAndShowForwarding(ctx)` for cluster mode. Error/output
// semantics are preserved.
//
// `chassis-hardware` is left in the dispatcher: it is a trivial
// `return s.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis"})`
// alias and extracting it would not improve readability.

package grpcapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
)

// showChassisForwarding renders the Junos-style forwarding-daemon
// health view (#877). In cluster mode it composes node0:/node1:
// blocks; the `xpf-no-peer:1` gRPC metadata bypasses the peer dial
// to prevent infinite recursion (#879).
func (s *Server) showChassisForwarding(ctx context.Context, buf *strings.Builder) {
	// #5883: the no-peer hop marker is read from the unforgeable in-process
	// capability, not from caller-supplied metadata.
	isPeerCall := peerMarkersFromContext(ctx).noPeer

	localBuf := s.buildLocalForwarding()

	if s.cluster == nil || isPeerCall {
		buf.WriteString(localBuf)
		return
	}

	// Cluster mode, original (non-peer) call — compose two blocks.
	localNodeID := s.cluster.NodeID()
	fmt.Fprintf(buf, "node%d:\n%s\n%s",
		localNodeID, chassisForwardingSeparator, localBuf)

	peerBuf, peerErr := s.dialAndShowForwarding(ctx)
	// Codex round-1 fix: guard against PeerNodeID() returning 0
	// before the first heartbeat — would produce two `node0:`
	// headers. If peer was never seen, label it as unknown.
	peerLabel := "node?"
	if s.cluster.PeerAlive() {
		peerLabel = fmt.Sprintf("node%d", s.cluster.PeerNodeID())
	}
	fmt.Fprintf(buf, "\n%s:\n%s\n", peerLabel, chassisForwardingSeparator)
	if peerErr != nil {
		fmt.Fprintf(buf, "FWDD status:\n  (peer unreachable: %s)\n", peerErr)
	} else {
		buf.WriteString(peerBuf)
	}
}

// showChassisClusterStatus renders the cluster status (also serves the
// `chassis-cluster-status` alias).
func (s *Server) showChassisClusterStatus(buf *strings.Builder) {
	if s.cluster != nil {
		buf.WriteString(s.cluster.FormatStatus())
		s.appendFabricClockSkew(buf)
	} else {
		fmt.Fprintln(buf, "Cluster not configured")
	}
	s.appendClockSkewAlarm(buf)
}

// appendFabricClockSkew surfaces the #6708 measured peer wall-clock skew.
//
// It is written HERE rather than inside cluster.FormatStatus because the
// measurement belongs to the fabric gRPC listener, which lives in this package;
// pushing it down into pkg/cluster would invert the dependency for one line of
// output. Nothing is printed when no skew has been measured, so a healthy
// cluster's status is byte-identical to before.
//
// Why it matters here specifically: a skew past the fabric auth window kills
// every cross-node RPC while VRRP and failover keep working, so `show chassis
// cluster status` reports a perfectly healthy cluster while every cross-node
// query returns LOCAL-ONLY. This is the line that connects the two.
func (s *Server) appendFabricClockSkew(buf *strings.Builder) {
	skew, ok := s.FabricPeerClockSkew()
	if !ok {
		return
	}
	dir := "ahead of"
	if skew < 0 {
		dir = "behind"
		skew = -skew
	}
	fmt.Fprintf(buf, "\nWarning: peer wall clock is %ds %s this node (fabric auth window %ds).\n"+
		"  Cross-node fabric RPCs (session queries, aggregation, clear propagation,\n"+
		"  cross-node failover) are failing authentication. Forwarding, VRRP and\n"+
		"  failover are unaffected. Synchronise NTP on both nodes.\n",
		skew, dir, fabricAuthWindowSeconds)
}

// appendClockSkewAlarm surfaces the daemon-resident pre-break clock alarm
// beside the post-break measured-skew diagnosis above (#10025). The callback
// is nil in standalone/unit-test servers, and an empty snapshot is silent.
func (s *Server) appendClockSkewAlarm(buf *strings.Builder) {
	if s.clockSkewAlarmsFn == nil {
		return
	}
	for _, alarm := range s.clockSkewAlarmsFn() {
		fmt.Fprintf(buf, "\nWarning: %s\n", alarm.Summary())
	}
}

// showChassisClusterInterfaces renders cluster RETH interfaces.
func (s *Server) showChassisClusterInterfaces(buf *strings.Builder) {
	if s.cluster == nil {
		fmt.Fprintln(buf, "Cluster not configured")
		return
	}
	input := s.buildInterfacesInput()
	buf.WriteString(s.cluster.FormatInterfaces(input))
}

// showChassisClusterInformation renders cluster identity (cluster-id,
// node-id, RETH count, heartbeat tunables, redundancy-group count).
// Falls back to config-derived values when no live cluster manager.
func (s *Server) showChassisClusterInformation(buf *strings.Builder) {
	if s.cluster != nil {
		buf.WriteString(s.cluster.FormatInformation())
		return
	}
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		fmt.Fprintln(buf, "Cluster not configured")
		return
	}
	cc := cfg.Chassis.Cluster
	hbInterval := cc.HeartbeatInterval
	if hbInterval == 0 {
		hbInterval = 1000
	}
	hbThreshold := cc.HeartbeatThreshold
	if hbThreshold == 0 {
		hbThreshold = 3
	}
	fmt.Fprintf(buf, "Cluster ID: %d\n", cc.ClusterID)
	fmt.Fprintf(buf, "Node ID: %d\n", cc.NodeID)
	fmt.Fprintf(buf, "RETH count: %d\n", cc.RethCount)
	fmt.Fprintf(buf, "Heartbeat interval: %d ms\n", hbInterval)
	fmt.Fprintf(buf, "Heartbeat threshold: %d\n", hbThreshold)
	fmt.Fprintf(buf, "Redundancy groups: %d\n", len(cc.RedundancyGroups))
}

// showChassisClusterStatistics renders aggregate cluster statistics.
func (s *Server) showChassisClusterStatistics(buf *strings.Builder) {
	if s.cluster == nil {
		fmt.Fprintln(buf, "Cluster not configured")
		return
	}
	buf.WriteString(s.cluster.FormatStatistics())
}

// showChassisClusterControlPlaneStatistics renders control-plane
// (heartbeat / sync) cluster statistics.
func (s *Server) showChassisClusterControlPlaneStatistics(buf *strings.Builder) {
	if s.cluster == nil {
		fmt.Fprintln(buf, "Cluster not configured")
		return
	}
	buf.WriteString(s.cluster.FormatControlPlaneStatistics())
}

// showChassisClusterDataPlaneStatistics renders data-plane cluster
// statistics, plus the userspace data-plane status summary if
// available.
func (s *Server) showChassisClusterDataPlaneStatistics(buf *strings.Builder) {
	if s.cluster == nil {
		fmt.Fprintln(buf, "Cluster not configured")
		return
	}
	buf.WriteString(s.cluster.FormatDataPlaneStatistics())
	if status, err := s.userspaceDataplaneStatus(); err == nil {
		buf.WriteString("\n")
		buf.WriteString(dpformat.FormatStatusSummary(status))
	}
}

// showChassisClusterDataPlaneInterfaces renders cluster data-plane
// interface bindings, plus the userspace data-plane bindings list if
// available.
func (s *Server) showChassisClusterDataPlaneInterfaces(buf *strings.Builder) {
	if s.cluster == nil {
		fmt.Fprintln(buf, "Cluster not configured")
		return
	}
	buf.WriteString(s.cluster.FormatDataPlaneInterfaces())
	if status, err := s.userspaceDataplaneStatus(); err == nil {
		buf.WriteString("\n")
		buf.WriteString(dpformat.FormatBindings(status))
	}
}

// showChassisClusterDataPlaneFairness renders the userspace per-CoS
// fairness RSS structure snapshot.
func (s *Server) showChassisClusterDataPlaneFairness(buf *strings.Builder) {
	if s.cluster == nil {
		fmt.Fprintln(buf, "Cluster not configured")
		return
	}
	status, err := s.userspaceDataplaneStatus()
	if err != nil {
		fmt.Fprintf(buf, "Userspace status unavailable: %v\n", err)
		return
	}
	buf.WriteString(dpformat.FormatFairnessRSS(status, dpuserspace.FairnessRSSExpectationsFromConfig(s.store.ActiveConfig())))
}

// showChassisClusterDataPlaneFlows renders the bounded active
// flow-to-worker diagnostic map.
func (s *Server) showChassisClusterDataPlaneFlows(filter string, buf *strings.Builder) {
	if s.cluster == nil {
		fmt.Fprintln(buf, "Cluster not configured")
		return
	}
	limit, err := dpformat.ParseFlowWorkerMapLimitSpec(filter)
	if err != nil {
		fmt.Fprintf(buf, "syntax error: %v\n", err)
		return
	}
	status, err := s.userspaceDataplaneStatus()
	if err != nil {
		fmt.Fprintf(buf, "Userspace status unavailable: %v\n", err)
		return
	}
	buf.WriteString(dpformat.FormatFlowWorkerMap(status, limit))
}

// showChassisClusterIPMonitoringStatus renders the IP-monitoring
// (RPM-driven RG transition) status table.
func (s *Server) showChassisClusterIPMonitoringStatus(buf *strings.Builder) {
	if s.cluster == nil {
		fmt.Fprintln(buf, "Cluster not configured")
		return
	}
	buf.WriteString(s.cluster.FormatIPMonitoringStatus())
}

// showChassisClusterFabricStatistics renders BPF-level fabric redirect
// counters (cross-chassis forwarding telemetry).
func (s *Server) showChassisClusterFabricStatistics(buf *strings.Builder) {
	if s.dp == nil || !s.dp.IsLoaded() {
		fmt.Fprintln(buf, "Dataplane not loaded")
		return
	}
	// #3345: surface a counter-read failure rather than emitting clean zeros
	// that hide a degraded counter bridge.
	var readErr error
	readCtr := func(idx uint32) uint64 {
		v, err := s.dp.ReadGlobalCounter(idx)
		if err != nil && readErr == nil {
			readErr = err
		}
		return v
	}
	total := readCtr(dataplane.GlobalCtrFabricRedirect)
	fab0 := readCtr(dataplane.GlobalCtrFabricRedirectFab0)
	fab1 := readCtr(dataplane.GlobalCtrFabricRedirectFab1)
	zone := readCtr(dataplane.GlobalCtrFabricRedirectZone)
	drops := readCtr(dataplane.GlobalCtrFabricFwdDrop)
	fmt.Fprintln(buf, "Fabric redirect statistics:")
	if readErr != nil {
		fmt.Fprintf(buf, "warning: fabric counter read failed (statistics may be incomplete): %v\n", readErr)
	}
	fmt.Fprintf(buf, "    Total redirects:          %d\n", total)
	fmt.Fprintf(buf, "    fab0 redirects:           %d\n", fab0)
	fmt.Fprintf(buf, "    fab1 redirects:           %d\n", fab1)
	fmt.Fprintf(buf, "    Zone-encoded redirects:   %d\n", zone)
	fmt.Fprintf(buf, "    Redirect drops:           %d\n", drops)
	fmt.Fprintln(buf)
	fmt.Fprintln(buf, "Note: XDP-redirected packets bypass AF_PACKET (tcpdump).")
	fmt.Fprintln(buf, "Use these counters or 'monitor interface <fab>' for fabric telemetry.")
}
