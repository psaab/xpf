package grpcapi

import (
	"context"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/bootstrapshow"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/upgrade"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/termsafe"
)

// --- Operational show RPCs ---

// --- GetSystemInfo RPC ---

// --- ShowText RPC ---

// rpcStatus converts a handler's error into one carrying a gRPC status code.
//
// #8629: 65 error returns on this RPC surface were bare errors, which gRPC
// surfaces as codes.Unknown — so a caller could not distinguish a malformed
// request from a server fault. 63 of those 65 are arms of ShowText's single
// topic dispatch, and every one of them either returns a showXxx helper's
// error directly or propagates it unchanged.
//
// CONVERTING THEM INDIVIDUALLY WOULD BE WORSE THAN THIS. Show topics are added
// routinely; a sweep leaves the next one bare and produces a surface where some
// errors carry a meaningful code and most do not, with nothing telling a caller
// which is which. That non-uniformity is the state the issue says is worse than
// today's uniform wrongness. Converting at the BOUNDARY covers every current
// arm and every future one.
//
// An error that ALREADY carries a status passes through untouched, which is not
// a nicety: show helpers return codes.InvalidArgument for a bad zone id and
// codes.ResourceExhausted for a bounded scan, and a sweep that rewrote every
// site would have flattened those into Internal.
//
// Internal, and not NotFound/FailedPrecondition/Unavailable, is deliberate. No
// site here distinguishes "no such object" from "failed to render", and
// inferring a retry contract from an error string would be guessing — a wrong
// Unavailable is a retry storm against a permanent failure, and a wrong
// FailedPrecondition makes a transient look permanent. Where the caller cannot
// be shown to be wrong, Internal is the honest answer.
func rpcStatus(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	return status.Error(codes.Internal, err.Error())
}

// ShowText is the boundary that types every error the topic dispatch produces.
// The body is `showText`; see rpcStatus for why the conversion lives here and
// not at the 63 individual returns.
func (s *Server) ShowText(ctx context.Context, req *pb.ShowTextRequest) (*pb.ShowTextResponse, error) {
	resp, err := s.showText(ctx, req)
	if err == nil && resp != nil && req != nil && req.Topic == "chassis-forwarding" && s.cluster != nil {
		nodeID := int32(s.cluster.NodeID())
		resp.ResponderNodeId = &nodeID
	}
	return resp, rpcStatus(err)
}

func (s *Server) showText(ctx context.Context, req *pb.ShowTextRequest) (*pb.ShowTextResponse, error) {
	cfg := s.store.ActiveConfig()
	var buf strings.Builder

	// Handle parameterized topics (prefix:value format)
	if strings.HasPrefix(req.Topic, "route-table:") {
		return s.showRouteTable(req, cfg, &buf)
	}

	if strings.HasPrefix(req.Topic, "route-protocol:") {
		return s.showRouteProtocol(req, &buf)
	}

	if strings.HasPrefix(req.Topic, "route-prefix:") {
		return s.showRoutePrefix(req, cfg, &buf)
	}

	if req.Topic == "class-of-service" || strings.HasPrefix(req.Topic, "class-of-service:") {
		return s.showClassOfService(req, cfg, &buf)
	}

	// #4228 Gap 7: vSRX CoS show commands over existing data.
	if req.Topic == "interfaces-queue" || strings.HasPrefix(req.Topic, "interfaces-queue:") {
		return s.showInterfacesQueue(req, &buf)
	}
	if req.Topic == "cos-classifier" || strings.HasPrefix(req.Topic, "cos-classifier:") {
		return s.showCoSClassifier(req, cfg, &buf)
	}
	// #6848 (#4228 Gap 7 residual): the rewrite-rule view. Registered here as
	// well as in the local CLI so the REMOTE cli binary — the surface most
	// operators use — gets the command too.
	if req.Topic == "cos-rewrite-rule" || strings.HasPrefix(req.Topic, "cos-rewrite-rule:") {
		return s.showCoSRewriteRule(req, cfg, &buf)
	}
	if req.Topic == "cos-scheduler-map" || strings.HasPrefix(req.Topic, "cos-scheduler-map:") {
		return s.showCoSSchedulerMap(req, cfg, &buf)
	}
	if req.Topic == "cos-forwarding-class" {
		return s.showCoSForwardingClass(cfg, &buf)
	}

	if strings.HasPrefix(req.Topic, "screen-ids-option:") {
		return s.showScreenIDSOption(req, cfg, &buf)
	}

	if strings.HasPrefix(req.Topic, "screen-statistics:") {
		return s.showScreenStatistics(req, cfg, &buf)
	}

	// #8597 K47: the remote `cli`'s `request security policies check`.
	if req.Topic == "policies-check" {
		return s.showPoliciesCheck(cfg, &buf)
	}

	if req.Topic == "screen-statistics-all" {
		return s.showScreenStatisticsAll(cfg, &buf)
	}

	if strings.HasPrefix(req.Topic, "screen-ids-option-detail:") {
		return s.showScreenIDSOptionDetail(req, cfg, &buf)
	}

	// test policy: "test-policy:from=X,to=Y,src=A,dst=B,srcport=Q,port=P,proto=TCP"
	if strings.HasPrefix(req.Topic, "test-policy:") {
		return s.showTestPolicy(req, cfg, &buf)
	}

	// test routing: "test-routing:dest=10.0.0.0/24" or "test-routing:dest=10.0.0.0/24,instance=dmz-vr"
	if strings.HasPrefix(req.Topic, "test-routing:") {
		return s.showTestRouting(req, &buf)
	}

	// test security-zone: "test-zone:interface=trust0"
	if strings.HasPrefix(req.Topic, "test-zone:") {
		return s.showTestZone(req, cfg, &buf)
	}

	if strings.HasPrefix(req.Topic, "firewall-filter:") {
		return s.showFirewallFilter(req, cfg, &buf)
	}

	// #4967: `show firewall [filter <name>] effective [family <f>]` renders the
	// compiled FirewallFilterSnapshot the dataplane actually receives. The
	// remote CLI advertises these leaves (cmdtree) and the local CLI implements
	// them, so the remote dispatcher routes them here to the shared SSOT
	// renderer (dpuserspace.RenderFirewallFilterSnapshot) — the advertised and
	// executable grammars can no longer diverge into the raw-config view.
	if strings.HasPrefix(req.Topic, "firewall-effective-filter:") {
		return s.showEffectiveFirewallFilter(req, cfg, &buf)
	}
	if req.Topic == "firewall-effective" || strings.HasPrefix(req.Topic, "firewall-effective:") {
		return s.showEffectiveFirewallFilters(req, cfg, &buf)
	}

	switch req.Topic {
	case "zones-detail":
		// #1043 Phase 8: case body extracted to server_show_zones_text.go
		s.showZonesDetail(cfg, req.Filter, &buf)

	case "ipsec-statistics":
		// #1043 Phase 12: case body extracted to server_show_security_text.go
		if err := s.showIPsecStatistics(cfg, &buf); err != nil {
			return nil, err
		}

	case "schedulers":
		// #1043 Phase 12: case body extracted to server_show_security_text.go
		s.showSchedulers(cfg, &buf)

	case "snmp":
		// #1043 Phase 4: case body extracted to server_show_dhcp_lldp_snmp.go
		s.showSNMP(cfg, &buf)

	case "snmp-v3":
		// #1043 Phase 4: case body extracted to server_show_dhcp_lldp_snmp.go
		s.showSNMPv3(cfg, &buf)

	case "dhcp-server":
		// #1043 Phase 4: case body extracted to server_show_dhcp_lldp_snmp.go
		s.showDHCPServer(&buf)

	case "dhcp-server-detail":
		// #1043 Phase 4: case body extracted to server_show_dhcp_lldp_snmp.go
		s.showDHCPServerDetail(cfg, &buf)

	case "dhcp-server-dynamic-dns":
		// #1387 inc-2: DHCP dynamic-DNS status + counters.
		s.showDHCPDynamicDNS(cfg, &buf, false)

	case "dhcp-server-dynamic-dns-detail":
		s.showDHCPDynamicDNS(cfg, &buf, true)

	case "services-dynamic-dns":
		// #2691 P2: Surface A (router/interface-address) DDNS status + counters.
		s.showServicesDynamicDNS(cfg, &buf, false)

	case "services-dynamic-dns-detail":
		s.showServicesDynamicDNS(cfg, &buf, true)

	case "dhcp-relay":
		// #1043 Phase 4: case body extracted to server_show_dhcp_lldp_snmp.go
		s.showDHCPRelay(cfg, &buf)

	case "lldp":
		// #1043 Phase 4: case body extracted to server_show_dhcp_lldp_snmp.go
		s.showLLDP(cfg, &buf)

	case "lldp-neighbors":
		// #1043 Phase 4: case body extracted to server_show_dhcp_lldp_snmp.go
		s.showLLDPNeighbors(&buf)

	case "firewall":
		// #1043 Phase 1: case body extracted to server_show_firewall.go
		s.showFirewall(cfg, &buf)

	case "alg":
		s.showAlg(cfg, &buf)

	case "dynamic-address":
		s.showDynamicAddress(cfg, &buf)

	case "address-book":
		s.showAddressBook(cfg, &buf)

	case "applications":
		// #1043 Phase 12: case body extracted to server_show_security_text.go
		s.showApplications(cfg, &buf)

	case "flow-monitoring":
		// #1043 Phase 5: case body extracted to server_show_flow.go
		s.showFlowMonitoring(cfg, &buf)

	case "flow-monitoring-statistics":
		// #2464: per-collector NetFlow v9 / IPFIX write-health.
		s.showFlowMonitoringStatistics(&buf)

	case "flow-timeouts":
		// #1043 Phase 5: case body extracted to server_show_flow.go
		s.showFlowTimeouts(cfg, &buf)

	case "flow-statistics":
		// #1043 Phase 5: case body extracted to server_show_flow.go
		s.showFlowStatistics(&buf)

	case "sessions-top:bytes", "sessions-top:packets":
		// #1043 Phase 5: case body extracted to server_show_flow.go
		// #5319: bounded top-K selection; surface iterator errors.
		if err := s.showSessionsTop(cfg, req.Topic, &buf); err != nil {
			return nil, err
		}

	case "flow-traceoptions":
		// #1043 Phase 5: case body extracted to server_show_flow.go
		s.showFlowTraceoptions(cfg, &buf)

	case "nat-static":
		// #1043 Phase 3: case body extracted to server_show_nat.go
		s.showNATStatic(cfg, &buf)

	case "nat-nptv6":
		// #1043 Phase 3: case body extracted to server_show_nat.go
		s.showNATNPTv6(cfg, &buf)

	case "persistent-nat":
		// #1043 Phase 3: case body extracted to server_show_nat.go
		// #6553: admission-gated, error propagated. NOT a conntrack walk —
		// see showPersistentNAT (#7315).
		if err := s.showPersistentNAT(ctx, &buf); err != nil {
			return nil, err
		}

	case "nat-source-rule-detail":
		// #1043 Phase 3: case body extracted to server_show_nat.go
		// #6553: full-table conntrack walk — admission-gated, error
		// propagated. #7315: the walk runs under the admission-lease ctx.
		if err := s.showNATSourceRuleDetail(ctx, cfg, &buf); err != nil {
			return nil, err
		}

	case "nat-dest-rule-detail":
		// #1043 Phase 3: case body extracted to server_show_nat.go
		// #6553: full-table conntrack walk — admission-gated, error
		// propagated. #7315: the walk runs under the admission-lease ctx.
		if err := s.showNATDestRuleDetail(ctx, cfg, &buf); err != nil {
			return nil, err
		}

	case "persistent-nat-detail":
		// #1043 Phase 3: case body extracted to server_show_nat.go
		// #6553: full-table conntrack walk — admission-gated, error
		// propagated. #7315: the walk runs under the admission-lease ctx.
		if err := s.showPersistentNATDetail(ctx, &buf); err != nil {
			return nil, err
		}

	case "tunnels":
		// #1043 Phase 12: case body extracted to server_show_security_text.go
		s.showTunnels(&buf)

	case "rpm":
		// #1043 Phase 12: case body extracted to server_show_security_text.go
		s.showRPM(&buf)

	case "services-ip-monitoring-status":
		// #1827: services ip-monitoring policy status (distinct from
		// chassis-cluster-ip-monitoring-status, the RG-weight feature).
		s.showServicesIPMonitoringStatus(&buf)

	case "application-identification-status":
		// #653: surface what xpf AppID actually does today vs the
		// vSRX `services application-identification` feature.
		// Topic name carries `-status` so the showText topic stays
		// consistent with the cmdtree leaf
		// `application-identification status` (per Copilot review).
		s.showApplicationIdentificationStatus(cfg, &buf)

	case "version":
		// #1043 Phase 7: case body extracted to server_show_system.go
		s.showVersion(&buf)

	case "security-log":
		// #1043 Phase 12: case body extracted to server_show_security_text.go
		s.showSecurityLog(req.Filter, &buf)

	case "chassis":
		// #1043 Phase 2: case body extracted to server_show_chassis.go
		s.showChassis(&buf)

	case "chassis-device-map":
		// #1956: bare-metal device-map resolved bindings.
		s.showChassisDeviceMap(cfg, &buf)

	case "chassis-device-map-candidates":
		// #1956: copy-paste NIC inventory for authoring a device-map.
		s.showChassisDeviceMapCandidates(&buf)

	case "storage":
		// #1043 Phase 7: case body extracted to server_show_system.go
		s.showStorage(&buf)

	case "commit-history":
		// #1043 Phase 7: case body extracted to server_show_system.go
		if err := s.showCommitHistory(&buf); err != nil {
			return nil, err
		}

	case "alarms":
		// #1043 Phase 7: case body extracted to server_show_system.go
		s.showAlarms(&buf)

	case "security-alarms", "security-alarms-detail":
		// #1043 Phase 12: case body extracted to server_show_security_text.go
		s.showSecurityAlarms(cfg, req.Topic, &buf)

	case "route-all":
		// #1043 Phase 9: case body extracted to server_show_routes_text.go
		if err := s.showRouteAll(cfg, &buf); err != nil {
			return nil, err
		}

	case "route-summary":
		// #1043 Phase 9: case body extracted to server_show_routes_text.go
		if err := s.showRouteSummary(cfg, &buf); err != nil {
			return nil, err
		}

	case "route-terse":
		// #1043 Phase 9: case body extracted to server_show_routes_text.go
		if err := s.showRouteTerse(&buf); err != nil {
			return nil, err
		}

	case "route-detail":
		// #1043 Phase 9: case body extracted to server_show_routes_text.go
		if err := s.showRouteDetail(ctx, &buf); err != nil {
			return nil, err
		}

	case "interfaces-extensive":
		// #1043 Phase 6: case body extracted to server_show_interfaces_text.go
		if err := s.showInterfacesExtensive(cfg, req.Filter, &buf); err != nil {
			return nil, err
		}

	case "interfaces-detail":
		// #1043 Phase 6: case body extracted to server_show_interfaces_text.go
		if err := s.showInterfacesDetail(cfg, req.Filter, &buf); err != nil {
			return nil, err
		}

	case "interfaces-statistics":
		// #1043 Phase 6: case body extracted to server_show_interfaces_text.go
		if err := s.showInterfacesStatistics(req.Filter, &buf); err != nil {
			return nil, err
		}

	case "policies-hit-count":
		// #1043 Phase 10: case body extracted to server_show_policies_text.go
		s.showPoliciesHitCount(req.Filter, &buf)

	case "policies-detail":
		// #1043 Phase 10: case body extracted to server_show_policies_text.go
		s.showPoliciesDetail(req.Filter, &buf)

	case "chassis-hardware":
		// Alias: same output as "chassis" (CPU, memory, NICs).
		// Forward the caller's context so metadata like #879's
		// xpf-no-peer guard propagates correctly through the alias.
		return s.ShowText(ctx, &pb.ShowTextRequest{Topic: "chassis"})

	case "chassis-forwarding":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisForwarding(ctx, &buf)

	case "chassis-cluster", "chassis-cluster-status":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterStatus(&buf)

	case "chassis-cluster-interfaces":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterInterfaces(&buf)

	case "chassis-cluster-information":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterInformation(&buf)

	case "chassis-cluster-statistics":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterStatistics(&buf)

	case "chassis-cluster-control-plane-statistics":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterControlPlaneStatistics(&buf)

	case "chassis-cluster-data-plane-statistics":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterDataPlaneStatistics(&buf)

	case "chassis-cluster-data-plane-interfaces":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterDataPlaneInterfaces(&buf)

	case "chassis-cluster-data-plane-fairness":
		s.showChassisClusterDataPlaneFairness(&buf)

	case "chassis-cluster-data-plane-flows":
		s.showChassisClusterDataPlaneFlows(req.Filter, &buf)

	case "chassis-cluster-ip-monitoring-status":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterIPMonitoringStatus(&buf)

	case "chassis-cluster-fabric-statistics":
		// #1043 Phase 11: case body extracted to server_show_cluster_text.go
		s.showChassisClusterFabricStatistics(&buf)

	case "chassis-environment":
		// #1043 Phase 7: case body extracted to server_show_system.go
		s.showChassisEnvironment(&buf)

	case "system-services":
		// #1043 Phase 7: case body extracted to server_show_system.go
		s.showSystemServices(&buf)

	case "ntp":
		// #1043 Phase 7: case body extracted to server_show_system.go
		s.showNTP(ctx, &buf)

	case "system-syslog":
		// #1043 Phase 7: case body extracted to server_show_system.go
		s.showSystemSyslog(&buf)

	case "policy-options":
		// #1043 Phase 10: case body extracted to server_show_policies_text.go
		s.showPolicyOptions(cfg, &buf)

	case "backup-router":
		s.showBackupRouter(cfg, &buf)

	case "nat64":
		// #1043 Phase 3: case body extracted to server_show_nat.go
		s.showNAT64(cfg, &buf)

	case "ike":
		s.showIKE(cfg, &buf)

	case "event-options":
		s.showEventOptions(cfg, &buf)

	case "routing-options":
		s.showRoutingOptions(cfg, &buf)

	case "forwarding-options":
		s.showForwardingOptions(cfg, &buf)

	case "forwarding-options-port-mirroring":
		s.showForwardingOptionsPortMirroring(cfg, &buf)

	case "vlans":
		s.showVLANs(cfg, &buf)

	case "routing-instances":
		s.showRoutingInstances(cfg, &buf)

	case "routing-instances-detail":
		s.showRoutingInstancesDetail(cfg, &buf)

	case "route-instance":
		s.showRouteInstance(req.Filter, cfg, &buf)

	case "login":
		s.showLogin(cfg, &buf)

	case "screen":
		s.showScreen(cfg, &buf)

	case "log":
		out, err := combinedOutputTimeout(ctx, "journalctl", "-u", "xpfd", "-n", "50", "--no-pager")
		if err != nil {
			return nil, diagExecError("journalctl", err)
		}
		// #6584: the remote `cli` prints resp.Output VERBATIM, so this is the
		// same terminal reached over a different transport — and it is the
		// more common operator posture.
		buf.WriteString(termsafe.SanitizeBlockForDisplay(string(out)))

	case "internet-options":
		s.showInternetOptions(cfg, &buf)

	case "root-authentication":
		s.showRootAuthentication(cfg, &buf)

	case "buffers":
		if err := s.showBuffers(cfg, &buf); err != nil {
			return nil, err
		}

	case "buffers-detail":
		if err := s.showBuffersDetail(cfg, &buf); err != nil {
			return nil, err
		}

	case "wireguard":
		// #1865: WG tunnel telemetry (summary).
		s.showWireguard(&buf, false)

	case "wireguard-detail":
		s.showWireguard(&buf, true)

	case "wireguard-public-key":
		// #1434 Increment 1: local public key per tunnel.
		s.showWireguardPublicKey(&buf)

	case "bfd-peers":
		if err := s.showBFDPeers(ctx, &buf); err != nil {
			return nil, err
		}

	case "route-map":
		if err := s.showRouteMap(ctx, cfg, &buf); err != nil {
			return nil, err
		}

	case "core-dumps":
		s.showCoreDumps(cfg, &buf)

	case "kernel-upgrade":
		// #6495: the LANE-1 kernel channel, in-band. Rendered through
		// pkg/upgrade so this and the in-process CLI cannot disagree about a
		// node mid-roll.
		st := upgrade.ChannelStatus{}
		if s.kernelUpgradeStatusFn != nil {
			st = s.kernelUpgradeStatusFn()
		}
		upgrade.RenderChannelStatus(&buf, st)
	case "bootstrap-import":
		// #6496: the day-0 config-import verdict, in-band. Renders through the
		// shared bootstrapshow package so this and the in-process CLI cannot
		// disagree about the same recorded fact.
		snap := bootstrapshow.Snapshot{}
		if s.bootstrapImportFn != nil {
			snap = s.bootstrapImportFn()
		}
		bootstrapshow.Render(&buf, snap)

	case "task":
		s.showTask(cfg, &buf)

	case "ipv6-router-advertisement":
		s.showIPv6RouterAdvertisement(cfg, &buf)

	default:
		// Handle "log:<filename>[:<count>]" for syslog file destinations
		if req.Topic == "monitor-security-flow" {
			buf.WriteString("  Monitor security flow session status: Inactive\n")
			buf.WriteString("  Monitor security flow trace file: (not configured)\n")
			buf.WriteString("  Monitor security flow filters: 0\n")
			buf.WriteString("\n  Note: Flow monitor state is per-CLI-session.\n")
			buf.WriteString("  Use the local CLI on the firewall for flow tracing.\n")
		} else if strings.HasPrefix(req.Topic, "log:") {
			parts := strings.SplitN(req.Topic, ":", 3)
			n := 50
			if len(parts) >= 3 {
				if v, err := strconv.Atoi(parts[2]); err == nil {
					n = v
				}
			}
			// The line count is request-controlled; clamp it because
			// the 15s exec bound does not limit how many bytes a fast
			// tail of a huge N can return (see clampTailLines).
			n = clampTailLines(n)
			// Allowlist the log name against the configured `system syslog
			// file` set (#4860): the remote CLI reaches `show log <name>`
			// through this path, so tailing an arbitrary /var/log child would
			// leak root-readable host logs (auth.log, audit.log, ...) to a
			// view-only account. SyslogLogFilePath refuses a non-bare or
			// non-allowlisted name.
			logPath, err := config.SyslogLogFilePath(cfg, parts[1])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "%v", err)
			}
			out, err := combinedOutputTimeout(ctx, "tail", "-n", strconv.Itoa(n), logPath)
			if err != nil {
				return nil, diagExecError("read "+logPath, err)
			}
			buf.WriteString(termsafe.SanitizeBlockForDisplay(string(out)))
		} else {
			return nil, status.Errorf(codes.InvalidArgument, "unknown topic: %s", req.Topic)
		}
	}

	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

// chassisForwardingSeparator is the dashed separator that frames each
// per-node block in cluster-mode `show chassis forwarding` output,
// matching the shape used by `show chassis cluster`.
const chassisForwardingSeparator = "--------------------------------------------------------------------------"

// buildLocalForwarding renders a single-node FWDD-status block for
// the local node. Used both for standalone-mode output and as the
// local half of cluster-mode composition.
// dialAndShowForwarding queries the cluster peer for its single-node
// FWDD-status block. Injects the `xpf-no-peer:1` outgoing metadata
// so the peer renders local-only and never recurses back. Returns
// the peer's formatted block or an error if the peer is unreachable.
//
// Timeout note: dialPeer derives each 2s × N-fabric probe deadline from
// `ctx`, so caller cancellation/deadline now aborts the full path. The 5s
// WithTimeout below only covers the post-dial ShowText RPC. When the caller
// has no deadline, total worst case remains up to ~9s. On the peer side,
// buildLocalForwarding may block on userspace.Manager.mu during a failover —
// under that case the 5s outer can fire spuriously and the peer block renders
// "(peer unreachable)" even on a healthy-but-loaded peer.
