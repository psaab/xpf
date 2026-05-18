package grpcapi

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/monitoriface"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// --- Diagnostic RPCs ---

func (s *Server) Ping(req *pb.PingRequest, stream grpc.ServerStreamingServer[pb.PingResponse]) error {
	if req.Target == "" {
		return status.Error(codes.InvalidArgument, "target required")
	}
	count := int(req.Count)
	if count <= 0 {
		count = 5
	}
	if count > 100 {
		count = 100
	}
	args := []string{"-c", fmt.Sprintf("%d", count)}
	if req.Source != "" {
		args = append(args, "-I", req.Source)
	}
	if req.Size > 0 {
		args = append(args, "-s", fmt.Sprintf("%d", req.Size))
	}
	args = append(args, req.Target)

	var cmd []string
	if req.RoutingInstance != "" {
		vrfDev := req.RoutingInstance
		if !strings.HasPrefix(vrfDev, "vrf-") {
			vrfDev = "vrf-" + vrfDev
		}
		cmd = append(cmd, "ip", "vrf", "exec", vrfDev)
	}
	cmd = append(cmd, "ping")
	cmd = append(cmd, args...)

	return streamDiagCmd(stream.Context(), cmd, func(line string) error {
		return stream.Send(&pb.PingResponse{Output: line})
	})
}

func (s *Server) Traceroute(req *pb.TracerouteRequest, stream grpc.ServerStreamingServer[pb.TracerouteResponse]) error {
	if req.Target == "" {
		return status.Error(codes.InvalidArgument, "target required")
	}
	args := []string{}
	if req.Source != "" {
		args = append(args, "-s", req.Source)
	}
	args = append(args, req.Target)

	var cmd []string
	if req.RoutingInstance != "" {
		vrfDev := req.RoutingInstance
		if !strings.HasPrefix(vrfDev, "vrf-") {
			vrfDev = "vrf-" + vrfDev
		}
		cmd = append(cmd, "ip", "vrf", "exec", vrfDev)
	}
	cmd = append(cmd, "traceroute")
	cmd = append(cmd, args...)

	return streamDiagCmd(stream.Context(), cmd, func(line string) error {
		return stream.Send(&pb.TracerouteResponse{Output: line})
	})
}

// streamDiagCmd runs a command and streams each line of combined output via sendFn.
func streamDiagCmd(ctx context.Context, cmd []string, sendFn func(string) error) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)

	// Merge stdout and stderr into a single pipe.
	pr, pw := io.Pipe()
	c.Stdout = pw
	c.Stderr = pw

	if err := c.Start(); err != nil {
		return status.Errorf(codes.Internal, "exec: %v", err)
	}

	// Scan lines and stream each one.
	scanner := bufio.NewScanner(pr)
	scanDone := make(chan error, 1)
	go func() {
		for scanner.Scan() {
			if err := sendFn(scanner.Text()); err != nil {
				scanDone <- err
				return
			}
		}
		scanDone <- scanner.Err()
	}()

	// Wait for the command to finish, then close the write end so scanner terminates.
	cmdErr := c.Wait()
	pw.Close()
	scanErr := <-scanDone

	if scanErr != nil {
		return scanErr
	}
	if cmdErr != nil {
		// Send the exit error as a final line rather than failing the RPC,
		// so the client still sees partial output (e.g. "ping: unknown host").
		_ = sendFn(cmdErr.Error())
	}
	return nil
}

// MonitorPacketDrop streams packet drop events matching the request filters.
func (s *Server) MonitorPacketDrop(req *pb.MonitorPacketDropRequest, stream grpc.ServerStreamingServer[pb.MonitorPacketDropResponse]) error {
	if s.eventBuf == nil {
		return status.Error(codes.Unavailable, "event buffer not available")
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
	sub := s.eventBuf.Subscribe(256)
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
			if req.Protocol != "" && !strings.EqualFold(rec.Protocol, req.Protocol) {
				continue
			}
			if req.FromZone != "" && rec.InZoneName != req.FromZone {
				continue
			}
			if req.Interface != "" && rec.IngressIface != req.Interface {
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
	resolveToKernel := func(cfgName string) string {
		resolved := cfg.ResolveReth(cfgName)
		return config.LinuxIfName(resolved)
	}

	// isRethName returns true if the name is a RETH interface (reth0, reth1, etc).
	isRethName := func(name string) bool {
		return strings.HasPrefix(name, "reth")
	}

	// rethRG returns the redundancy group for a RETH interface, or -1.
	rethRG := func(name string) int {
		parts := strings.SplitN(name, ".", 2)
		if ifc, ok := cfg.Interfaces.Interfaces[parts[0]]; ok && ifc.RedundancyGroup > 0 {
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
	if isSingle {
		singleDisplayName = req.InterfaceName
		singleKernelName = monitoriface.ResolvePhysicalParent(resolveToKernel(req.InterfaceName))

		// Check if interface should be proxied to the cluster peer.
		needProxy := false
		if _, err := net.InterfaceByName(singleKernelName); err != nil {
			// Interface doesn't exist locally. Check if it's a peer's physical member.
			if isPeerInterface(req.InterfaceName) {
				needProxy = true
			} else {
				return status.Errorf(codes.NotFound, "interface %s not found", req.InterfaceName)
			}
		} else if isRethName(req.InterfaceName) {
			// RETH exists locally but may be MASTER on the peer node.
			if rg := rethRG(req.InterfaceName); rg > 0 && s.cluster != nil && !s.cluster.IsLocalPrimary(rg) {
				needProxy = true
			}
		}

		if needProxy {
			return s.proxyMonitorInterface(req, stream)
		}
	}

	summaryInterfaces := func() ([]string, map[string]string) {
		if names, kernelNames := monitoriface.TrafficSummaryInterfaces(cfg); len(names) > 0 {
			return names, kernelNames
		}

		c := s.store.ActiveConfig()
		if c == nil || c.Interfaces.Interfaces == nil {
			return nil, nil
		}
		names := make([]string, 0, len(c.Interfaces.Interfaces))
		kernelNames := make(map[string]string, len(c.Interfaces.Interfaces))
		for name := range c.Interfaces.Interfaces {
			names = append(names, name)
			kernelNames[name] = monitoriface.ResolvePhysicalParent(resolveToKernel(name))
		}
		sort.Strings(names)
		return names, kernelNames
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

	readSnap := func(name string) *monitoriface.Snapshot {
		snap, err := monitoriface.ReadSnapshot(s.dp, s.userspaceDataplaneStatus, name)
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

		if err := stream.Send(&pb.MonitorInterfaceResponse{Frame: buf.String()}); err != nil {
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
func (s *Server) proxyMonitorInterface(req *pb.MonitorInterfaceRequest, stream grpc.ServerStreamingServer[pb.MonitorInterfaceResponse]) error {
	conn, err := s.dialPeer()
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx := stream.Context()

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
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

// dialPeer establishes a gRPC connection to the cluster peer via the fabric link.
// Tries fab0 first, then fab1 if dual-fabric is configured and fab0 fails.
// Returns the connection or an error if not in cluster mode / all addresses fail.
func (s *Server) dialPeer() (*grpc.ClientConn, error) {
	if s.fabricPeerAddrFn == nil {
		return nil, status.Error(codes.Unavailable, "not in cluster mode")
	}
	peerIPs := s.fabricPeerAddrFn()
	if len(peerIPs) == 0 {
		return nil, status.Error(codes.Unavailable, "cluster peer address not available")
	}

	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if s.fabricVRFDevice != "" {
		dialOpts = append(dialOpts, grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Control: func(network, address string, c syscall.RawConn) error {
					var err error
					c.Control(func(fd uintptr) {
						err = unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, s.fabricVRFDevice)
					})
					return err
				},
			}
			return dialer.DialContext(ctx, "tcp", addr)
		}))
	}

	// Try each fabric address; return first successful connection.
	var lastErr error
	for _, ip := range peerIPs {
		peerAddr := fmt.Sprintf("%s:50051", ip)
		conn, err := grpc.NewClient(peerAddr, dialOpts...)
		if err != nil {
			lastErr = err
			continue
		}
		// Verify the connection is usable with a short deadline.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		client := pb.NewBpfrxServiceClient(conn)
		_, err = client.GetStatus(ctx, &pb.GetStatusRequest{})
		cancel()
		if err != nil {
			conn.Close()
			lastErr = err
			slog.Debug("peer dial failed, trying next fabric address", "addr", peerAddr, "err", err)
			continue
		}
		return conn, nil
	}
	return nil, status.Errorf(codes.Unavailable, "cannot connect to peer on any fabric address: %v", lastErr)
}

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

func (s *Server) SystemAction(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
	switch req.Action {
	case "reboot":
		slog.Warn("system reboot requested via gRPC")
		go func() {
			time.Sleep(1 * time.Second)
			exec.Command("systemctl", "reboot").Run()
		}()
		return &pb.SystemActionResponse{Message: "System going down for reboot NOW!"}, nil

	case "halt":
		slog.Warn("system halt requested via gRPC")
		go func() {
			time.Sleep(1 * time.Second)
			exec.Command("systemctl", "halt").Run()
		}()
		return &pb.SystemActionResponse{Message: "System halting NOW!"}, nil

	case "power-off":
		slog.Warn("system power-off requested via gRPC")
		go func() {
			time.Sleep(1 * time.Second)
			exec.Command("systemctl", "poweroff").Run()
		}()
		return &pb.SystemActionResponse{Message: "System powering off NOW!"}, nil

	case "zeroize":
		slog.Warn("system zeroize requested via gRPC")
		// Remove configs
		configDir := "/etc/xpf"
		files, _ := os.ReadDir(configDir)
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".conf") || strings.HasPrefix(f.Name(), "rollback") {
				os.Remove(configDir + "/" + f.Name())
			}
		}
		// Remove BPF pins
		os.RemoveAll("/sys/fs/bpf/xpf")
		// Remove managed networkd files
		ndFiles, _ := os.ReadDir("/etc/systemd/network")
		for _, f := range ndFiles {
			if strings.HasPrefix(f.Name(), "10-xpf-") {
				os.Remove("/etc/systemd/network/" + f.Name())
			}
		}
		return &pb.SystemActionResponse{Message: "System zeroized. Configuration erased. Reboot to complete factory reset."}, nil

	case "clear-config-lock":
		holder, locked := s.store.ConfigHolder()
		if !locked {
			return &pb.SystemActionResponse{Message: "No configuration lock held"}, nil
		}
		s.store.ForceExitConfigure()
		return &pb.SystemActionResponse{Message: fmt.Sprintf("Configuration lock cleared (was held by %s)", holder)}, nil

	case "clear-arp":
		out, err := exec.Command("ip", "-4", "neigh", "flush", "all").CombinedOutput()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "flush ARP: %s", strings.TrimSpace(string(out)))
		}
		return &pb.SystemActionResponse{Message: "ARP cache cleared"}, nil

	case "clear-interfaces-statistics":
		return &pb.SystemActionResponse{
			Message: "Interface statistics counters noted\n(kernel counters are cumulative and cannot be reset)",
		}, nil

	case "clear-ipv6-neighbors":
		out, err := exec.Command("ip", "-6", "neigh", "flush", "all").CombinedOutput()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "flush IPv6 neighbors: %s", strings.TrimSpace(string(out)))
		}
		return &pb.SystemActionResponse{Message: "IPv6 neighbor cache cleared"}, nil

	case "clear-policy-counters":
		if s.dp == nil || !s.dp.IsLoaded() {
			return nil, status.Error(codes.Unavailable, "dataplane not loaded")
		}
		if err := s.dp.ClearPolicyCounters(); err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &pb.SystemActionResponse{Message: "policy hit counters cleared"}, nil

	case "clear-firewall-counters":
		if s.dp == nil || !s.dp.IsLoaded() {
			return nil, status.Error(codes.Unavailable, "dataplane not loaded")
		}
		if err := s.dp.ClearFilterCounters(); err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &pb.SystemActionResponse{Message: "Firewall filter counters cleared"}, nil

	case "clear-nat-counters":
		if s.dp == nil || !s.dp.IsLoaded() {
			return nil, status.Error(codes.Unavailable, "dataplane not loaded")
		}
		if err := s.dp.ClearNATRuleCounters(); err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &pb.SystemActionResponse{Message: "NAT translation statistics cleared"}, nil

	case "clear-persistent-nat":
		if s.dp == nil || s.dp.GetPersistentNAT() == nil {
			return &pb.SystemActionResponse{Message: "Persistent NAT table not available"}, nil
		}
		count := s.dp.GetPersistentNAT().Len()
		s.dp.GetPersistentNAT().Clear()
		return &pb.SystemActionResponse{
			Message: fmt.Sprintf("Cleared %d persistent NAT bindings", count),
		}, nil

	case "ospf-clear":
		if s.frr == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "FRR manager not available")
		}
		if _, err := s.frr.ExecVtysh("clear ip ospf process"); err != nil {
			return nil, status.Errorf(codes.Internal, "clear OSPF: %v", err)
		}
		return &pb.SystemActionResponse{Message: "OSPF process cleared"}, nil

	case "bgp-clear":
		if s.frr == nil {
			return nil, status.Errorf(codes.FailedPrecondition, "FRR manager not available")
		}
		if _, err := s.frr.ExecVtysh("clear bgp * soft"); err != nil {
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
		return &pb.SystemActionResponse{
			Message: "Node is now secondary for all redundancy groups.\n" +
				"Traffic has been drained to peer.\n" +
				"You may now replace the binary and restart the service:\n" +
				"  systemctl stop xpfd && <replace binary> && systemctl start xpfd",
		}, nil

	default:
		// Handle cluster failover actions: "cluster-failover:<rgID>" and "cluster-failover-reset:<rgID>"
		if strings.HasPrefix(req.Action, "cluster-failover-reset:") {
			if s.cluster == nil {
				return nil, status.Error(codes.Unavailable, "cluster not configured")
			}
			rgStr := strings.TrimPrefix(req.Action, "cluster-failover-reset:")
			rgID, err := strconv.Atoi(rgStr)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid redundancy-group ID: %s", rgStr)
			}
			if err := s.cluster.ResetFailover(rgID); err != nil {
				return nil, status.Errorf(codes.NotFound, "%v", err)
			}
			return &pb.SystemActionResponse{
				Message: fmt.Sprintf("Failover reset for redundancy group %d", rgID),
			}, nil
		}
		if strings.HasPrefix(req.Action, "cluster-failover-data:node") {
			if s.cluster == nil {
				return nil, status.Error(codes.Unavailable, "cluster not configured")
			}
			nodeStr := strings.TrimPrefix(req.Action, "cluster-failover-data:node")
			targetNode, err := strconv.Atoi(nodeStr)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid node ID: %s", nodeStr)
			}
			if !cluster.IsSupportedClusterNodeID(targetNode) {
				return nil, status.Errorf(codes.InvalidArgument, "unsupported cluster failover target node %d", targetNode)
			}
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
		}
		if strings.HasPrefix(req.Action, "cluster-failover:") {
			if s.cluster == nil {
				return nil, status.Error(codes.Unavailable, "cluster not configured")
			}
			rest := strings.TrimPrefix(req.Action, "cluster-failover:")

			// Parse "cluster-failover:<rgID>[:node<N>]"
			var rgStr, nodeStr string
			if idx := strings.Index(rest, ":node"); idx >= 0 {
				rgStr = rest[:idx]
				nodeStr = rest[idx+5:] // skip ":node"
			} else {
				rgStr = rest
			}

			rgID, err := strconv.Atoi(rgStr)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid redundancy-group ID: %s", rgStr)
			}

			// If "node <N>" specified, route to correct node.
			if nodeStr != "" {
				targetNode, err := strconv.Atoi(nodeStr)
				if err != nil {
					return nil, status.Errorf(codes.InvalidArgument, "invalid node ID: %s", nodeStr)
				}
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
				if s.cluster.IsLocalPrimary(rgID) {
					return &pb.SystemActionResponse{
						Message: fmt.Sprintf("Redundancy group %d is already primary on node %d", rgID, targetNode),
					}, nil
				}
				// Ask peer to transfer out so we can take primary.
				if err := s.cluster.RequestPeerFailover(rgID); err != nil {
					return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
				}
				return &pb.SystemActionResponse{
					Message: fmt.Sprintf("Manual failover completed for redundancy group %d (transfer committed)", rgID),
				}, nil
			}

			if err := s.cluster.ManualFailover(rgID); err != nil {
				return nil, status.Errorf(codes.NotFound, "%v", err)
			}
			return &pb.SystemActionResponse{
				Message: fmt.Sprintf("Manual failover triggered for redundancy group %d", rgID),
			}, nil
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
			msg := dpuserspace.FormatStatusSummary(statusAfter) + "\n" + dpuserspace.FormatBindings(statusAfter)
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
			msg := dpuserspace.FormatStatusSummary(statusAfter) + "\n" + dpuserspace.FormatBindings(statusAfter)
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
			msg := dpuserspace.FormatStatusSummary(statusAfter) + "\n" + dpuserspace.FormatBindings(statusAfter)
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
			registered, armed, err := dpuserspace.ParseRegistrationOperation(parts[1])
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
			statusAfter, err := provider.SetBindingState(uint32(slot), registered, armed)
			if err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "userspace binding control: %v", err)
			}
			msg := dpuserspace.FormatStatusSummary(statusAfter) + "\n" + dpuserspace.FormatBindings(statusAfter)
			return &pb.SystemActionResponse{Message: msg}, nil
		}
		return nil, status.Errorf(codes.InvalidArgument, "unknown action: %s", req.Action)
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
