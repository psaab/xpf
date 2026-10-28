package grpcapi

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/sysinfo"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/termsafe"
)

func (s *Server) GetStatus(ctx context.Context, _ *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	resp := &pb.GetStatusResponse{
		Uptime:          time.Since(s.startTime).Truncate(time.Second).String(),
		DataplaneLoaded: s.dp != nil && s.dp.IsLoaded(),
		ConfigLoaded:    s.store.ActiveConfig() != nil,
	}
	if cfg := s.store.ActiveConfig(); cfg != nil {
		resp.ZoneCount = int32(len(cfg.Security.Zones))
	}
	// #3929: read the live session count from the dataplane session table (the
	// same source `show security flow session` uses), NOT the BPF GC sweep
	// stats. On the userspace dataplane (the only live forwarding path) the BPF
	// GC sweep is skipped (#333), so gc.Stats().TotalEntries is permanently 0 —
	// this reported 0 sessions on every real deployment. SessionCount counts
	// forward entries only, so it is the live session total.
	if s.dp != nil && s.dp.IsLoaded() {
		// Gate the cancellable full-table walk through the same admission
		// limiter as the other session scans.
		release, err := sessionWalkLimiter.Acquire()
		if err != nil {
			return nil, status.Error(codes.ResourceExhausted,
				"session scan concurrency limit reached; retry shortly")
		}
		defer release()
		v4, v6, err := backendSessionCountContext(ctx, s.dp)
		if err != nil {
			if ctx.Err() != nil {
				return nil, status.FromContextError(ctx.Err()).Err()
			}
			return nil, sessionCountStatus(ctx, err)
		}
		resp.SessionCount = int32(v4 + v6)
	}
	if s.cluster != nil {
		rg0 := s.cluster.GroupState(0)
		if rg0 != nil {
			if rg0.State == cluster.StatePrimary {
				resp.ClusterRole = "primary"
			} else {
				resp.ClusterRole = "secondary"
			}
		}
		resp.ClusterNodeId = int32(s.cluster.NodeID())
	}
	return resp, nil
}

func (s *Server) GetGlobalStats(_ context.Context, _ *pb.GetGlobalStatsRequest) (*pb.GetGlobalStatsResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}
	// #17193: one shared snapshot classifies every global counter once.
	// #3345: a genuine read failure still fails the RPC (codes.Internal
	// below) instead of returning zeros indistinguishable from "no
	// events". #13274: ErrCounterNotPopulated is known-unsourced, NOT a
	// failure — the snapshot records it in Unavailable, and the response
	// names those counters in unavailable_counters so the remote CLI
	// renders "unavailable" instead of failing on every call.
	indexes := []uint32{
		dataplane.GlobalCtrRxPackets, dataplane.GlobalCtrTxPackets,
		dataplane.GlobalCtrDrops, dataplane.GlobalCtrUnknownVLANDrops,
		dataplane.GlobalCtrDstMACDrops, dataplane.GlobalCtrSessionsNew,
		dataplane.GlobalCtrSessionsClosed, dataplane.GlobalCtrScreenDrops,
		dataplane.GlobalCtrPolicyDeny, dataplane.GlobalCtrNATAllocFail,
		dataplane.GlobalCtrHostInboundDeny, dataplane.GlobalCtrTCEgressPackets,
		dataplane.GlobalCtrNAT64Xlate, dataplane.GlobalCtrHostInbound,
	}
	for i := range dataplane.ScreenReasonCounters {
		indexes = append(indexes, dataplane.ScreenReasonCounters[i].Index)
	}
	indexes = append(indexes,
		dataplane.GlobalCtrSyncookieSent, dataplane.GlobalCtrSyncookieValid,
		dataplane.GlobalCtrSyncookieInvalid, dataplane.GlobalCtrSyncookieBypass)
	snap := dataplane.ReadGlobalCounters(s.dp, indexes...)

	// Collect per-screen-type drop counters. #3343: iterate the shared
	// dataplane.ScreenReasonCounters table so this RPC and every other
	// screen-statistics surface agree on the reason set. The SYN-cookie
	// counters are a distinct set and stay appended. Unavailable counters
	// are absent from Values, so they never appear as fabricated zeros.
	screenDetails := make(map[string]uint64)
	for i := range dataplane.ScreenReasonCounters {
		rc := &dataplane.ScreenReasonCounters[i]
		if v, ok := snap.Value(rc.Index); ok && v > 0 {
			screenDetails[rc.Reason] = v
		}
	}
	for _, sc := range []struct {
		idx  uint32
		name string
	}{
		{dataplane.GlobalCtrSyncookieSent, "syncookie-sent"},
		{dataplane.GlobalCtrSyncookieValid, "syncookie-valid"},
		{dataplane.GlobalCtrSyncookieInvalid, "syncookie-invalid"},
		{dataplane.GlobalCtrSyncookieBypass, "syncookie-bypass"},
	} {
		if v, ok := snap.Value(sc.idx); ok && v > 0 {
			screenDetails[sc.name] = v
		}
	}

	value := func(idx uint32) uint64 {
		v, _ := snap.Value(idx)
		return v
	}
	resp := &pb.GetGlobalStatsResponse{
		RxPackets:           value(dataplane.GlobalCtrRxPackets),
		TxPackets:           value(dataplane.GlobalCtrTxPackets),
		Drops:               value(dataplane.GlobalCtrDrops),
		UnknownVlanDrops:    value(dataplane.GlobalCtrUnknownVLANDrops),
		DstMacDrops:         value(dataplane.GlobalCtrDstMACDrops),
		SessionsCreated:     value(dataplane.GlobalCtrSessionsNew),
		SessionsClosed:      value(dataplane.GlobalCtrSessionsClosed),
		ScreenDrops:         value(dataplane.GlobalCtrScreenDrops),
		PolicyDenies:        value(dataplane.GlobalCtrPolicyDeny),
		NatAllocFailures:    value(dataplane.GlobalCtrNATAllocFail),
		HostInboundDenies:   value(dataplane.GlobalCtrHostInboundDeny),
		TcEgressPackets:     value(dataplane.GlobalCtrTCEgressPackets),
		Nat64Translations:   value(dataplane.GlobalCtrNAT64Xlate),
		HostInboundAllowed:  value(dataplane.GlobalCtrHostInbound),
		ScreenDropDetails:   screenDetails,
		UnavailableCounters: snap.SortedUnavailableNames(),
	}

	// #3345: check Err AFTER the full snapshot so EVERY global read is
	// covered — a genuine failure on any of them must not return a
	// zero-valued field. Unavailable counters never reach Err.
	if snap.Err != nil {
		return nil, status.Errorf(codes.Internal,
			"reading global counter: %v", snap.Err)
	}

	return resp, nil
}

func (s *Server) GetSystemInfo(ctx context.Context, req *pb.GetSystemInfoRequest) (*pb.GetSystemInfoResponse, error) {
	var buf strings.Builder

	switch req.Type {
	case "uptime":
		data, err := os.ReadFile("/proc/uptime")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "reading uptime: %v", err)
		}
		fields := strings.Fields(string(data))
		if len(fields) < 1 {
			return nil, status.Error(codes.Internal, "unexpected /proc/uptime format")
		}
		var upSec float64
		fmt.Sscanf(fields[0], "%f", &upSec)

		days := int(upSec) / 86400
		hours := (int(upSec) % 86400) / 3600
		mins := (int(upSec) % 3600) / 60
		secs := int(upSec) % 60

		now := time.Now()
		fmt.Fprintf(&buf, "Current time: %s\n", now.Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&buf, "System booted: %s\n", now.Add(-time.Duration(upSec)*time.Second).Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&buf, "Daemon uptime: %s\n", time.Since(s.startTime).Truncate(time.Second))
		if days > 0 {
			fmt.Fprintf(&buf, "System uptime: %d days, %d hours, %d minutes, %d seconds\n", days, hours, mins, secs)
		} else {
			fmt.Fprintf(&buf, "System uptime: %d hours, %d minutes, %d seconds\n", hours, mins, secs)
		}

	case "memory":
		data, err := os.ReadFile("/proc/meminfo")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "reading meminfo: %v", err)
		}
		info := make(map[string]uint64)
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				key := strings.TrimSuffix(parts[0], ":")
				val, _ := strconv.ParseUint(parts[1], 10, 64)
				info[key] = val
			}
		}
		total := info["MemTotal"]
		free := info["MemFree"]
		buffers := info["Buffers"]
		cached := info["Cached"]
		available := info["MemAvailable"]
		used := total - free - buffers - cached

		fmt.Fprintf(&buf, "%-20s %10s\n", "Type", "kB")
		fmt.Fprintf(&buf, "%-20s %10d\n", "Total memory", total)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Used memory", used)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Free memory", free)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Buffers", buffers)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Cached", cached)
		fmt.Fprintf(&buf, "%-20s %10d\n", "Available", available)
		if total > 0 {
			fmt.Fprintf(&buf, "Utilization: %.1f%%\n", float64(used)/float64(total)*100)
		}

	case "processes":
		out, err := outputTimeout(ctx, "ps", "aux", "--sort=-rss")
		if err != nil {
			return nil, diagExecError("running ps", err)
		}
		buf.WriteString(termsafe.SanitizeBlockForDisplay(string(out)))

	case "processes-summary":
		psOutput, err := outputTimeout(ctx, "ps", "-eo", "pid,user,pri,ni,vsz,rss,stat,time,pcpu,comm", "--sort=-pcpu")
		if err != nil {
			return nil, diagExecError("running process summary", err)
		}
		var output strings.Builder
		sysinfo.WriteProcessesSummary(&output, psOutput)
		buf.WriteString(termsafe.SanitizeBlockForDisplay(output.String()))

	case "rescue-configuration":
		content, err := s.store.LoadRescueConfigRedacted()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "loading rescue configuration: %v", err)
		}
		if content == "" {
			buf.WriteString("No rescue configuration saved\n")
		} else {
			buf.WriteString(content)
		}

	case "storage":
		out, err := outputTimeout(ctx, "df", "-h")
		if err != nil {
			return nil, diagExecError("running df", err)
		}
		// #6584: guarded even though this text is root-controlled rather than
		// device-originated. GetSystemInfo forks FOUR binaries from one
		// function, so leaving three raw would let the guarded one vouch for
		// them under any function-granularity check — the half-applied-sweep
		// shape #6579 shipped.
		buf.WriteString(termsafe.SanitizeBlockForDisplay(string(out)))

	case "arp":
		neighbors, err := netlink.NeighList(0, netlink.FAMILY_V4)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "listing ARP entries: %v", err)
		}
		linkNames := neighborLinkNames(neighbors, netlink.LinkByIndex)
		writeNeighSummary(&buf, neighbors, neighStateStr, linkNames)
		fmt.Fprintf(&buf, "%-18s %-20s %-12s %-10s\n", "MAC Address", "Address", "Interface", "State")
		for _, n := range neighbors {
			if !neighDisplayable(n) {
				continue
			}
			fmt.Fprintf(&buf, "%-18s %-20s %-12s %-10s\n",
				neighMACDisplay(n), n.IP, linkNames[n.LinkIndex], neighStateStr(n.State))
		}

	case "ipv6-neighbors":
		neighbors, err := netlink.NeighList(0, netlink.FAMILY_V6)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "listing IPv6 neighbors: %v", err)
		}
		linkNames := neighborLinkNames(neighbors, netlink.LinkByIndex)
		writeNeighSummary(&buf, neighbors, neighStateStr, linkNames)
		fmt.Fprintf(&buf, "%-18s %-40s %-12s %-10s\n", "MAC Address", "IPv6 Address", "Interface", "State")
		for _, n := range neighbors {
			if !neighDisplayable(n) {
				continue
			}
			fmt.Fprintf(&buf, "%-18s %-40s %-12s %-10s\n",
				neighMACDisplay(n), n.IP, linkNames[n.LinkIndex], neighStateStr(n.State))
		}

	case "boot-messages":
		out, err := outputTimeout(ctx, "journalctl", "-k", "--boot", "-n", "100", "--no-pager")
		if err != nil {
			return nil, diagExecError("running journalctl", err)
		}
		// #16725: -k restricts to kernel messages only (the Junos
		// boot-messages contract). Without it, --boot returns the
		// whole system journal (sshd/sudo/other daemons) to this
		// PermView RPC. #6584: still sanitize the kernel text.
		buf.WriteString(termsafe.SanitizeBlockForDisplay(string(out)))

	case "connections":
		out, err := outputTimeout(ctx, "ss", "-tnp")
		if err != nil {
			return nil, diagExecError("running ss", err)
		}
		// #6584: guarded even though this text is root-controlled rather than
		// device-originated. GetSystemInfo forks FOUR binaries from one
		// function, so leaving three raw would let the guarded one vouch for
		// them under any function-granularity check — the half-applied-sweep
		// shape #6579 shipped.
		buf.WriteString(termsafe.SanitizeBlockForDisplay(string(out)))

	case "users":
		cfg := s.store.ActiveConfig()
		if cfg == nil || cfg.System.Login == nil || len(cfg.System.Login.Users) == 0 {
			fmt.Fprintln(&buf, "No login users configured")
		} else {
			fmt.Fprintf(&buf, "%-20s %-8s %-20s %s\n", "Username", "UID", "Class", "SSH Keys")
			for _, u := range cfg.System.Login.Users {
				uid := "-"
				if u.UID > 0 {
					uid = strconv.Itoa(u.UID)
				}
				class := u.Class
				if class == "" {
					class = "-"
				}
				fmt.Fprintf(&buf, "%-20s %-8s %-20s %d\n", u.Name, uid, class, len(u.SSHKeys))
			}
		}

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown system info type: %s", req.Type)
	}

	return &pb.GetSystemInfoResponse{Output: buf.String()}, nil
}
