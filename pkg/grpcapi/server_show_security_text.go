// Phase 12 of #1043: extract the seven residual ShowText case bodies
// (`ipsec-statistics`, `tunnels`, `rpm`, `security-log`,
// `security-alarms`/`security-alarms-detail`, `schedulers`,
// `applications`) into dedicated methods. Same methodology as Phases
// 1-11: semantic relocation, no behavior change. Each case body is
// moved verbatim apart from `&buf` references becoming `buf`
// (passed-in `*strings.Builder`) and `if … { … } else { … }`
// flattened into early-return form where it shortens an indent level.
//
// `showIPsecStatistics` returns `error` (the original case had a
// `return nil, status.Errorf` path); the dispatcher rewraps via
// `if err := …; err != nil { return nil, err }`.
//
// `showSecurityLog` and `showSecurityAlarms` take their gRPC-request
// inputs (`filter` and `topic` respectively) as parameters so the
// bodies no longer reference the `req` struct directly.
//
// This phase brings server_show.go below the 2,000 LOC modularity
// threshold (#1043) — closing the audit that started at 4,072 LOC.

package grpcapi

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// showIPsecStatistics renders the IPsec SA table with active-tunnel
// count and per-SA byte counters.
func (s *Server) showIPsecStatistics(cfg *config.Config, buf *strings.Builder) error {
	if s.ipsec == nil {
		buf.WriteString("IPsec manager not available\n")
		return nil
	}
	sas, err := s.ipsec.GetSAStatus()
	if err != nil {
		return status.Errorf(codes.Internal, "IPsec statistics: %v", err)
	}
	activeTunnels := 0
	for _, sa := range sas {
		if sa.State == "ESTABLISHED" || sa.State == "INSTALLED" {
			activeTunnels++
		}
	}
	fmt.Fprintf(buf, "IPsec statistics:\n")
	fmt.Fprintf(buf, "  Active tunnels: %d\n", activeTunnels)
	fmt.Fprintf(buf, "  Total SAs:      %d\n", len(sas))
	buf.WriteString("\n")
	if len(sas) > 0 {
		fmt.Fprintf(buf, "  %-20s %-14s %-12s %-12s\n", "Name", "State", "Bytes In", "Bytes Out")
		for _, sa := range sas {
			inBytes := sa.InBytes
			if inBytes == "" {
				inBytes = "-"
			}
			outBytes := sa.OutBytes
			if outBytes == "" {
				outBytes = "-"
			}
			fmt.Fprintf(buf, "  %-20s %-14s %-12s %-12s\n", sa.Name, sa.State, inBytes, outBytes)
		}
	}
	if cfg != nil && len(cfg.Security.IPsec.VPNs) > 0 {
		fmt.Fprintf(buf, "\n  Configured VPNs: %d\n", len(cfg.Security.IPsec.VPNs))
	}
	return nil
}

// showTunnels renders GRE/XFRM tunnel interface state from the routing
// manager.
func (s *Server) showTunnels(buf *strings.Builder) {
	if s.routing == nil {
		buf.WriteString("Routing manager not available\n")
		return
	}
	tunnels, err := s.routing.GetTunnelStatus()
	if err != nil {
		fmt.Fprintf(buf, "Error: %v\n", err)
		return
	}
	if len(tunnels) == 0 {
		buf.WriteString("No tunnel interfaces configured\n")
		return
	}
	for _, t := range tunnels {
		fmt.Fprintf(buf, "Tunnel %s:\n", t.Name)
		fmt.Fprintf(buf, "  State:       %s\n", t.State)
		fmt.Fprintf(buf, "  Source:      %s\n", t.Source)
		fmt.Fprintf(buf, "  Destination: %s\n", t.Destination)
		for _, addr := range t.Addresses {
			fmt.Fprintf(buf, "  Address:     %s\n", addr)
		}
		if t.KeepaliveInfo != "" {
			fmt.Fprintf(buf, "  Keepalive:   %s\n", t.KeepaliveInfo)
		}
		buf.WriteString("\n")
	}
}

// showRPM renders RPM probe results, falling back to configured-probe
// listing when no live results are available.
func (s *Server) showRPM(buf *strings.Builder) {
	if s.rpmResultsFn != nil {
		results := s.rpmResultsFn()
		if len(results) > 0 {
			buf.WriteString("RPM Probe Results:\n")
			for _, r := range results {
				fmt.Fprintf(buf, "  Probe: %s, Test: %s\n", r.ProbeName, r.TestName)
				fmt.Fprintf(buf, "    Type: %s, Target: %s\n", r.ProbeType, r.Target)
				fmt.Fprintf(buf, "    Status: %s", r.LastStatus)
				if r.LastRTT > 0 {
					fmt.Fprintf(buf, ", RTT: %s", r.LastRTT)
				}
				buf.WriteString("\n")
				if r.MinRTT > 0 {
					fmt.Fprintf(buf, "    RTT: min %s, max %s, avg %s, jitter %s\n",
						r.MinRTT, r.MaxRTT, r.AvgRTT, r.Jitter)
				}
				fmt.Fprintf(buf, "    Sent: %d, Received: %d", r.TotalSent, r.TotalRecv)
				if r.TotalSent > 0 {
					loss := float64(r.TotalSent-r.TotalRecv) / float64(r.TotalSent) * 100
					fmt.Fprintf(buf, ", Loss: %.1f%%", loss)
				}
				buf.WriteString("\n")
				if !r.LastProbeAt.IsZero() {
					fmt.Fprintf(buf, "    Last probe: %s\n", r.LastProbeAt.Format("2006-01-02 15:04:05"))
				}
			}
			return
		}
	}
	writeRPMConfig(buf, s.store.ActiveConfig())
}

// showSecurityLog renders recent security events from the daemon's
// event ring buffer. `filter`, when numeric, sets the event count
// (default 50).
func (s *Server) showSecurityLog(filter string, buf *strings.Builder) {
	if s.eventBuf == nil {
		buf.WriteString("no events (event buffer not initialized)\n")
		return
	}
	n := 50
	if filter != "" {
		if v, err := strconv.Atoi(filter); err == nil && v > 0 {
			n = v
		}
	}
	events := s.eventBuf.Latest(n)
	if len(events) == 0 {
		buf.WriteString("no events recorded\n")
		return
	}
	// Build zone name map
	evZoneNames := make(map[uint16]string)
	if s.dp != nil {
		if cr := s.applyResult(); cr != nil {
			for name, id := range cr.ZoneIDs {
				evZoneNames[id] = name
			}
		}
	}
	zoneName := func(id uint16) string {
		if n, ok := evZoneNames[id]; ok {
			return n
		}
		return fmt.Sprintf("%d", id)
	}
	for _, e := range events {
		ts := e.Time.Format("15:04:05")
		policyDisp := e.PolicyName
		if policyDisp == "" {
			policyDisp = fmt.Sprintf("%d", e.PolicyID)
		}
		switch e.Type {
		case "SCREEN_DROP":
			fmt.Fprintf(buf, "%s %-14s screen=%-16s %s -> %s %s action=%s zone=%s\n",
				ts, e.Type, e.ScreenCheck, e.SrcAddr, e.DstAddr, e.Protocol, e.Action, zoneName(e.InZone))
		case "SESSION_CLOSE":
			fmt.Fprintf(buf, "%s %-14s %s -> %s %s action=%-6s policy=%s zone=%s->%s client=%d/%d server=%d/%d reason=%q\n",
				ts, e.Type, e.SrcAddr, e.DstAddr, e.Protocol, e.Action,
				policyDisp, zoneName(e.InZone), zoneName(e.OutZone),
				e.SessionPkts, e.SessionBytes, e.RevSessionPkts, e.RevSessionBytes, e.CloseReason)
		default:
			fmt.Fprintf(buf, "%s %-14s %s -> %s %s action=%-6s policy=%s zone=%s->%s\n",
				ts, e.Type, e.SrcAddr, e.DstAddr, e.Protocol, e.Action,
				policyDisp, zoneName(e.InZone), zoneName(e.OutZone))
		}
	}
	fmt.Fprintf(buf, "(%d events shown)\n", len(events))
}

// showSchedulers renders the configured scheduler entries
// (start/stop time + recurrence).
func (s *Server) showSchedulers(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.Schedulers) == 0 {
		buf.WriteString("No schedulers configured\n")
		return
	}
	for name, sched := range cfg.Schedulers {
		fmt.Fprintf(buf, "Scheduler: %s\n", name)
		if sched.StartTime != "" {
			fmt.Fprintf(buf, "  Start time: %s\n", sched.StartTime)
		}
		if sched.StopTime != "" {
			fmt.Fprintf(buf, "  Stop time:  %s\n", sched.StopTime)
		}
		if sched.StartDate != "" {
			fmt.Fprintf(buf, "  Start date: %s\n", sched.StartDate)
		}
		if sched.StopDate != "" {
			fmt.Fprintf(buf, "  Stop date:  %s\n", sched.StopDate)
		}
		if sched.Daily {
			buf.WriteString("  Recurrence: daily\n")
		}
		buf.WriteString("\n")
	}
}

// showApplications renders the configured Junos applications and
// application-sets, sorted by name.
func (s *Server) showApplications(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
		return
	}
	if len(cfg.Applications.Applications) > 0 {
		buf.WriteString("Applications:\n")
		names := make([]string, 0, len(cfg.Applications.Applications))
		for name := range cfg.Applications.Applications {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			app := cfg.Applications.Applications[name]
			fmt.Fprintf(buf, "  %-24s proto=%-6s", name, app.Protocol)
			if app.DestinationPort != "" {
				fmt.Fprintf(buf, " dst-port=%s", app.DestinationPort)
			}
			if app.SourcePort != "" {
				fmt.Fprintf(buf, " src-port=%s", app.SourcePort)
			}
			if app.InactivityTimeout > 0 {
				fmt.Fprintf(buf, " timeout=%ds", app.InactivityTimeout)
			}
			if app.ALG != "" {
				fmt.Fprintf(buf, " alg=%s", app.ALG)
			}
			if app.Description != "" {
				fmt.Fprintf(buf, " (%s)", app.Description)
			}
			buf.WriteString("\n")
		}
	}
	if len(cfg.Applications.ApplicationSets) > 0 {
		buf.WriteString("Application sets:\n")
		names := make([]string, 0, len(cfg.Applications.ApplicationSets))
		for name := range cfg.Applications.ApplicationSets {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			as := cfg.Applications.ApplicationSets[name]
			fmt.Fprintf(buf, "  %-24s members: %s\n", name, strings.Join(as.Applications, ", "))
		}
	}
}

// showSecurityAlarms renders config-validation warnings plus screen
// counter alarms. `topic` is "security-alarms" or
// "security-alarms-detail" (the latter expands each alarm to a
// per-record block).
func (s *Server) showSecurityAlarms(cfg *config.Config, topic string, buf *strings.Builder) {
	detail := topic == "security-alarms-detail"
	var alarmCount int

	if cfg != nil {
		warnings := config.ValidateConfig(cfg)
		for _, w := range warnings {
			alarmCount++
			if detail {
				fmt.Fprintf(buf, "Alarm %d:\n  Class: Configuration\n  Severity: Warning\n  Description: %s\n\n", alarmCount, w)
			}
		}
	}

	if s.dp != nil && s.dp.IsLoaded() {
		readCtr := func(idx uint32) uint64 {
			v, _ := s.dp.ReadGlobalCounter(idx)
			return v
		}
		screenNames := []struct {
			idx  uint32
			name string
		}{
			{dataplane.GlobalCtrScreenSynFlood, "SYN flood"},
			{dataplane.GlobalCtrScreenICMPFlood, "ICMP flood"},
			{dataplane.GlobalCtrScreenUDPFlood, "UDP flood"},
			{dataplane.GlobalCtrScreenLandAttack, "LAND attack"},
			{dataplane.GlobalCtrScreenPingOfDeath, "Ping of death"},
			{dataplane.GlobalCtrScreenTearDrop, "Tear-drop"},
			{dataplane.GlobalCtrScreenTCPSynFin, "TCP SYN+FIN"},
			{dataplane.GlobalCtrScreenTCPNoFlag, "TCP no-flag"},
			{dataplane.GlobalCtrScreenTCPFinNoAck, "TCP FIN-no-ACK"},
			{dataplane.GlobalCtrScreenWinNuke, "WinNuke"},
			{dataplane.GlobalCtrScreenIPSrcRoute, "IP source-route"},
			{dataplane.GlobalCtrScreenSynFrag, "SYN fragment"},
		}
		for _, sc := range screenNames {
			val := readCtr(sc.idx)
			if val > 0 {
				alarmCount++
				if detail {
					fmt.Fprintf(buf, "Alarm %d:\n  Class: IDS\n  Severity: Major\n  Description: %s attack detected (%d drops)\n\n", alarmCount, sc.name, val)
				}
			}
		}
	}

	if alarmCount == 0 {
		buf.WriteString("No security alarms currently active\n")
	} else if !detail {
		fmt.Fprintf(buf, "%d security alarm(s) currently active\n", alarmCount)
		buf.WriteString("  run 'show security alarms detail' for details\n")
	}
}
