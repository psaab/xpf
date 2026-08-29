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
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
	"github.com/psaab/xpf/pkg/feeds"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/natpoolalarm"
	"github.com/psaab/xpf/pkg/rpm"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// screenSYNCookieCounterRows renders the aggregated userspace
// SYN-cookie counters (moved from server_show.go in #1700).
func (s *Server) screenSYNCookieCounterRows() string {
	status, err := s.userspaceDataplaneStatus()
	if err != nil {
		return ""
	}
	return dpformat.FormatSYNCookieCounterRows(dpformat.SumSYNCookieCounters(status))
}

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

// showServicesIPMonitoringStatus renders live `services
// ip-monitoring` policy status via the shared pkg/ipmon formatter
// (#1827) so gRPC and local CLI output stay byte-identical.
func (s *Server) showServicesIPMonitoringStatus(buf *strings.Builder) {
	if s.ipmonStatusFn == nil {
		buf.WriteString("IP monitoring engine not running\n")
		return
	}
	ipmon.FormatStatus(buf, s.ipmonStatusFn())
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
// event ring buffer. `filter` carries the full `show security log`
// argument string forwarded by the remote `cli` (`[<count>] [zone
// <name>] [protocol <proto>] [action <action>]`), parsed by the shared
// logging.ParseEventFilterArgs so this path and the local CLI cannot
// drift (#3547). Before #3547 this handler treated `filter` as a bare
// count and dropped any zone/protocol/action selector, so the remote
// CLI silently dumped every event for `show security log zone <name>`
// (including the unknown/none/0 zone-0 selector #3338) instead of
// isolating the requested zone.
func (s *Server) showSecurityLog(filter string, buf *strings.Builder) {
	if s.eventBuf == nil {
		buf.WriteString("no events (event buffer not initialized)\n")
		return
	}

	// Resolve zone names through the active apply result, mirroring the local
	// CLI. Parsing fails CLOSED: a bad token / unknown zone surfaces the same
	// message the local CLI returns rather than silently widening to all
	// events.
	cr := s.applyResult()
	var zoneIDs map[string]uint16
	if cr != nil {
		zoneIDs = cr.ZoneIDs
	}
	n, evFilter, err := logging.ParseEventFilterArgs(strings.Fields(filter), zoneIDs, cr != nil)
	if err != nil {
		fmt.Fprintf(buf, "%s\n", err)
		return
	}

	var events []logging.EventRecord
	if evFilter.IsEmpty() {
		events = s.eventBuf.Latest(n)
	} else {
		events = s.eventBuf.LatestFiltered(n, evFilter)
	}
	if len(events) == 0 {
		buf.WriteString("no events recorded\n")
		return
	}
	// Build the CURRENT-config reverse zone ID → name map. This is only a
	// fallback for legacy records that lack a resolved-at-event-time name
	// (#3335): each EventRecord stores InZoneName/OutZoneName as resolved when
	// the event fired, so a later zone rename / delete / ID reuse (#3075) must
	// NOT retroactively rewrite an old event's zone name from the live config.
	// Prefer the stored name; consult this map (then a bare numeric fallback)
	// only when the record carries no resolved name. This is the showText
	// "security-log" topic that the remote `cli` binary routes to.
	evZoneNames := make(map[uint16]string)
	if s.dp != nil {
		if cr := s.applyResult(); cr != nil {
			for name, id := range cr.ZoneIDs {
				evZoneNames[id] = name
			}
		}
	}
	zoneName := func(stored string, id uint16) string {
		if stored != "" {
			return stored
		}
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
				ts, e.Type, e.ScreenCheck, e.SrcAddr, e.DstAddr, e.Protocol, e.Action, zoneName(e.InZoneName, e.InZone))
		case "SESSION_CLOSE":
			fmt.Fprintf(buf, "%s %-14s %s -> %s %s action=%-6s policy=%s zone=%s->%s client=%d/%d server=%d/%d reason=%q\n",
				ts, e.Type, e.SrcAddr, e.DstAddr, e.Protocol, e.Action,
				policyDisp, zoneName(e.InZoneName, e.InZone), zoneName(e.OutZoneName, e.OutZone),
				e.SessionPkts, e.SessionBytes, e.RevSessionPkts, e.RevSessionBytes, e.CloseReason)
		default:
			fmt.Fprintf(buf, "%s %-14s %s -> %s %s action=%-6s policy=%s zone=%s->%s\n",
				ts, e.Type, e.SrcAddr, e.DstAddr, e.Protocol, e.Action,
				policyDisp, zoneName(e.InZoneName, e.InZone), zoneName(e.OutZoneName, e.OutZone))
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
			if as == nil {
				// #5221: a present-but-nil application-set map value is admitted
				// by the tolerant-load / peer-sync path (#1960) that the resolver
				// (#5179) already tolerates. Skip it rather than dereferencing
				// as.Applications and panicking the display handler.
				continue
			}
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
		// #3345: track a counter-read failure so a degraded counter bridge
		// is reported as a warning rather than masquerading as "no alarms".
		var readErr error
		readCtr := func(idx uint32) uint64 {
			v, err := s.dp.ReadGlobalCounter(idx)
			if err != nil && readErr == nil {
				readErr = err
			}
			return v
		}
		// #3343: iterate the shared screen-reason table so port-scan, ip-sweep,
		// and session-limit (previously omitted) raise alarms too, and the reason
		// set matches every other screen-statistics surface.
		for i := range dataplane.ScreenReasonCounters {
			rc := &dataplane.ScreenReasonCounters[i]
			val := readCtr(rc.Index)
			if val > 0 {
				alarmCount++
				if detail {
					fmt.Fprintf(buf, "Alarm %d:\n  Class: IDS\n  Severity: Major\n  Description: %s attack detected (%d drops)\n\n", alarmCount, rc.Label, val)
				}
			}
		}
		if readErr != nil {
			fmt.Fprintf(buf, "warning: screen counter read failed (counters may be incomplete): %v\n", readErr)
		}
	}

	// #2079: NAT source pool-utilization alarms from the daemon monitor.
	if s.natPoolAlarmsFn != nil {
		alarmCount = natpoolalarm.RenderAlarms(buf, s.natPoolAlarmsFn(), alarmCount, detail)
	}

	if alarmCount == 0 {
		buf.WriteString("No security alarms currently active\n")
	} else if !detail {
		fmt.Fprintf(buf, "%d security alarm(s) currently active\n", alarmCount)
		buf.WriteString("  run 'show security alarms detail' for details\n")
	}
}

// --- #1700: residual ShowText security/screen branches ---
//
// The four screen-* prefix handlers and the `screen`, `ike`, `alg`,
// `dynamic-address`, and `address-book` switch cases moved here from
// server_show.go verbatim (only `&buf` → `buf`). Prefix handlers
// return the response directly because they were early-returns in the
// dispatcher; the shared buf they receive is empty on entry.

func (s *Server) showScreenIDSOption(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	profileName := strings.TrimPrefix(req.Topic, "screen-ids-option:")
	// #7060: the per-profile query is the natural next command after seeing a
	// zone reference a profile, and it was the one surface that did not answer.
	// Both blocks are emitted BEFORE the empty-inventory / not-found line for the
	// same reason the wide renderers do it: an operator who reads "No screen
	// profiles configured" or "not found" first has already been told nothing is
	// there, and a correction printed below it is not the same signal. Filtered
	// to the queried profile, through the same SSOT the wide renderers use.
	for _, line := range dpuserspace.ScreenUnresolvedProfileLinesFor(cfg, profileName) {
		buf.WriteString(line)
		buf.WriteString("\n")
	}
	for _, line := range dpuserspace.ScreenInertProfileLinesFor(cfg, profileName) {
		buf.WriteString(line)
		buf.WriteString("\n")
	}
	if cfg == nil || len(cfg.Security.Screen) == 0 {
		buf.WriteString("No screen profiles configured\n")
	} else {
		profile, ok := cfg.Security.Screen[profileName]
		if !ok || profile == nil {
			// #3476: a present-but-nil profile value (tolerant / HA-sync
			// path) must not panic on the profile.TCP.* derefs below.
			fmt.Fprintf(buf, "Screen profile '%s' not found\n", profileName)
		} else {
			fmt.Fprintf(buf, "Screen object status:\n\n")
			fmt.Fprintf(buf, "  Name                                        Value\n")
			if profile.TCP.Land {
				fmt.Fprintf(buf, "  TCP land attack                             enabled\n")
			}
			if profile.TCP.SynFin {
				fmt.Fprintf(buf, "  TCP SYN+FIN                                 enabled\n")
			}
			if profile.TCP.NoFlag {
				fmt.Fprintf(buf, "  TCP no-flag                                 enabled\n")
			}
			if profile.TCP.FinNoAck {
				fmt.Fprintf(buf, "  TCP FIN-no-ACK                              enabled\n")
			}
			if profile.TCP.WinNuke {
				fmt.Fprintf(buf, "  TCP WinNuke                                 enabled\n")
			}
			if profile.TCP.SynFrag {
				fmt.Fprintf(buf, "  TCP SYN fragment                            enabled\n")
			}
			if profile.TCP.SynFlood != nil {
				fmt.Fprintf(buf, "  TCP SYN flood attack threshold              %d\n",
					profile.TCP.SynFlood.AttackThreshold)
				if profile.TCP.SynFlood.SourceThreshold > 0 {
					fmt.Fprintf(buf, "  TCP SYN flood source threshold              %d\n",
						profile.TCP.SynFlood.SourceThreshold)
				}
				if profile.TCP.SynFlood.DestinationThreshold > 0 {
					fmt.Fprintf(buf, "  TCP SYN flood destination threshold          %d\n",
						profile.TCP.SynFlood.DestinationThreshold)
				}
				if profile.TCP.SynFlood.Timeout > 0 {
					fmt.Fprintf(buf, "  TCP SYN flood timeout                       %d\n",
						profile.TCP.SynFlood.Timeout)
				}
			}
			if profile.ICMP.PingDeath {
				fmt.Fprintf(buf, "  ICMP ping of death                          enabled\n")
			}
			if profile.ICMP.FloodThreshold > 0 {
				fmt.Fprintf(buf, "  ICMP flood threshold                        %d\n",
					profile.ICMP.FloodThreshold)
			}
			if profile.IP.SourceRouteOption {
				fmt.Fprintf(buf, "  IP source route option                      enabled\n")
			}
			if profile.IP.TearDrop {
				fmt.Fprintf(buf, "  IP teardrop (tear-drop)                     enabled\n")
			}
			if profile.UDP.FloodThreshold > 0 {
				fmt.Fprintf(buf, "  UDP flood threshold                         %d\n",
					profile.UDP.FloodThreshold)
			}
			// #3327: this enabled-only status table is the same class of
			// hand-built inventory as the detail table — before #3327 it
			// omitted icmp-fragment, port-scan, ip-sweep, and the
			// source/destination session limits even though they are enforced.
			// Surface them so no screen-inventory renderer drifts from the
			// config.ScreenChecks SSOT. The trailing token matches the
			// canonical config.ScreenCheck* name.
			if profile.ICMP.Fragment {
				fmt.Fprintf(buf, "  ICMP fragment (icmp-fragment)               enabled\n")
			}
			if profile.TCP.PortScanThreshold > 0 {
				fmt.Fprintf(buf, "  TCP port scan window (port-scan)            %d us\n",
					profile.TCP.PortScanThreshold)
			}
			if profile.IP.IPSweepThreshold > 0 {
				fmt.Fprintf(buf, "  IP sweep window (ip-sweep)                  %d us\n",
					profile.IP.IPSweepThreshold)
			}
			if profile.LimitSession.SourceIPBased > 0 {
				fmt.Fprintf(buf, "  Session limit source (limit-session-source) %d\n",
					profile.LimitSession.SourceIPBased)
			}
			if profile.LimitSession.DestinationIPBased > 0 {
				fmt.Fprintf(buf, "  Session limit destination (limit-session-destination) %d\n",
					profile.LimitSession.DestinationIPBased)
			}
			// Show which zones use this profile
			var zones []string
			for name, zone := range cfg.Security.Zones {
				if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
					continue
				}
				if zone.ScreenProfile == profileName {
					zones = append(zones, name)
				}
			}
			if len(zones) > 0 {
				sort.Strings(zones)
				fmt.Fprintf(buf, "\n  Bound to zones: %s\n", strings.Join(zones, ", "))
			}
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

func (s *Server) showScreenStatistics(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	zoneName := strings.TrimPrefix(req.Topic, "screen-statistics:")
	if cfg == nil {
		buf.WriteString("No active configuration\n")
	} else if s.dp == nil || !s.dp.IsLoaded() {
		buf.WriteString("Dataplane not loaded\n")
	} else {
		cr := s.applyResult()
		if cr == nil {
			buf.WriteString("No compile result available\n")
		} else {
			zoneID, ok := cr.ZoneIDs[zoneName]
			if !ok {
				fmt.Fprintf(buf, "Zone '%s' not found\n", zoneName)
			} else {
				fs, err := s.dp.ReadFloodCounters(zoneID)
				screenProfile := ""
				if z, ok := cfg.Security.Zones[zoneName]; ok && z != nil { // #3493: nil zone value
					screenProfile = z.ScreenProfile
				}
				switch {
				case errors.Is(err, dataplane.ErrCounterNotPopulated):
					// #3651: per-zone flood counters ARE sourced now; this zone
					// has none published (helper predates the accounting, the
					// zone lost its hot-path slot, or it never tripped a flood
					// check). Say so explicitly rather than a misleading 0.
					fmt.Fprintf(buf, "Screen statistics for zone '%s':\n", zoneName)
					if screenProfile != "" {
						fmt.Fprintf(buf, "  Screen profile: %s\n", screenProfile)
					}
					buf.WriteString("  Per-zone flood counters: not available " +
						"(no per-zone flood counts published for this zone: helper predates " +
						"per-zone flood accounting, the zone exceeded the dataplane's " +
						"hot-path slot capacity, or the zone has recorded no flood events)\n")
					buf.WriteString(s.screenSYNCookieCounterRows())
				case err != nil:
					fmt.Fprintf(buf, "Error reading flood counters: %v\n", err)
				default:
					fmt.Fprintf(buf, "Screen statistics for zone '%s':\n", zoneName)
					if screenProfile != "" {
						fmt.Fprintf(buf, "  Screen profile: %s\n", screenProfile)
					}
					fmt.Fprintf(buf, "  %-30s %s\n", "Counter", "Value")
					fmt.Fprintf(buf, "  %-30s %d\n", "SYN flood events", fs.SynCount)
					fmt.Fprintf(buf, "  %-30s %d\n", "ICMP flood events", fs.ICMPCount)
					fmt.Fprintf(buf, "  %-30s %d\n", "UDP flood events", fs.UDPCount)
					buf.WriteString(s.screenSYNCookieCounterRows())
				}
			}
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

func (s *Server) showScreenStatisticsAll(cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
	} else if s.dp == nil || !s.dp.IsLoaded() {
		buf.WriteString("Dataplane not loaded\n")
	} else if cr := s.applyResult(); cr == nil {
		buf.WriteString("No compile result available\n")
	} else {
		var zones []string
		for name := range cr.ZoneIDs {
			zones = append(zones, name)
		}
		sort.Strings(zones)
		// #3408: surface a per-zone flood-counter read failure as a warning
		// AFTER all zones rather than silently dropping the zone.
		var readErr error
		for _, zoneName := range zones {
			zoneID := cr.ZoneIDs[zoneName]
			fs, err := s.dp.ReadFloodCounters(zoneID)
			screenProfile := ""
			if z, ok := cfg.Security.Zones[zoneName]; ok && z != nil { // #3493: nil zone value
				screenProfile = z.ScreenProfile
			}
			if errors.Is(err, dataplane.ErrCounterNotPopulated) {
				// #3651: per-zone flood counters ARE sourced now; this zone has
				// none published. NOT a read failure -- do not set readErr
				// (no false #3408 warning) and do not print a misleading 0;
				// render an explicit "not available" row.
				fmt.Fprintf(buf, "Screen statistics for zone '%s':\n", zoneName)
				if screenProfile != "" {
					fmt.Fprintf(buf, "  Screen profile: %s\n", screenProfile)
				}
				buf.WriteString("  Per-zone flood counters: not available " +
					"(no per-zone flood counts published for this zone: helper predates " +
					"per-zone flood accounting, the zone exceeded the dataplane's " +
					"hot-path slot capacity, or the zone has recorded no flood events)\n")
				buf.WriteString("\n")
				continue
			}
			if err != nil {
				if readErr == nil {
					readErr = err
				}
				// #3344: emit a per-zone error row naming the affected zone
				// instead of silently dropping it (mirrors the local CLI
				// path). The trailing #3408 warning is an aggregate flag and
				// cannot identify WHICH zone is degraded.
				fmt.Fprintf(buf, "Screen statistics for zone '%s':\n", zoneName)
				fmt.Fprintf(buf, "  Error reading flood counters: %v\n", err)
				buf.WriteString("\n")
				continue
			}
			fmt.Fprintf(buf, "Screen statistics for zone '%s':\n", zoneName)
			if screenProfile != "" {
				fmt.Fprintf(buf, "  Screen profile: %s\n", screenProfile)
			}
			fmt.Fprintf(buf, "  %-30s %s\n", "Counter", "Value")
			fmt.Fprintf(buf, "  %-30s %d\n", "SYN flood events", fs.SynCount)
			fmt.Fprintf(buf, "  %-30s %d\n", "ICMP flood events", fs.ICMPCount)
			fmt.Fprintf(buf, "  %-30s %d\n", "UDP flood events", fs.UDPCount)
			buf.WriteString("\n")
		}
		buf.WriteString(s.screenSYNCookieCounterRows())
		if readErr != nil {
			fmt.Fprintf(buf, "warning: flood counter read failed (screen statistics may be incomplete): %v\n", readErr)
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

func (s *Server) showScreenIDSOptionDetail(req *pb.ShowTextRequest, cfg *config.Config, buf *strings.Builder) (*pb.ShowTextResponse, error) {
	profileName := strings.TrimPrefix(req.Topic, "screen-ids-option-detail:")
	// #7060: same as showScreenIDSOption — both blocks ahead of the
	// empty-inventory / not-found line, filtered to the queried profile.
	for _, line := range dpuserspace.ScreenUnresolvedProfileLinesFor(cfg, profileName) {
		buf.WriteString(line)
		buf.WriteString("\n")
	}
	for _, line := range dpuserspace.ScreenInertProfileLinesFor(cfg, profileName) {
		buf.WriteString(line)
		buf.WriteString("\n")
	}
	if cfg == nil || len(cfg.Security.Screen) == 0 {
		buf.WriteString("No screen profiles configured\n")
	} else {
		profile, ok := cfg.Security.Screen[profileName]
		if !ok || profile == nil {
			// #3476: a present-but-nil profile value must not panic on the
			// profile.TCP.* derefs below.
			fmt.Fprintf(buf, "Screen profile '%s' not found\n", profileName)
		} else {
			fmt.Fprintf(buf, "Screen object status (detail):\n\n")
			fmt.Fprintf(buf, "  %-45s %-12s %s\n", "Name", "Value", "Default")
			enabledS := func(v bool) string {
				if v {
					return "enabled"
				}
				return "disabled"
			}
			fmt.Fprintf(buf, "  %-45s %-12s %s\n", "TCP land attack", enabledS(profile.TCP.Land), "disabled")
			fmt.Fprintf(buf, "  %-45s %-12s %s\n", "TCP SYN+FIN", enabledS(profile.TCP.SynFin), "disabled")
			fmt.Fprintf(buf, "  %-45s %-12s %s\n", "TCP no-flag", enabledS(profile.TCP.NoFlag), "disabled")
			fmt.Fprintf(buf, "  %-45s %-12s %s\n", "TCP FIN-no-ACK", enabledS(profile.TCP.FinNoAck), "disabled")
			fmt.Fprintf(buf, "  %-45s %-12s %s\n", "TCP WinNuke", enabledS(profile.TCP.WinNuke), "disabled")
			fmt.Fprintf(buf, "  %-45s %-12s %s\n", "TCP SYN fragment", enabledS(profile.TCP.SynFrag), "disabled")
			if profile.TCP.SynFlood != nil {
				fmt.Fprintf(buf, "  %-45s %-12s %s\n", "TCP SYN flood protection", "enabled", "disabled")
				fmt.Fprintf(buf, "  %-45s %-12d %s\n", "  Attack threshold", profile.TCP.SynFlood.AttackThreshold, "200")
				if profile.TCP.SynFlood.AlarmThreshold > 0 {
					fmt.Fprintf(buf, "  %-45s %-12d %s\n", "  Alarm threshold", profile.TCP.SynFlood.AlarmThreshold, "512")
				} else {
					fmt.Fprintf(buf, "  %-45s %-12s %s\n", "  Alarm threshold", "(default)", "512")
				}
				if profile.TCP.SynFlood.SourceThreshold > 0 {
					fmt.Fprintf(buf, "  %-45s %-12d %s\n", "  Source threshold", profile.TCP.SynFlood.SourceThreshold, "4000")
				} else {
					fmt.Fprintf(buf, "  %-45s %-12s %s\n", "  Source threshold", "(default)", "4000")
				}
				if profile.TCP.SynFlood.DestinationThreshold > 0 {
					fmt.Fprintf(buf, "  %-45s %-12d %s\n", "  Destination threshold", profile.TCP.SynFlood.DestinationThreshold, "4000")
				} else {
					fmt.Fprintf(buf, "  %-45s %-12s %s\n", "  Destination threshold", "(default)", "4000")
				}
				if profile.TCP.SynFlood.Timeout > 0 {
					fmt.Fprintf(buf, "  %-45s %-12d %s\n", "  Timeout (seconds)", profile.TCP.SynFlood.Timeout, "20")
				} else {
					fmt.Fprintf(buf, "  %-45s %-12s %s\n", "  Timeout (seconds)", "(default)", "20")
				}
			} else {
				fmt.Fprintf(buf, "  %-45s %-12s %s\n", "TCP SYN flood protection", "disabled", "disabled")
			}
			fmt.Fprintf(buf, "  %-45s %-12s %s\n", "ICMP ping of death", enabledS(profile.ICMP.PingDeath), "disabled")
			if profile.ICMP.FloodThreshold > 0 {
				fmt.Fprintf(buf, "  %-45s %-12d %s\n", "ICMP flood threshold", profile.ICMP.FloodThreshold, "1000")
			} else {
				fmt.Fprintf(buf, "  %-45s %-12s %s\n", "ICMP flood threshold", "disabled", "disabled")
			}
			fmt.Fprintf(buf, "  %-45s %-12s %s\n", "IP source route option", enabledS(profile.IP.SourceRouteOption), "disabled")
			fmt.Fprintf(buf, "  %-45s %-12s %s\n", "IP teardrop", enabledS(profile.IP.TearDrop), "disabled")
			if profile.UDP.FloodThreshold > 0 {
				fmt.Fprintf(buf, "  %-45s %-12d %s\n", "UDP flood threshold", profile.UDP.FloodThreshold, "1000")
			} else {
				fmt.Fprintf(buf, "  %-45s %-12s %s\n", "UDP flood threshold", "disabled", "disabled")
			}
			// #3327: the detail table is a full-universe view (it lists every
			// check with its value AND default, including disabled ones), so it
			// cannot be driven by the enabled-only config.ScreenChecks list the
			// `show security zones`/`show security screen` summaries use.
			// Instead it must carry a row for every screen check so it never
			// drifts from the enforced/SSOT inventory. Before #3327 it omitted
			// these five rows even though the compiler and userspace dataplane
			// fully enforce them. The trailing token in each Name matches the
			// canonical config.ScreenCheck* inventory name.
			fmt.Fprintf(buf, "  %-45s %-12s %s\n", "ICMP fragment (icmp-fragment)", enabledS(profile.ICMP.Fragment), "disabled")
			if profile.TCP.PortScanThreshold > 0 {
				fmt.Fprintf(buf, "  %-45s %-12s %s\n", "TCP port scan window (port-scan)", fmt.Sprintf("%d us", profile.TCP.PortScanThreshold), "disabled")
			} else {
				fmt.Fprintf(buf, "  %-45s %-12s %s\n", "TCP port scan window (port-scan)", "disabled", "disabled")
			}
			if profile.IP.IPSweepThreshold > 0 {
				fmt.Fprintf(buf, "  %-45s %-12s %s\n", "IP sweep window (ip-sweep)", fmt.Sprintf("%d us", profile.IP.IPSweepThreshold), "disabled")
			} else {
				fmt.Fprintf(buf, "  %-45s %-12s %s\n", "IP sweep window (ip-sweep)", "disabled", "disabled")
			}
			if profile.LimitSession.SourceIPBased > 0 {
				fmt.Fprintf(buf, "  %-45s %-12d %s\n", "Session limit source (limit-session-source)", profile.LimitSession.SourceIPBased, "disabled")
			} else {
				fmt.Fprintf(buf, "  %-45s %-12s %s\n", "Session limit source (limit-session-source)", "disabled", "disabled")
			}
			if profile.LimitSession.DestinationIPBased > 0 {
				fmt.Fprintf(buf, "  %-45s %-12d %s\n", "Session limit destination (limit-session-destination)", profile.LimitSession.DestinationIPBased, "disabled")
			} else {
				fmt.Fprintf(buf, "  %-45s %-12s %s\n", "Session limit destination (limit-session-destination)", "disabled", "disabled")
			}
			var zones []string
			for name, zone := range cfg.Security.Zones {
				if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
					continue
				}
				if zone.ScreenProfile == profileName {
					zones = append(zones, name)
				}
			}
			if len(zones) > 0 {
				sort.Strings(zones)
				fmt.Fprintf(buf, "\n  Bound to zones: %s\n", strings.Join(zones, ", "))
			} else {
				fmt.Fprintf(buf, "\n  Bound to zones: (none)\n")
			}
		}
	}
	return &pb.ShowTextResponse{Output: buf.String()}, nil
}

// screenEnabledCheckList renders the enabled screen checks for a profile as a
// stable, SSOT-sourced list, each threshold-bearing token annotated with its
// configured value (e.g. "icmp-flood(threshold:1000)"). It is the single
// rendering of the enabled-screen inventory shared by the `show security zones`
// and `show security screen` text renderers so neither can drift from
// config.ScreenChecks / config.ScreenThresholds (#3327). Before #3327 each
// renderer hand-built its own presence list and silently omitted port-scan,
// ip-sweep, the source/destination session limits, and icmp-fragment even
// though the compiler and userspace dataplane fully enforce them.
func screenEnabledCheckList(profile *config.ScreenProfile) []string {
	// Delegate to the cross-package SSOT so the gRPC, REST, and local-CLI
	// enabled-check renderers share one rendering and cannot drift (#3327).
	return config.ScreenEnabledCheckList(profile)
}

func (s *Server) showScreen(cfg *config.Config, buf *strings.Builder) {
	// #5806: report unresolved screen-profile references FIRST, sharing the
	// local-CLI renderer's SSOT so the two cannot drift. The empty-Screen
	// branch below is the worst case for this: when the profile definitions are
	// absent entirely it says "No screen profiles configured", which reads as
	// "nothing was asked for" even though a zone still claims a screen and none
	// of that zone's screen checks are applied.
	//
	// Do not restore "forwarded unscreened" here (#6839 round 2). This PR removed
	// that framing from the operator-facing string and tests against it — see
	// dpuserspace.ScreenUnresolvedDisposition and the assertion in
	// server_show_screen_unresolved_5806_test.go — because it reads as a permit
	// and suggests the firewall is passing traffic it would otherwise deny. Zone
	// security policy still evaluates the packet normally; only the screen checks
	// are skipped. The comment shipped the removed wording anyway.
	for _, line := range dpuserspace.ScreenUnresolvedProfileLines(cfg) {
		buf.WriteString(line)
		buf.WriteString("\n")
	}
	// #7059: the THIRD state — defined but enabling no checks. See the local-CLI
	// renderer; same SSOT, same ordering requirement.
	for _, line := range dpuserspace.ScreenInertProfileLines(cfg) {
		buf.WriteString(line)
		buf.WriteString("\n")
	}
	if cfg == nil || len(cfg.Security.Screen) == 0 {
		buf.WriteString("No screen profiles configured\n")
	} else {
		// Build reverse map: profile name -> zones
		zonesByProfile := make(map[string][]string)
		for name, zone := range cfg.Security.Zones {
			if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
			if zone.ScreenProfile != "" {
				zonesByProfile[zone.ScreenProfile] = append(zonesByProfile[zone.ScreenProfile], name)
			}
		}
		var names []string
		for name := range cfg.Security.Screen {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			profile := cfg.Security.Screen[name]
			// #3476: skip a nil profile map value (tolerant / HA-sync path)
			// rather than dereferencing profile.TCP.Land below.
			if profile == nil {
				continue
			}
			fmt.Fprintf(buf, "Screen profile: %s\n", name)
			// #3327: drive the enabled-check inventory from the shared SSOT
			// (config.ScreenChecks / config.ScreenThresholds via
			// screenEnabledCheckList) instead of a hand-built presence list
			// that omitted port-scan, ip-sweep, the source/destination session
			// limits, and icmp-fragment — the same drift the structured
			// REST/gRPC inventory was fixed for. One line per enabled check,
			// threshold-bearing checks annotated with the configured value.
			for _, c := range screenEnabledCheckList(profile) {
				fmt.Fprintf(buf, "  %s\n", c)
			}
			if zones, ok := zonesByProfile[name]; ok {
				sort.Strings(zones)
				fmt.Fprintf(buf, "  Applied to zones: %s\n", strings.Join(zones, ", "))
			}
			buf.WriteString("\n")
		}
		// Per-type drop counters
		if s.dp != nil && s.dp.IsLoaded() {
			// #3345: surface a counter-read failure rather than printing a
			// clean zero that hides a degraded counter bridge.
			var readErr error
			readCtr := func(idx uint32) uint64 {
				v, err := s.dp.ReadGlobalCounter(idx)
				if err != nil && readErr == nil {
					readErr = err
				}
				return v
			}
			totalDrops := readCtr(dataplane.GlobalCtrScreenDrops)
			fmt.Fprintf(buf, "Total screen drops: %d\n", totalDrops)
			if totalDrops > 0 {
				// #3343: shared screen-reason table — port-scan / ip-sweep /
				// session-limit now appear in the per-reason breakdown.
				for i := range dataplane.ScreenReasonCounters {
					rc := &dataplane.ScreenReasonCounters[i]
					v := readCtr(rc.Index)
					if v > 0 {
						fmt.Fprintf(buf, "  %-25s %d\n", rc.Label+":", v)
					}
				}
			}
			// #3345: check AFTER all reads (incl. the per-type loop) so a
			// failure on a late read is surfaced, not just the first.
			if readErr != nil {
				fmt.Fprintf(buf, "warning: screen counter read failed (counters may be incomplete): %v\n", readErr)
			}
		}
	}
}

func (s *Server) showAlg(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
	} else {
		alg := cfg.Security.ALG
		fmt.Fprintf(buf, "SIP:  %s\n", boolStatus(!alg.SIPDisable))
		fmt.Fprintf(buf, "FTP:  %s\n", boolStatus(!alg.FTPDisable))
		fmt.Fprintf(buf, "TFTP: %s\n", boolStatus(!alg.TFTPDisable))
		fmt.Fprintf(buf, "DNS:  %s\n", boolStatus(!alg.DNSDisable))
	}
}

func (s *Server) showDynamicAddress(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.Security.DynamicAddress.FeedServers) == 0 {
		buf.WriteString("No dynamic address feeds configured\n")
	} else {
		var runtimeFeeds map[string]feeds.FeedInfo
		if s.feedsFn != nil {
			runtimeFeeds = s.feedsFn()
		}
		for name, feed := range cfg.Security.DynamicAddress.FeedServers {
			fmt.Fprintf(buf, "Feed server: %s\n", name)
			// Redact any embedded basic-auth userinfo / query-string token —
			// dynamic-address feeds routinely carry per-tenant bearer tokens in
			// the URL, and this render reaches read-only management clients and
			// command-output logs / support bundles (#5521).
			fmt.Fprintf(buf, "  URL: %s\n", config.RedactURL(feed.URL))
			if feed.FeedName != "" {
				fmt.Fprintf(buf, "  Feed name: %s\n", feed.FeedName)
			}
			if feed.UpdateInterval > 0 {
				fmt.Fprintf(buf, "  Update interval: %ds\n", feed.UpdateInterval)
			}
			if feed.HoldInterval > 0 {
				fmt.Fprintf(buf, "  Hold interval: %ds\n", feed.HoldInterval)
			}
			if fi, ok := runtimeFeeds[name]; ok {
				fmt.Fprintf(buf, "  Prefixes: %d\n", fi.Prefixes)
				if !fi.LastFetch.IsZero() {
					age := time.Since(fi.LastFetch).Truncate(time.Second)
					fmt.Fprintf(buf, "  Last fetch: %s (%s ago)\n", fi.LastFetch.Format("2006-01-02 15:04:05"), age)
				} else {
					fmt.Fprintf(buf, "  Last fetch: never\n")
				}
				if fi.Degraded {
					fmt.Fprintf(buf, "  DEGRADED: %d invalid line(s) skipped (partial set installed)\n", fi.InvalidLines)
					if len(fi.InvalidSample) > 0 {
						fmt.Fprintf(buf, "    Sample: %s\n", strings.Join(fi.InvalidSample, ", "))
					}
				}
			}
			buf.WriteString("\n")
		}
	}
}

func (s *Server) showAddressBook(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || cfg.Security.AddressBook == nil {
		buf.WriteString("No address book configured\n")
	} else {
		ab := cfg.Security.AddressBook
		if len(ab.Addresses) > 0 {
			buf.WriteString("Addresses:\n")
			for name, addr := range ab.Addresses {
				fmt.Fprintf(buf, "  %-20s %s\n", name, addr.Value)
			}
		}
		if len(ab.AddressSets) > 0 {
			buf.WriteString("Address sets:\n")
			for name, as := range ab.AddressSets {
				fmt.Fprintf(buf, "  %-20s members: %s\n", name, strings.Join(as.Addresses, ", "))
			}
		}
	}
}

func (s *Server) showIKE(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.Security.IPsec.Gateways) == 0 {
		buf.WriteString("No IKE gateways configured\n")
	} else {
		names := make([]string, 0, len(cfg.Security.IPsec.Gateways))
		for name := range cfg.Security.IPsec.Gateways {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			gw := cfg.Security.IPsec.Gateways[name]
			fmt.Fprintf(buf, "IKE gateway: %s\n", name)
			if gw.Address != "" {
				fmt.Fprintf(buf, "  Remote address:     %s\n", gw.Address)
			}
			if gw.DynamicHostname != "" {
				fmt.Fprintf(buf, "  Dynamic hostname:   %s\n", gw.DynamicHostname)
			}
			if gw.LocalAddress != "" {
				fmt.Fprintf(buf, "  Local address:      %s\n", gw.LocalAddress)
			}
			if gw.ExternalIface != "" {
				fmt.Fprintf(buf, "  External interface: %s\n", gw.ExternalIface)
			}
			if gw.LocalCertificate != "" {
				fmt.Fprintf(buf, "  Local certificate:  %s\n", gw.LocalCertificate)
			}
			if gw.IKEPolicy != "" {
				fmt.Fprintf(buf, "  IKE policy:         %s\n", gw.IKEPolicy)
				if pol, ok := cfg.Security.IPsec.IKEPolicies[gw.IKEPolicy]; ok {
					fmt.Fprintf(buf, "    Mode:     %s\n", pol.Mode)
					fmt.Fprintf(buf, "    Proposal: %s\n", strings.Join(pol.Proposals, " "))
				}
			}
			ver := gw.Version
			if ver == "" {
				ver = "v1+v2"
			}
			fmt.Fprintf(buf, "  IKE version:        %s\n", ver)
			if gw.DPDEnable || gw.DeadPeerDetect != "" {
				mode := gw.DeadPeerDetect
				if mode == "" {
					mode = "enabled"
				}
				fmt.Fprintf(buf, "  DPD:                %s\n", mode)
				if gw.DPDInterval > 0 {
					fmt.Fprintf(buf, "  DPD interval:       %ds\n", gw.DPDInterval)
				}
				if gw.DPDThreshold > 0 {
					fmt.Fprintf(buf, "  DPD threshold:      %d\n", gw.DPDThreshold)
				}
			}
			if gw.NoNATTraversal {
				buf.WriteString("  NAT-T:              disabled\n")
			} else if gw.NATTraversal == "force" {
				buf.WriteString("  NAT-T:              force\n")
			} else if gw.NATTraversal == "enable" {
				buf.WriteString("  NAT-T:              enabled\n")
			}
			if gw.LocalIDValue != "" {
				fmt.Fprintf(buf, "  Local identity:     %s %s\n", gw.LocalIDType, gw.LocalIDValue)
			}
			if gw.RemoteIDValue != "" {
				fmt.Fprintf(buf, "  Remote identity:    %s %s\n", gw.RemoteIDType, gw.RemoteIDValue)
			}
			buf.WriteString("\n")
		}
		// IKE proposals
		if len(cfg.Security.IPsec.IKEProposals) > 0 {
			pNames := make([]string, 0, len(cfg.Security.IPsec.IKEProposals))
			for name := range cfg.Security.IPsec.IKEProposals {
				pNames = append(pNames, name)
			}
			sort.Strings(pNames)
			buf.WriteString("IKE proposals:\n")
			for _, name := range pNames {
				p := cfg.Security.IPsec.IKEProposals[name]
				fmt.Fprintf(buf, "  %s: auth=%s enc=%s dh=group%d", name, p.AuthMethod, p.EncryptionAlg, p.DHGroup)
				if p.LifetimeSeconds > 0 {
					fmt.Fprintf(buf, " lifetime=%ds", p.LifetimeSeconds)
				}
				buf.WriteString("\n")
			}
		}
	}
}

// writeRPMConfig renders the configured RPM probe set (moved from
// server_show.go in #1700; consumed by showRPM and the rpm test).
func writeRPMConfig(buf *strings.Builder, cfg *config.Config) {
	if cfg == nil {
		buf.WriteString("No active configuration\n")
		return
	}
	if cfg.Services.RPM == nil || len(cfg.Services.RPM.Probes) == 0 {
		buf.WriteString("No RPM probes configured\n")
		return
	}

	buf.WriteString("RPM Probe Configuration:\n")
	for _, probeName := range rpm.SortedProbeNames(cfg.Services.RPM.Probes) {
		probe := cfg.Services.RPM.Probes[probeName]
		for _, testName := range rpm.SortedTestNames(probe.Tests) {
			rpm.WriteConfiguredTest(buf, probeName, testName, probe.Tests[testName])
			buf.WriteString("\n")
		}
	}
}

// showWireguard renders `show security wireguard [detail]` for the
// remote CLI from the userspace helper's per-tunnel telemetry rows
// (#1865). Shared rendering with the local CLI via
// dpformat.FormatWireguardStatus.
func (s *Server) showWireguard(buf *strings.Builder, detail bool) {
	// #2114/#6743 r2-B4: the publication check must ask the CELL, not the
	// field. `s.dp == nil` is permanently false under the daemon's live
	// indirection, so an emptied cell fell into the arm below and told the
	// operator the firewall is running a non-userspace dataplane — the
	// r6-F3 defect ("a claim about a LOADED backend for a daemon that had
	// just lost its backend") at a site the dpProbe() conversion left
	// behind. The only runtime forwarding path is the userspace helper
	// (#1373), so that answer names a backend class that cannot exist and
	// points the operator at `system dataplane-type` instead of at the arm
	// that failed.
	//
	// ONE resolution feeds both decisions, for the same reason showBuffers
	// takes exactly one (r7): a setDataplane(nil) landing between a
	// publication check and a separate probe re-creates the confusion the
	// check exists to prevent.
	backend := dataplane.Unwrap(s.dp)
	if backend == nil {
		buf.WriteString("Dataplane not loaded\n")
		return
	}
	provider, ok := backend.(userspaceStatusProvider)
	if !ok {
		buf.WriteString("WireGuard telemetry requires the userspace dataplane\n")
		return
	}
	status, err := provider.Status()
	if err != nil {
		fmt.Fprintf(buf, "WireGuard telemetry unavailable: %v\n", err)
		return
	}
	buf.WriteString(dpformat.FormatWireguardStatus(status, detail, time.Now()))
}

// showWireguardPublicKey renders `show security wireguard public-key`
// for the remote CLI (#1434 Increment 1): the local public key per WG
// tunnel in WireGuard-canonical base64. Shared rendering with the local
// CLI via dpformat.FormatWireguardPublicKeys.
func (s *Server) showWireguardPublicKey(buf *strings.Builder) {
	// #2114/#6743 r2-B4: same single-resolution publication check as
	// showWireguard — ask the cell, not the permanently non-nil field.
	backend := dataplane.Unwrap(s.dp)
	if backend == nil {
		buf.WriteString("Dataplane not loaded\n")
		return
	}
	provider, ok := backend.(userspaceStatusProvider)
	if !ok {
		buf.WriteString("WireGuard telemetry requires the userspace dataplane\n")
		return
	}
	status, err := provider.Status()
	if err != nil {
		fmt.Fprintf(buf, "WireGuard telemetry unavailable: %v\n", err)
		return
	}
	buf.WriteString(dpformat.FormatWireguardPublicKeys(status))
}
