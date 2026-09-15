package cli

import (
	"fmt"
	"os"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/natpoolalarm"
)

func (c *CLI) showSecurityLog(args []string) error {
	if c.eventBuf == nil {
		fmt.Println("no events (event buffer not initialized)")
		return nil
	}

	cr := c.applyResult()

	// Parse arguments: [N] [zone <name>] [protocol <proto>] [action <act>].
	//
	// The grammar is owned by logging.ParseEventFilterArgs (#3547) so the
	// local CLI and the remote `cli` gRPC text path share one parser and
	// cannot drift. Parsing fails CLOSED (#3347): an unknown token, a filter
	// keyword with no value, a non-positive count, or an unresolvable named
	// zone is a usage error — never silently ignored. A typo (`show security
	// log zon trust`) or a bare trailing keyword (`show security log action`)
	// used to fall through to an unfiltered dump of every event; in incident
	// response, silently widening a scoped forensic query is worse than
	// refusing it. The unknown/none/0 sentinels select the unassigned zone 0
	// (#3338); a named zone filter requires the apply result for name -> ID
	// resolution (M02).
	var zoneIDs map[string]uint16
	if cr != nil {
		zoneIDs = cr.ZoneIDs
	}
	n, filter, err := logging.ParseEventFilterArgs(args, zoneIDs, cr != nil)
	if err != nil {
		return err
	}

	var events []logging.EventRecord
	if !filter.IsEmpty() {
		events = c.eventBuf.LatestFiltered(n, filter)
	} else {
		events = c.eventBuf.Latest(n)
	}
	if len(events) == 0 {
		fmt.Println("no events recorded")
		return nil
	}

	// Build reverse zone ID → name map from the CURRENT config. This is only a
	// fallback for legacy records that lack a resolved-at-event-time name
	// (#3335): each EventRecord stores InZoneName/OutZoneName as resolved when
	// the event fired, so a later zone rename / delete / ID reuse (#3075) must
	// NOT retroactively rewrite an old event's zone name from the live config.
	// Prefer the stored name; consult this map (then a bare numeric fallback)
	// only when the record carries no resolved name.
	evZoneNames := make(map[uint16]string)
	if cr != nil {
		for name, id := range cr.ZoneIDs {
			evZoneNames[id] = name
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

	policyName := func(e logging.EventRecord) string {
		if e.PolicyName != "" {
			return e.PolicyName
		}
		return fmt.Sprintf("%d", e.PolicyID)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}

	for _, e := range events {
		ts := e.Time.Format("2006-01-02T15:04:05")

		// Parse source/destination address:port
		srcAddr, srcPort := splitAddrPort(e.SrcAddr)
		dstAddr, dstPort := splitAddrPort(e.DstAddr)
		natSrcAddr, natSrcPort := splitAddrPort(e.NATSrcAddr)
		natDstAddr, natDstPort := splitAddrPort(e.NATDstAddr)
		if natSrcAddr == "" {
			natSrcAddr = srcAddr
			natSrcPort = srcPort
		}
		if natDstAddr == "" {
			natDstAddr = dstAddr
			natDstPort = dstPort
		}

		inIface := e.IngressIface
		if inIface == "" {
			inIface = zoneName(e.InZoneName, e.InZone)
		}
		appName := e.AppName
		if appName == "" {
			appName = "UNKNOWN"
		}

		switch e.Type {
		case "SESSION_OPEN":
			fmt.Printf("%s %s RT_FLOW - RT_FLOW_SESSION_CREATE [source-address=\"%s\" source-port=\"%s\" destination-address=\"%s\" destination-port=\"%s\" nat-source-address=\"%s\" nat-source-port=\"%s\" nat-destination-address=\"%s\" nat-destination-port=\"%s\" protocol-id=\"%s\" policy-name=\"%s\" source-zone-name=\"%s\" destination-zone-name=\"%s\" session-id-32=\"%d\" application=\"%s\" packet-incoming-interface=\"%s\"]\n",
				ts, hostname, srcAddr, srcPort, dstAddr, dstPort,
				natSrcAddr, natSrcPort, natDstAddr, natDstPort,
				protoNameToID(e.Protocol), policyName(e),
				zoneName(e.InZoneName, e.InZone), zoneName(e.OutZoneName, e.OutZone),
				e.SessionID, appName, inIface)

		case "SESSION_CLOSE":
			reason := e.CloseReason
			if reason == "" {
				reason = "N/A"
			}
			fmt.Printf("%s %s RT_FLOW - RT_FLOW_SESSION_CLOSE [reason=\"%s\" source-address=\"%s\" source-port=\"%s\" destination-address=\"%s\" destination-port=\"%s\" nat-source-address=\"%s\" nat-source-port=\"%s\" nat-destination-address=\"%s\" nat-destination-port=\"%s\" protocol-id=\"%s\" policy-name=\"%s\" source-zone-name=\"%s\" destination-zone-name=\"%s\" session-id-32=\"%d\" packets-from-client=\"%d\" bytes-from-client=\"%d\" packets-from-server=\"%d\" bytes-from-server=\"%d\" elapsed-time=\"%d\" application=\"%s\" packet-incoming-interface=\"%s\"]\n",
				ts, hostname, reason, srcAddr, srcPort, dstAddr, dstPort,
				natSrcAddr, natSrcPort, natDstAddr, natDstPort,
				protoNameToID(e.Protocol), policyName(e),
				zoneName(e.InZoneName, e.InZone), zoneName(e.OutZoneName, e.OutZone),
				e.SessionID, e.SessionPkts, e.SessionBytes,
				e.RevSessionPkts, e.RevSessionBytes, e.ElapsedTime,
				appName, inIface)

		case "POLICY_DENY", "POLICY_REJECT":
			fmt.Printf("%s %s RT_FLOW - RT_FLOW_SESSION_DENY [source-address=\"%s\" source-port=\"%s\" destination-address=\"%s\" destination-port=\"%s\" protocol-id=\"%s\" policy-name=\"%s\" source-zone-name=\"%s\" destination-zone-name=\"%s\" application=\"%s\" packet-incoming-interface=\"%s\"]\n",
				ts, hostname, srcAddr, srcPort, dstAddr, dstPort,
				protoNameToID(e.Protocol), policyName(e),
				zoneName(e.InZoneName, e.InZone), zoneName(e.OutZoneName, e.OutZone),
				appName, inIface)

		case "SCREEN_DROP":
			fmt.Printf("%s %s RT_IDS - RT_SCREEN_DROP [attack-name=\"%s\" source-address=\"%s\" destination-address=\"%s\" protocol-id=\"%s\" source-zone-name=\"%s\" action=\"%s\"]\n",
				ts, hostname, e.ScreenCheck, srcAddr, dstAddr,
				protoNameToID(e.Protocol), zoneName(e.InZoneName, e.InZone), e.Action)

		default:
			// Fallback for other event types
			fmt.Printf("%s %s RT_FLOW - %s [source-address=\"%s\" source-port=\"%s\" destination-address=\"%s\" destination-port=\"%s\" protocol-id=\"%s\" policy-name=\"%s\" source-zone-name=\"%s\" destination-zone-name=\"%s\" application=\"%s\" packet-incoming-interface=\"%s\"]\n",
				ts, hostname, e.Type, srcAddr, srcPort, dstAddr, dstPort,
				protoNameToID(e.Protocol), policyName(e),
				zoneName(e.InZoneName, e.InZone), zoneName(e.OutZoneName, e.OutZone),
				appName, inIface)
		}
	}
	fmt.Printf("(%d events shown)\n", len(events))
	return nil
}

func (c *CLI) showSecurityAlarms(args []string) error {
	detail := len(args) >= 1 && args[0] == "detail"

	cfg := c.store.ActiveConfig()
	var alarmCount int

	// Config validation warnings
	if cfg != nil {
		warnings := config.ValidateConfig(cfg)
		for _, w := range warnings {
			alarmCount++
			if detail {
				fmt.Printf("Alarm %d:\n  Class: Configuration\n  Severity: Warning\n  Description: %s\n\n", alarmCount, w)
			}
		}
	}

	// Screen drop alarms — any non-zero screen counter indicates detected attacks
	if c.dp != nil && c.dp.IsLoaded() {
		// #3345: track a counter-read failure so a degraded counter bridge
		// is reported as a warning rather than masquerading as "no alarms".
		var readErr error
		readCtr := func(idx uint32) uint64 {
			v, err := c.dp.ReadGlobalCounter(idx)
			if err != nil && readErr == nil {
				readErr = err
			}
			return v
		}
		// #3343: iterate the shared screen-reason table so port-scan, ip-sweep,
		// and session-limit raise alarms too (they were omitted before, so an
		// active scan/sweep/session-limit attack read "No security alarms
		// currently active"), and the reason set matches the other surfaces.
		for i := range dataplane.ScreenReasonCounters {
			rc := &dataplane.ScreenReasonCounters[i]
			val := readCtr(rc.Index)
			if val > 0 {
				alarmCount++
				if detail {
					fmt.Printf("Alarm %d:\n  Class: IDS\n  Severity: Major\n  Description: %s attack detected (%d drops)\n\n", alarmCount, rc.Label, val)
				}
			}
		}
		if readErr != nil {
			fmt.Printf("warning: screen counter read failed (alarms may be incomplete): %v\n", readErr)
		}
	}

	// #2079: NAT source pool-utilization alarms from the daemon monitor.
	if c.natPoolAlarmsFn != nil {
		alarmCount = natpoolalarm.RenderAlarms(os.Stdout, c.natPoolAlarmsFn(), alarmCount, detail)
	}
	// #9902 F-026: NAT source pool-exhaustion alarms from the daemon monitor.
	if c.natPoolExhaustionAlarmsFn != nil {
		alarmCount = natpoolalarm.RenderExhaustionAlarms(os.Stdout, c.natPoolExhaustionAlarmsFn(), alarmCount, detail)
	}

	if alarmCount == 0 {
		fmt.Println("No security alarms currently active")
	} else if !detail {
		fmt.Printf("%d security alarm(s) currently active\n", alarmCount)
		fmt.Println("  run 'show security alarms detail' for details")
	}

	return nil
}
