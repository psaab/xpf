package natpoolalarm

import (
	"fmt"
	"io"
)

// RenderAlarms writes the active NAT pool-utilization alarms to w in the
// `show security alarms` style shared by both the gRPC text render
// (server_show_security_text.go) and the local CLI render
// (cli_show_security.go), so the two sites cannot diverge. It follows the
// existing count-in-summary, body-in-detail convention: in detail mode it
// writes one numbered "Alarm N:" block per alarm; in summary mode it writes
// nothing (the caller prints only the aggregate count). The alarms are
// numbered starting at startCount+1; the returned int is the running count
// after these alarms, which the caller uses to continue numbering and to
// decide the summary line.
//
// alarms must already be sorted (Monitor.ActiveAlarms returns a sorted
// snapshot). A nil/empty slice writes nothing and returns startCount.
func RenderAlarms(w io.Writer, alarms []ActiveAlarm, startCount int, detail bool) int {
	count := startCount
	for _, a := range alarms {
		count++
		if detail {
			fmt.Fprintf(w,
				"Alarm %d:\n  Class: NAT\n  Severity: Minor\n  Description: NAT source pool %s utilization %d%% exceeds raise-threshold %d%%\n",
				count, a.PoolName, a.CurrentPct, a.RaiseThreshold)
			if !a.FirstSeen.IsZero() {
				fmt.Fprintf(w, "  First seen: %s\n", a.FirstSeen.Format("2006-01-02 15:04:05"))
			}
			fmt.Fprintf(w, "\n")
		}
	}
	return count
}

// RenderExhaustionAlarms writes the active NAT pool-exhaustion alarms
// (#9902 F-026) in the same `show security alarms` style as RenderAlarms,
// shared by both render sites so the two cannot diverge. Numbering continues
// from startCount exactly like RenderAlarms; the returned int is the running
// count after these alarms.
//
// alarms must already be sorted (Monitor.ActiveExhaustionAlarms returns a
// sorted snapshot). A nil/empty slice writes nothing and returns startCount.
func RenderExhaustionAlarms(w io.Writer, alarms []ActiveExhaustionAlarm, startCount int, detail bool) int {
	count := startCount
	for _, a := range alarms {
		count++
		if detail {
			fmt.Fprintf(w,
				"Alarm %d:\n  Class: NAT\n  Severity: Minor\n  Description: NAT source pool %s allocator-reported exhaustion events: %d (most recent sample)\n",
				count, a.PoolName, a.Events)
			if !a.FirstSeen.IsZero() {
				fmt.Fprintf(w, "  First seen: %s\n", a.FirstSeen.Format("2006-01-02 15:04:05"))
			}
			fmt.Fprintf(w, "\n")
		}
	}
	return count
}
