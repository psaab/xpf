package ipmon

import (
	"fmt"
	"io"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// riName renders a routing-instance for display, defaulting the empty
// (main) instance to inet.0.
func riName(ri string) string {
	if ri == "" {
		return "inet.0"
	}
	return ri
}

// FormatStatus renders `show services ip-monitoring status` so the
// local CLI and the gRPC text-show surface stay byte-identical.
func FormatStatus(w io.Writer, statuses []PolicyStatus) {
	if len(statuses) == 0 {
		fmt.Fprintln(w, "No IP monitoring policies configured")
		return
	}
	for _, ps := range statuses {
		// #3761 H7: an unknown health (no probe result yet) is NOT PASS —
		// reporting PASS would tell an operator failover protection is
		// active and healthy when no probe has run. #16632 A49-02: a
		// PARTIAL health (some tests have verdicts, others have never
		// been measured) is not PASS either — the verdict-less tests
		// are named as UNKNOWN rows below instead of hidden behind a
		// wildcard "* PASS" row.
		state := "PASS"
		switch {
		case ps.Failed:
			state = "FAIL"
		case len(ps.UnknownTests) > 0 && (len(ps.PassingTests) > 0 || len(ps.FailingTests) > 0):
			// Mixed: some tests measured, some never (#16632).
			state = "PARTIAL"
		case len(ps.UnknownTests) > 0:
			state = "UNKNOWN"
		case !ps.Known:
			state = "UNKNOWN"
		}
		fmt.Fprintf(w, "Policy - %s (Status: %s)\n", ps.Name, state)
		fmt.Fprintf(w, "  RPM Probes:\n")
		fmt.Fprintf(w, "    Probe name           Test Name        Address          Status\n")
		fmt.Fprintf(w, "    ---------------------- --------------- ---------------- ---------\n")
		if len(ps.FailingTests) == 0 && len(ps.UnknownTests) == 0 && len(ps.PassingTests) == 0 {
			rowStatus := "PASS"
			if !ps.Known {
				rowStatus = "UNKNOWN"
			}
			fmt.Fprintf(w, "    %-22s %-15s %-16s %s\n", ps.Probe, "*", "-", rowStatus)
		} else {
			for _, test := range ps.PassingTests {
				fmt.Fprintf(w, "    %-22s %-15s %-16s %s\n", ps.Probe, test, "-", "PASS")
			}
			for _, test := range ps.FailingTests {
				fmt.Fprintf(w, "    %-22s %-15s %-16s %s\n", ps.Probe, test, "-", "FAIL")
			}
			for _, test := range ps.UnknownTests {
				fmt.Fprintf(w, "    %-22s %-15s %-16s %s\n", ps.Probe, test, "-", "UNKNOWN")
			}
		}

		// #3761 H8/M9/M10: distinguish APPLIED (live in the FIB) from
		// PENDING (desired, actuation not yet converged), SUPPRESSED (lost
		// winner resolution to another policy), and UNRESOLVED (no DHCP
		// next-hop). A bare "(none applied)" hid all three apart.
		appliedKey := func(r config.RouteOverlayEntry) string {
			return r.RoutingInstance + "|" + r.Destination + "|" + r.NextHop
		}
		applied := make(map[string]bool, len(ps.AppliedRoutes))
		for _, r := range ps.AppliedRoutes {
			applied[appliedKey(r)] = true
		}
		rows := len(ps.Routes) + len(ps.SuppressedRoutes) + len(ps.UnresolvedRoutes)
		fmt.Fprintf(w, "  Route-Action%s:\n", pluralSuffix(rows))
		if rows == 0 {
			fmt.Fprintf(w, "    (none applied)\n")
		} else {
			fmt.Fprintf(w, "    route-instance    route             next-hop         state\n")
			fmt.Fprintf(w, "    ----------------- ----------------- ---------------- --------------------\n")
			for _, r := range ps.Routes {
				st := "PENDING"
				if applied[appliedKey(r)] {
					st = "APPLIED"
				}
				fmt.Fprintf(w, "    %-17s %-17s %-16s %s\n", riName(r.RoutingInstance), r.Destination, r.NextHop, st)
			}
			for _, s := range ps.SuppressedRoutes {
				fmt.Fprintf(w, "    %-17s %-17s %-16s suppressed by policy %s\n",
					riName(s.RoutingInstance), s.Destination, s.NextHop, s.WinnerPolicy)
			}
			// #1844/#3761 M9: interface-typed routes whose DHCP gateway is
			// currently unknown are skipped from the overlay — surface the
			// routing-instance + tracked unit + reason so the operator sees
			// WHICH unit is missing, not just the prefix.
			for _, u := range ps.UnresolvedRoutes {
				fmt.Fprintf(w, "    %-17s %-17s %-16s unresolved (%s) — skipped\n",
					riName(u.RoutingInstance), u.Destination, u.NextHopInterface, u.Reason)
			}
		}
		if !ps.Since.IsZero() {
			fmt.Fprintf(w, "  Last state change: %s\n", ps.Since.Format("2006-01-02 15:04:05"))
		}
		if !ps.PendingRecoveryAt.IsZero() {
			fmt.Fprintf(w, "  Recovery hold-down expires in %s\n",
				time.Until(ps.PendingRecoveryAt).Round(time.Second))
		}
		fmt.Fprintf(w, "  Transitions: %d\n", ps.Transitions)
		fmt.Fprintln(w)
	}
}

func pluralSuffix(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
