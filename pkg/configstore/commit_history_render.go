package configstore

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/termsafe"
)

// RenderCommitHistory renders `show system commit history` most-recent-first
// (#16721), shared by the in-process CLI and the gRPC ShowText renderer so
// the two surfaces cannot diverge. Each history-pushing row is labelled
// with its Junos rollback label (see CommitHistoryRow: label k names
// the commit `rollback k` restores); rows without a label
// (commit_confirm, auto_rollback, rotated-out commits) print a blank
// label. Principal is rendered termsafe-escaped so a legacy or
// confirmation row names its actor without forging lines. While a
// commit-confirmed window is pending a trailing "<rollback pending>"
// line is printed (Junos parity); it disappears once the window is
// confirmed or rolled back because IsConfirmPending then reads false.
func RenderCommitHistory(rows []CommitHistoryRow, confirmPending bool) string {
	if len(rows) == 0 && !confirmPending {
		return "No commit history available\n"
	}
	var b strings.Builder
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		e := r.Entry
		label := "  "
		if r.RollbackSlot >= 0 {
			label = fmt.Sprintf("%2d", r.RollbackSlot)
		}
		detail := ""
		if e.Detail != "" {
			// #15144: legacy journal lines may carry control
			// characters; escape Detail so one entry renders as
			// one line (new descriptions are rejected at commit).
			detail = "  " + termsafe.SanitizeForDisplay(e.Detail)
		}
		principal := termsafe.SanitizeForDisplay(e.Principal)
		fmt.Fprintf(&b, "  %s  %s  %s  %s%s\n", label, e.Timestamp.Format("2006-01-02 15:04:05"), e.Action, principal, detail)
	}
	if confirmPending {
		b.WriteString("<rollback pending>\n")
	}
	return b.String()
}
