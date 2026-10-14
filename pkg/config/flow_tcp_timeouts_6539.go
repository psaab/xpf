package config

// #6539: the `security flow tcp-session <kind>-timeout` leaves, and whether
// each one actually reaches the userspace AF_XDP dataplane.
//
// MECHANISM. buildFlowSnapshot (pkg/dataplane/userspace/flow.go) lowers a set
// value into FlowSnapshot and the helper reads it back into SessionTimeouts
// (userspace-dp/src/session/mod.rs). A leaf with no wire carrier, or with a
// carrier but no live consumer on the far side, is committed and stored and
// goes no further. The failure mode that motivated this file is that such a
// leaf is INDISTINGUISHABLE on a `show` surface from one that works: before
// #6539 all three operator surfaces printed every leaf in the same shape, so a
// deliberate hardening action looked applied while doing nothing. That is worse
// than a plainly unimplemented feature, because the surface an operator checks
// AFTER committing confirms the false belief.
//
// The table below is the SINGLE authority for which leaves are enforced, and
// the three render surfaces read it: surfaces disagreeing about whether a knob
// is enforced is always a bug and never a legitimate divergence, so they share
// one authority rather than each carrying a copy of the wording. A commit-time
// advisory read this table from #6539 until #8129 deleted it — its deferral
// was "one release past the boundary", v0.9.3 shipped 2026-03 and master is
// far past it — so the render surfaces are the table's only readers now.
//
// Do not restate the table's contents in prose anywhere, including here. The
// enforced/unenforced split changed once already (#7342) and every sentence
// that had restated it — a file header, a type doc, three field comments, and
// a function doc that ended up contradicting the switch four lines below it —
// silently became false. Nothing binds prose to a table, and nothing cheaply
// can; one statement of the fact is the fix.

// Junos leaf names under `security flow tcp-session`. Callers key the
// enforcement table by these rather than by a bare string literal.
const (
	TCPSessionEstablishedTimeoutLeaf = "established-timeout"
	TCPSessionInitialTimeoutLeaf     = "initial-timeout"
	TCPSessionClosingTimeoutLeaf     = "closing-timeout"
	TCPSessionTimeWaitTimeoutLeaf    = "time-wait-timeout"
)

// Fixed session windows the three unenforced leaves would have controlled.
// These MIRROR userspace-dp/src/session/mod.rs, which is the source of truth:
//
//	DEFAULT_TCP_OPENING_TIMEOUT_NS = 20_000_000_000  // half-open / OPENING
//	TCP_CLOSING_TIMEOUT_NS         = 30_000_000_000  // graceful FIN close
//	TCP_RST_TIMEOUT_NS             =  2_000_000_000  // RST abort
//
// They are quoted in operator-facing text, so flow_tcp_timeouts_6539_test.go
// re-reads the Rust constants and fails if either side drifts — otherwise the
// annotation added here to stop one false claim would quietly become another.
const (
	DataplaneTCPEstablishedWindowSecs = 300
	DataplaneTCPOpeningWindowSecs     = 20
	DataplaneTCPClosingWindowSecs     = 30
	DataplaneTCPRSTWindowSecs         = 2
)

// TCPSessionTimeoutDataplaneDefault returns the window the dataplane actually
// applies for leaf when the operator has NOT set it, and whether such a window
// exists at all.
//
// It exists because "default" on a `show` surface is itself an enforcement
// claim, and the CLI's were wrong in the same way the missing annotation was:
// it printed established-timeout's Junos default of 1800s, but nothing in the
// Go path ever fills that in — an unset leaf lowers as 0 and the helper falls
// back to its own constant, so the session actually idles out at 300s. Report
// the DATAPLANE's fallback here, never the Junos book value.
//
// The second return distinguishes "this leaf has no window to report" from a
// zero-valued one. Which leaves those are is the switch below; it is not
// restated in this comment.
func TCPSessionTimeoutDataplaneDefault(leaf string) (int, bool) {
	switch leaf {
	case TCPSessionEstablishedTimeoutLeaf:
		return DataplaneTCPEstablishedWindowSecs, true
	case TCPSessionInitialTimeoutLeaf:
		return DataplaneTCPOpeningWindowSecs, true
	case TCPSessionClosingTimeoutLeaf:
		return DataplaneTCPClosingWindowSecs, true
	case TCPSessionTimeWaitTimeoutLeaf:
		// #7342: TIME_WAIT now exists as a distinct state, so it has a default
		// window to report. It is the same value as closing-timeout's, and
		// deliberately so: an operator who sets neither leaf must see exactly
		// the reaping they saw before the state was split, and before #7342
		// every post-FIN close — half or fully closed — reaped on this one
		// window.
		return DataplaneTCPClosingWindowSecs, true
	default:
		return 0, false
	}
}

// TCPSessionTimeoutEnforcement describes whether one `security flow
// tcp-session` timeout leaf reaches the userspace AF_XDP dataplane.
type TCPSessionTimeoutEnforcement struct {
	// Leaf is the Junos leaf name, e.g. "initial-timeout".
	Leaf string
	// Enforced is true only when the value has BOTH a wire carrier and a live
	// dataplane consumer. A leaf that is merely modeled and committed is not
	// enforced, however faithfully it round-trips through the config store.
	Enforced bool
	// Note is the suffix a `show` surface renders beside a configured value.
	// Empty when Enforced. It names the SPECIFIC consequence rather than a
	// generic "no effect" (the #5804 rule): an operator who set the knob needs
	// to know which window is actually in force, not merely that theirs is not.
	Note string
}

// tcpSessionTimeoutEnforcement is the table itself, in Junos config order.
// #7342: all four are enforced. The three that were not each needed a
// different thing, and the order matters for why this is one change:
//
//   - initial-timeout and closing-timeout needed only a wire carrier — they map
//     1:1 onto windows the dataplane already had (`tcp_opening_ns`, and the
//     post-FIN window);
//   - time-wait-timeout needed a STATE first. `session_timeout_ns` split a TCP
//     close only into RST and not-RST, so there was no TIME_WAIT window
//     distinct from closing-timeout's, and a carrier would have had nothing to
//     drive. `SessionEntry` now tracks a FIN per DIRECTION, so a close with a
//     FIN in both is TIME_WAIT and a close with one is CLOSING.
//
// Carrying all three behind one additive wire bump is why this is one protocol
// change, one cluster smoke and one release note rather than three.
var tcpSessionTimeoutEnforcement = []TCPSessionTimeoutEnforcement{
	{Leaf: TCPSessionEstablishedTimeoutLeaf, Enforced: true},
	{Leaf: TCPSessionInitialTimeoutLeaf, Enforced: true},
	{Leaf: TCPSessionClosingTimeoutLeaf, Enforced: true},
	{Leaf: TCPSessionTimeWaitTimeoutLeaf, Enforced: true},
}

// TCPSessionTimeoutLeaves returns the enforcement table in Junos config order.
func TCPSessionTimeoutLeaves() []TCPSessionTimeoutEnforcement {
	out := make([]TCPSessionTimeoutEnforcement, len(tcpSessionTimeoutEnforcement))
	copy(out, tcpSessionTimeoutEnforcement)
	return out
}

// TCPSessionTimeoutNote returns the render suffix for leaf: "" when the leaf is
// enforced (or unknown — an unknown leaf is not something a surface may
// annotate on a guess). Render surfaces call this instead of hard-coding the
// enforced/unenforced split, so a leaf that later gains a wire carrier stops
// being annotated everywhere at once.
func TCPSessionTimeoutNote(leaf string) string {
	for _, e := range tcpSessionTimeoutEnforcement {
		if e.Leaf == leaf {
			return e.Note
		}
	}
	return ""
}

// unenforcedTCPSessionTimeouts returns the configured-but-unenforced timeout
// leaves of ts, in config order. A leaf is "configured" only when positive: 0
// means unset, and reporting a knob the operator never set is noise that
// trains them to ignore the report.
func unenforcedTCPSessionTimeouts(ts *TCPSessionConfig) []string {
	return unenforcedTCPSessionTimeoutsIn(tcpSessionTimeoutEnforcement, ts)
}

// unenforcedTCPSessionTimeoutsIn is the body, against a caller-supplied table.
//
// #7342 made every entry in the production table `Enforced`, and #8129 deleted
// the commit-time advisory that consumed this, so against the production table
// it selects nothing and no production caller remains. It is kept rather than
// deleted because `TestTCPSessionTimeoutTableCoversSchema_6539` exists
// precisely so that a FIFTH timeout leaf added to the schema cannot render
// unannotated and unadvised; that leaf's advisory will need this selection,
// and deleting the machinery would remove the thing that test protects.
// Taking the table as a parameter is what lets a test drive it with a synthetic
// unenforced leaf, so the mechanism stays proven while the production data no
// longer exercises it.
func unenforcedTCPSessionTimeoutsIn(
	table []TCPSessionTimeoutEnforcement,
	ts *TCPSessionConfig,
) []string {
	if ts == nil {
		return nil
	}
	set := map[string]int{
		TCPSessionInitialTimeoutLeaf:  ts.InitialTimeout,
		TCPSessionClosingTimeoutLeaf:  ts.ClosingTimeout,
		TCPSessionTimeWaitTimeoutLeaf: ts.TimeWaitTimeout,
	}
	var out []string
	for _, e := range table {
		if e.Enforced {
			continue
		}
		if set[e.Leaf] > 0 {
			out = append(out, e.Leaf)
		}
	}
	return out
}

// AnnotateTCPSessionTimeout appends leaf's not-enforced annotation to an
// already-rendered timeout cell (e.g. "45s", or the CLI's "30s (default)"),
// and returns the cell unchanged when leaf IS enforced.
//
// The three `show security flow ...` surfaces compose their own value text —
// they use different column widths and the CLI additionally marks defaults —
// but they must not each spell the annotation themselves: a REST reader and a
// CLI reader disagreeing about whether a knob is enforced is always a bug.
// Routing every surface through this one function makes the annotation
// byte-identical everywhere and retires it from all three at once on the day
// the leaf gains a wire carrier.
func AnnotateTCPSessionTimeout(leaf, rendered string) string {
	note := TCPSessionTimeoutNote(leaf)
	if note == "" {
		return rendered
	}
	return rendered + " (" + note + ")"
}
