package config

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// #6539 recorded that `security flow tcp-session
// initial/closing/time-wait-timeout` were modeled, parsed and committable but
// had NO dataplane wire carrier, while REST, CLI and gRPC printed them in the
// same shape as the one leaf that IS carried. #7342 carried all three and made
// them live, so the half of these tests that pinned "not enforced" now pins the
// opposite — that is the fix landing, not a guard being loosened.
//
// What did NOT change is the reason the file exists: the enforcement table is
// the single authority the three render surfaces read, it must stay in
// agreement with the schema, and its operator-facing text must keep quoting
// the Rust constants it claims to. Those cells are untouched, and the
// unenforced-selection MECHANISM is still exercised — against a synthetic
// table — because it is what a fifth timeout leaf's advisory would fall into.
// The commit-time advisory itself (#6539, inverted by #7342) was deleted by
// #8129, and so were the cells that pinned its text.

// The unenforced-selection MECHANISM must still work, because it is what a
// fifth timeout leaf's advisory would fall into. #7342 left the production
// table with nothing unenforced, so this drives the body against a SYNTHETIC
// table — otherwise the path is inert code whose claims nothing checks, and it
// would rot until the next leaf silently reproduced #6539. (#8129 deleted the
// #7342 commit-time advisory; the selection machinery it was built on is what
// stays, so the next advisory starts from a proven base.)
func TestTCPSessionTimeoutAdvisoryMechanismStillWorks_7342(t *testing.T) {
	synthetic := []TCPSessionTimeoutEnforcement{
		{Leaf: TCPSessionEstablishedTimeoutLeaf, Enforced: true},
		{Leaf: TCPSessionInitialTimeoutLeaf, Note: "synthetic"},
		{Leaf: TCPSessionClosingTimeoutLeaf, Enforced: true},
		{Leaf: TCPSessionTimeWaitTimeoutLeaf, Note: "synthetic"},
	}
	ts := &TCPSessionConfig{
		EstablishedTimeout: 600,
		InitialTimeout:     45,
		ClosingTimeout:     15,
		// TimeWaitTimeout deliberately UNSET: the helper reports only leaves the
		// operator actually configured, and a version that reported every
		// unenforced leaf regardless would pass a fixture that set them all.
	}
	got := unenforcedTCPSessionTimeoutsIn(synthetic, ts)
	want := []string{TCPSessionInitialTimeoutLeaf}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("unenforcedTCPSessionTimeoutsIn = %v, want %v — the selection body no longer "+
			"selects configured-AND-unenforced leaves, so a fifth leaf would render unannotated",
			got, want)
	}
	// And the production table selects nothing — every leaf is enforced since
	// #7342, so there is nothing left to advise about.
	if live := unenforcedTCPSessionTimeouts(ts); len(live) != 0 {
		t.Fatalf("production table still reports unenforced leaves %v after #7342", live)
	}
}

// The enforcement table must cover EVERY value-bearing `<kind>-timeout` leaf
// the set-schema declares under tcp-session. Without this, adding a fifth
// timeout leaf to the schema would render it through the surfaces with no
// annotation — silently reproducing #6539 for the new leaf. (There is no
// commit-time backstop any more: #8129 deleted the #7342 advisory, so the
// render annotation is the surface that catches it.)
func TestTCPSessionTimeoutTableCoversSchema_6539(t *testing.T) {
	node := setSchema
	for _, key := range []string{"security", "flow", "tcp-session"} {
		next, ok := node.children[key]
		if !ok {
			t.Fatalf("set-schema path %q not found (schema moved?)", key)
		}
		node = next
	}

	covered := map[string]bool{}
	for _, e := range TCPSessionTimeoutLeaves() {
		covered[e.Leaf] = true
	}

	found := 0
	for leaf, child := range node.children {
		if !strings.HasSuffix(leaf, "-timeout") {
			continue // presence flags — the #2078 advisory owns those
		}
		found++
		if child.args != 1 {
			t.Errorf("schema leaf %q takes %d args, want 1 (not a value leaf?)", leaf, child.args)
		}
		if !covered[leaf] {
			t.Errorf("schema declares tcp-session %q but the #6539 enforcement table does not cover it — "+
				"it would render with no enforcement annotation", leaf)
		}
	}
	if found != len(covered) {
		t.Errorf("schema declares %d tcp-session *-timeout leaves, table covers %d", found, len(covered))
	}
	if found == 0 {
		t.Fatal("found no tcp-session *-timeout leaves in the schema — the walk is vacuous")
	}
}

// #7342: EVERY tcp-session timeout leaf is enforced, so none may carry a
// render annotation and every one must render its value unannotated.
//
// The invariant this really pins is the two-way agreement — enforced implies no
// note, unenforced implies a note AND an annotated cell — which is what keeps
// the three surfaces from disagreeing with each other. #7342 changes which
// side of it each leaf sits on, not the invariant.
func TestTCPSessionTimeoutTableEnforcedSet_7342(t *testing.T) {
	var enforced []string
	for _, e := range TCPSessionTimeoutLeaves() {
		if e.Enforced {
			enforced = append(enforced, e.Leaf)
			if e.Note != "" {
				t.Errorf("leaf %q is enforced but still carries a not-enforced note %q", e.Leaf, e.Note)
			}
			continue
		}
		if e.Note == "" {
			t.Errorf("leaf %q is unenforced but carries no render annotation", e.Leaf)
		}
		if got := AnnotateTCPSessionTimeout(e.Leaf, "45s"); got == "45s" {
			t.Errorf("AnnotateTCPSessionTimeout(%q) left the cell unannotated: %q", e.Leaf, got)
		}
	}
	want := []string{
		TCPSessionEstablishedTimeoutLeaf,
		TCPSessionInitialTimeoutLeaf,
		TCPSessionClosingTimeoutLeaf,
		TCPSessionTimeWaitTimeoutLeaf,
	}
	if len(enforced) != len(want) {
		t.Fatalf("enforced leaves = %v, want all four %v", enforced, want)
	}
	for i, leaf := range want {
		if enforced[i] != leaf {
			t.Fatalf("enforced leaves = %v, want %v (Junos config order)", enforced, want)
		}
		if got := AnnotateTCPSessionTimeout(leaf, "600s"); got != "600s" {
			t.Fatalf("%s is enforced and must render unannotated, got %q", leaf, got)
		}
	}
}

// The `show` defaults and any not-enforced annotations quote fixed windows
// that live in userspace-dp/src/session/mod.rs. Go cannot import a Rust
// constant, so read the Rust source and fail if either side drifts — otherwise
// the text added here to retire one false claim quietly becomes another.
func TestTCPSessionTimeoutWindowsMatchRust_6539(t *testing.T) {
	const rustPath = "../../userspace-dp/src/session/mod.rs"
	src, err := os.ReadFile(rustPath)
	if err != nil {
		t.Fatalf("read %s: %v", rustPath, err)
	}

	// The Rust constants are nanoseconds; the Go constants are seconds.
	want := map[string]int{
		"DEFAULT_TCP_SESSION_TIMEOUT_NS": DataplaneTCPEstablishedWindowSecs,
		"DEFAULT_TCP_OPENING_TIMEOUT_NS": DataplaneTCPOpeningWindowSecs,
		"TCP_CLOSING_TIMEOUT_NS":         DataplaneTCPClosingWindowSecs,
		"TCP_RST_TIMEOUT_NS":             DataplaneTCPRSTWindowSecs,
	}
	for name, wantSecs := range want {
		re := regexp.MustCompile(`(?m)^const ` + name + `: u64 = ([0-9_]+);`)
		m := re.FindSubmatch(src)
		if m == nil {
			t.Errorf("constant %s not found in %s (renamed or moved?)", name, rustPath)
			continue
		}
		ns, err := strconv.ParseUint(strings.ReplaceAll(string(m[1]), "_", ""), 10, 64)
		if err != nil {
			t.Errorf("%s: parse %q: %v", name, m[1], err)
			continue
		}
		if gotSecs := int(ns / 1_000_000_000); gotSecs != wantSecs {
			t.Errorf("%s = %ds in Rust, but the Go operator-facing text says %ds — "+
				"the `show` defaults and annotations now quote a window the dataplane does not use",
				name, gotSecs, wantSecs)
		}
	}
}

// TCPSessionTimeoutDataplaneDefault must report a window for all four leaves.
//
// #6539 returned nothing for time-wait because the dataplane had no TIME_WAIT
// state, and printing "(default)" for it would have been the same unbacked
// enforcement claim that issue was about. #7342 gave it a state, so it has a
// window — and that window is deliberately the SAME as closing-timeout's,
// because before the state was split every post-FIN close reaped on that one
// window and an operator who sets neither leaf must see no change.
func TestTCPSessionTimeoutDataplaneDefault_7342(t *testing.T) {
	cases := []struct {
		leaf     string
		wantSecs int
		wantOK   bool
	}{
		{TCPSessionEstablishedTimeoutLeaf, DataplaneTCPEstablishedWindowSecs, true},
		{TCPSessionInitialTimeoutLeaf, DataplaneTCPOpeningWindowSecs, true},
		{TCPSessionClosingTimeoutLeaf, DataplaneTCPClosingWindowSecs, true},
		{TCPSessionTimeWaitTimeoutLeaf, DataplaneTCPClosingWindowSecs, true},
	}
	for _, tc := range cases {
		got, ok := TCPSessionTimeoutDataplaneDefault(tc.leaf)
		if ok != tc.wantOK || got != tc.wantSecs {
			t.Errorf("TCPSessionTimeoutDataplaneDefault(%q) = (%d, %v), want (%d, %v)",
				tc.leaf, got, ok, tc.wantSecs, tc.wantOK)
		}
	}
	// #15127 (A93-02): the established default IS the Junos 1800 s — the
	// dataplane fallback was raised from 300 s to 1800 s so an unset leaf
	// no longer idles out at 300 s. The constant, the Rust constant and
	// this pin must move together (TestTCPSessionTimeoutWindowsMatchRust).
	if DataplaneTCPEstablishedWindowSecs != 1800 {
		t.Fatalf("established default is %d, want 1800 — the Junos default the dataplane now applies (#15127)",
			DataplaneTCPEstablishedWindowSecs)
	}
}
