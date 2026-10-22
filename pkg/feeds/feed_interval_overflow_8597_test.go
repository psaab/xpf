package feeds

import (
	"math"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 (muse-004 K34) — the feeds instance of the duration-overflow family
// that #5723 (RPM) and #6769 (flow-export) each fixed in their own package and
// never swept.
//
// overflowSeconds is the value whose `time.Duration(n) * time.Second` residue
// is the smallest positive one: gcd(1e9, 2^64) = 512, so the wrap lands on
// exactly 512ns. It is the same fixture #6769 uses, deliberately — the two
// packages guard the same arithmetic and a reader comparing them should see
// the same number.
const overflowSeconds8597 = 20211507185753197

// TestFeedOverflowFixtureActuallyWraps_8597 is the non-vacuity guard for every
// other cell here. Without it, someone editing the fixture down to a merely
// large-but-valid number would leave the range-check cells passing while
// testing nothing.
func TestFeedOverflowFixtureActuallyWraps_8597(t *testing.T) {
	if overflowSeconds8597 <= config.MaxDurationSeconds {
		t.Fatalf("fixture %d is within MaxDurationSeconds (%d) — it cannot overflow, "+
			"and the cells below would be vacuous", overflowSeconds8597, config.MaxDurationSeconds)
	}
	// Through a variable: Go rejects the constant form at compile time, which
	// is itself the story — the value only reaches this multiply at RUNTIME,
	// as an int the compiler read with strconv.Atoi.
	n := overflowSeconds8597
	wrapped := time.Duration(n) * time.Second
	if wrapped <= 0 {
		t.Fatalf("fixture wraps to %v; the cells here guard the POSITIVE wrap — the half "+
			"the `<= 0` checks in this package do NOT catch", wrapped)
	}
	if wrapped != 512*time.Nanosecond {
		t.Errorf("fixture wraps to %v, want 512ns (gcd(1e9, 2^64) = 512)", wrapped)
	}
	if config.MaxDurationSeconds != int64(math.MaxInt64)/int64(time.Second) {
		t.Errorf("MaxDurationSeconds = %d, want math.MaxInt64/1e9 — the ceiling must stay "+
			"the runtime-derived overflow point, not a policy cap", config.MaxDurationSeconds)
	}
}

// TestLenientLoadKeepsAnOutOfRangeFeedInterval_8597 is the REACHABILITY cell,
// and the one that makes the rest of this file about a live defect rather than
// about arithmetic.
//
// The strict schema bounds both knobs to [1, MaxDurationSeconds]
// (schema_security.go). The premise the whole finding rests on is that the
// lenient ingress — the tolerant on-disk Load / HA peer-sync path that #1960
// requires so a persisted config still BOOTS — does not. This cell drives that
// path and asserts the raw value survives into the compiled config, so nobody
// has to take the premise on the review document's word.
//
// If a future change starts rejecting or clamping at compile time, this cell
// fails and says so, rather than the package-level guards quietly becoming
// unreachable belts.
func TestLenientLoadKeepsAnOutOfRangeFeedInterval_8597(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set security dynamic-address feed-server srv hostname feeds.example.net",
		"set security dynamic-address feed-server srv update-interval 20211507185753197",
		"set security dynamic-address feed-server srv hold-interval 20211507185753197",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}

	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must not fail (#1960 no-brick), got: %v", err)
	}
	fs := cfg.Security.DynamicAddress.FeedServers["srv"]
	if fs == nil {
		t.Fatal("lenient compile produced no feed-server 'srv'")
	}
	if fs.UpdateInterval != overflowSeconds8597 {
		t.Errorf("lenient UpdateInterval = %d, want the raw %d — if the ingress now bounds "+
			"this, the runtime guards below are unreachable and should be re-argued, "+
			"not silently kept", fs.UpdateInterval, overflowSeconds8597)
	}
	if fs.HoldInterval != overflowSeconds8597 {
		t.Errorf("lenient HoldInterval = %d, want the raw %d", fs.HoldInterval, overflowSeconds8597)
	}

	// The other half of the split this finding depends on: STRICT still
	// rejects. A change that made both paths accept would satisfy the
	// assertions above for the wrong reason.
	//
	// The strict gate is the typed-leaf walk (config.SchemaValidate), NOT
	// CompileConfig — the compiler stores the raw Atoi on both paths, and
	// Store.compileTreeLenient's own comment states the split precisely: "the
	// typed-leaf SchemaValidate gate is STRICT only on the operator-driven
	// commit / commit-check path ... Here — the tolerant Store.Load /
	// Store.SyncApply ingress — a violation downgrades to a warning."
	if serr := config.SchemaValidate(tree); serr == nil {
		t.Error("SchemaValidate accepted an out-of-range update-interval; the schema bound " +
			"is gone, and the lenient/strict split this finding describes no longer exists")
	}
}

// TestUpdateIntervalRejectsOverflow_8597: an out-of-range update-interval falls
// back to the 1h default instead of arming a 512ns ticker (a per-feed HTTP
// fetch storm against every configured feed server).
//
// Reverting feedIntervalSeconds to `d := time.Duration(n) * time.Second; if d
// <= 0 { d = time.Hour }` makes this 512ns.
func TestUpdateIntervalRejectsOverflow_8597(t *testing.T) {
	if got := feedIntervalSeconds(overflowSeconds8597, time.Hour); got != time.Hour {
		t.Errorf("update-interval %d -> %v, want 1h (fall back, do not wrap)",
			overflowSeconds8597, got)
	}
	// The negative-wrap half, and a plain negative, both already fell back —
	// keep them asserted so a fix aimed only at the positive residue cannot
	// drop them.
	if got := feedIntervalSeconds(-1, time.Hour); got != time.Hour {
		t.Errorf("update-interval -1 -> %v, want 1h", got)
	}
	if got := feedIntervalSeconds(0, time.Hour); got != time.Hour {
		t.Errorf("update-interval 0 (unset) -> %v, want 1h", got)
	}
}

// TestUpdateIntervalHonoursValidValues_8597 is the OVER-BROAD control: a fix
// that rejected everything, or clamped every value to the default, would pass
// the cell above and break every real config. Both a small and a very large
// in-range value must convert exactly.
func TestUpdateIntervalHonoursValidValues_8597(t *testing.T) {
	for _, sec := range []int{1, 300, 3600, 86400, int(config.MaxDurationSeconds)} {
		want := time.Duration(sec) * time.Second
		if got := feedIntervalSeconds(sec, time.Hour); got != want {
			t.Errorf("update-interval %d -> %v, want %v (a valid value must be honoured "+
				"exactly, including the boundary)", sec, got, want)
		}
	}
}

// TestHoldIntervalRejectsOverflowFailClosed_8597 is the security half, and the
// reason this finding is not merely an availability bug.
//
// hold-interval is the opt-in "drop the last-good snapshot to empty after N
// seconds of fetch failure". The #2050 operator decision is that the DEFAULT
// retains forever, because a DENY feed that fail-OPENs to empty is worse than a
// stale one. A wrapped hold-interval inverts exactly that: `retain forever`
// becomes `drop after 512 nanoseconds of failure`.
//
// Falling back to retainForever is the direction that errs toward keeping
// enforcement, matching #2050.
func TestHoldIntervalRejectsOverflowFailClosed_8597(t *testing.T) {
	if got := resolveHoldInterval(overflowSeconds8597); got != retainForever {
		t.Errorf("hold-interval %d -> %v, want retainForever — an out-of-range value must "+
			"never turn 'retain the last-good denylist' into 'drop it to empty almost "+
			"immediately' (#2050)", overflowSeconds8597, got)
	}
}

// TestHoldIntervalHonoursValidValues_8597 is the matching over-broad control:
// the explicit opt-in must still work, or the fix has quietly removed a
// documented feature instead of bounding it.
func TestHoldIntervalHonoursValidValues_8597(t *testing.T) {
	for _, sec := range []int{1, 86400, int(config.MaxDurationSeconds)} {
		want := time.Duration(sec) * time.Second
		if got := resolveHoldInterval(sec); got != want {
			t.Errorf("hold-interval %d -> %v, want %v", sec, got, want)
		}
	}
	if got := resolveHoldInterval(0); got != retainForever {
		t.Errorf("hold-interval 0 (unset) -> %v, want retainForever (the #2050 default)", got)
	}
}
