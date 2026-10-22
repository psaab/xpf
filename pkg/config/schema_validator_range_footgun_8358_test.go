package config

import (
	"strings"
	"testing"
)

// #8358: a reversed range silently disabled the check.
//
// `ValidateInteger`'s body guards its comparison with `min <= max`, so
// `ValidateInteger(1, 0)` — the shape a caller reaches for when they mean "at
// least 1" and mis-order the arguments — returned a validator that accepted
// EVERY integer, and nothing said so.
//
// That is the worst shape a check can have. It fails to a value
// indistinguishable from a healthy one: the leaf has a validator, review sees a
// validator, `?` completion shows a typed leaf, and the gate does nothing. It
// would be found the way this class is always found — by an operator committing
// something absurd that works.
//
// Found while establishing that #8358's premise was wrong: the two-sided
// constructor it asks for already exists (109 sites, three times as many as
// `ValidateIntegerMin`). This footgun is the one real residue of that issue.

func TestAReversedRangePanicsAtConstruction8358(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("ValidateInteger(1, 0) must PANIC. Returning a validator that " +
				"accepts every integer is the defect: a leaf that looks validated and " +
				"is not, which review cannot see and no test would catch unless it " +
				"happened to try an out-of-range value on that exact leaf.")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value is %T, want string", r)
		}
		// The message must say what to do instead. A panic that only reports the
		// numbers sends the reader back to the source to work out which argument
		// they got wrong.
		for _, want := range []string{"min > max", "ValidateIntegerMin", "(min, max)"} {
			if !strings.Contains(msg, want) {
				t.Errorf("the panic must mention %q so it is actionable; got: %s", want, msg)
			}
		}
	}()
	_ = ValidateInteger(1, 0)
}

func TestAWellOrderedRangeStillValidates8358(t *testing.T) {
	// CONTROL. Without this, a constructor that panicked unconditionally would
	// satisfy the cell above while disabling every numeric leaf in the schema.
	v := ValidateInteger(1, 10)
	for _, ok := range []string{"1", "5", "10"} {
		if err := v(ok); err != nil {
			t.Errorf("ValidateInteger(1, 10)(%q): unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{"0", "11", "-1"} {
		if err := v(bad); err == nil {
			t.Errorf("ValidateInteger(1, 10)(%q): expected an out-of-range error", bad)
		}
	}
}

func TestAnEqualRangeIsAllowedAndExact8358(t *testing.T) {
	// min == max is well-ordered and meaningful: a leaf with exactly one legal
	// value. Panicking on it would be an off-by-one in the guard itself, and
	// the guard is the thing this file adds.
	v := ValidateInteger(7, 7)
	if err := v("7"); err != nil {
		t.Errorf("ValidateInteger(7, 7)(\"7\"): unexpected error: %v", err)
	}
	if err := v("8"); err == nil {
		t.Error("ValidateInteger(7, 7)(\"8\"): expected an out-of-range error")
	}
}

// TestTheWholeSchemaIsWellOrdered8358 is the census, and it is the reason the
// guard can be a panic at all.
//
// `setSchema` is a package-level var built at init, so a reversed range in ANY
// of the ~141 numeric leaves would panic before a single test ran — this file
// included. The fact that this test executes at all is the assertion.
//
// Written explicitly rather than left implicit because "the package loaded, so
// the schema is well-ordered" is exactly the kind of reasoning that is true,
// load-bearing, and invisible to the next person deciding whether the panic is
// too aggressive.
func TestTheWholeSchemaIsWellOrdered8358(t *testing.T) {
	if setSchema == nil || len(setSchema.children) == 0 {
		t.Fatal("setSchema is empty, so its construction proved nothing")
	}
	t.Logf("setSchema built with %d top-level stanzas and no reversed integer "+
		"range; the construction guard did not fire", len(setSchema.children))
}
