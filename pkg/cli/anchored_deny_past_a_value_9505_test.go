package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9505: AN ANCHORED deny-commands REGEX AGAINST A VALUE WAS DEFEATED BY
// APPENDING ANY WORD. `Canonicalize`'s dynamic arm shared AcceptsArgs's
// `continue`, so it absorbed every later word. The matched string carried
// them, `$` stopped matching, and the handler dropped them and ran the denied
// command:
//
//	deny="^show route table secret-vrf$"  line="show route table secret-vrf"         -> denied
//	deny="^show route table secret-vrf$"  line="show route table secret-vrf bypass"  -> ALLOWED
//
// #9022 fixed the AcceptsArgs half of the same `||`. This is the other half,
// plus the placeholder arm, which had the same shape.
func TestAnchoredDenyHoldsPastAValue9505(t *testing.T) {
	for _, tc := range []struct {
		deny, line string
		wantDeny   bool
		why        string
	}{
		{"^show route table secret-vrf$", "show route table secret-vrf", true, "positive control: the bare command"},
		{"^show route table secret-vrf$", "show route table secret-vrf bypass", true,
			"one appended word; handleShowRoute drops it and runs the denied command"},
		{"^show route table secret-vrf$", "show route table secret-vrf a b", true, "two appended words"},
		{"^show route table secret-vrf$", "show route table secret-vrf a b c d", true, "four appended words"},
		{"^show route table secret-vrf$", "show route table secret-vrf protocol bgp", true,
			"a SIBLING keyword: show route dispatches on args[0], so this still runs table secret-vrf"},
		{"^show route table secret-vrf$", "show route table public-vrf", false, "negative control: the deny stays narrow"},
		{"^show route table secret-vrf$", "show version", false, "negative control: an unrelated command"},
		{"^show route table secret-vrf$", "show route table public-vrf junk", true,
			"refused too, and deliberately: the tree cannot say which command this is, so a restricted class fails closed"},
		{"^show interfaces ge-0/0/0$", "show interfaces ge-0/0/0 bypass", true,
			"a dynamic node WITH children, and the word is not one of them"},
		{"^show interfaces ge-0/0/0$", "show interfaces ge-0/0/0 extensive", false,
			"a modelled child is a distinct command, and an anchored rule binds to its own command (#9022)"},
		{"^ping 1.1.1.1$", "ping 1.1.1.1 junk", true, "the placeholder arm; the ping loop ignores `junk`"},
		{"^ping 1.1.1.1 count 5$", "ping 1.1.1.1 count 5 junk", true,
			"a typed option value inside an option list; AcceptsArgs used to absorb `junk`"},
		{"^test security-zone interface ge-0/0/0$", "test security-zone interface ge-0/0/0 junk", true,
			"testSecurityZone ignores the extra word"},
		{"^clear security flow session zone trust$", "clear security flow session zone trust", true, "positive control"},
		{"^clear security flow session zone trust$", "clear security flow session zone trust destination-port 22", false,
			"an option list still resolves under a restricted class: a declared option is a different, narrower command"},
	} {
		t.Run(tc.line, func(t *testing.T) {
			rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, tc.deny, true)
			if err != nil {
				t.Fatalf("CompileLoginRegexes: %v", err)
			}
			err = evaluateCommandRegex(rules, "restricted", tc.line, "")
			if tc.wantDeny && err == nil {
				t.Fatalf("deny=%q line=%q was ALLOWED, want denied.\n%s", tc.deny, tc.line, tc.why)
			}
			if !tc.wantDeny && err != nil {
				t.Fatalf("deny=%q line=%q was DENIED (%v), want allowed.\n%s", tc.deny, tc.line, err, tc.why)
			}
		})
	}
}

// The AcceptsArgs arm is a separate contract, which #9505 must not change. Its
// node consumes arbitrary trailing words by design, and #9022's prefix form is
// what holds an anchored deny there. A fix to one arm must not silently change
// the other, so each arm gets its own cell.
func TestAcceptsArgsArmUnchanged9505(t *testing.T) {
	for _, tc := range []struct {
		deny, line string
		wantDeny   bool
	}{
		{"^show version$", "show log 100 foo", false},
		{"^show version$", "show configuration security zones", false},
		{"^show log$", "show log 100 foo", true},
	} {
		rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, tc.deny, true)
		if err != nil {
			t.Fatalf("CompileLoginRegexes: %v", err)
		}
		err = evaluateCommandRegex(rules, "restricted", tc.line, "")
		if (err != nil) != tc.wantDeny {
			t.Errorf("deny=%q line=%q: denied=%v, want %v (%v)", tc.deny, tc.line, err != nil, tc.wantDeny, err)
		}
	}
}

// deny-with-exceptions still resolves by longest match. That includes an
// exception naming options AFTER a dynamic value, which is the shape an
// evaluation-side fix, re-matching a value-truncated string, would have
// broken.
func TestDenyWithExceptionsPastAValue9505(t *testing.T) {
	for _, tc := range []struct {
		allow, deny, line string
		wantDeny          bool
	}{
		{"^show route table public-vrf$", "^show route table", "show route table public-vrf", false},
		{"^show route table public-vrf$", "^show route table", "show route table secret-vrf", true},
		{"^clear security flow session zone trust destination-port 22$", "^clear security flow session",
			"clear security flow session zone trust destination-port 22", false},
		{"^clear security flow session zone trust destination-port 22$", "^clear security flow session",
			"clear security flow session zone trust", true},
	} {
		rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, tc.allow, true, tc.deny, true)
		if err != nil {
			t.Fatalf("CompileLoginRegexes: %v", err)
		}
		err = evaluateCommandRegex(rules, "restricted", tc.line, "")
		if (err != nil) != tc.wantDeny {
			t.Errorf("allow=%q deny=%q line=%q: denied=%v, want %v (%v)", tc.allow, tc.deny, tc.line, err != nil, tc.wantDeny, err)
		}
	}
}
