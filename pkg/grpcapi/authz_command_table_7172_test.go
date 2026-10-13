package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
)

// #7172 cut 5a — the gRPC method → canonical command table.
//
// Two tests, and they catch different failures. Completeness alone would pass a
// table full of plausible-looking WRONG strings, which is exactly why the
// validity check exists.

// VALIDITY: every entry must be a real, already-canonical operational command.
//
// This is what structurally excludes the error class that killed the idea of
// DERIVING these strings from method or topic names. `buffers-detail` looks like
// `show buffers detail`; that is wrong, because `buffers` is not a child of
// `show`, and only `show system buffers detail` resolves. A derivation would be
// right for most entries and quietly wrong for some — the worst distribution for
// an authorization input — and this test rejects the wrong ones by construction
// rather than asking a reviewer to spot them.
func TestEveryMappedCommandIsCanonical7172(t *testing.T) {
	if len(methodCanonicalCommand) == 0 {
		t.Fatal("the table is empty, so this test would certify nothing")
	}
	for method, cmd := range methodCanonicalCommand {
		words := strings.Fields(cmd)
		if len(words) == 0 {
			t.Errorf("%s maps to an empty command", method)
			continue
		}
		// EVERY WORD MUST BE A KEYWORD, checked before canonicalization.
		//
		// This is the half the original #8057 check was missing, and its absence
		// made that PR's claim ("a real, already-canonical operational command")
		// too strong. Canonicalize returns OK for `show interfaces zzbogus`,
		// because `interfaces` carries a dynamic child and value slots absorb
		// arbitrary words BY DESIGN — they are operator data, and cut 1 is right
		// to leave them alone.
		//
		// That is correct for canonicalizing a command an operator typed, and
		// wrong as a validity check for THIS table, whose entries are pure
		// command paths with no arguments. Without this arm, an entry could name
		// a command nobody can run and still pass, so long as the garbage landed
		// in a value slot rather than at a keyword position.
		//
		// The mutation that motivated it: `show zzbogus nonexistent` reds
		// (nothing under `show` matches), but `show interfaces zzbogus` did not.
		//
		// #12527 added the other half: a LEAF must be the last word.
		// `show security flow session summary zone` is two keywords, and
		// Canonicalize accepts it by re-entering the `session` Options map
		// (#9505), but a leaf is a complete command, so whatever follows it
		// is an argument or a second option.
		if !cmdtree.EveryWordIsAKeyword(cmdtree.OperationalTree, words) {
			t.Errorf("%s maps to %q, which is not a pure command path: either some word "+
				"is not a command KEYWORD — a value slot (a dynamic, typed or "+
				"placeholder child) is absorbing it — or a word follows a LEAF, which "+
				"fails even when both words are keywords (an option after a complete "+
				"command, #12527). Table entries are pure command paths with no "+
				"arguments, so every word must be a real node and only the last may "+
				"be a leaf.", method, cmd)
			continue
		}
		canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, words)
		if res != cmdtree.CanonicalOK {
			t.Errorf("%s maps to %q, which does not resolve against the operational tree "+
				"(%v). A deny regex is matched against this string, so an unresolvable "+
				"entry means the gate compares against a command no operator can run.",
				method, cmd, res)
			continue
		}
		if got := strings.Join(canon, " "); got != cmd {
			t.Errorf("%s maps to %q, which canonicalizes to %q. The table must hold the "+
				"CANONICAL spelling: cut 3 matches deny regexes against canonicalized "+
				"input, so a non-canonical entry here would be compared against a "+
				"different string than the on-box CLI produces for the same command.",
				method, cmd, got)
		}
	}
}

// COMPLETENESS, both directions.
//
// Mirrors TestEveryShowTextTopicHasAPermission_5278: a method priced for coarse
// permissions but absent from both maps here is a method 5b cannot produce a
// command for, and an entry naming a method that no longer exists is stale.
//
// Absences are permitted only when NAMED with a reason in
// methodsWithoutCanonicalCommand. A bare absence is indistinguishable from a
// forgotten one, and this test would otherwise have to choose between failing
// on every intended absence and accepting every accidental one.
func TestEveryPricedMethodIsMappedOrNamedAbsent7172(t *testing.T) {
	if len(methodPermissions) < 40 {
		t.Fatalf("only %d priced methods found; the coarse table is the enumeration this "+
			"test walks, so a pass would certify nothing", len(methodPermissions))
	}
	for method := range methodPermissions {
		_, mapped := methodCanonicalCommand[method]
		reason, excused := methodsWithoutCanonicalCommand[method]
		switch {
		case mapped && excused:
			t.Errorf("%s is BOTH mapped to a command and named as deliberately absent; one "+
				"of the two is wrong and a reader cannot tell which", method)
		case !mapped && !excused:
			t.Errorf("%s is priced for coarse permissions but has no canonical command and "+
				"no stated reason for having none. 5b cannot evaluate deny-commands for "+
				"it, so for a class that configured regexes it will be DENIED — add an "+
				"entry, or name it in methodsWithoutCanonicalCommand with why.", method)
		case excused && strings.TrimSpace(reason) == "":
			t.Errorf("%s is named absent with an empty reason, which is the same as an "+
				"unnamed absence", method)
		}
	}
	// Stale direction: an entry for a method that is no longer served.
	for method := range methodCanonicalCommand {
		if _, priced := methodPermissions[method]; !priced {
			t.Errorf("%s has a canonical command but is not a priced method — the entry is "+
				"stale and would never be consulted", method)
		}
	}
	for method := range methodsWithoutCanonicalCommand {
		if _, priced := methodPermissions[method]; !priced {
			t.Errorf("%s is named as deliberately absent but is not a priced method; the "+
				"exemption is stale", method)
		}
	}
}

// #12527 and #12582: the shared pure-command-path predicate rejects trailing
// keywords after a leaf and argument placeholders. Both authz surfaces use it.

// #12527: option-suffixed mutants must be rejected by the keyword arm.
func TestEveryWordIsAKeywordRejectsOptionSuffix12527(t *testing.T) {
	// A multi-option line an operator can run: the CLI shows the session
	// summary filtered to zone trust.
	const runnable = "show security flow session summary zone trust"
	for _, tc := range []struct {
		cmd  string
		want bool
	}{
		{"show security flow session summary zone", false}, // the #12096-row mutant
		{"show security flow session summary brief", false},
		{runnable, false}, // the mechanism pin's line
		{"show security flow session zone trust", false},   // option value after leaf
		{"show version configuration", false},              // trailing sibling after leaf (#8289 shape)
		{"show security flow session summary", true},       // #12096 charge stays valid
		{"show security flow session", true},               // bare Options node
		{"show security flow session sort-by bytes", true}, // nested option path (sessions-top)
		{"show version", true},
	} {
		if got := cmdtree.EveryWordIsAKeyword(cmdtree.OperationalTree, strings.Fields(tc.cmd)); got != tc.want {
			t.Errorf("EveryWordIsAKeyword(%q) = %v, want %v", tc.cmd, got, tc.want)
		}
	}
	// Mechanism pin: Canonicalize legitimately accepts the runnable line
	// (Options re-entry, #9505), so the keyword arm is what must reject it.
	// Not the `…summary zone` mutant: the CLI refuses that line (missing
	// value for "zone"), so a correct tightening of Canonicalize could
	// refuse it too and red this pin for a reason unrelated to the table.
	if _, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(runnable)); res != cmdtree.CanonicalOK {
		t.Errorf("precondition: Canonicalize must accept the runnable multi-option "+
			"line %q (got %v)", runnable, res)
	}
}
