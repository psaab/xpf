package ipsec

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// #9068: the SA-listing parser must be fed STDOUT ALONE.
//
// One parser (`parseSAOutput`) was reached through two different exec channels.
// `GetSAStatus` used a stdout-only buffer with the explicit comment "the parser
// needs stdout alone"; `liveConnNames` routed through `CombinedOutput` — on the
// security-critical TEARDOWN path — justified in place by "parseSAOutput ignores
// any unrecognized stderr lines CombinedOutput may fold in". That justification
// was asserted and never tested, and it is true for WHOLE lines and false in the
// one direction that matters: a mid-line splice into an IKE header renames the
// connection (`vpn-corp` -> `vpn-cowarning`).
//
// A lost name is a FAIL-OPEN, not a cosmetic error. `terminateRemovedConns`
// iterates `for name := range live`, so an affected connection absent from
// `live` is neither terminated nor entered into teardown debt — and its stale
// SA keeps forwarding with no retry.
//
// Whether swanctl can splice mid-line on a SUCCESSFUL listing is not
// established. These cells do not try to answer that: they pin the CHANNEL, so
// the question cannot arise.

// splitRecorder is a stdout/stderr-separated swanctl double (#9068). The
// pre-#9068 seam could not express this at all — it returned one buffer — which
// is why no cell could distinguish the two channels.
type splitRecorder9068 struct {
	calls  [][]string
	stdout string
	stderr string
	err    error
}

func (r *splitRecorder9068) run(args ...string) (stdout, stderr []byte, err error) {
	r.calls = append(r.calls, args)
	return []byte(r.stdout), []byte(r.stderr), r.err
}

// A listing whose stderr, IF PARSED, would yield a connection name. The issue's
// executed tolerance matrix records exactly this: a stderr line containing `": #"`
// produces a spurious extra name.
const stderrThatParses9068 = "bogus-from-stderr: #9, ESTABLISHED, IKEv2, deadbeef_i deadbeef_r\n"

const listingStdout9068 = `vpn-corp: #1, ESTABLISHED, IKEv2, 1111111111111111_i* 2222222222222222_r
  local  'CN=fw' @ 203.0.113.5[500]
  remote 'CN=peer' @ 198.51.100.9[500]
`

// STDERR MUST NOT REACH THE PARSER.
func TestLiveConnNamesParsesStdoutOnly9068(t *testing.T) {
	rec := &splitRecorder9068{stdout: listingStdout9068, stderr: stderrThatParses9068}
	m := &Manager{swanctlSplit: rec.run}

	names, err := m.liveConnNames()
	if err != nil {
		t.Fatalf("liveConnNames: %v", err)
	}
	if !names["vpn-corp"] {
		t.Errorf("#9068: the real connection name was not reported: %v", names)
	}
	if names["bogus-from-stderr"] {
		t.Errorf("#9068: a name was parsed out of STDERR (%v). The parser is being "+
			"fed the combined stream. A stderr line that merely LOOKS like a listing "+
			"row is the benign direction; the same fold can splice MID-LINE into a "+
			"real IKE header and LOSE a name, and a name missing from `live` is "+
			"never terminated and never recorded as teardown debt", names)
	}
	if len(names) != 1 {
		t.Errorf("#9068: expected exactly the one real name, got %v", names)
	}
}

// The failure diagnostic must carry STDERR, not the combined stream — stderr is
// where the failure is described, and stdout on a failed listing is noise.
func TestLiveConnNamesErrorCarriesStderr9068(t *testing.T) {
	boom := errors.New("exit status 1")
	rec := &splitRecorder9068{
		stdout: "irrelevant stdout chatter",
		stderr: "swanctl: connecting to 'unix:///var/run/charon.vici' failed",
		err:    boom,
	}
	m := &Manager{swanctlSplit: rec.run}

	_, err := m.liveConnNames()
	if err == nil {
		t.Fatal("#9068: a failed listing must surface an error")
	}
	if !errors.Is(err, boom) {
		t.Errorf("#9068: the underlying error must be wrapped: %v", err)
	}
	if !strings.Contains(err.Error(), "charon.vici") {
		t.Errorf("#9068: the diagnostic must carry stderr, which is where the "+
			"failure is described: %v", err)
	}
}

// BACK-COMPATIBILITY, and it is load-bearing rather than incidental: every
// pre-#9068 test double sets the COMBINED `swanctl` seam. `scSplit` must fall
// back to it and treat its output as stdout — a double returns canned listing
// text with no stderr to fold. Without this the change would silently stop
// every existing double from reaching the parsed call, and those cells would
// pass while exercising nothing.
func TestCombinedSeamStillFeedsTheParsedCall9068(t *testing.T) {
	rec := &swanctlRecorder{listSAs: listingStdout9068}
	m := &Manager{swanctl: rec.run}

	names, err := m.liveConnNames()
	if err != nil {
		t.Fatalf("liveConnNames: %v", err)
	}
	if !names["vpn-corp"] {
		t.Errorf("#9068: the legacy combined seam no longer reaches the parser (%v) "+
			"— every pre-#9068 double would be silently inert", names)
	}
	if len(rec.calls) != 1 || rec.calls[0][0] != "--list-sas" {
		t.Errorf("#9068: expected exactly one `--list-sas` invocation, got %v", rec.calls)
	}
}

// WIRING: the PARSED call must use the stdout-only seam, and the non-parsed
// calls must keep the combined one.
//
// Structural because the distinction is which EXEC a call site chose, and a
// behavioural cell cannot see a call site silently moved back — the combined
// seam still works (that is the point of the cell above), so a revert of
// `liveConnNames` to `m.sc` would keep every double green.
func TestTheParsedCallUsesTheStdoutOnlySeam9068(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "manager.go", nil, 0)
	if err != nil {
		t.Fatalf("parse manager.go: %v", err)
	}
	seamOf := map[string][]string{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "m" {
				return true
			}
			if sel.Sel.Name == "sc" || sel.Sel.Name == "scSplit" {
				seamOf[fn.Name.Name] = append(seamOf[fn.Name.Name], sel.Sel.Name)
			}
			return true
		})
	}
	// NON-VACUITY: an empty walk passes every assertion below for free.
	if len(seamOf) == 0 {
		t.Fatal("#9068: no swanctl exec call sites found in manager.go — the guard " +
			"scanned nothing and would report a clean result either way")
	}
	if got := seamOf["liveConnNames"]; len(got) != 1 || got[0] != "scSplit" {
		t.Errorf("#9068: liveConnNames must use the STDOUT-ONLY seam (scSplit), got "+
			"%v. Its output is PARSED, and stderr folded into a listing can rename "+
			"or lose a connection — which terminateRemovedConns then cannot tear "+
			"down and cannot record as debt", got)
	}
	// The non-parsed calls keep CombinedOutput on purpose: their only consumer
	// is an error message, and folding stderr in is what makes it useful.
	for _, fn := range []string{"terminateRemovedConns"} {
		for _, seam := range seamOf[fn] {
			if seam == "scSplit" {
				t.Errorf("#9068: %s moved to the stdout-only seam; its swanctl output "+
					"feeds a DIAGNOSTIC, not a parser, and stderr belongs in it", fn)
			}
		}
	}
}
