package userspace

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// #7588: the safety of stale `userspace_bindings` rows is an EMERGENT PROPERTY
// of shim ordering, and this is the assertion that makes it an invariant.
//
// ── THE HAZARD ───────────────────────────────────────────────────────────
//
// programBootstrapMapsLocked zeroes stale binding rows via
// clearAllBindingRowsLocked, which iterates m.lastBindingIndices — an
// in-process field that is NIL on a freshly constructed Manager. The
// `userspace_bindings` Array is PinByName-pinned under /sys/fs/bpf/xpf, so its
// rows OUTLIVE xpfd. On the first apply after a daemon restart the bootstrap
// clear therefore zeroes nothing, and rows written by the previous process
// survive in a pinned map.
//
// Nothing bad happens today, and the reason is entirely accidental: the shim
// fetches the ingress flags (`userspace_ingress_metadata`) and returns early
// from the ADJUDICATED-bit test BEFORE the binding lookup, so a stale row for a
// de-configured interface is never read. Reorder those statements, or add a
// path that reaches USERSPACE_BINDINGS without passing the ingress test, and
// the stale rows become live routing state — with no test anywhere going red.
//
// ── WHY THIS IS THE FIX AND NOT THE OTHER OPTION ─────────────────────────
//
// #7588 offers an alternative: make the bootstrap clear authoritative by
// reconstructing the occupied-slot inventory from the helper's reported
// bindings at first status. MEASURED AT HEAD, that does not close this hazard.
// The helper reports the queues it is CURRENTLY serving; the stale rows that
// matter are exactly the ones for interfaces the config no longer has, which
// the helper does not report and which such an inventory therefore cannot
// name. It would make the Manager able to name rows that are about to be
// rewritten anyway (applyPrimaryBindingRowsLocked rewrites every live row on
// each ~1/s status poll) and still leave the de-configured ones behind.
//
// A blanket sweep is the other alternative and #7588 measured it out:
// BindingArrayMaxEntries is MaxInterfaces * BindingQueuesPerIface = 1,048,576
// rows, against userspace_heartbeat's 4096 — a million map syscalls on every
// non-same-plan apply. The #6702 "zero the Array's own capacity" precedent
// does not port at this size.
//
// So the dependency stays, and this test is what stops it being silent.
//
// ── WHY IT CHECKS CONTROL FLOW AND NOT LINE ORDER ────────────────────────
//
// "the gate's line number is lower than the lookup's" is NOT the property.
// A second function that reads USERSPACE_BINDINGS with no helper call and
// ADJUDICATED-bit early return would satisfy a file-wide line-order check, and
// that is precisely the "adds a path that reaches USERSPACE_BINDINGS without
// passing the ingress test" case #7588 names. So this locates EVERY read,
// resolves each to its enclosing function, and requires both steps earlier
// IN THAT SAME FUNCTION.
const shimSourcePath7588 = "../../../userspace-xdp/src/lib.rs"

// The statements whose ORDER is the invariant. The gate is matched as the
// helper CALL plus the ADJUDICATED-bit test on the flags it returns: #12055
// moved the lookup into `userspace_ingress_metadata`, so the call marks the
// consultation and the bit test marks the early return, and either one
// drifting past a binding read is the reorder this guards against. Matched on
// names rather than whole lines, so reformatting does not red this while a
// reorder still does.
var (
	bindingReadRe7588        = regexp.MustCompile(`USERSPACE_BINDINGS\s*\.\s*get\s*\(`)
	ingressGateRe7588        = regexp.MustCompile(`userspace_ingress_metadata\s*\(\s*ctx\s*\)`)
	ingressAdjudicatedRe7588 = regexp.MustCompile(`if\s+ingress_iface_flags\s*&\s*USERSPACE_INGRESS_IFACE_FLAG_ADJUDICATED\s*==\s*0`)
	rustFnRe7588             = regexp.MustCompile(`(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?fn\s+([A-Za-z0-9_]+)`)
)

func TestEveryBindingReadIsGatedByTheIngressMap_7588(t *testing.T) {
	raw, err := os.ReadFile(shimSourcePath7588)
	if err != nil {
		t.Fatalf("read shim source: %v", err)
	}
	src := stripRustLineComments7588(string(raw))

	reads := bindingReadRe7588.FindAllStringIndex(src, -1)
	if len(reads) == 0 {
		t.Fatal("no USERSPACE_BINDINGS read found in the shim — the enumeration source " +
			"moved and a pass here would certify nothing about gating")
	}
	// The count is deliberately NOT pinned to 1: a second gated read is a
	// legitimate change, and pinning the number would make this test a
	// nuisance that gets loosened. What is pinned is that EVERY read is gated.
	fns := rustFnRe7588.FindAllStringSubmatchIndex(src, -1)
	if len(fns) < 5 {
		t.Fatalf("only %d fn declarations parsed out of the shim; the scan is broken and "+
			"a pass would certify nothing", len(fns))
	}

	for _, read := range reads {
		name, start := enclosingFn7588(src, fns, read[0])
		if name == "" {
			t.Errorf("a USERSPACE_BINDINGS read at offset %d is outside any fn the scan "+
				"recognised — the scan cannot vouch for it, which is the same as no "+
				"guard", read[0])
			continue
		}
		body := src[start:read[0]]
		call := ingressGateRe7588.FindStringIndex(body)
		adjudicated := ingressAdjudicatedRe7588.FindStringIndex(body)
		if call == nil || adjudicated == nil || call[0] >= adjudicated[0] {
			t.Errorf("fn %s reads USERSPACE_BINDINGS without calling "+
				"userspace_ingress_metadata(ctx) and testing its ADJUDICATED bit "+
				"first.\n\n"+
				"The bootstrap clear does NOT zero stale binding rows on a fresh "+
				"Manager (m.lastBindingIndices is nil), and the array is PinByName-"+
				"pinned, so rows from a previous xpfd survive a restart. They are "+
				"harmless ONLY because the helper call is followed by the ingress "+
				"gate's early return before this lookup is reached. A read that "+
				"skips that gate turns inherited rows into live routing state for "+
				"interfaces the config no longer has (#7588).", name)
		}
	}
}

// The gate must also RETURN, not merely be consulted: a gate whose branch fell
// through would satisfy the ordering check above while gating nothing. Asserted
// separately so a failure names which of the two properties broke.
func TestIngressGateReturnsEarly_7588(t *testing.T) {
	raw, err := os.ReadFile(shimSourcePath7588)
	if err != nil {
		t.Fatalf("read shim source: %v", err)
	}
	src := stripRustLineComments7588(string(raw))
	loc := ingressGateRe7588.FindStringIndex(src)
	if loc == nil {
		t.Fatal("the ingress gate is gone from the shim entirely (#7588)")
	}
	// The call only FETCHES the flags; the gate is the `if` testing the
	// ADJUDICATED bit on them. Scope to the first such test at/after the call —
	// the `const` definition precedes every call site, so it cannot match it —
	// Then brace-match that `if`'s own block rather than a window after it.
	// The first draft scanned 160 characters past the match for the word
	// `return`. The mutation that earns the change is NOT "delete the early
	// return" — a window catches that one too, because the block then holds
	// nothing and the next `return` is far enough away. It is:
	//
	//	if ingress_iface_flags & USERSPACE_INGRESS_IFACE_FLAG_ADJUDICATED == 0 {
	//	    let _gated = 1;
	//	}
	//	return Ok(cpumap_or_pass(ctrl));   // moved OUT of the branch
	//
	// The mutation leaves the helper call in place but makes the gate's branch
	// decide nothing, then moves the return outside it. A proximity check sees
	// that return and passes; brace-matching the gate's own block fails. Verified
	// both ways rather than assumed — the window version escapes this, which
	// makes the containment check load-bearing rather than merely tidier.
	rel := ingressAdjudicatedRe7588.FindStringIndex(src[loc[1]:])
	if rel == nil {
		t.Fatal("the ADJUDICATED-bit ingress test is gone from the shim (#7588)")
	}
	block, ok := ifBlockAfter7588(src, loc[1]+rel[1])
	if !ok {
		t.Fatalf("could not brace-match the ingress gate's block; the scan cannot vouch "+
			"for it, which is the same as no guard:\n%.200s", src[loc[0]:])
	}
	if !strings.Contains(block, "return") {
		t.Errorf("the ADJUDICATED-bit ingress test no longer returns from its own "+
			"branch. Fetching the flags without leaving the function gates NOTHING, "+
			"and the stale-row hazard #7588 describes becomes reachable while the "+
			"ordering test above still passes:\n%s", block)
	}
}

// ifBlockAfter7588 returns the body of the first braced block at or after off,
// brace-matched so a nested block cannot terminate it early.
func ifBlockAfter7588(src string, off int) (string, bool) {
	open := strings.IndexByte(src[off:], '{')
	if open < 0 {
		return "", false
	}
	open += off
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open : i+1], true
			}
		}
	}
	return "", false
}

// enclosingFn7588 returns the name and body-start offset of the fn containing
// off, or "" when off precedes every fn declaration.
func enclosingFn7588(src string, fns [][]int, off int) (string, int) {
	name, start := "", -1
	for _, m := range fns {
		if m[0] > off {
			break
		}
		name, start = src[m[2]:m[3]], m[0]
	}
	if start < 0 {
		return "", 0
	}
	return name, start
}

// stripRustLineComments7588 blanks `//` comments so a guard cannot be satisfied
// — or broken — by prose that mentions the symbols it looks for. This file's
// own doc comment names both maps, and so does the shim's.
func stripRustLineComments7588(src string) string {
	lines := strings.Split(src, "\n")
	for i, ln := range lines {
		if idx := strings.Index(ln, "//"); idx >= 0 {
			lines[i] = ln[:idx]
		}
	}
	return strings.Join(lines, "\n")
}
