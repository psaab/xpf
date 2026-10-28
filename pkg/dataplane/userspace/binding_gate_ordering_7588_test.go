package userspace

import (
	"os"
	"regexp"
	"sort"
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
// ── WHY IT CHECKS REACHABILITY, NOT SAME-FUNCTION ORDER ────────────────
//
// The raw USERSPACE_BINDINGS read now lives in the outlined helper
// binding_ready_slot (#15854). Any intra-function model reds that
// outlining — the false RED #17235 records — while the property (no stale
// row is read for a non-adjudicated interface) still holds. So this test
// builds the shim's call graph instead: parsing `fn` items and the calls
// between them, marking try_xdp_userspace entered UNGATED, and propagating
// a gated/ungated entry state. A call site reached ungated propagates
// gated only when the ingress fetch and a returning ADJUDICATED-bit branch
// precede it in the caller; a function entered gated propagates gated to
// all its callees. A USERSPACE_BINDINGS read fails when its function can
// be entered ungated and no returning gate precedes the read itself.
// Outlining a read into a further gated callee therefore stays green, a
// call placed before the gate reds, and a direct ungated read reds.
const shimSourcePath7588 = "../../../userspace-xdp/src/lib.rs"

// The statements whose ORDER is the invariant. Each is matched on the map /
// helper names rather than whole lines, so reformatting does not red this
// while a reorder still does.
var (
	bindingReadRe7588        = regexp.MustCompile(`USERSPACE_BINDINGS\s*\.\s*get\s*\(`)
	ingressGateRe7588        = regexp.MustCompile(`userspace_ingress_metadata\s*\(\s*ctx\s*\)`)
	ingressAdjudicatedRe7588 = regexp.MustCompile(`if\s+ingress_iface_flags\s*&\s*USERSPACE_INGRESS_IFACE_FLAG_ADJUDICATED\s*==\s*0`)
	rustFnRe7588             = regexp.MustCompile(`(?m)^\s*(?:pub\s+)?(?:unsafe\s+)?fn\s+([A-Za-z0-9_]+)`)
	returnRe7588             = regexp.MustCompile(`\breturn\b`)
)

type fnItem7588 struct {
	name      string
	declStart int
	bodyStart int // offset of '{'
	bodyEnd   int // offset just past matching '}'
}

type callSite7588 struct {
	caller string
	callee string
	offset int
}

// braceMatch7588 returns the offset just past the '}' matching the '{' at
// open, or -1. src must already have comments/strings blanked so braces in
// prose or literals cannot skew the depth.
func braceMatch7588(src string, open int) int {
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

// parseFns7588 returns every fn item with its brace-matched body span.
func parseFns7588(src string) []fnItem7588 {
	var fns []fnItem7588
	for _, m := range rustFnRe7588.FindAllStringSubmatchIndex(src, -1) {
		open := strings.IndexByte(src[m[0]:], '{')
		if open < 0 {
			continue
		}
		open += m[0]
		end := braceMatch7588(src, open)
		if end < 0 {
			continue
		}
		fns = append(fns, fnItem7588{name: src[m[2]:m[3]], declStart: m[0], bodyStart: open, bodyEnd: end})
	}
	return fns
}

func fnContaining7588(fns []fnItem7588, off int) *fnItem7588 {
	var best *fnItem7588
	for i := range fns {
		if fns[i].bodyStart <= off && off < fns[i].bodyEnd {
			if best == nil || fns[i].bodyStart > best.bodyStart {
				best = &fns[i]
			}
		}
	}
	return best
}

// gatePrecedes7588 reports whether, before off inside fn, the caller fetched
// ingress metadata and a following ADJUDICATED-bit branch whose own block
// returns closed before off.
func gatePrecedes7588(src string, fn fnItem7588, off int) bool {
	prefix := src[fn.bodyStart:off]
	gateCalls := ingressGateRe7588.FindAllStringIndex(prefix, -1)
	if len(gateCalls) == 0 {
		return false
	}
	for _, check := range ingressAdjudicatedRe7588.FindAllStringIndex(prefix, -1) {
		prior := false
		for _, g := range gateCalls {
			if g[1] <= check[0] {
				prior = true
				break
			}
		}
		if !prior {
			continue
		}
		absCheckEnd := fn.bodyStart + check[1]
		open := strings.IndexByte(src[absCheckEnd:], '{')
		if open < 0 {
			continue
		}
		open += absCheckEnd
		end := braceMatch7588(src, open)
		if end < 0 || end > off {
			continue
		}
		if returnRe7588.MatchString(src[open:end]) {
			return true
		}
	}
	return false
}

// checkBindingGate7588 returns every violation of the transitive gate
// invariant in stripped-or-raw shim source (it strips internally). Split
// from the Test so mutation cells can run it over synthetic sources.
func checkBindingGate7588(raw string) []string {
	src := stripRustCommentsAndStrings7588(raw)
	fns := parseFns7588(src)
	if len(fns) < 1 {
		return []string{"parsed no fn declarations out of the shim; the scan is broken and a pass would certify nothing"}
	}
	byName := map[string]*fnItem7588{}
	for i := range fns {
		byName[fns[i].name] = &fns[i]
	}
	entry, ok := byName["try_xdp_userspace"]
	if !ok {
		return []string{"fn try_xdp_userspace not found; the scan cannot vouch for the entry point"}
	}
	// Call graph: bare calls to known fns inside each fn body, excluding the
	// `fn name(` declaration itself and method calls (`.name(`).
	callsByCaller := map[string][]callSite7588{}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\(`)
		for i := range fns {
			fn := &fns[i]
			body := src[fn.bodyStart:fn.bodyEnd]
			for _, m := range re.FindAllStringIndex(body, -1) {
				off := fn.bodyStart + m[0]
				if fn.name == name && off >= fn.declStart && off < fn.bodyStart {
					continue
				}
				if off > 0 && src[off-1] == '.' {
					continue
				}
				// The declaration `fn name(`: name sits right after "fn ".
				if off >= 3 && src[off-3:off] == "fn " && fn.name == name {
					continue
				}
				callsByCaller[fn.name] = append(callsByCaller[fn.name], callSite7588{caller: fn.name, callee: name, offset: off})
			}
		}
	}
	// Propagate gated/ungated entry states from the entry point.
	enteredGated := map[string]bool{}
	enteredUngated := map[string]bool{entry.name: true}
	type work struct {
		name  string
		gated bool
	}
	queue := []work{{entry.name, false}}
	seen := map[work]bool{{entry.name, false}: true}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		fn := byName[cur.name]
		if fn == nil {
			continue
		}
		for _, cs := range callsByCaller[cur.name] {
			gated := cur.gated || gatePrecedes7588(src, *fn, cs.offset)
			k := work{cs.callee, gated}
			if seen[k] {
				continue
			}
			seen[k] = true
			if gated {
				enteredGated[cs.callee] = true
			} else {
				enteredUngated[cs.callee] = true
			}
			queue = append(queue, k)
		}
	}
	reads := bindingReadRe7588.FindAllStringIndex(src, -1)
	if len(reads) == 0 {
		return []string{"found no USERSPACE_BINDINGS reads; the census has no positive control"}
	}
	var problems []string
	for _, read := range reads {
		fn := fnContaining7588(fns, read[0])
		if fn == nil {
			problems = append(problems, "a USERSPACE_BINDINGS read is outside any fn the scan recognised; the scan cannot vouch for it")
			continue
		}
		if enteredUngated[fn.name] && !gatePrecedes7588(src, *fn, read[0]) {
			problems = append(problems, "fn "+fn.name+" reads USERSPACE_BINDINGS on a path reachable without the ingress gate: it can be entered ungated and no userspace_ingress_metadata(ctx) fetch followed by a returning ADJUDICATED-bit branch precedes the read; inherited pinned rows can become live routing state (#7588)")
			continue
		}
		if !enteredGated[fn.name] && !enteredUngated[fn.name] {
			problems = append(problems, "fn "+fn.name+" reads USERSPACE_BINDINGS but is not reachable from try_xdp_userspace; the census cannot vouch for its gating (#7588)")
			continue
		}
	}
	return problems
}

func TestEveryBindingReadIsGatedByTheIngressMap_7588(t *testing.T) {
	raw, err := os.ReadFile(shimSourcePath7588)
	if err != nil {
		t.Fatalf("read shim source: %v", err)
	}
	src := stripRustCommentsAndStrings7588(string(raw))
	if len(parseFns7588(src)) < 5 {
		t.Fatalf("only %d fn declarations parsed out of the shim; the scan is broken and a pass would certify nothing", len(parseFns7588(src)))
	}
	for _, p := range checkBindingGate7588(string(raw)) {
		t.Error(p)
	}
}

// The gate must also RETURN, not merely be consulted: a gate whose branch
// fell through would satisfy the reachability check above only if the same
// defect were not also required there — gatePrecedes7588 already demands a
// returning branch, and this cell names the property separately on the
// entry function so a failure says which of the two broke.
func TestIngressGateReturnsEarly_7588(t *testing.T) {
	raw, err := os.ReadFile(shimSourcePath7588)
	if err != nil {
		t.Fatalf("read shim source: %v", err)
	}
	src := stripRustCommentsAndStrings7588(string(raw))
	fns := parseFns7588(src)
	var entry *fnItem7588
	for i := range fns {
		if fns[i].name == "try_xdp_userspace" {
			entry = &fns[i]
			break
		}
	}
	if entry == nil {
		t.Fatal("fn try_xdp_userspace not found in the shim (#7588)")
	}
	body := src[entry.bodyStart:entry.bodyEnd]
	loc := ingressGateRe7588.FindStringIndex(body)
	if loc == nil {
		t.Fatal("the ingress gate is gone from try_xdp_userspace entirely (#7588)")
	}
	rel := ingressAdjudicatedRe7588.FindStringIndex(body[loc[1]:])
	if rel == nil {
		t.Fatal("the ADJUDICATED-bit ingress test is gone from try_xdp_userspace (#7588)")
	}
	absEnd := entry.bodyStart + loc[1] + rel[1]
	open := strings.IndexByte(src[absEnd:], '{')
	if open < 0 {
		t.Fatal("could not brace-match the ingress gate's block; the scan cannot vouch for it")
	}
	open += absEnd
	end := braceMatch7588(src, open)
	if end < 0 {
		t.Fatalf("could not brace-match the ingress gate's block; the scan cannot vouch for it, which is the same as no guard:\n%.200s", src[entry.bodyStart:])
	}
	if !returnRe7588.MatchString(src[open:end]) {
		t.Errorf("the ADJUDICATED-bit ingress test no longer returns from its own branch. Fetching the flags without leaving the function gates NOTHING, and the stale-row hazard #7588 describes becomes reachable while the ordering test above still passes:\n%s", src[open:end])
	}
}

// ifBlockAfter7588 returns the body of the first braced block at or after
// off, brace-matched so a nested block cannot terminate it early. Kept for
// the synthetic mutation cells' readability; production paths use
// braceMatch7588 directly.
func ifBlockAfter7588(src string, off int) (string, bool) {
	open := strings.IndexByte(src[off:], '{')
	if open < 0 {
		return "", false
	}
	open += off
	end := braceMatch7588(src, open)
	if end < 0 {
		return "", false
	}
	return src[open:end], true
}

// stripRustCommentsAndStrings7588 blanks // and /* */ comments and string /
// char literals (including raw strings) to spaces, preserving length and
// newlines, so a guard can neither be satisfied nor broken by prose or
// literal contents that mention the symbols it looks for — and braces in
// prose cannot skew brace matching.
func stripRustCommentsAndStrings7588(src string) string {
	b := []byte(src)
	out := make([]byte, len(b))
	copy(out, b)
	blank := func(i int) {
		if b[i] != '\n' {
			out[i] = ' '
		}
	}
	i := 0
	for i < len(b) {
		switch {
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				blank(i)
				i++
			}
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '*':
			depth := 0
			for i < len(b) {
				if i+1 < len(b) && b[i] == '/' && b[i+1] == '*' {
					blank(i)
					blank(i + 1)
					depth++
					i += 2
				} else if i+1 < len(b) && b[i] == '*' && b[i+1] == '/' {
					blank(i)
					blank(i + 1)
					depth--
					i += 2
					if depth == 0 {
						break
					}
				} else {
					blank(i)
					i++
				}
			}
		case isRawStringStart7588(b, i):
			start, hashes := rawStringStart7588(b, i)
			for ; i < start; i++ {
				blank(i)
			}
			// i is at the opening quote; blank until closing quote+hashes.
			blank(i)
			i++
			for i < len(b) {
				if b[i] == '"' && rawStringClose7588(b, i, hashes) {
					for k := range 1 + hashes {
						blank(i + k)
					}
					i += 1 + hashes
					break
				}
				blank(i)
				i++
			}
		case b[i] == '"':
			blank(i)
			i++
			for i < len(b) {
				if b[i] == '\\' && i+1 < len(b) {
					blank(i)
					blank(i + 1)
					i += 2
				} else if b[i] == '"' {
					blank(i)
					i++
					break
				} else {
					blank(i)
					i++
				}
			}
		case b[i] == '\'' && isCharLiteral7588(b, i):
			// Blank from opening to closing quote, honouring escapes.
			j := i + 1
			for j < len(b) {
				if b[j] == '\\' {
					j += 2
					continue
				}
				if b[j] == '\'' {
					j++
					break
				}
				j++
			}
			for ; i < j && i < len(b); i++ {
				blank(i)
			}
		default:
			i++
		}
	}
	return string(out)
}

func isRawStringStart7588(b []byte, i int) bool {
	_, _, ok := rawStringPrefix7588(b, i)
	return ok
}

// rawStringStart7588 returns the offset of the opening quote.
func rawStringStart7588(b []byte, i int) (int, int) {
	start, hashes, _ := rawStringPrefix7588(b, i)
	return start, hashes
}

func rawStringPrefix7588(b []byte, i int) (quote int, hashes int, ok bool) {
	if i > 0 && (isIdentByte7588(b[i-1])) {
		return 0, 0, false
	}
	j := i
	if b[j] == 'b' && j+1 < len(b) && b[j+1] == 'r' {
		j++
	}
	if j >= len(b) || b[j] != 'r' {
		return 0, 0, false
	}
	j++
	for j < len(b) && b[j] == '#' {
		hashes++
		j++
	}
	if j < len(b) && b[j] == '"' {
		return j, hashes, true
	}
	return 0, 0, false
}

func rawStringClose7588(b []byte, i int, hashes int) bool {
	for k := 0; k < hashes; k++ {
		if i+1+k >= len(b) || b[i+1+k] != '#' {
			return false
		}
	}
	return true
}

func isIdentByte7588(c byte) bool {
	return c == '_' || ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

func isCharLiteral7588(b []byte, i int) bool {
	// 'x' , '\'' , '\\', '\n', '\u{...}' ; lifetimes ('a) have no closing
	// quote within a few bytes and are left alone.
	if i+1 < len(b) && b[i+1] == '\\' {
		for j := i + 2; j < len(b) && j < i+14; j++ {
			if b[j] == '\'' {
				return true
			}
			if b[j] == '\n' {
				return false
			}
		}
		return false
	}
	return i+2 < len(b) && b[i+2] == '\''
}

// Synthetic mutation cells for the transitive checker (#17235). Each runs
// checkBindingGate7588 over a hand-built source, never the real shim, so the
// acceptance shapes are proven without touching lib.rs (object md5 unchanged).
func TestBindingGateTransitiveMutations17235(t *testing.T) {
	gated := "fn try_xdp_userspace(ctx: &XdpContext) -> u32 { let (ingress_ifindex, ingress_iface_flags) = userspace_ingress_metadata(ctx); if ingress_iface_flags & USERSPACE_INGRESS_IFACE_FLAG_ADJUDICATED == 0 { return 1; } helper(ingress_ifindex) }\n" +
		"fn helper(x: u32) -> u32 { USERSPACE_BINDINGS.get(0); 0 }\n"
	if p := checkBindingGate7588(gated); len(p) != 0 {
		t.Errorf("gated outlined callee: want no problems, got %v", p)
	}
	// Outlining ANOTHER read into a gated callee does not red it.
	deeper := "fn try_xdp_userspace(ctx: &XdpContext) -> u32 { let (ingress_ifindex, ingress_iface_flags) = userspace_ingress_metadata(ctx); if ingress_iface_flags & USERSPACE_INGRESS_IFACE_FLAG_ADJUDICATED == 0 { return 1; } helper(ingress_ifindex) }\n" +
		"fn helper(x: u32) -> u32 { deeper(x) }\nfn deeper(x: u32) -> u32 { USERSPACE_BINDINGS.get(0); 0 }\n"
	if p := checkBindingGate7588(deeper); len(p) != 0 {
		t.Errorf("deeper gated outline: want no problems, got %v", p)
	}
	// A call placed BEFORE the gate reds.
	before := "fn try_xdp_userspace(ctx: &XdpContext) -> u32 { helper(0); let (ingress_ifindex, ingress_iface_flags) = userspace_ingress_metadata(ctx); if ingress_iface_flags & USERSPACE_INGRESS_IFACE_FLAG_ADJUDICATED == 0 { return 1; } 0 }\n" +
		"fn helper(x: u32) -> u32 { USERSPACE_BINDINGS.get(0); 0 }\n"
	if p := checkBindingGate7588(before); len(p) == 0 {
		t.Error("call before gate: want problems, got none")
	}
	// A direct ungated read in the entry reds.
	direct := "fn try_xdp_userspace(ctx: &XdpContext) -> u32 { USERSPACE_BINDINGS.get(0); 0 }\n"
	if p := checkBindingGate7588(direct); len(p) == 0 {
		t.Error("direct ungated read: want problems, got none")
	}
	// Comment/string mentions of the read and gate neither satisfy nor break.
	prose := "fn try_xdp_userspace(ctx: &XdpContext) -> u32 { let s = \"USERSPACE_BINDINGS.get(\"; /* userspace_ingress_metadata(ctx) */ helper(0) }\n" +
		"fn helper(x: u32) -> u32 { USERSPACE_BINDINGS.get(0); 0 }\n"
	if p := checkBindingGate7588(prose); len(p) == 0 {
		t.Error("prose-only gate: want problems, got none")
	}
	// A gate whose branch does not return does not gate.
	fall := "fn try_xdp_userspace(ctx: &XdpContext) -> u32 { let (ingress_ifindex, ingress_iface_flags) = userspace_ingress_metadata(ctx); if ingress_iface_flags & USERSPACE_INGRESS_IFACE_FLAG_ADJUDICATED == 0 { let _z = 1; } helper(ingress_ifindex) }\n" +
		"fn helper(x: u32) -> u32 { USERSPACE_BINDINGS.get(0); 0 }\n"
	if p := checkBindingGate7588(fall); len(p) == 0 {
		t.Error("non-returning gate: want problems, got none")
	}
}
