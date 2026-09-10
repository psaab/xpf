package userspace

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Issue 9428: the #5144 external-tuple-overlap gate enumerates source-NAT
// allocator OWNERS and states its own soundness condition in a comment --
// "Allocator instances (owners) are enumerated exactly as the Rust helper keys
// its allocators, so Go and the dataplane agree on what is 'one allocator'" --
// and nothing checked it. #9062 added `from_routing_instance` to
// `SourceNatPoolAllocatorKey`, the claim was false for several hours, and every
// suite stayed green. #9389 removed the field again, so it is true today.
//
// WHAT "AGREE" MEANS, AND WHY IT IS NOT "THE TWO FIELD LISTS ARE EQUAL". The
// issue proposed comparing the Go owner-key struct fields against the Rust key
// fields. On the Go side there is no such struct: `natAllocOwner` is
// `{desc, pool, members}`, an operator-facing DESCRIPTOR. The Go owner
// identity is the dedupe key of the enumeration loop,
// `srcSeen[rule.Then.PoolName]` -- one owner per referenced pool NAME. The Rust
// key is five fields. Compared as lists they differ by construction, so a cell
// asserting equality would red on a correct tree on its first run.
//
// The property #5144 actually depends on is two containments, and this guard
// checks exactly those, deriving every hop from source:
//
//	(i)  Rust never SPLITS one Go owner: every SourceNatPoolAllocatorKey field
//	     is derived from a snapshot field the Go builder fills ONLY from the
//	     pool looked up by that name. Violated, the dataplane builds several
//	     allocators the gate counts as one owner, and the gate UNDER-refuses --
//	     the #9062 shape, and the dangerous direction.
//	(ii) Rust never MERGES two Go owners: every dimension of the Go owner key
//	     reaches a snapshot field the Rust key carries. Violated, the gate
//	     splits owners the dataplane shares and OVER-refuses.
//
// THE CHAIN, derived rather than transcribed (a hand-copied list is a third
// artifact that agrees with itself -- #8901's lesson):
//
//	Rust key field  <- allocator_key_for literal (`self.X` / positional param)
//	param           <- EVERY allocator_key_for call site's argument
//	                   (`self.X`, `rule.X`, or `pending.Y` -> EVERY
//	                   PendingPoolAllocator construction)
//	rule field / local <- the snapshot parse loop (`X: snap.W`,
//	                   `expand_pool_address(.., &mut rule.X, ..)` inside
//	                   `for .. in &snap.W`, `rule.X = L` with
//	                   `let L = if snap.W > 0`)
//	wire field W    -> Go SourceNATRuleSnapshot json tag (go/ast)
//	Go field        -> the builder's composite literal value (go/ast), and
//	                   every assignment to that local in the builder
//
// The call sites are a POPULATION: allocator_key_for has four, two passing
// `self.pool_port_*` and two passing `pending.port_*`. A resolver written
// against the two I noticed first would have been blind to the apply path.
//
// LIMITS, stated so they are not rediscovered as surprises:
//   - Parsing is bounded to the syntactic forms listed above. A form the
//     resolver does not know is a LIVENESS failure naming the field and the
//     dead end -- never a silent "agreement".
//   - "Filled only from the pool" recognises a call whose sole argument is
//     `pool`, a selector on `pool`, the pool-name expression itself, and
//     zero-value assignments (a rule with no pool builds no allocator). A
//     pool-derived value assigned some other way (a literal under a
//     pool-conditional) is NOT recognised; if a key field ever needs one, widen
//     goExprIsPoolScoped9428 -- do not work around it.
//   - NAT64 owners are out of scope. The same comment makes the analogous
//     claim about the NAT64 allocator key, and it is equally unenforced; this
//     issue names SourceNatPoolAllocatorKey.

type ownerKeyParitySources9428 struct {
	rust      string // userspace-dp/src/nat/source/mod.rs
	builder   string // pkg/dataplane/userspace/nat_source.go
	protocol  string // pkg/dataplane/userspace/protocol_nat.go
	validator string // pkg/config/compiler_validate_strict_nat.go
}

func loadOwnerKeyParitySources9428(t *testing.T) ownerKeyParitySources9428 {
	t.Helper()
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("cannot read %s: %v -- this guard is blind without it", p, err)
		}
		return string(b)
	}
	return ownerKeyParitySources9428{
		rust:      read(filepath.Join("..", "..", "..", "userspace-dp", "src", "nat", "source", "mod.rs")),
		builder:   read("nat_source.go"),
		protocol:  read("protocol_nat.go"),
		validator: read(filepath.Join("..", "..", "config", "compiler_validate_strict_nat.go")),
	}
}

// parityReport9428 is what the checker derived, printed on failure so a red
// cell shows the whole chain rather than only the conclusion.
type parityReport9428 struct {
	rustKey      []string          // SourceNatPoolAllocatorKey fields, in order
	rustKeyWire  map[string]string // key field -> snapshot wire field
	goPoolScoped map[string]string // wire field -> Go value, pool-scoped only
	goAllWire    map[string]string // wire field -> Go value, every literal field
	ownerDims    []string          // Go owner-key leaf expressions
	ownerWire    map[string]string // owner leaf -> wire field ("" if none)
}

func (r parityReport9428) table() string {
	var b strings.Builder
	b.WriteString("derived chain:\n")
	for _, f := range r.rustKey {
		w := r.rustKeyWire[f]
		scoped := "NOT pool-scoped"
		if _, ok := r.goPoolScoped[w]; ok {
			scoped = "pool-scoped"
		}
		fmt.Fprintf(&b, "  rust key %-20s <- wire %-16s <- go %-40s [%s]\n",
			f, w, r.goAllWire[w], scoped)
	}
	for _, d := range r.ownerDims {
		fmt.Fprintf(&b, "  go owner key leaf %-30s -> wire %q\n", d, r.ownerWire[d])
	}
	return b.String()
}

var (
	rustKeyStructRe9428  = regexp.MustCompile(`struct\s+SourceNatPoolAllocatorKey\s*\{`)
	rustFieldRe9428      = regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?([a-z_][a-z0-9_]*)\s*:`)
	rustKeyForDefRe9428  = regexp.MustCompile(`fn\s+allocator_key_for\s*\(\s*&self\s*,([^)]*)\)`)
	rustKeyForCallRe9428 = regexp.MustCompile(`allocator_key_for\(\s*([A-Za-z_][\w.]*)\s*,\s*([A-Za-z_][\w.]*)\s*\)`)
	rustPendingLitRe9428 = regexp.MustCompile(`(struct\s+|impl\s+)?PendingPoolAllocator\s*\{`)
	rustRuleLitRe9428    = regexp.MustCompile(`let\s+mut\s+rule\s*=\s*SourceNatRule\s*\{`)
	rustSnapFieldRe9428  = regexp.MustCompile(`(?m)^\s*([a-z_][a-z0-9_]*)\s*:\s*snap\.([a-z_][a-z0-9_]*)\s*(?:\.clone\(\))?\s*,`)
	rustForSnapRe9428    = regexp.MustCompile(`for\s+(\w+)\s+in\s+&snap\.(\w+)\s*\{`)
	rustExpandRe9428     = regexp.MustCompile(`expand_pool_address\(\s*(\w+)\s*,\s*&mut\s+rule\.(\w+)\s*,\s*&mut\s+rule\.(\w+)\s*,?\s*\)`)
	rustRuleAssignRe9428 = regexp.MustCompile(`rule\.(\w+)\s*=\s*(\w+)\s*;`)
	rustLetIfSnapRe9428  = regexp.MustCompile(`let\s+(\w+)\s*=\s*if\s+snap\.(\w+)\s*>\s*0`)
	rustSelfOrRuleRe9428 = regexp.MustCompile(`^(?:self|rule)\.(\w+)(?:\.clone\(\))?$`)
	rustIdentRe9428      = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
)

// braceBody9428 returns the text between the `{` at open and its matching `}`,
// skipping `//` line comments so a brace in a comment cannot unbalance it.
func braceBody9428(src string, open int) (string, bool) {
	if open < 0 || open >= len(src) || src[open] != '{' {
		return "", false
	}
	depth := 0
	for i := open; i < len(src); i++ {
		if src[i] == '/' && i+1 < len(src) && src[i+1] == '/' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open+1 : i], true
			}
		}
	}
	return "", false
}

func stripRustLineComments9428(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if j := strings.Index(l, "//"); j >= 0 {
			lines[i] = l[:j]
		}
	}
	return strings.Join(lines, "\n")
}

// splitRustEntries9428 splits a struct-literal body into trimmed entries.
func splitRustEntries9428(body string) []string {
	var out []string
	for _, e := range strings.Split(stripRustLineComments9428(body), ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

func lineOf9428(src string, off int) int { return strings.Count(src[:off], "\n") + 1 }

// rustKeyWire9428 derives SourceNatPoolAllocatorKey field -> snapshot wire field.
func rustKeyWire9428(rust string) (fields []string, wire map[string]string, liveness, violations []string) {
	wire = map[string]string{}

	// Key fields.
	locs := rustKeyStructRe9428.FindAllStringIndex(rust, -1)
	if len(locs) != 1 {
		return nil, wire, []string{fmt.Sprintf(
			"LIVENESS: expected exactly one `struct SourceNatPoolAllocatorKey {`, found %d -- "+
				"the key was renamed or moved, and a guard that cannot find it must not report agreement", len(locs))}, nil
	}
	body, ok := braceBody9428(rust, locs[0][1]-1)
	if !ok {
		return nil, wire, []string{"LIVENESS: unterminated SourceNatPoolAllocatorKey struct body"}, nil
	}
	for _, l := range strings.Split(stripRustLineComments9428(body), "\n") {
		if m := rustFieldRe9428.FindStringSubmatch(l); m != nil {
			fields = append(fields, m[1])
		}
	}
	if len(fields) == 0 {
		return nil, wire, []string{"LIVENESS: parsed zero SourceNatPoolAllocatorKey fields"}, nil
	}

	// The snapshot parse loop: rule fields and locals -> wire.
	ruleWire := map[string]string{}
	localWire := map[string]string{}
	ruleLit := rustRuleLitRe9428.FindAllStringIndex(rust, -1)
	if len(ruleLit) != 1 {
		return fields, wire, []string{fmt.Sprintf(
			"LIVENESS: expected exactly one `let mut rule = SourceNatRule {` snapshot parse, found %d", len(ruleLit))}, nil
	}
	loopStart := ruleLit[0][0]
	loopLen := strings.Index(rust[loopStart:], "out.push(rule);")
	if loopLen < 0 {
		return fields, wire, []string{"LIVENESS: snapshot parse loop has no `out.push(rule);` to bound it"}, nil
	}
	loop := rust[loopStart : loopStart+loopLen]
	for _, m := range rustSnapFieldRe9428.FindAllStringSubmatch(loop, -1) {
		ruleWire[m[1]] = m[2]
	}
	forVar := map[string]string{}
	for _, m := range rustForSnapRe9428.FindAllStringSubmatch(loop, -1) {
		forVar[m[1]] = m[2]
	}
	for _, m := range rustExpandRe9428.FindAllStringSubmatch(loop, -1) {
		if w, ok := forVar[m[1]]; ok {
			ruleWire[m[2]] = w
			ruleWire[m[3]] = w
		}
	}
	for _, m := range rustLetIfSnapRe9428.FindAllStringSubmatch(loop, -1) {
		localWire[m[1]] = m[2]
	}
	for _, m := range rustRuleAssignRe9428.FindAllStringSubmatch(loop, -1) {
		if w, ok := localWire[m[2]]; ok {
			ruleWire[m[1]] = w
		}
	}

	// PendingPoolAllocator constructions: pending field -> origins.
	type origin struct{ kind, name string } // kind: rule | local | unresolved
	pendingOrigins := map[string][]origin{}
	for _, loc := range rustPendingLitRe9428.FindAllStringSubmatchIndex(rust, -1) {
		if loc[2] >= 0 { // `struct PendingPoolAllocator {` / `impl PendingPoolAllocator {`
			continue
		}
		body, ok := braceBody9428(rust, loc[1]-1)
		if !ok {
			continue
		}
		inLoop := loc[0] >= loopStart && loc[0] < loopStart+loopLen
		for _, e := range splitRustEntries9428(body) {
			name, expr, hasColon := strings.Cut(e, ":")
			name = strings.TrimSpace(name)
			expr = strings.TrimSpace(expr)
			switch {
			case !hasColon && inLoop:
				pendingOrigins[name] = append(pendingOrigins[name], origin{"local", name})
			case !hasColon:
				pendingOrigins[name] = append(pendingOrigins[name], origin{"unresolved",
					fmt.Sprintf("shorthand `%s` at line %d is outside the snapshot parse loop", name, lineOf9428(rust, loc[0]))})
			case rustSelfOrRuleRe9428.MatchString(expr):
				pendingOrigins[name] = append(pendingOrigins[name], origin{"rule", rustSelfOrRuleRe9428.FindStringSubmatch(expr)[1]})
			default:
				pendingOrigins[name] = append(pendingOrigins[name], origin{"unresolved",
					fmt.Sprintf("`%s: %s` at line %d", name, expr, lineOf9428(rust, loc[0]))})
			}
		}
	}

	resolveOrigin := func(o origin) (string, string) {
		switch o.kind {
		case "rule":
			if w, ok := ruleWire[o.name]; ok {
				return w, ""
			}
			return "", fmt.Sprintf("rule field `%s` is set from no snapshot field the resolver recognises", o.name)
		case "local":
			if w, ok := localWire[o.name]; ok {
				return w, ""
			}
			return "", fmt.Sprintf("local `%s` is bound from no `if snap.W > 0` form", o.name)
		default:
			return "", o.name
		}
	}

	// allocator_key_for: key field -> rule field or positional param.
	def := rustKeyForDefRe9428.FindAllStringSubmatchIndex(rust, -1)
	if len(def) != 1 {
		return fields, wire, []string{fmt.Sprintf(
			"LIVENESS: expected exactly one `fn allocator_key_for(&self, ..)`, found %d", len(def))}, nil
	}
	var params []string
	for _, p := range strings.Split(rust[def[0][2]:def[0][3]], ",") {
		if n, _, ok := strings.Cut(p, ":"); ok && strings.TrimSpace(n) != "" {
			params = append(params, strings.TrimSpace(n))
		}
	}
	fnOpen := strings.Index(rust[def[0][1]:], "{")
	fnBody, ok := braceBody9428(rust, def[0][1]+fnOpen)
	if fnOpen < 0 || !ok {
		return fields, wire, []string{"LIVENESS: allocator_key_for has no body"}, nil
	}
	litOpen := strings.Index(fnBody, "SourceNatPoolAllocatorKey {")
	if litOpen < 0 {
		return fields, wire, []string{"LIVENESS: allocator_key_for builds no `SourceNatPoolAllocatorKey {` literal"}, nil
	}
	lit, ok := braceBody9428(fnBody, litOpen+len("SourceNatPoolAllocatorKey "))
	if !ok {
		return fields, wire, []string{"LIVENESS: unterminated SourceNatPoolAllocatorKey literal in allocator_key_for"}, nil
	}
	keyRule := map[string]string{}
	keyParam := map[string]int{}
	for _, e := range splitRustEntries9428(lit) {
		name, expr, hasColon := strings.Cut(e, ":")
		name, expr = strings.TrimSpace(name), strings.TrimSpace(expr)
		if !hasColon {
			expr = name
		}
		if m := rustSelfOrRuleRe9428.FindStringSubmatch(expr); m != nil {
			keyRule[name] = m[1]
			continue
		}
		for i, p := range params {
			if expr == p {
				keyParam[name] = i
			}
		}
	}

	// Every call site. The population is counted INDEPENDENTLY of the parse:
	// the argument regex only understands simple paths, so a call written any
	// other way (`pending.port_low + 0`) would simply not match it and drop out
	// of the population -- an inventory built by running the pass is blind to
	// what the pass does not recognise. Every `allocator_key_for(` other than
	// the definition must therefore be parsed, or the guard reports LIVENESS.
	calls := rustKeyForCallRe9428.FindAllStringSubmatchIndex(rust, -1)
	if len(calls) == 0 {
		return fields, wire, []string{"LIVENESS: allocator_key_for has no call site"}, nil
	}
	parsed := map[int]bool{}
	for _, c := range calls {
		parsed[c[0]] = true
	}
	for off := 0; ; {
		i := strings.Index(rust[off:], "allocator_key_for(")
		if i < 0 {
			break
		}
		at := off + i
		off = at + len("allocator_key_for(")
		if at >= def[0][0] && at < def[0][1] {
			continue // the definition itself
		}
		if !parsed[at] {
			end := strings.Index(rust[at:], ")")
			if end < 0 {
				end = len(rust) - at - 1
			}
			liveness = append(liveness, fmt.Sprintf(
				"LIVENESS: allocator_key_for call at line %d (`%s`) has arguments this guard cannot trace -- "+
					"it is part of the population, so it cannot be skipped", lineOf9428(rust, at), rust[at:at+end+1]))
		}
	}

	for _, f := range fields {
		if rf, ok := keyRule[f]; ok {
			w, why := resolveOrigin(origin{"rule", rf})
			if w == "" {
				liveness = append(liveness, fmt.Sprintf("LIVENESS: cannot trace key field `%s`: %s", f, why))
				continue
			}
			wire[f] = w
			continue
		}
		pi, ok := keyParam[f]
		if !ok {
			liveness = append(liveness, fmt.Sprintf(
				"LIVENESS: allocator_key_for sets key field `%s` from neither `self.X` nor a parameter", f))
			continue
		}
		seen := map[string][]string{} // wire -> provenance
		for _, c := range calls {
			arg := rust[c[2+2*pi]:c[3+2*pi]]
			line := lineOf9428(rust, c[0])
			var origins []origin
			switch {
			case strings.HasPrefix(arg, "pending."):
				origins = pendingOrigins[strings.TrimPrefix(arg, "pending.")]
				if len(origins) == 0 {
					liveness = append(liveness, fmt.Sprintf(
						"LIVENESS: call at line %d passes `%s`, and no PendingPoolAllocator construction sets it", line, arg))
				}
			case rustSelfOrRuleRe9428.MatchString(arg):
				origins = []origin{{"rule", rustSelfOrRuleRe9428.FindStringSubmatch(arg)[1]}}
			case rustIdentRe9428.MatchString(arg):
				origins = []origin{{"local", arg}}
			default:
				origins = []origin{{"unresolved", fmt.Sprintf("argument `%s` at line %d", arg, line)}}
			}
			for _, o := range origins {
				w, why := resolveOrigin(o)
				if w == "" {
					liveness = append(liveness, fmt.Sprintf(
						"LIVENESS: cannot trace key field `%s` through the call at line %d: %s", f, line, why))
					continue
				}
				seen[w] = append(seen[w], fmt.Sprintf("line %d `%s`", line, arg))
			}
		}
		switch len(seen) {
		case 0:
			// already reported as liveness
		case 1:
			for w := range seen {
				wire[f] = w
			}
		default:
			violations = append(violations, fmt.Sprintf(
				"RUST DISAGREES WITH ITSELF: key field `%s` is derived from different snapshot fields at different "+
					"allocator_key_for call sites: %v -- one pool could key two allocators", f, seen))
		}
	}
	return fields, wire, liveness, violations
}

// goExprIsPoolScoped9428 reports whether a builder value is filled only from the
// name-keyed pool: the pool-name expression itself, a call whose sole argument
// is `pool`, a selector on `pool`, or a zero value (no pool, no allocator).
func goExprIsPoolScoped9428(e ast.Expr, nameExpr string) bool {
	if types.ExprString(e) == nameExpr {
		return true
	}
	switch x := e.(type) {
	case *ast.CallExpr:
		if len(x.Args) == 1 {
			if id, ok := x.Args[0].(*ast.Ident); ok && id.Name == "pool" {
				return true
			}
		}
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok && id.Name == "pool" {
			return true
		}
	case *ast.Ident:
		return x.Name == "nil"
	case *ast.BasicLit:
		return x.Value == "0" || x.Value == `""`
	}
	return false
}

func goSnapshotWireNames9428(protocol string) (map[string]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), "protocol_nat.go", protocol, 0)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "SourceNATRuleSnapshot" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, fld := range st.Fields.List {
			if fld.Tag == nil {
				continue
			}
			tag := reflect.StructTag(strings.Trim(fld.Tag.Value, "`")).Get("json")
			name, _, _ := strings.Cut(tag, ",")
			for _, id := range fld.Names {
				out[id.Name] = name
			}
		}
		return false
	})
	return out, nil
}

func exprLeaves9428(e ast.Expr) []string {
	switch x := e.(type) {
	case *ast.BinaryExpr:
		return append(exprLeaves9428(x.X), exprLeaves9428(x.Y)...)
	case *ast.ParenExpr:
		return exprLeaves9428(x.X)
	case *ast.BasicLit:
		return nil
	default:
		return []string{types.ExprString(e)}
	}
}

func checkOwnerKeyParity9428(src ownerKeyParitySources9428) (rep parityReport9428, liveness, violations []string) {
	rep.goPoolScoped = map[string]string{}
	rep.goAllWire = map[string]string{}
	rep.ownerWire = map[string]string{}

	var rl, rv []string
	rep.rustKey, rep.rustKeyWire, rl, rv = rustKeyWire9428(src.rust)
	liveness = append(liveness, rl...)
	violations = append(violations, rv...)

	// Go builder.
	wireOf, err := goSnapshotWireNames9428(src.protocol)
	if err != nil || len(wireOf) == 0 {
		return rep, append(liveness, fmt.Sprintf("LIVENESS: no SourceNATRuleSnapshot json tags parsed (%v)", err)), violations
	}
	bf, err := parser.ParseFile(token.NewFileSet(), "nat_source.go", src.builder, 0)
	if err != nil {
		return rep, append(liveness, fmt.Sprintf("LIVENESS: nat_source.go does not parse: %v", err)), violations
	}
	var fn *ast.FuncDecl
	for _, d := range bf.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "buildSourceNATSnapshotsWithFeeds" {
			fn = fd
		}
	}
	if fn == nil {
		return rep, append(liveness, "LIVENESS: buildSourceNATSnapshotsWithFeeds not found"), violations
	}
	assigns := map[string][]ast.Expr{}
	var lits []*ast.CompositeLit
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, l := range x.Lhs {
				id, ok := l.(*ast.Ident)
				if !ok || id.Name == "_" {
					continue
				}
				if len(x.Rhs) == len(x.Lhs) {
					assigns[id.Name] = append(assigns[id.Name], x.Rhs[i])
				} else if len(x.Rhs) == 1 {
					assigns[id.Name] = append(assigns[id.Name], x.Rhs[0])
				}
			}
		case *ast.CompositeLit:
			if id, ok := x.Type.(*ast.Ident); ok && id.Name == "SourceNATRuleSnapshot" {
				lits = append(lits, x)
			}
		}
		return true
	})

	// `pool` must be bound only by the name-keyed lookup; its index IS the name.
	nameExpr := ""
	for _, rhs := range assigns["pool"] {
		ix, ok := rhs.(*ast.IndexExpr)
		if !ok {
			violations = append(violations, fmt.Sprintf(
				"GO BUILDER: `pool` is assigned from `%s`, not a lookup by pool name, so nothing "+
					"derived from it is provably a function of the name", types.ExprString(rhs)))
			continue
		}
		if nameExpr == "" {
			nameExpr = types.ExprString(ix.Index)
		} else if nameExpr != types.ExprString(ix.Index) {
			violations = append(violations, fmt.Sprintf(
				"GO BUILDER: `pool` is looked up by two different keys (%s, %s)", nameExpr, types.ExprString(ix.Index)))
		}
	}
	if nameExpr == "" {
		return rep, append(liveness, "LIVENESS: no `pool := ...[<name>]` binding in the builder"), violations
	}
	if len(lits) != 1 {
		return rep, append(liveness, fmt.Sprintf(
			"LIVENESS: expected exactly one SourceNATRuleSnapshot literal in the builder, found %d", len(lits))), violations
	}
	valueByExpr := map[string]string{} // Go value expression -> wire
	for _, el := range lits[0].Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		w := wireOf[key.Name]
		if w == "" {
			continue
		}
		vs := types.ExprString(kv.Value)
		rep.goAllWire[w] = vs
		valueByExpr[vs] = w
		scoped := goExprIsPoolScoped9428(kv.Value, nameExpr)
		if id, ok := kv.Value.(*ast.Ident); ok && !scoped {
			rhs := assigns[id.Name]
			scoped = len(rhs) > 0
			for _, r := range rhs {
				if !goExprIsPoolScoped9428(r, nameExpr) {
					scoped = false
				}
			}
		}
		if scoped {
			rep.goPoolScoped[w] = vs
		}
	}

	// Go owner key.
	vf, err := parser.ParseFile(token.NewFileSet(), "compiler_validate_strict_nat.go", src.validator, 0)
	if err != nil {
		return rep, append(liveness, fmt.Sprintf("LIVENESS: validator does not parse: %v", err)), violations
	}
	var ownerIndexes []ast.Expr
	for _, d := range vf.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "validateNATPoolExternalTupleOverlapStrict" {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, l := range as.Lhs {
				if ix, ok := l.(*ast.IndexExpr); ok {
					if id, ok := ix.X.(*ast.Ident); ok && id.Name == "srcSeen" {
						ownerIndexes = append(ownerIndexes, ix.Index)
					}
				}
			}
			return true
		})
	}
	if len(ownerIndexes) != 1 {
		return rep, append(liveness, fmt.Sprintf(
			"LIVENESS: expected exactly one `srcSeen[...] = ...` owner dedupe in "+
				"validateNATPoolExternalTupleOverlapStrict, found %d", len(ownerIndexes))), violations
	}
	rep.ownerDims = exprLeaves9428(ownerIndexes[0])
	if len(rep.ownerDims) == 0 {
		return rep, append(liveness, "LIVENESS: the owner dedupe key has no non-literal dimension"), violations
	}

	rustWires := map[string]bool{}
	for _, w := range rep.rustKeyWire {
		rustWires[w] = true
	}

	// (i) Rust never splits one Go owner.
	for _, f := range rep.rustKey {
		w, ok := rep.rustKeyWire[f]
		if !ok {
			continue // liveness already reported
		}
		if _, scoped := rep.goPoolScoped[w]; scoped {
			continue
		}
		from := rep.goAllWire[w]
		if from == "" {
			from = "nothing -- the Go builder does not set it"
		}
		violations = append(violations, fmt.Sprintf(
			"RUST HAS IT, GO DOES NOT: SourceNatPoolAllocatorKey.%s is derived from snapshot field %q, which the Go "+
				"builder fills from %s -- not from the pool the #5144 gate keys owners by (one owner per %s). The "+
				"dataplane would build separate allocators the gate counts as ONE owner, so the gate under-refuses "+
				"(#9062 was exactly this)", f, w, from, nameExpr))
	}

	// (ii) Rust never merges two Go owners.
	for _, d := range rep.ownerDims {
		w := valueByExpr[d]
		rep.ownerWire[d] = w
		switch {
		case w == "":
			violations = append(violations, fmt.Sprintf(
				"GO HAS IT, RUST DOES NOT: the #5144 owner key reads `%s`, which feeds no SourceNATRuleSnapshot "+
					"field, so no Rust allocator key can carry it -- the gate splits owners the dataplane shares", d))
		case !rustWires[w]:
			violations = append(violations, fmt.Sprintf(
				"GO HAS IT, RUST DOES NOT: the #5144 owner key reads `%s` (snapshot field %q), which "+
					"SourceNatPoolAllocatorKey does not carry -- the gate splits owners the dataplane shares "+
					"(over-refusal)", d, w))
		}
	}
	sort.Strings(liveness)
	return rep, liveness, violations
}

// TestSourceNATOwnerKeyMatchesRustAllocatorKey9428 is the guard on the real tree.
func TestSourceNATOwnerKeyMatchesRustAllocatorKey9428(t *testing.T) {
	rep, liveness, violations := checkOwnerKeyParity9428(loadOwnerKeyParitySources9428(t))
	if len(liveness) > 0 {
		t.Fatalf("#9428: the parity guard is BLIND, not agreeing:\n%s\n\n%s", strings.Join(liveness, "\n"), rep.table())
	}
	// POSITIVE CONTROL -- the part the issue names as most likely omitted. A
	// parser that found nothing on either side would otherwise pass every
	// containment check below vacuously.
	if len(rep.rustKey) == 0 || len(rep.rustKeyWire) != len(rep.rustKey) {
		t.Fatalf("#9428 positive control: %d Rust key fields, %d traced to the wire -- both must be non-zero and equal\n%s",
			len(rep.rustKey), len(rep.rustKeyWire), rep.table())
	}
	if len(rep.ownerDims) == 0 || len(rep.goPoolScoped) == 0 {
		t.Fatalf("#9428 positive control: %d Go owner-key dimensions, %d pool-scoped Go snapshot fields -- both must be non-zero\n%s",
			len(rep.ownerDims), len(rep.goPoolScoped), rep.table())
	}
	if len(violations) > 0 {
		t.Fatalf("#9428: the #5144 owner enumeration and the Rust allocator key DISAGREE:\n%s\n\n%s",
			strings.Join(violations, "\n"), rep.table())
	}
	t.Logf("\n%s", rep.table())
}

func mustReplaceOnce9428(t *testing.T, s, old, repl, what string) string {
	t.Helper()
	if n := strings.Count(s, old); n != 1 {
		t.Fatalf("fixture edit %q: anchor found %d times, want exactly 1 -- an edit that does not apply "+
			"turns this cell into a copy of the real-tree cell, which passes for the wrong reason", what, n)
	}
	return strings.Replace(s, old, repl, 1)
}

// The fixture cells below run the SAME checker on the REAL sources with one
// planted edit each, and assert the exact message. They are what makes "the
// real tree agrees" mean something: the checker that reports agreement there is
// shown, on the same inputs, to report each kind of disagreement and to name
// the field and the side.

// A field added to the RUST key only -- the #9062 shape.
func TestOwnerKeyParityNamesARustOnlyKeyField9428(t *testing.T) {
	src := loadOwnerKeyParitySources9428(t)
	src.rust = mustReplaceOnce9428(t, src.rust,
		"    port_high: u16,\n    // #9389: `from_routing_instance` was ADDED here",
		"    port_high: u16,\n    from_routing_instance: String,\n    // #9389: `from_routing_instance` was ADDED here",
		"add from_routing_instance to SourceNatPoolAllocatorKey")
	src.rust = mustReplaceOnce9428(t, src.rust,
		"            port_low,\n            port_high,\n        }\n    }\n}",
		"            port_low,\n            port_high,\n            from_routing_instance: self.from_routing_instance.clone(),\n        }\n    }\n}",
		"populate from_routing_instance in allocator_key_for")
	_, liveness, violations := checkOwnerKeyParity9428(src)
	if len(liveness) > 0 {
		t.Fatalf("the planted Rust field made the checker BLIND instead of reporting it:\n%s", strings.Join(liveness, "\n"))
	}
	if len(violations) != 1 ||
		!strings.Contains(violations[0], "RUST HAS IT, GO DOES NOT") ||
		!strings.Contains(violations[0], "SourceNatPoolAllocatorKey.from_routing_instance") {
		t.Fatalf("#9428: a Rust-only key field must produce exactly one violation naming the field and the Rust side; got %d:\n%s",
			len(violations), strings.Join(violations, "\n"))
	}
}

// A dimension added to the GO owner key only.
func TestOwnerKeyParityNamesAGoOnlyOwnerDimension9428(t *testing.T) {
	src := loadOwnerKeyParitySources9428(t)
	src.validator = mustReplaceOnce9428(t, src.validator,
		"srcSeen[rule.Then.PoolName] = true",
		`srcSeen[rule.Then.PoolName+"/"+rs.FromRoutingInstance] = true`,
		"widen the Go owner dedupe key by routing instance")
	_, liveness, violations := checkOwnerKeyParity9428(src)
	if len(liveness) > 0 {
		t.Fatalf("the planted Go dimension made the checker BLIND instead of reporting it:\n%s", strings.Join(liveness, "\n"))
	}
	if len(violations) != 1 ||
		!strings.Contains(violations[0], "GO HAS IT, RUST DOES NOT") ||
		!strings.Contains(violations[0], "rs.FromRoutingInstance") {
		t.Fatalf("#9428: a Go-only owner dimension must produce exactly one violation naming the dimension and the Go side; got %d:\n%s",
			len(violations), strings.Join(violations, "\n"))
	}
}

// SURVIVE-direction control: an inert edit inside the parsed struct must not
// register as a disagreement, or the two cells above prove nothing about
// discrimination.
func TestOwnerKeyParityIgnoresAnInertEdit9428(t *testing.T) {
	src := loadOwnerKeyParitySources9428(t)
	src.rust = mustReplaceOnce9428(t, src.rust,
		"pub(crate) struct SourceNatPoolAllocatorKey {\n    pool_name: String,\n",
		"pub(crate) struct SourceNatPoolAllocatorKey {\n    // an inert comment: port_low: u16, not a field\n    pool_name: String,\n",
		"insert a comment into the key struct")
	_, liveness, violations := checkOwnerKeyParity9428(src)
	if len(liveness) > 0 || len(violations) > 0 {
		t.Fatalf("#9428: an inert comment must change nothing; got liveness=%v violations=%v", liveness, violations)
	}
}

// A checker that cannot find the key must say BLIND, never "agree".
func TestOwnerKeyParityIsBlindNotAgreeingWithoutTheKey9428(t *testing.T) {
	src := loadOwnerKeyParitySources9428(t)
	src.rust = mustReplaceOnce9428(t, src.rust,
		"struct SourceNatPoolAllocatorKey",
		"struct SourceNatPoolAllocatorKeyRenamed",
		"rename the key struct")
	_, liveness, _ := checkOwnerKeyParity9428(src)
	if len(liveness) == 0 {
		t.Fatalf("#9428: with the key struct renamed the checker must report LIVENESS; it reported none, " +
			"which is how an empty parse reads as agreement")
	}
}

// Two allocator_key_for call sites deriving one key field from DIFFERENT
// snapshot fields is a Rust-internal disagreement: one pool could key two
// allocators. This is the branch a swapped-argument edit reaches, and no
// behavioural cell in either suite would see it.
func TestOwnerKeyParityNamesARustSelfDisagreement9428(t *testing.T) {
	src := loadOwnerKeyParitySources9428(t)
	src.rust = mustReplaceOnce9428(t, src.rust,
		".then(|| self.allocator_key_for(self.pool_port_low, self.pool_port_high))",
		".then(|| self.allocator_key_for(self.pool_port_high, self.pool_port_low))",
		"swap the port arguments at one call site")
	_, liveness, violations := checkOwnerKeyParity9428(src)
	if len(liveness) > 0 {
		t.Fatalf("a swapped call site made the checker BLIND instead of reporting it:\n%s", strings.Join(liveness, "\n"))
	}
	if len(violations) == 0 {
		t.Fatalf("#9428: call sites deriving one key field from different snapshot fields must be reported; got none")
	}
	for _, v := range violations {
		if !strings.Contains(v, "RUST DISAGREES WITH ITSELF") {
			t.Fatalf("#9428: expected only self-disagreement violations, got:\n%s", strings.Join(violations, "\n"))
		}
	}
}

// A call site the argument parser cannot read is part of the population and
// must make the guard say BLIND. Before this was counted independently, such a
// call silently dropped out and the guard reported agreement over the rest.
func TestOwnerKeyParityCannotSkipAnUnparseableCallSite9428(t *testing.T) {
	src := loadOwnerKeyParitySources9428(t)
	src.rust = mustReplaceOnce9428(t, src.rust,
		".then(|| self.allocator_key_for(self.pool_port_low, self.pool_port_high))",
		".then(|| self.allocator_key_for(self.pool_port_low + 0, self.pool_port_high))",
		"make one call site's argument unparseable")
	_, liveness, _ := checkOwnerKeyParity9428(src)
	found := false
	for _, l := range liveness {
		if strings.Contains(l, "has arguments this guard cannot trace") {
			found = true
		}
	}
	if !found {
		t.Fatalf("#9428: an unparseable allocator_key_for call must be a LIVENESS failure; got liveness=%v", liveness)
	}
}
