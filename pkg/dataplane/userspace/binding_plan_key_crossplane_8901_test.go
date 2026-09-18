package userspace

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Issue 8901: the Go binding-plan key and the Rust binding-plan hash are two
// independently-maintained answers to ONE question -- "did the AF_XDP binding
// plan change?" -- and they disagreed about six inputs.
//
// WHY A ONE-SIDED CELL IS NOT ENOUGH, which is the whole design here. A Go test
// asserting "snapshotBindingPlanKey covers field X" re-derives the Go side's
// own opinion and passes no matter what Rust hashes. The failure being guarded
// is a DISAGREEMENT between two hashes, so the guard has to read both.
//
// It is the #8892 shape-digest shape applied to a pair of functions rather than
// to a struct: it cannot tell a deliberate difference from an accidental one
// and does not try. It forces a decision at the moment a field is added to
// either side, which is the moment the decision is cheap.
//
// THE CONSEQUENCE OF DISAGREEING. `snapshotBindingPlanKey` gates the
// same-plan refresh exception -- the rule that lets a FIB-only update publish
// during the pending-XSK-startup window, because blocking it deadlocks (XSK
// liveness needs RX traffic, transit traffic needs FIB data). A field Rust
// hashes and Go does not means Go classifies the change as "same plan" and
// publishes it straight through, while the helper rebuilds its AF_XDP
// bindings underneath -- back-to-back reconciles in the window whose entire
// purpose is to avoid them.

// rustPlanKeyIfaceFields8901 extracts the interface-tuple field names the Rust
// plan hash reads, from the `iface={}/{}...` format call in planning.rs.
//
// Parsed rather than transcribed: a transcribed list is a SECOND copy of the
// Rust source that agrees with itself and drifts silently (#8901 is exactly
// that failure one level up).
func rustPlanKeyIfaceFields8901(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "userspace-dp", "src", "server", "helpers", "planning.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v -- this guard is blind without the Rust side", path, err)
	}
	body := string(src)
	start := strings.Index(body, `"iface={}`)
	if start < 0 {
		t.Fatal("LIVENESS: planning.rs no longer contains an `iface={}` plan-key format " +
			"string. Either the hash was restructured or this guard is reading the wrong " +
			"file; it cannot report agreement it did not check")
	}
	end := strings.Index(body[start:], ")")
	if end < 0 {
		t.Fatal("LIVENESS: unterminated iface format call in planning.rs")
	}
	seg := body[start : start+end]
	re := regexp.MustCompile(`iface\.([a-z_]+)`)
	var out []string
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(seg, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	// `rx_queues` is passed as a local resolved by `plan_key_rx_queues`, not as
	// `iface.rx_queues`, so the regex above cannot see it. Recover it from the
	// binding rather than hardcoding the tuple.
	if strings.Contains(seg, "rx_queues") {
		if !seen["rx_queues"] {
			out = append(out, "rx_queues")
		}
	}
	sort.Strings(out)
	return out
}

// goPlanKeyIfaceFields8901 extracts the same set from the Go side, by parsing
// `snapshotBindingPlanKey`'s own Fprintf rather than by listing it here.
func goPlanKeyIfaceFields8901(t *testing.T) []string {
	t.Helper()
	// #9009: parsed with go/ast, not a regex over a text window.
	//
	// The previous extractor took the segment from `"iface=` to the FIRST `)`
	// and matched `iface\.([A-Za-z]+)` in it. That worked only while every
	// argument was a bare field selector: the moment one became a CALL —
	// `planKeyRXQueues(snapshot, iface, resolvedLinux)`, which is how #9009
	// aligns the effective rx_queues — its inner `)` truncated the window and
	// SILENTLY dropped every field after it. The failure reported four fields
	// as "hashed by Rust and not by Go" that Go still hashes, i.e. it
	// misattributed an instrument break to the code under test, in the
	// direction that reads as a real defect.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "maps_sync.go", nil, 0)
	if err != nil {
		t.Fatalf("parse maps_sync.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "snapshotBindingPlanKey" {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("LIVENESS: snapshotBindingPlanKey no longer exists under that name")
	}

	// The Fprintf whose format literal starts the `iface=` tuple.
	var tuple *ast.CallExpr
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || tuple != nil {
			return true
		}
		for _, a := range call.Args {
			lit, ok := a.(*ast.BasicLit)
			if ok && lit.Kind == token.STRING && strings.HasPrefix(lit.Value, `"iface=`) {
				tuple = call
				return false
			}
		}
		return true
	})
	if tuple == nil {
		t.Fatal("LIVENESS: snapshotBindingPlanKey no longer emits an `iface=` tuple")
	}

	seen := map[string]bool{}
	var out []string
	add := func(wire string) {
		if !seen[wire] {
			seen[wire] = true
			out = append(out, wire)
		}
	}
	for _, arg := range tuple.Args {
		ast.Inspect(arg, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.SelectorExpr:
				// A field read off the row itself.
				if id, ok := e.X.(*ast.Ident); ok && id.Name == "iface" {
					add(goFieldToWireName8901(e.Sel.Name))
				}
			case *ast.CallExpr:
				// A field supplied by a RESOLVER rather than read directly.
				// #9009 routes rx_queues through planKeyRXQueues so the key
				// follows the value the planner will actually use; the field is
				// still hashed, by a different expression.
				if id, ok := e.Fun.(*ast.Ident); ok && id.Name == "planKeyRXQueues" {
					add("rx_queues")
				}
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

// goFieldToWireName8901 maps a Go struct field to the snake_case name the Rust
// side uses, so the two sets are comparable at all.
func goFieldToWireName8901(f string) string {
	switch f {
	case "Name":
		return "name"
	case "LinuxName":
		return "linux_name"
	case "Ifindex":
		return "ifindex"
	case "ParentIfindex":
		return "parent_ifindex"
	case "ParentLinuxName":
		return "parent_linux_name"
	case "RXQueues":
		return "rx_queues"
	case "LogicalOnly":
		return "logical_only"
	case "Tunnel":
		return "tunnel"
	case "VLANID":
		return "vlan_id"
	}
	return strings.ToLower(f)
}

// adjudicated8901 records differences that are DELIBERATE, each with the reason
// it is correct for the two planes to disagree about that field.
//
// An entry here is a claim, not a suppression: it says someone decided this
// field belongs on one side only. Adding one to silence a failure without a
// reason is the stale-allowlist failure this guard exists to prevent.
var adjudicated8901 = map[string]string{
	// `logical_only` is Go-only, and the reason recorded here until #9009 was
	// FALSE. It claimed "Rust excludes the row upstream via
	// include_userspace_binding_interface" — but that function tests
	// zone-empty, local_fabric_member, userspace_unbindable_netdev, and
	// nothing about logical-only. `logical_only` appears NOWHERE in
	// userspace-dp (positive control: `parent_unbindable` hits main_tests.rs),
	// and InterfaceSnapshot has no such field and no deny_unknown_fields, so
	// the wire value is silently discarded.
	//
	// The CONCLUSION survives, which is why the entry survives: a LogicalOnly
	// flip also swaps the row between a real and a synthetic ifindex
	// (shouldUseLogicalOnlyParentBoundRethVLAN), and BOTH sides hash the
	// ifindex — so the extra field cannot move Go's key alone, and Go
	// over-detects on nothing. What changed is that the reason is now true.
	// A false rationale that licenses a real difference is worse than none:
	// it is inherited as established and reasoned from.
	"logical_only": "Go-only; a LogicalOnly flip also swaps the row's ifindex, which BOTH sides hash, so it cannot move Go's key alone (#9009 D5 — the pre-#9009 reason, 'Rust excludes it upstream', was false)",
}

// WHAT THIS GUARD DOES NOT CHECK, stated because a guard that reports
// agreement on a set it never examined is worse than no guard.
//
// It compares the FIELD NAMES in each side's interface tuple. The #8901 census
// found two further classes of disagreement that this cell is structurally
// blind to, both recorded here rather than left implied:
//
//   1. VALUE-level. Same field name, different value on each side.
//   2. POPULATION-level. Same fields hashed over a different ROW SET.
//
// BOTH CLASSES WERE REAL AND ARE NOW CLOSED (#9009), which is recorded here
// because the previous wording named them as open and would otherwise keep
// describing a state that no longer exists — the same rot the `logical_only`
// adjudication above suffered. Go now resolves the effective rx_queues
// including the orphan-VLAN re-key (`planKeyRXQueues`) and applies the refusal
// filters to BOTH loops. THIS CELL STILL CANNOT SEE EITHER CLASS: it compares
// field NAMES, so it would pass just as happily if they were re-opened
// tomorrow. What actually holds them is plan_key_crossplane_9009_test.go, which
// EXECUTES the hash over paired snapshots and asserts whether the key moves.
//
// THE DIRECTION OF EACH MATTERS AND IS NOT SYMMETRIC. A field RUST hashes and
// Go does not means Go UNDER-detects: it calls a real plan change "same plan"
// and publishes through the pending-XSK-startup window while the helper
// rebuilds. That is the dangerous direction and it is what this cell catches.
// A field GO hashes and Rust does not means Go OVER-detects -- it blocks or
// restarts where the helper would not have. Conservative, wasteful, not
// unsafe. The two open classes above are: (1) Go under-detects an out-of-band
// `ethtool -L` queue change, though that is not a config commit and this key is
// about config snapshots; (2) Go over-detects on refused rows.
//
// Neither is CHECKED here, and this cell passing must not be read as
// adjudicating them — it never executes either hash. It forces a decision when
// a field NAME is added to an interface tuple, and that is all it does.

func TestBindingPlanKeyAgreesAcrossPlanes8901(t *testing.T) {
	rust := rustPlanKeyIfaceFields8901(t)
	golang := goPlanKeyIfaceFields8901(t)

	if len(rust) == 0 || len(golang) == 0 {
		t.Fatal("NON-VACUITY: one side parsed to an EMPTY field set, so the comparison " +
			"below would pass by having nothing to compare")
	}

	inRust := map[string]bool{}
	for _, f := range rust {
		inRust[f] = true
	}
	inGo := map[string]bool{}
	for _, f := range golang {
		inGo[f] = true
	}

	for _, f := range rust {
		if inGo[f] {
			continue
		}
		if why, ok := adjudicated8901[f]; ok {
			t.Logf("adjudicated Rust-only input %q: %s", f, why)
			continue
		}
		t.Errorf("binding-plan input %q is hashed by RUST and not by Go (#8901).\n"+
			"  Go's snapshotBindingPlanKey gates the same-plan refresh exception, so a "+
			"config changing only this field is classified as SAME PLAN and published "+
			"straight through the pending-XSK-startup window -- while the helper, whose "+
			"hash does include it, rebuilds its AF_XDP bindings. Two planes disagreeing "+
			"about whether the plan moved, with the Go side deciding whether it is safe "+
			"to publish.\n"+
			"  Either add it to snapshotBindingPlanKey, or record in adjudicated8901 why "+
			"the two SHOULD differ here.\n"+
			"  rust=%v\n  go=%v", f, rust, golang)
	}
	for _, f := range golang {
		if inRust[f] {
			continue
		}
		if why, ok := adjudicated8901[f]; ok {
			t.Logf("adjudicated Go-only input %q: %s", f, why)
			continue
		}
		t.Errorf("binding-plan input %q is hashed by GO and not by Rust (#8901).\n"+
			"  This direction is the less obvious one and it is why the guard is "+
			"two-sided: a fix that makes Go match Rust cannot resolve it. Either the "+
			"Rust hash is missing an input the planner reads, or the field is a Go-side "+
			"concept and belongs in adjudicated8901 with the reason.\n"+
			"  rust=%v\n  go=%v", f, rust, golang)
	}
}

// The top-level (non-per-interface) inputs, checked the same way. `shared_umem`
// is the input this issue was filed for.
func TestBindingPlanKeyTopLevelInputsAgree8901(t *testing.T) {
	path := filepath.Join("..", "..", "..", "userspace-dp", "src", "server", "helpers", "planning.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	rustHashesSharedUMEM := strings.Contains(string(src), `hash_update(hasher, "shared_umem=")`)
	if !rustHashesSharedUMEM {
		t.Fatal("LIVENESS: the Rust plan hash no longer covers shared_umem. If that was " +
			"deliberate, this cell and #8901's premise both need re-deriving -- it must " +
			"not silently start reporting agreement because the Rust side dropped the field")
	}

	goSrc, err := os.ReadFile("maps_sync.go")
	if err != nil {
		t.Fatalf("cannot read maps_sync.go: %v", err)
	}
	body := string(goSrc)
	start := strings.Index(body, "func snapshotBindingPlanKey(")
	if start < 0 {
		t.Fatal("LIVENESS: snapshotBindingPlanKey no longer exists under that name")
	}
	seg := body[start:]
	if e := strings.Index(seg, "\nfunc "); e > 0 {
		seg = seg[:e]
	}
	// Look for the EMITTED KEY LITERAL, not the identifier.
	//
	// This cell first searched `seg` for "SharedUMEM" and was VACUOUS: the
	// explanatory comment beside the fix names SharedUMEM three times, so the
	// check passed on the prose and survived deleting the code it guards.
	// Caught by mutation, which is the only thing that could have caught it --
	// the cell was green before and after.
	//
	// `shared_umem=` is the wire-visible key fragment; a comment would have to
	// contain the literal format string to fool this, and the mutation below
	// confirms it does not.
	if !strings.Contains(seg, `"shared_umem=`) {
		t.Error("#8901: the Rust plan hash covers `shared_umem` and Go's " +
			"snapshotBindingPlanKey does not.\n" +
			"  A config changing only SharedUMEM leaves the Go key unchanged, so the " +
			"same-plan refresh exception fires and the update publishes during the " +
			"pending-XSK-startup window -- while the helper rebuilds its bindings. The " +
			"window exists precisely to avoid back-to-back AF_XDP reconciles that " +
			"self-collide.\n" +
			"  This is NOT the #8899 question: that one is process identity (argv, " +
			"binary, sockets) and correctly excludes SharedUMEM, because a SharedUMEM " +
			"change reaches the helper inside the snapshot rather than on the command " +
			"line. This is whether the two PLAN hashes agree.")
	}
}
