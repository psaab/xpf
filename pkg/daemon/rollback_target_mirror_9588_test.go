package daemon

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9588: the #6707 commit-confirmed pre-flight predicted a refused rollback
// target from LenientContentDropped alone, so every other whole-snapshot
// refusal the Go mirror (dpuserspace.PolicyContentRejectionReasons) reproduces
// still armed a rollback that reverts the store but not forwarding. The gate
// now asks the mirror. Each row below is first confirmed to be a strict reject
// (so it can only be the active config via a tolerant load) and then must be
// refused by the gate with its reason named.

const zones9588 = `zones { security-zone trust; security-zone untrust; }`
const anyMatch9588 = `match { source-address any; destination-address any; application any; }`

func lenientText9588(t *testing.T, text string) (*config.Config, error) {
	t.Helper()
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	_, strictErr := config.CompileConfig(tree)
	tree2, _ := config.NewParser(text).Parse()
	cfg, err := config.CompileConfigLenient(tree2)
	if err != nil {
		t.Fatalf("the tolerant compile must accept the fixture: %v", err)
	}
	return cfg, strictErr
}

func lenientSets9588(t *testing.T, lines ...string) (*config.Config, error) {
	t.Helper()
	build := func() *config.ConfigTree {
		tree := &config.ConfigTree{}
		for _, line := range lines {
			path, err := config.ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		return tree
	}
	_, strictErr := config.CompileConfig(build())
	cfg, err := config.CompileConfigLenient(build())
	if err != nil {
		t.Fatalf("the tolerant compile must accept the fixture: %v", err)
	}
	return cfg, strictErr
}

func TestRollbackPreflightRefusesEveryMirroredRefusalClass9588(t *testing.T) {
	type row struct {
		name  string
		build func(t *testing.T) (*config.Config, error)
		want  string
	}
	text := func(s string) func(t *testing.T) (*config.Config, error) {
		return func(t *testing.T) (*config.Config, error) { return lenientText9588(t, s) }
	}
	rows := []row{
		{"#5575 missing match (the original arm)", text(`security { ` + zones9588 +
			` policies { from-zone trust to-zone untrust { policy p1 { then { permit; } } } } }`), "p1"},
		{"#9584 one policy name split across two security roots", text(`security { ` + zones9588 +
			` policies { from-zone trust to-zone untrust { policy p1 { ` + anyMatch9588 + ` then { deny; } } } } }
security { policies { from-zone trust to-zone untrust { policy p1 { ` + anyMatch9588 + ` then { permit; } } } } }`), "p1"},
		{"#9570 zone-pair stanza naming junos-global", text(`security { ` + zones9588 +
			` policies { from-zone junos-global to-zone untrust { policy g1 { ` + anyMatch9588 + ` then { permit; } } } } }`), "g1"},
		{"#9410 zone pair naming an undefined zone", text(`security { ` + zones9588 +
			` policies { from-zone trust to-zone gone { policy bad1 { ` + anyMatch9588 + ` then { permit; } } } } }`), "bad1"},
		{"#9410 global match from-zone naming an undefined zone", func(t *testing.T) (*config.Config, error) {
			return lenientSets9588(t,
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies global policy g1 match source-address any",
				"set security policies global policy g1 match destination-address any",
				"set security policies global policy g1 match application any",
				"set security policies global policy g1 match from-zone typo-zone",
				"set security policies global policy g1 then permit")
		}, "g1"},
		{"#3261 undefined address-book name", text(`security { ` + zones9588 +
			` policies { from-zone trust to-zone untrust { policy p1 { match { source-address missing-book; destination-address any; application any; } then { permit; } } } } }`), "missing-book"},
		{"#9524 one address carrying a prefix and a dns-name", text(`security { address-book { global { address mixed { 10.10.0.0/24; dns-name evil.example; } } } ` + zones9588 +
			` policies { from-zone trust to-zone untrust { policy p1 { match { source-address mixed; destination-address any; application any; } then { permit; } } } } }`), "mixed"},
		{"#9525 destination-port on icmp", text(`applications { application a { protocol icmp; destination-port 80; } } security { ` + zones9588 +
			` policies { from-zone trust to-zone untrust { policy p1 { match { source-address any; destination-address any; application a; } then { deny; } } } } }`), `application "a"`},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			cfg, strictErr := r.build(t)
			if strictErr == nil {
				t.Fatalf("premise broken: strict commit ACCEPTS this fixture, so it is not the tolerant-only population the gate is about")
			}
			err := rollbackTargetAppliablePreflight(cfg, nil)
			if err == nil {
				t.Fatal("a rollback target the helper refuses as a whole snapshot was ACCEPTED; " +
					"`commit confirmed` would arm a safety net that reverts the store without reverting forwarding (#9588)")
			}
			if !errors.Is(err, errRollbackTargetUnappliable) {
				t.Errorf("error %v does not wrap errRollbackTargetUnappliable", err)
			}
			for _, want := range []string{r.want, "commit"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal must name %q so the operator can act on it; got: %v", want, err)
				}
			}
		})
	}
}

// The load-bearing half: a feed-backed target must still ARM when the gate is
// handed the live overlay, and the overlay must be what makes it arm.
// feedBackedTarget9588 is a strict-valid target whose policy matches the
// dynamic-address binding dyn1, fed by the feed `malware`.
func feedBackedTarget9588(t *testing.T) *config.Config {
	t.Helper()
	cfg, strictErr := lenientSets9588(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
		"set security dynamic-address address-name dyn1 profile feed-name malware",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address dyn1",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then deny")
	if strictErr != nil {
		t.Fatalf("premise broken: the feed-backed fixture must be a valid commit: %v", strictErr)
	}
	return cfg
}

func TestRollbackPreflightArmsAFeedBackedTargetWithTheLiveOverlay9588(t *testing.T) {
	cfg := feedBackedTarget9588(t)
	overlay := map[string][]string{"dyn1": {"192.0.2.0/24"}}
	if err := rollbackTargetAppliablePreflight(cfg, overlay); err != nil {
		t.Fatalf("a healthy feed-backed rollback target must ARM with the live overlay; refusing it "+
			"blocks `commit confirmed` on every box that uses dynamic-address feeds: %v", err)
	}
	if err := rollbackTargetAppliablePreflight(cfg, nil); err == nil {
		t.Fatal("control: without an overlay the feed binding reads as unrepresentable, so the gate " +
			"must refuse; if it arms here too, the cell above cannot show that the live overlay is what matters")
	}
}

func TestRollbackPreflightArmsAHealthyTarget9588(t *testing.T) {
	cfg, strictErr := lenientText9588(t, `security { `+zones9588+
		` policies { from-zone trust to-zone untrust { policy p1 { `+anyMatch9588+` then { permit; } } } } }`)
	if strictErr != nil {
		t.Fatalf("premise broken: the healthy fixture must be a valid commit: %v", strictErr)
	}
	if err := rollbackTargetAppliablePreflight(cfg, nil); err != nil {
		t.Fatalf("a healthy rollback target must ARM: %v", err)
	}
}

// The wiring: the call inside commitConfirmedAndApply must pass the daemon's
// feed overlay for the target, not nil. A nil there compiles and passes every
// cell above while refusing every feed-backed box in production.
func TestRollbackPreflightIsFedTheLiveFeedOverlay9588(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon_apply_commit.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon_apply_commit.go: %v", err)
	}
	found := 0
	ast.Inspect(f, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := ce.Fun.(*ast.Ident)
		if !ok || id.Name != "rollbackTargetAppliablePreflight" {
			return true
		}
		found++
		if len(ce.Args) != 2 {
			t.Errorf("rollbackTargetAppliablePreflight takes the target AND the live feed overlay; got %d args", len(ce.Args))
			return true
		}
		inner, ok := ce.Args[1].(*ast.CallExpr)
		sel, selOK := func() (*ast.SelectorExpr, bool) {
			if !ok {
				return nil, false
			}
			s, k := inner.Fun.(*ast.SelectorExpr)
			return s, k
		}()
		if !ok || !selOK || sel.Sel.Name != "feedSnapshotsForConfig" {
			t.Errorf("the overlay argument must be d.feedSnapshotsForConfig(target); a nil or other overlay " +
				"refuses healthy feed-backed rollback targets")
			return true
		}
		target, targetOK := ce.Args[0].(*ast.Ident)
		var overlayFor *ast.Ident
		if len(inner.Args) == 1 {
			overlayFor, _ = inner.Args[0].(*ast.Ident)
		}
		if !targetOK || overlayFor == nil || overlayFor.Name != target.Name {
			t.Errorf("the overlay must be built for the SAME config the gate checks (the rollback target); " +
				"bindings joined for another config resolve the wrong dynamic-address names")
		}
		return true
	})
	if found == 0 {
		t.Fatal("no call to rollbackTargetAppliablePreflight found in daemon_apply_commit.go")
	}
}

// A strict-valid target whose dynamic-address binding has an unready feed is
// refused. SnapshotForBindings omits a binding until ALL its feeds have a
// snapshot, and the mirror fails a declared-but-omitted binding closed (#5645),
// so the helper would refuse this snapshot now. The gate agrees with the mirror
// instead of predicting the feed will be ready when the timer fires. The
// overlay is non-nil here, so this is the unready-feed path, not the nil
// control above.
func TestRollbackPreflightRefusesWhileAReferencedFeedIsUnready9588(t *testing.T) {
	cfg := feedBackedTarget9588(t)
	overlay := map[string][]string{"other-binding": {"198.51.100.0/24"}}
	err := rollbackTargetAppliablePreflight(cfg, overlay)
	if err == nil {
		t.Fatal("a target whose referenced feed binding is not in the live overlay was ARMED; the helper " +
			"refuses that snapshot (#5645), so the rollback would revert the store without reverting forwarding")
	}
	if !errors.Is(err, errRollbackTargetUnappliable) || !strings.Contains(err.Error(), "dyn1") {
		t.Errorf("the refusal must wrap errRollbackTargetUnappliable and name the unresolved binding dyn1; got: %v", err)
	}
}
