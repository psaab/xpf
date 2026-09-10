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

// #6707: `commit confirmed` must refuse to ARM when its rollback target cannot
// become the running snapshot.
//
// The rollback timer applies its target UNCONDITIONALLY and deliberately — by
// then PromoteRollback has already reverted the STORE, so aborting there would
// leave store and dataplane disagreeing (#1956 OQ-15.2). That is precisely why
// the decision belongs at arm time. Without this gate the sequence is: boot from
// a persisted config A whose policy hits the #5575 poison, correct it in B,
// `commit confirmed` B, lose contact — and at timeout the store reverts to A,
// the dataplane refuses A's snapshot (logged only,
// daemon_apply_commit.go's `slog.Error("commit confirmed auto-rollback
// dataplane apply failed")`), forwarding stays on the UNCONFIRMED B, and the
// rollback is announced as done.
//
// FAIL-ON-REVERT: make rollbackTargetAppliablePreflight return nil
// unconditionally and the poisoned cell reds; drop the call from
// CommitConfirmed's preflight closure and the wiring test reds.

func poisonedTarget6707(t *testing.T) *config.Config {
	t.Helper()
	// Compiled by the REAL tolerant compiler, so the poison is set by the
	// production path rather than asserted into a struct literal.
	tree, perrs := config.NewParser(`security {
  policies {
    from-zone trust to-zone untrust {
      policy rollback-bad {
        then { permit; }
      }
    }
  }
}`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if config.LenientDroppedPolicyLocator(cfg) == "" {
		t.Fatal("premise broken: the fixture config is not poisoned, so this test " +
			"cannot measure the gate")
	}
	return cfg
}

func cleanTarget6707(t *testing.T) *config.Config {
	t.Helper()
	// #9588: the zones are declared. Once the gate asks the whole refusal
	// mirror, a policy naming undeclared zones is correctly refused (#9410:
	// the helper rejects an unresolvable zone reference), so a fixture that was
	// "clean" only under the old LenientContentDropped-only predicate would no
	// longer be clean at all.
	tree, perrs := config.NewParser(`security {
  zones { security-zone trust; security-zone untrust; }
  policies {
    from-zone trust to-zone untrust {
      policy rollback-ok {
        match { source-address any; destination-address any; application any; }
        then { permit; }
      }
    }
  }
}`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if got := config.LenientDroppedPolicyLocator(cfg); got != "" {
		t.Fatalf("premise broken: the clean fixture is poisoned (%q), so the "+
			"over-gating cell below would pass for the wrong reason", got)
	}
	return cfg
}

func TestRollbackTargetAppliablePreflight6707(t *testing.T) {
	t.Run("poisoned target is refused", func(t *testing.T) {
		err := rollbackTargetAppliablePreflight(poisonedTarget6707(t), nil)
		if err == nil {
			t.Fatal("a rollback target the dataplane is guaranteed to refuse was ACCEPTED; " +
				"`commit confirmed` would arm a safety net that reverts the store without " +
				"reverting forwarding")
		}
		if !errors.Is(err, errRollbackTargetUnappliable) {
			t.Errorf("error %v does not wrap errRollbackTargetUnappliable", err)
		}
		// The operator has to be able to act on it: name the offending rule and
		// the way forward.
		for _, want := range []string{"rollback-bad", "commit"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("gate error does not mention %q; a refusal the operator cannot "+
					"act on is a support ticket, not a fence. Got: %v", want, err)
			}
		}
	})

	t.Run("clean target is accepted", func(t *testing.T) {
		if err := rollbackTargetAppliablePreflight(cleanTarget6707(t), nil); err != nil {
			t.Fatalf("a clean rollback target was refused: %v — over-gating denies an "+
				"operator the confirmed-commit safety net they are entitled to", err)
		}
	})

	t.Run("nil target (first commit) is accepted", func(t *testing.T) {
		// The timeout path handles a nil rollback target by reverting to
		// bootstrap mode (#1922 Item 1b); refusing here would block the FIRST
		// commit-confirmed on a fresh store — a brick, not a fence.
		if err := rollbackTargetAppliablePreflight(nil, nil); err != nil {
			t.Fatalf("nil rollback target refused: %v", err)
		}
	})
}

// The gate must be REACHED, and reached from the CONFIRMED commit only. A gate
// that exists but is never called is the same as no gate; a gate wired into the
// plain commit path would refuse an operator's only route OFF a poisoned active
// config.
func TestRollbackTargetGateIsWiredIntoCommitConfirmedOnly6707(t *testing.T) {
	t.Parallel()

	const file = "daemon_apply_commit.go"
	fset := token.NewFileSet()
	// Mode 0: comments are not attached, so a comment naming the call cannot
	// satisfy this guard (#6647).
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	callers := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := ce.Fun.(*ast.Ident)
			if !ok || id.Name != "rollbackTargetAppliablePreflight" {
				return true
			}
			callers[fn.Name.Name] = true
			return true
		})
	}

	// commitConfirmedAndApply is the single confirmed-commit implementation;
	// commitConfirmedAndApplyOperator is a thin peer-policy wrapper over it.
	if !callers["commitConfirmedAndApply"] {
		t.Fatalf("commitConfirmedAndApply does not call rollbackTargetAppliablePreflight. "+
			"The #6707 gate exists but nothing invokes it, so a confirmed commit still "+
			"arms a rollback timer whose target the dataplane refuses. Callers found: %v",
			callers)
	}
	for _, forbidden := range []string{"commitAndApply", "commitAndApplyOperator"} {
		if callers[forbidden] {
			t.Errorf("%s calls rollbackTargetAppliablePreflight. A PLAIN commit has no "+
				"rollback target to protect, and gating it would refuse the operator's only "+
				"way to replace a poisoned active config", forbidden)
		}
	}
}
