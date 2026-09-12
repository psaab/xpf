package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #9892 on the LOCAL CLI, bound BEHAVIOURALLY.
//
// These cells exist because the structural census
// (TestEveryLoadSurfaceCallsTheSharedEvaluator9892) is not sufficient on its
// own, and that was MEASURED, not anticipated: a mutation that kept the call to
// config.AuthorizeConfigLoad and discarded only its verdict
// (`…; false && err != nil {`) ESCAPED the whole matrix. A census of call sites
// answers "is the evaluator called"; it cannot answer "is its answer obeyed".
// Both questions need an answer, and only this one reaches the candidate.
//
// The store here is real, because the defect is in the wiring between the gate
// and the store: a gate that returns an error while the load has already
// mutated the candidate is the same outage as no gate at all.

const cliClassConfig9892 = `system {
    host-name authz-9892;
    login {
        class limited {
            permissions [ configure view ];
            deny-configuration "system root-authentication";
        }
    }
}
`

// cliWithRestrictedClass9892 returns a CLI whose ACTIVE config carries the
// regex-restricted class, plus the store, so a cell can read the candidate back.
func cliWithRestrictedClass9892(t *testing.T, userClass string) (*CLI, *configstore.Store) {
	t.Helper()
	st, err := configstore.New(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := st.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := st.LoadMerge(cliClassConfig9892); err != nil {
		t.Fatalf("seeding the class config failed, so every cell below is vacuous: %v", err)
	}
	if _, err := st.Commit(); err != nil {
		t.Fatalf("committing the class config failed, so every cell below is vacuous: %v", err)
	}
	// PREMISE, asserted rather than assumed. ActiveConfig is what the gate
	// reads; if the class did not survive the commit, a refusal below would be
	// measuring nothing and an allowance would mean nothing.
	active := st.ActiveConfig()
	if active == nil {
		t.Fatal("no active config after commit; the cells below would be vacuous")
	}
	found := false
	for _, cl := range active.System.Login.Classes {
		if cl.Name == "limited" && cl.DenyConfiguration != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("active config has no `limited` class with deny-configuration; the cells below would be vacuous")
	}
	c := New(st, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	c.userClass = userClass
	return c, st
}

func writeConf9892(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.conf")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

// TestCLILoadOfADeniedPathIsRefusedAndChangesNothing9892 is the cell that
// mutation M8 escaped. It fails if the verdict is computed and then discarded.
func TestCLILoadOfADeniedPathIsRefusedAndChangesNothing9892(t *testing.T) {
	for _, mode := range []string{"merge", "override"} {
		t.Run(mode, func(t *testing.T) {
			c, st := cliWithRestrictedClass9892(t, "limited")
			before := st.ShowCandidate()
			path := writeConf9892(t, "system {\n    root-authentication {\n        plain-text-password hunter2;\n    }\n}\n")

			err := c.handleLoad([]string{mode, path})
			if err == nil {
				t.Fatalf("load %s of a DENIED path was ALLOWED on the local CLI (#9892)", mode)
			}
			if strings.Contains(err.Error(), "hunter2") {
				t.Errorf("the refusal echoed the secret from the denied path: %v", err)
			}
			// The refusal must happen BEFORE the store is touched. An error
			// returned after the candidate already carries the denied path
			// leaves the operator one `commit` away from the outcome the gate
			// exists to prevent.
			if after := st.ShowCandidate(); after != before {
				t.Errorf("the candidate CHANGED despite the refusal:\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

// TestCLILoadOfAnAllowedPathStillWorks9892 is the POSITIVE CONTROL, and it is
// not optional: without it, a CLI that refused every load would satisfy the
// cell above and the regex would be untested.
func TestCLILoadOfAnAllowedPathStillWorks9892(t *testing.T) {
	c, st := cliWithRestrictedClass9892(t, "limited")
	before := st.ShowCandidate()
	path := writeConf9892(t, "system {\n    domain-name example.net;\n}\n")

	if err := c.handleLoad([]string{"merge", path}); err != nil {
		t.Fatalf("load merge of an ALLOWED path was refused for a restricted class: %v", err)
	}
	after := st.ShowCandidate()
	if after == before {
		t.Error("the candidate did not change after an allowed load; this control proves nothing")
	}
	if !strings.Contains(after, "example.net") {
		t.Errorf("the allowed value did not reach the candidate:\n%s", after)
	}
}

// TestCLILoadIsUnrestrictedForAnUnrestrictedClass9892 is the NARROWNESS control
// in the other direction: the same denied path, the same content, a class with
// no deny-configuration. Over-denial locks a legitimate operator out, which is
// a different outage rather than a fix.
func TestCLILoadIsUnrestrictedForAnUnrestrictedClass9892(t *testing.T) {
	c, st := cliWithRestrictedClass9892(t, "super-user")
	path := writeConf9892(t, "system {\n    root-authentication {\n        plain-text-password hunter2;\n    }\n}\n")
	if err := c.handleLoad([]string{"merge", path}); err != nil {
		t.Fatalf("load merge was refused for a class with NO deny-configuration: %v", err)
	}
	if !strings.Contains(st.ShowCandidate(), "root-authentication") {
		t.Error("the load did not reach the candidate for an unrestricted class")
	}
}

// TestCLIRollbackNIsRefusedForARestrictedClass9892 is the cell that mutation M9
// escaped, for the same reason M8 did: the census could see the call and not
// the verdict.
//
// `rollback n` for n>0 replaces the candidate with an older configuration whose
// paths cannot be enumerated one by one, so it is REFUSED for a restricted
// class rather than adjudicated. `rollback 0` returns to the COMMITTED
// configuration, every path of which was adjudicated when it was written, and
// must stay available — that row is the narrowness control, and without it a
// dispatcher that refused every rollback would satisfy the refusal.
func TestCLIRollbackNIsRefusedForARestrictedClass9892(t *testing.T) {
	for name, tc := range map[string]struct {
		userClass  string
		line       string
		wantRefuse bool
	}{
		"restricted, rollback 1":    {"limited", "rollback 1", true},
		"restricted, rollback 2":    {"limited", "rollback 2", true},
		"restricted, rollback 0":    {"limited", "rollback 0", false},
		"restricted, bare rollback": {"limited", "rollback", false},
		"unrestricted, rollback 1":  {"super-user", "rollback 1", false},
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := cliWithRestrictedClass9892(t, tc.userClass)
			err := c.dispatchConfig(tc.line)
			if tc.wantRefuse {
				if err == nil {
					t.Fatalf("%q was ALLOWED for class %q; it replaces the candidate with paths the regex cannot adjudicate (#9892)", tc.line, tc.userClass)
				}
				if !strings.Contains(err.Error(), "permission denied") {
					t.Errorf("%q failed for a reason other than the authorization gate, so this row proves nothing: %v", tc.line, err)
				}
				return
			}
			// The allowed rows must not be refused BY THE GATE. They may still
			// fail for an unrelated store reason (there is nothing to roll back
			// to in a fresh store), and that is not what this cell measures —
			// so the assertion is on the gate's own refusal text, not on nil.
			if err != nil && strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("%q was refused by the authorization gate for class %q; over-denial locks a legitimate operator out: %v", tc.line, tc.userClass, err)
			}
		})
	}
}
