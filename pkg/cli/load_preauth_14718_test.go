package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #14718 (ordering arm): handleLoad read the file with the daemon's
// privileges BEFORE AuthorizeConfigLoad ran, so a class the load gate
// refuses categorically (any restricted class using `override`, or a
// `deny-configuration ".*"` class using merge) still triggered a
// root-privileged open and got distinguishable errors — a filesystem
// existence/type oracle (not-exist vs non-regular vs empty vs parse).
//
// The gate must be consulted before the file is opened for any class
// it would refuse without needing the content. FAIL-ON-REVERT: moving
// ReadBoundedConfigFile back above the pre-authorization makes the
// existent and nonexistent paths yield different errors and fails.

const denyAllClassConfig14718 = `system {
    host-name authz-14718;
    login {
        class denyall {
            permissions [ configure view ];
            deny-configuration ".*";
        }
        class limited {
            permissions [ configure view ];
            deny-configuration "system root-authentication";
        }
    }
}
`

func cliWithClass14718(t *testing.T, userClass string) (*CLI, *configstore.Store) {
	t.Helper()
	st, err := configstore.New(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := st.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := st.LoadMerge(denyAllClassConfig14718); err != nil {
		t.Fatalf("seeding class config: %v", err)
	}
	if _, err := st.Commit(); err != nil {
		t.Fatalf("commit class config: %v", err)
	}
	// Commit leaves the "" session holding the lock with the committed
	// candidate still live (same shape as cliWithRestrictedClass9892),
	// so handleLoad's store calls with session "" proceed.
	active := st.ActiveConfig()
	if active == nil {
		t.Fatal("no active config")
	}
	found := map[string]bool{}
	for _, cl := range active.System.Login.Classes {
		if cl.DenyConfiguration != "" {
			found[cl.Name] = true
		}
	}
	if userClass == "limited" || userClass == "denyall" {
		if !found[userClass] {
			t.Fatalf("active config lacks restricted class %q (found %v)", userClass, found)
		}
	}
	c := New(st, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	c.userClass = userClass
	return c, st
}

func TestHandleLoadRefusesBeforeOpeningFile14718(t *testing.T) {
	secret := "SECRET-MARKER-14718-preauth"
	existent := writeConf9892(t, "set system host-name ok14718\n"+secret+"\n")
	nonexistent := filepath.Join(t.TempDir(), "does-not-exist-14718.conf")

	cases := []struct {
		name  string
		class string
		mode  string
	}{
		{"override restricted refused categorically", "limited", "override"},
		{"merge deny-all", "denyall", "merge"},
		{"override deny-all", "denyall", "override"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cExist, _ := cliWithClass14718(t, tc.class)
			errExist := cExist.handleLoad([]string{tc.mode, existent})
			if errExist == nil {
				t.Fatalf("load %s by class %q must be refused", tc.mode, tc.class)
			}
			cMissing, _ := cliWithClass14718(t, tc.class)
			errMissing := cMissing.handleLoad([]string{tc.mode, nonexistent})
			if errMissing == nil {
				t.Fatalf("load %s of a nonexistent file by refused class %q must still be refused (not a read error)", tc.mode, tc.class)
			}
			if errExist.Error() != errMissing.Error() {
				t.Errorf("refusal differs by file existence (filesystem oracle, #14718):\n existent: %v\n missing:  %v", errExist, errMissing)
			}
			if strings.Contains(errExist.Error(), secret) {
				t.Errorf("refusal echoed file content: %v", errExist)
			}
		})
	}
}

// A content-dependent merge for a restricted (but not deny-all) class
// still needs the file read — and must still work for allowed paths
// and refuse denied ones without echoing the secret.
func TestHandleLoadContentGateStillWorks14718(t *testing.T) {
	c, st := cliWithClass14718(t, "limited")
	allowed := writeConf9892(t, "system {\n    domain-name example.net;\n}\n")
	if err := c.handleLoad([]string{"merge", allowed}); err != nil {
		t.Fatalf("allowed merge refused: %v", err)
	}
	if !strings.Contains(st.ShowCandidate(), "example.net") {
		t.Errorf("allowed merge did not reach candidate:\n%s", st.ShowCandidate())
	}

	c2, _ := cliWithClass14718(t, "limited")
	denied := writeConf9892(t, "system {\n    root-authentication {\n        plain-text-password hunter2-14718;\n    }\n}\n")
	err := c2.handleLoad([]string{"merge", denied})
	if err == nil {
		t.Fatal("denied merge allowed")
	}
	if strings.Contains(err.Error(), "hunter2-14718") {
		t.Errorf("denied merge refusal echoed secret: %v", err)
	}

	// Unrestricted class: file read proceeds normally (incl. its errors).
	c3, _ := cliWithClass14718(t, "super-user")
	missing := filepath.Join(t.TempDir(), "nope.conf")
	if err := c3.handleLoad([]string{"merge", missing}); err == nil {
		t.Error("unrestricted load of nonexistent file must surface the read error")
	}
	// Restricted merge of a nonexistent file: read error, but identical
	// shape to any other read failure and no content to echo.
	c4, _ := cliWithClass14718(t, "limited")
	if err := c4.handleLoad([]string{"merge", missing}); err == nil {
		t.Error("restricted merge of nonexistent file must fail")
	}
}
