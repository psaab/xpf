package config

import (
	"strings"
	"testing"
)

// #12635: Junos permits apply-groups, apply-groups-except and apply-macro at
// ANY hierarchy level (#7029), but closed-world subtrees without a wildcard
// slot strict-rejected them: schemaChildFor only resolved apply statements
// at wildcard slots, so inside `scheduler <name>`, a day container,
// `security ike proposal`, `address-set`, ... the keyword was an
// "unknown configuration keyword under closed-world subtree".

var closedWorldApplyCells12635 = []struct {
	name string
	text string
}{
	{"scheduler hier", "schedulers { scheduler S { apply-groups G; daily all-day; } }"},
	{"scheduler except hier", "schedulers { scheduler S { apply-groups-except G; daily all-day; } }"},
	{"scheduler macro hier", "schedulers { scheduler S { apply-macro M { k v; } daily all-day; } }"},
	{"day container hier", "schedulers { scheduler S { monday { apply-groups G; start-time 09:00:00; stop-time 17:00:00; } } }"},
	{"day except hier", "schedulers { scheduler S { daily { apply-groups-except G; all-day; } } }"},
	{"ike proposal hier", "security { ike { proposal P { apply-groups G; authentication-method pre-shared-keys; dh-group group14; encryption-algorithm aes-256-cbc; authentication-algorithm sha-256; } } }"},
	{"ike proposal macro", "security { ike { proposal P { apply-macro M { k v; } authentication-method pre-shared-keys; } } }"},
	{"address-set hier", "security { zones { security-zone Z { address-book { address-set S { apply-groups G; address A; } } } } }"},
	{"address-set except", "security { zones { security-zone Z { address-book { address-set S { apply-groups-except G; address A; } } } } }"},
}

func TestClosedWorldApplyStatementsAccepted12635(t *testing.T) {
	for _, tc := range closedWorldApplyCells12635 {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := NewParser(tc.text).Parse()
			if len(errs) != 0 {
				t.Fatalf("parse: %v", errs[0])
			}
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("closed-world subtree rejected Junos apply statement (#12635): %v", err)
			}
		})
	}
}

func TestClosedWorldApplyStatementsFlatSet12635(t *testing.T) {
	for _, cmd := range []string{
		"set schedulers scheduler S apply-groups G",
		"set schedulers scheduler S apply-groups-except G",
		"set schedulers scheduler S monday apply-groups G",
		"set security ike proposal P apply-groups G",
		"set security zones security-zone Z address-book address-set S apply-groups G",
	} {
		t.Run(cmd, func(t *testing.T) {
			tree := buildTree(t, []string{cmd})
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("flat %q rejected (#12635): %v", cmd, err)
			}
		})
	}
}

// End-to-end: apply-groups inside a closed-world scheduler must actually
// inherit, not merely pass validation and then be dropped.
func TestClosedWorldSchedulerApplyGroupsInherits12635(t *testing.T) {
	tree := buildTree(t, []string{
		"set groups G schedulers scheduler S daily all-day",
		"set schedulers scheduler S apply-groups G",
		"set schedulers scheduler S monday start-time 09:00:00",
		"set schedulers scheduler S monday stop-time 17:00:00",
	})
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	s := cfg.Schedulers["S"]
	if s == nil {
		t.Fatalf("scheduler S missing: %+v", cfg.Schedulers)
	}
	if !s.AllDay {
		t.Errorf("scheduler S did not inherit daily all-day from group G: %+v", s)
	}
}

// Negative controls: the fix must not blanket-allow unknown keywords, and
// apply statements with a missing group name must not pass as valueless.
func TestClosedWorldStillRejectsGarbage12635(t *testing.T) {
	for _, tc := range []struct{ name, text, bad string }{
		{"scheduler bogus", "schedulers { scheduler S { boguskw x; } }", "boguskw"},
		{"day bogus", "schedulers { scheduler S { monday { boguskw x; } } }", "boguskw"},
		{"ike bogus", "security { ike { proposal P { boguskw x; } } }", "boguskw"},
		{"address-set bogus", "security { zones { security-zone Z { address-book { address-set S { boguskw x; } } } } }", "boguskw"},
		{"apply-groups missing name", "schedulers { scheduler S { apply-groups; } }", "apply-groups"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := NewParser(tc.text).Parse()
			if len(errs) != 0 {
				t.Fatalf("parse: %v", errs[0])
			}
			err := SchemaValidate(tree, nil)
			if err == nil {
				t.Fatalf("garbage %q accepted under closed-world subtree", tc.bad)
			}
			if !strings.Contains(err.Error(), tc.bad) {
				t.Fatalf("error %q should name %q", err, tc.bad)
			}
		})
	}
	// Flat typo control.
	tree := buildTree(t, []string{"set schedulers scheduler S boguskw x"})
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatal("flat boguskw accepted under scheduler")
	}
}
