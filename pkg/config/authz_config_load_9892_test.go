package config

import (
	"strings"
	"testing"
)

// #9892: `load` could carry EVERY denied path at once while the per-path gate
// on set/delete stayed intact.
//
// The fixture class holds `configure`, so the coarse permission tier admits it
// — the regex is the only thing between this caller and the mutation. That is
// what makes these cells measure the regex rather than the permission bits.
const config9892 = `
system {
    host-name authz-9892;
    login {
        class limited {
            permissions [ configure view ];
            deny-configuration "system root-authentication";
        }
    }
}
`

func cfg9892(t *testing.T) *Config {
	t.Helper()
	tree, errs := NewParser(config9892).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture does not parse, so every cell below is vacuous: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("fixture does not compile, so every cell below is vacuous: %v", err)
	}
	// PREMISE, asserted rather than assumed: the class must actually be
	// regex-restricted, or every refusal below would be vacuous and every
	// allowance meaningless.
	if _, restricted, err := ConfigurationLoginRegexesFor(cfg, "limited"); err != nil || !restricted {
		t.Fatalf("fixture class `limited` is not regex-restricted (restricted=%v err=%v); "+
			"the cells below would measure nothing", restricted, err)
	}
	return cfg
}

// POSITIVE CONTROL FIRST. Without it, every refusal below could be a class that
// is refused everything, and the regex would be untested.
func TestLoadOfAnAllowedPathSucceeds9892(t *testing.T) {
	cfg := cfg9892(t)
	for _, content := range []string{
		"set system host-name fw9892",
		"system {\n    host-name fw9892;\n}",
	} {
		if err := AuthorizeConfigLoad(cfg, "limited", "merge", content); err != nil {
			t.Errorf("control failed: an unrelated load was refused: %v\ncontent: %s", err, content)
		}
	}
}

func TestLoadOfADeniedPathIsRefused9892(t *testing.T) {
	cfg := cfg9892(t)
	for name, content := range map[string]string{
		"set format":   "set system root-authentication plain-text-password hunter2",
		"hierarchical": "system {\n    root-authentication {\n        plain-text-password hunter2;\n    }\n}",
		// A verb OTHER than set, inside a set-format body. `load` carries the
		// whole verb vocabulary, so gating only `set` lines would leave the
		// same bypass one level in.
		//
		// This row does NOT prove the flat-verb table is complete, and the
		// mutation matrix is what established that rather than reading: deleting
		// `"deactivate"` from loadFlatVerbs leaves this row GREEN. The fixture's
		// rule is `deny-configuration "system root-authentication"`, UNANCHORED,
		// so `deactivate system root-authentication` still contains the pattern
		// and the denial fires either way — the matcher absorbs exactly the
		// difference the row is named for. Completeness of the verb table is
		// owned by TestEveryFlatVerbIsTakenVerbatimNotReparsed9892, whose
		// fixture anchors the rule with `^`.
		"deactivate inside a set body": "deactivate system root-authentication",
	} {
		err := AuthorizeConfigLoad(cfg, "limited", "merge", content)
		if err == nil {
			t.Errorf("%s: load merge of a DENIED path was allowed — `load` is the verb that can "+
				"carry every denied path at once (#9892)", name)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: the denial echoed the secret from the config path: %v", name, err)
		}
	}
}

// THE DENIED PATH IS LAST. A gate that adjudicated only the first rendered line
// would pass every cell above — they are all single-path bodies. This is the
// pinned-parameter lesson: when the code iterates, the fixture must put the
// interesting record somewhere other than first.
func TestLoadAdjudicatesEveryLineNotJustTheFirst9892(t *testing.T) {
	content := strings.Join([]string{
		"set system host-name fw9892",
		"set system domain-name example.net",
		"set system root-authentication plain-text-password hunter2",
	}, "\n")
	if err := AuthorizeConfigLoad(cfg9892(t), "limited", "merge", content); err == nil {
		t.Error("a load whose DENIED path is the LAST line was allowed — the gate stops early, " +
			"so any body can smuggle a denied path by putting an allowed one first (#9892)")
	}
}

// `override` is REFUSED, not adjudicated, and the distinction is the point: it
// replaces the whole candidate, so the paths it DELETES cannot be enumerated.
// A cell asserting "override of allowed content succeeds" would encode the
// opposite contract, so this asserts the refusal even for benign content.
func TestLoadOverrideIsRefusedForARestrictedClass9892(t *testing.T) {
	cfg := cfg9892(t)
	err := AuthorizeConfigLoad(cfg, "limited", "override", "set system host-name fw9892")
	if err == nil {
		t.Fatal("load override was allowed for a regex-restricted class; it replaces the whole " +
			"candidate, so the paths it deletes are never adjudicated (#9892)")
	}
	if !strings.Contains(err.Error(), "override") {
		t.Errorf("the refusal does not name override, so an operator cannot tell which mode to "+
			"use instead: %v", err)
	}
}

// NARROWNESS CONTROL. Over-refusing locks an UNRESTRICTED class out of a verb
// it legitimately holds, which is its own outage.
func TestOverrideAndRollbackStayAvailableToAnUnrestrictedClass9892(t *testing.T) {
	cfg := cfg9892(t)
	if err := AuthorizeConfigLoad(cfg, "unrestricted-class-with-no-regexes", "override", "x"); err != nil {
		t.Errorf("load override was refused for a class with NO configuration regexes: %v", err)
	}
	if err := AuthorizeConfigRollback(cfg, "unrestricted-class-with-no-regexes", 3); err != nil {
		t.Errorf("rollback 3 was refused for a class with NO configuration regexes: %v", err)
	}
	// And an empty class (no login model at all) must not be gated either.
	if err := AuthorizeConfigLoad(cfg, "", "override", "x"); err != nil {
		t.Errorf("load override was refused for an empty class: %v", err)
	}
}

func TestRollbackZeroStaysAvailableButNIsRefused9892(t *testing.T) {
	cfg := cfg9892(t)
	// rollback 0 returns to the COMMITTED configuration, every path of which
	// was adjudicated when it was written. Refusing it would strand a
	// restricted operator with no way to discard a candidate.
	if err := AuthorizeConfigRollback(cfg, "limited", 0); err != nil {
		t.Errorf("rollback 0 was refused; it returns to the committed configuration and must "+
			"stay available: %v", err)
	}
	if err := AuthorizeConfigRollback(cfg, "limited", 1); err == nil {
		t.Error("rollback 1 was allowed for a regex-restricted class — it replaces the candidate " +
			"with an older configuration whose paths are never adjudicated (#9892)")
	}
}

// #9892 M6: the flat-verb table decides whether a body is taken VERBATIM or
// re-parsed — and re-parsing MANGLES THE PATH.
//
// Measured: `deactivate system root-authentication` renders as
// ["deactivate system root-authentication"] with the verb in the table, and as
// ["set deactivate system root-authentication"] without it — the verb folds
// into the PATH. A substring deny regex still matches the mangled form, which
// is why the first version of this file's deactivate case passed under a
// mutant that dropped the verb: it was denied for the wrong reason.
//
// An ANCHORED regex does not. This class denies `^system root-authentication`,
// which matches the correct rendering and NOT the mangled one — so this cell
// fails exactly when a verb is missing from the table, which is the defect.
const configAnchored9892 = `
system {
    host-name authz-9892a;
    login {
        class anchored {
            permissions [ configure view ];
            deny-configuration "^system root-authentication";
        }
    }
}
`

func TestEveryFlatVerbIsTakenVerbatimNotReparsed9892(t *testing.T) {
	tree, errs := NewParser(configAnchored9892).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture does not parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("fixture does not compile: %v", err)
	}
	if _, restricted, err := ConfigurationLoginRegexesFor(cfg, "anchored"); err != nil || !restricted {
		t.Fatalf("fixture class is not regex-restricted (restricted=%v err=%v)", restricted, err)
	}

	// PREMISE, measured: the anchored regex must actually deny the plain `set`
	// spelling. If it does not, every row below is vacuous.
	if err := AuthorizeConfigLoad(cfg, "anchored", "merge", "set system root-authentication x"); err == nil {
		t.Fatal("premise failed: the anchored deny does not refuse `set system root-authentication`, " +
			"so this cell cannot distinguish a verbatim rendering from a mangled one")
	}

	for _, verb := range []string{"set", "delete", "deactivate", "activate", "copy", "rename", "insert", "annotate"} {
		line := verb + " system root-authentication"
		// The renderer must return the line VERBATIM — first token still the verb.
		got := LoadMutationLines(line)
		if len(got) != 1 || got[0] != line {
			t.Errorf("LoadMutationLines(%q) = %q; a verb missing from loadFlatVerbs makes the body "+
				"re-parse, folding the verb into the PATH", line, got)
		}
		// And the consequence: an anchored deny must still refuse it.
		if err := AuthorizeConfigLoad(cfg, "anchored", "merge", line); err == nil {
			t.Errorf("load merge of %q was ALLOWED under an anchored deny — the verb was folded "+
				"into the path, so `^system root-authentication` no longer matches (#9892)", line)
		}
	}
}

// The renderer is the shared half, so pin what it produces rather than only
// what the gate concludes: a defect here is invisible to every cell above that
// uses a single-path body.
func TestLoadMutationLinesRendersEveryLeaf9892(t *testing.T) {
	lines := LoadMutationLines("system {\n    host-name a;\n    domain-name b;\n}")
	if len(lines) < 2 {
		t.Fatalf("hierarchical content rendered %d set lines, want one per leaf: %v", len(lines), lines)
	}
	for _, want := range []string{"host-name", "domain-name"} {
		if !strings.Contains(strings.Join(lines, "\n"), want) {
			t.Errorf("rendered lines omit %q, so its path would never be adjudicated: %v", want, lines)
		}
	}
	// A set-format body is taken verbatim, not re-parsed.
	flat := LoadMutationLines("set system host-name a\ndelete system domain-name")
	if len(flat) != 2 {
		t.Errorf("set-format content rendered %d lines, want 2: %v", len(flat), flat)
	}
}
