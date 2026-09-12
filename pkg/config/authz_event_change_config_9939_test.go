package config

import (
	"strings"
	"testing"
)

// #9939. `event-options policy … then change-configuration commands "delete
// security policies …"` stores its payload as DATA. The line that plants it is
// gated as a path under `event-options`; the payload is gated by nothing, at
// plant time or at fire time, and the engine applies it with INTERNAL (root)
// authority — `commit_authority.go` answers `case authorityInternal: return nil`.
//
// So a class denied `security policies` but permitted `event-options` could
// delete a guard policy autonomously on a routine event.

const evtCfg9939 = `
system {
    host-name authz-9939;
    login {
        class planter {
            permissions [ configure view ];
            deny-configuration "^security policies";
        }
        class unanchored {
            permissions [ configure view ];
            deny-configuration "security policies";
        }
        class wideopen {
            permissions [ configure view ];
        }
    }
}
`

func evtCfgFor9939(t *testing.T) *Config {
	t.Helper()
	tree, errs := NewParser(evtCfg9939).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture does not parse, so every cell below is vacuous: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("fixture does not compile, so every cell below is vacuous: %v", err)
	}
	// PREMISE: the planting class must be regex-restricted AND must be able to
	// author `event-options` at all — if it were denied that too, every refusal
	// below would be the OUTER path's, not the payload's, and the cells would
	// prove nothing about this issue.
	rules, ok, err := ConfigurationLoginRegexesFor(cfg, "planter")
	if err != nil || !ok {
		t.Fatalf("fixture class `planter` is not regex-restricted (ok=%v err=%v)", ok, err)
	}
	if d := rules.Evaluate("event-options policy p1 then change-configuration commands x"); !d.Allowed {
		t.Fatalf("fixture class `planter` cannot author event-options at all (%s); a refusal below "+
			"would be the outer path's, not the payload's", d.Reason)
	}
	// THE PREMISE THAT DECIDES THIS ISSUE, and it is why the deny is ANCHORED.
	//
	// The payload text is part of the OUTER line, so an UNANCHORED
	// `security policies` deny matches the planting path incidentally and the
	// plant is already refused at master — the defect does not reproduce. It
	// needs a deny that matches the payload's own resolved path and NOT the
	// outer joined one, which is what `^security policies` is. Same shape as
	// #9938 F-029, where an unanchored deny also hid the mechanism.
	//
	// Asserted rather than commented, because if this stopped being true every
	// cell below would pass for the wrong reason.
	outer := "event-options policy p1 then change-configuration commands delete security policies guard"
	if d := rules.Evaluate(outer); !d.Allowed {
		t.Fatalf("the OUTER planting path is itself denied (%s); the cells below would be measuring "+
			"the path gate, not the payload gate", d.Reason)
	}
	return cfg
}

// TestAPlantedPayloadIsAdjudicatedAgainstThePlanter9939 is the defect.
func TestAPlantedPayloadIsAdjudicatedAgainstThePlanter9939(t *testing.T) {
	cfg := evtCfgFor9939(t)
	for name, line := range map[string]string{
		"delete op, quoted payload":     `set event-options policy p1 then change-configuration commands "delete security policies guard"`,
		"set op, quoted payload":        `set event-options policy p1 then change-configuration commands "set security policies guard match source-address any"`,
		"unquoted payload":              `set event-options policy p1 then change-configuration commands delete security policies guard`,
		"bracketed list, denied second": `set event-options policy p1 then change-configuration commands [ "set system host-name ok" "delete security policies guard" ]`,
	} {
		t.Run(name, func(t *testing.T) {
			err := AuthorizeConfigMutation(cfg, "planter", nil, line)
			if err == nil {
				t.Fatalf("a class denied `security policies` planted a payload targeting it; the "+
					"daemon would apply it as ROOT on a routine event (#9939)\n  %s", line)
			}
			if !strings.Contains(err.Error(), "#9939") {
				t.Errorf("the refusal does not say WHY a line about event-options was refused for a "+
					"path that is not under it: %v", err)
			}
		})
	}
}

// POSITIVE CONTROL, and it is not optional: without it every refusal above is
// equally consistent with a gate that refuses every change-configuration, which
// would break the feature for the class that may legitimately use it.
func TestAnAllowedPayloadStillPlants9939(t *testing.T) {
	cfg := evtCfgFor9939(t)
	for _, line := range []string{
		`set event-options policy p1 then change-configuration commands "set system host-name evented"`,
		`set event-options policy p1 then change-configuration commands "delete system host-name"`,
		`set event-options policy p1 then change-configuration commands [ "set system host-name a" "set system domain-name b" ]`,
		`set event-options policy p1 then change-configuration commands set system host-name evented`,
	} {
		if err := AuthorizeConfigMutation(cfg, "planter", nil, line); err != nil {
			t.Errorf("a payload touching NO denied path was refused: %v\n  %s", err, line)
		}
	}
}

// TestAnUnanchoredDenyCatchesThePlantIncidentally9939 records WHY this survived,
// and it is the row that explains the issue's own reachability note.
//
// The payload text is part of the outer line, so an unanchored deny matches the
// planting path by accident and refuses it at master with no payload gate at
// all. The escape needs an ANCHORED deny — the idiom Junos documents for complex
// expressions. Without this row a reader would reasonably conclude the outer gate
// was always sufficient.
func TestAnUnanchoredDenyCatchesThePlantIncidentally9939(t *testing.T) {
	cfg := evtCfgFor9939(t)
	line := `set event-options policy p1 then change-configuration commands "delete security policies guard"`
	if err := AuthorizeConfigMutation(cfg, "unanchored", nil, line); err == nil {
		t.Fatal("an unanchored deny did not catch the plant even incidentally; the reachability " +
			"note on #9939 would be wrong")
	}
}

// NARROWNESS CONTROL: a class with no configuration regexes is untouched. This
// walk now runs on every config-mode line, so the cost of getting it wrong is
// borne by every operator.
func TestAClassWithNoRegexesCanPlantAnything9939(t *testing.T) {
	cfg := evtCfgFor9939(t)
	line := `set event-options policy p1 then change-configuration commands "delete security policies guard"`
	for _, class := range []string{"wideopen", ""} {
		if err := AuthorizeConfigMutation(cfg, class, nil, line); err != nil {
			t.Errorf("class %q was refused with NO configuration regexes: %v", class, err)
		}
	}
}

// TestThePayloadBoundaryMatchesTheCompilersOwnRule9939 pins the token rule.
//
// The compiler's reader (`eventChangeConfigCommands`, #6659) treats a QUOTED
// value as one command per token and an UNQUOTED tail as a single command that
// must be re-joined. A gate using a different rule adjudicates a command the
// engine never runs, or misses one it does — which is #9938's defect one layer
// in, so it gets its own cell rather than being left to the behaviour above.
func TestThePayloadBoundaryMatchesTheCompilersOwnRule9939(t *testing.T) {
	for name, tc := range map[string]struct {
		parts  []string
		quoted []bool
		want   []string
	}{
		"quoted single": {
			[]string{"commands", "delete security policies guard"},
			[]bool{false, true},
			nil, // no `change-configuration` before it: not a payload
		},
		"quoted, one command": {
			[]string{"change-configuration", "commands", "delete security policies guard"},
			[]bool{false, false, true},
			[]string{"delete security policies guard"},
		},
		"quoted, two commands": {
			[]string{"change-configuration", "commands", "set a b", "delete c d"},
			[]bool{false, false, true, true},
			[]string{"set a b", "delete c d"},
		},
		"unquoted tail is ONE command": {
			[]string{"change-configuration", "commands", "delete", "security", "policies", "guard"},
			[]bool{false, false, false, false, false, false},
			[]string{"delete security policies guard"},
		},
		"no payload at all": {
			[]string{"set", "system", "host-name", "x"},
			[]bool{false, false, false, false},
			nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := embeddedChangeConfigCommands9939(tc.parts, tc.quoted)
			if len(got) != len(tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
			}
		})
	}
}

// TestTheRecursionBoundRefusesRatherThanWavesThrough9939 pins the bound's
// DIRECTION, which is the part that is easy to get backwards.
//
// Running out of budget must not read as "we found nothing", because then the
// nesting depth at which adjudication stops is chosen by whoever writes the
// payload. It is exercised at the boundary directly rather than through a
// nested LINE, and that is itself a measurement: a nested payload is not
// expressible in the config text, because the inner command would have to carry
// quotes inside an already-quoted value and the lexer terminates the outer
// string at the first inner quote. So the bound is belt-and-braces against a
// shape the grammar does not currently admit — which is exactly the kind of
// guard that rots into "unfalsifiable" unless its direction is pinned.
func TestTheRecursionBoundRefusesRatherThanWavesThrough9939(t *testing.T) {
	cfg := evtCfgFor9939(t)
	parts := []string{"change-configuration", "commands", "delete security policies guard"}
	quoted := []bool{false, false, true}

	// BELOW the limit: the payload is adjudicated and denied on its merits.
	if err := authorizeEmbeddedChangeConfig9939(cfg, "planter", parts, quoted, 0); err == nil {
		t.Fatal("below the limit a denied payload was allowed; this cell would prove nothing")
	}
	// AT the limit: refused, and for the BUDGET reason rather than the merits.
	err := authorizeEmbeddedChangeConfig9939(cfg, "planter", parts, quoted, changeConfigRecursionLimit9939)
	if err == nil {
		t.Fatal("at the recursion limit the payload was ALLOWED; running out of budget must not " +
			"read as having found nothing (#9939)")
	}
	if !strings.Contains(err.Error(), "nested deeper") {
		t.Errorf("at the limit the refusal does not name the budget as the reason: %v", err)
	}
	// And an ALLOWED payload at the limit is refused too — the bound is about
	// not having looked, not about what was found.
	allowed := []string{"change-configuration", "commands", "set system host-name ok"}
	if err := authorizeEmbeddedChangeConfig9939(cfg, "planter", allowed, quoted, changeConfigRecursionLimit9939); err == nil {
		t.Fatal("an ALLOWED payload passed at the recursion limit; the bound must refuse on not " +
			"having looked, not on what it found")
	}
}
