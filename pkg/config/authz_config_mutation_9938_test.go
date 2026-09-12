package config

import (
	"strings"
	"testing"
)

// #9938: the gate adjudicated a string the dispatcher never acts on.
//
// Three heads on one lever, all three reproduced at `6112e580c` before any fix:
//
//	F-019  gRPC `Set` sends a BARE PATH -> no leading verb -> "not gated" -> ALLOWED
//	F-020  strings.Fields keeps quotes  -> gated `security "policies" p1`,
//	                                       applied `security policies p1`
//	F-029  copy/rename joined into ONE string -> neither REAL endpoint adjudicated
//
// F-019's fix is at the gRPC resolver and is pinned in pkg/grpcapi; the two
// below are the gate's own, and the matrix is the acceptance artifact rather
// than a spot fix, because a patch to any one string leaves the other two open.

const mutCfg9938 = `
system {
    host-name authz-9938;
    login {
        class plainDeny {
            permissions [ configure view ];
            deny-configuration "security policies p1";
        }
        class anchoredDeny {
            permissions [ configure view ];
            deny-configuration "^security policies p1$";
        }
        class wideopen {
            permissions [ configure view ];
        }
    }
}
`

func mutCfgFor9938(t *testing.T) *Config {
	t.Helper()
	tree, errs := NewParser(mutCfg9938).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture does not parse, so every cell below is vacuous: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("fixture does not compile, so every cell below is vacuous: %v", err)
	}
	// PREMISE, asserted rather than assumed: BOTH restricted classes must carry
	// configuration regexes and the control must not, or a refusal below is
	// vacuous and an allowance means nothing.
	for _, c := range []string{"plainDeny", "anchoredDeny"} {
		if _, ok, err := ConfigurationLoginRegexesFor(cfg, c); err != nil || !ok {
			t.Fatalf("fixture class %q is not regex-restricted (ok=%v err=%v)", c, ok, err)
		}
	}
	if _, ok, _ := ConfigurationLoginRegexesFor(cfg, "wideopen"); ok {
		t.Fatal("fixture class `wideopen` HAS configuration regexes; it is the control and must have none")
	}
	return cfg
}

// TestQuotedTokensAreLexedBeforeAdjudication9938 pins F-020.
//
// The store lexes quotes away before it edits; the gate used strings.Fields,
// which keeps them. A quoted token anywhere in a denied path therefore made the
// gate judge a string the store never acts on.
func TestQuotedTokensAreLexedBeforeAdjudication9938(t *testing.T) {
	cfg := mutCfgFor9938(t)
	for name, line := range map[string]string{
		"quoted middle token": `deactivate security "policies" p1`,
		"quoted first token":  `deactivate "security" policies p1`,
		"quoted last token":   `delete security policies "p1"`,
		"every token quoted":  `set "security" "policies" "p1" description x`,
		"CONTROL unquoted":    `deactivate security policies p1`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := AuthorizeConfigMutation(cfg, "plainDeny", nil, line); err == nil {
				t.Fatalf("%q was ALLOWED; the store strips the quotes and edits the denied path (#9938 F-020)", line)
			}
		})
	}
}

// TestCopyAndRenameAdjudicateBOTHEndpoints9938 pins F-029.
//
// The escape needs an ANCHORED deny, which is the idiom Junos documents for
// complex expressions — an unanchored deny caught the joined string incidentally
// and that is why the mechanism survived. Both directions are cells because a
// fix that adjudicated only the source would pass one of them.
func TestCopyAndRenameAdjudicateBOTHEndpoints9938(t *testing.T) {
	cfg := mutCfgFor9938(t)
	for name, line := range map[string]string{
		"rename denied -> allowed": "rename security policies p1 to security policies ok",
		"rename allowed -> denied": "rename security policies ok to security policies p1",
		"copy denied -> allowed":   "copy security policies p1 to security policies ok",
		"copy allowed -> denied":   "copy security policies ok to security policies p1",
	} {
		t.Run(name, func(t *testing.T) {
			if err := AuthorizeConfigMutation(cfg, "anchoredDeny", nil, line); err == nil {
				t.Fatalf("%q was ALLOWED under an ANCHORED deny; half a copy is still a mutation "+
					"of a path the class was denied (#9938 F-029)", line)
			}
		})
	}
}

// The POSITIVE CONTROL for the cell above, and it is what stops the fix from
// being "refuse every copy": neither endpoint denied must still be allowed.
func TestCopyAndRenameWithNeitherEndpointDeniedAreAllowed9938(t *testing.T) {
	cfg := mutCfgFor9938(t)
	for _, line := range []string{
		"rename security policies ok to security policies alsook",
		"copy security zones trust to security zones dmz",
	} {
		if err := AuthorizeConfigMutation(cfg, "anchoredDeny", nil, line); err != nil {
			t.Errorf("%q was refused with neither endpoint denied: %v", line, err)
		}
	}
}

// TestInsertAndAnnotateAdjudicateTheElementPath9938 covers the two verbs the
// pre-#9938 test file had ZERO cases for, and whose payload is not simply
// `parts[1:]`.
//
// `insert <path> before|after <ref>` and `annotate <path> "comment"` both carry
// a trailing token that is not part of the acted-upon path. Joining the whole
// remainder made the gated string longer than the real one, which an anchored
// deny then failed to match.
func TestInsertAndAnnotateAdjudicateTheElementPath9938(t *testing.T) {
	cfg := mutCfgFor9938(t)
	for name, tc := range map[string]struct {
		line       string
		wantRefuse bool
	}{
		"insert denied element":     {"insert security policies p1 before security policies p0", true},
		"insert allowed element":    {"insert security policies ok before security policies p0", false},
		"annotate denied path":      {`annotate security policies p1 "why"`, true},
		"annotate allowed path":     {`annotate security policies ok "why"`, false},
		"annotate path IS the deny": {`annotate security policies p1 "p1 is fine really"`, true},
	} {
		t.Run(name, func(t *testing.T) {
			err := AuthorizeConfigMutation(cfg, "anchoredDeny", nil, tc.line)
			if tc.wantRefuse && err == nil {
				t.Fatalf("%q was ALLOWED; the element path is denied (#9938)", tc.line)
			}
			if !tc.wantRefuse && err != nil {
				t.Fatalf("%q was refused; over-denial is a different outage, not a fix: %v", tc.line, err)
			}
		})
	}
}

// TestAClassWithNoConfigurationRegexesIsUnaffected9938 is the narrowness
// control. This gate now lexes and multi-resolves on every config-mode line, so
// the cost of getting it wrong is borne by every operator, not only a restricted
// one.
func TestAClassWithNoConfigurationRegexesIsUnaffected9938(t *testing.T) {
	cfg := mutCfgFor9938(t)
	for _, line := range []string{
		`set "security" "policies" "p1" description x`,
		"rename security policies p1 to security policies ok",
		`annotate security policies p1 "why"`,
		"insert security policies p1 before security policies p0",
		"commit",
		"edit security policies",
	} {
		if err := AuthorizeConfigMutation(cfg, "wideopen", nil, line); err != nil {
			t.Errorf("%q refused for a class with NO configuration regexes: %v", line, err)
		}
		if err := AuthorizeConfigMutation(cfg, "", nil, line); err != nil {
			t.Errorf("%q refused for a principal with no class: %v", line, err)
		}
	}
}

// TestNavigationAndWholeCandidateVerbsStayUngated9938 is the other narrowness
// control, and it guards a specific regression this change could introduce.
//
// The lexer makes EVERY line tokenizable, so a version that treated any
// unrecognised leading token as an implicit `set` — which is what
// ParseSetVerb does, and is the tempting way to fix F-019 inside the gate —
// would start gating `commit`, `edit` and `rollback` as paths. Those are
// ungated for stated reasons: navigation changes nothing, and a deny that
// stopped `commit` would deny the operator's own already-authorized edits.
func TestNavigationAndWholeCandidateVerbsStayUngated9938(t *testing.T) {
	cfg := mutCfgFor9938(t)
	for _, line := range []string{
		"edit security policies p1",
		"top",
		"up",
		"commit",
		"rollback 1",
		"show security policies p1",
	} {
		if err := AuthorizeConfigMutation(cfg, "plainDeny", nil, line); err != nil {
			t.Errorf("%q was gated as a mutation: %v", line, err)
		}
	}
}

// The audit line must not echo the operator's data. A config path's trailing
// tokens carry secrets — `set system root-authentication plain-text-password
// <secret>` puts one in the path itself — so the refusal names the verb and the
// path's ROOT only. This travelled with the multi-path change and is re-pinned
// because the message is now emitted from inside a loop.
func TestTheRefusalDoesNotEchoTheOperatorsData9938(t *testing.T) {
	cfg := mutCfgFor9938(t)
	err := AuthorizeConfigMutation(cfg, "plainDeny", nil, `set security policies p1 description "S3CR3T-9938"`)
	if err == nil {
		t.Fatal("the denied path was allowed; this cell would prove nothing")
	}
	if strings.Contains(err.Error(), "S3CR3T-9938") {
		t.Fatalf("the refusal echoed operator data from the path: %v", err)
	}
}

// TestAMalformedTwoEndpointVerbFallsBackToTheWholeRemainder9938 pins the rule
// that keeps this change from being a coverage regression.
//
// Adding per-verb payload extraction makes the gate MORE PRECISE, and the first
// version of it also made the gate LESS COVERING: a `copy` with no `to`, an
// `insert` with no `before`/`after`, and an `annotate` with no quoted comment
// all stopped being gated at all, because "the dispatcher acts on nothing" is a
// true statement about the line and the wrong answer for the gate.
//
// It was caught by TestEveryFlatVerbIsTakenVerbatimNotReparsed9892 — a cell
// written for a different issue, whose fixture happened to use exactly these
// malformed shapes. That is the whole argument for running full packages rather
// than `-run 9938`.
//
// The rule: a precision gain must never remove coverage. When the payload does
// not parse for its verb, the WHOLE remainder is the path, which is the
// pre-#9938 behaviour kept as a floor.
func TestAMalformedTwoEndpointVerbFallsBackToTheWholeRemainder9938(t *testing.T) {
	cfg := mutCfgFor9938(t)
	for name, line := range map[string]string{
		"copy with no `to`":            "copy security policies p1",
		"rename with no `to`":          "rename security policies p1",
		"insert with no before/after":  "insert security policies p1",
		"annotate with no comment":     "annotate security policies p1",
		"annotate with unquoted trail": "annotate security policies p1 why",
		"copy with `to` first":         "copy to security policies p1",
	} {
		t.Run(name, func(t *testing.T) {
			if err := AuthorizeConfigMutation(cfg, "plainDeny", nil, line); err == nil {
				t.Fatalf("%q was ALLOWED; a malformed payload must fall back to gating the whole "+
					"remainder, never to gating nothing (#9938)", line)
			}
		})
	}
}
