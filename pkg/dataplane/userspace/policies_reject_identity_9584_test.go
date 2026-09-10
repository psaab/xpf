package userspace

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #9584 — the rule-identity arm. Channel: config.CompileConfigLenient (strict
// commit rejects every duplicate name, #3473, so only the tolerant path reaches
// these configs). Fixtures are hierarchical text: a flat `set` session merges at
// SetPath and cannot express a split duplicate.

const anyMatch9584 = `match { source-address any; destination-address any; application any; }`
const zones9584 = `zones { security-zone trust; security-zone untrust; }`

func pol9584(name, action string) string {
	return `policy ` + name + ` { ` + anyMatch9584 + ` then { ` + action + `; } }`
}

var shapeA9584 = `security { ` + zones9584 + ` policies { from-zone trust to-zone untrust { ` + pol9584("p1", "deny") + ` } } }
security { policies { from-zone trust to-zone untrust { ` + pol9584("p1", "permit") + ` } } }`

func TestDuplicateRuleIdentityRefusalIsMirrored9584(t *testing.T) {
	for _, tc := range []struct{ name, text, identity, scope string }{
		{"A: two security roots", shapeA9584, "trust->untrust/p1", "trust->untrust/p1"},
		{"B: two stanzas for one zone pair", `security { ` + zones9584 + ` policies { from-zone trust to-zone untrust { ` + pol9584("p1", "deny") + ` } from-zone trust to-zone untrust { ` + pol9584("p1", "permit") + ` } } }`, "trust->untrust/p1", "trust->untrust/p1"},
		{"C: two policies blocks", `security { ` + zones9584 + ` policies { from-zone trust to-zone untrust { ` + pol9584("p1", "deny") + ` } } policies { from-zone trust to-zone untrust { ` + pol9584("p1", "permit") + ` } } }`, "trust->untrust/p1", "trust->untrust/p1"},
		{"D: two global blocks", `security { ` + zones9584 + ` policies { global { ` + pol9584("g1", "deny") + ` } global { ` + pol9584("g1", "permit") + ` } } }`, "junos-global->junos-global/g1", "global/g1"},
		{"E: agreeing actions", `security { ` + zones9584 + ` policies { from-zone trust to-zone untrust { ` + pol9584("p1", "permit") + ` } } }
security { policies { from-zone trust to-zone untrust { ` + pol9584("p1", "permit") + ` } } }`, "trust->untrust/p1", "trust->untrust/p1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lenientHier9571(t, tc.text)
			rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			n := 0
			for i := range rules {
				if stableRuleIdentity9584(&rules[i]) == tc.identity {
					n++
				}
			}
			if n < 2 {
				t.Fatalf("fixture premise broken: %d built rule(s) resolve to %q, so the helper would not refuse it", n, tc.identity)
			}
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if len(reasons) != 1 {
				t.Fatalf("#9584: want exactly one reason for the helper's DuplicateRuleId refusal, got %d: %v", len(reasons), reasons)
			}
			for _, want := range []string{"policy " + tc.scope + " ", `"` + tc.identity + `"`, "WHOLE POLICY SNAPSHOT", "DuplicateRuleId"} {
				if !strings.Contains(reasons[0], want) {
					t.Errorf("reason lacks %q: %s", want, reasons[0])
				}
			}
		})
	}
}

// The load-bearing half: legitimate configs, and a duplicate the #8752 fold does
// merge, must produce no reason. A mirror that reported every repeated NAME
// rather than every repeated IDENTITY would fail the two different-context rows.
func TestDuplicateRuleIdentityControls9584(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"distinct names across two roots", `security { ` + zones9584 + ` policies { from-zone trust to-zone untrust { ` + pol9584("p1", "deny") + ` } } }
security { policies { from-zone trust to-zone untrust { ` + pol9584("p2", "permit") + ` } } }`},
		{"#8752 fold merges a single-stanza duplicate", `security { ` + zones9584 + ` policies { from-zone trust to-zone untrust { ` + pol9584("p1", "permit") + ` policy p1 { then { deny; } } } } }`},
		{"same name in two different zone pairs", `security { ` + zones9584 + ` policies { from-zone trust to-zone untrust { ` + pol9584("p1", "permit") + ` } from-zone untrust to-zone trust { ` + pol9584("p1", "permit") + ` } } }`},
		{"same name in a zone pair and in global", `security { ` + zones9584 + ` policies { from-zone trust to-zone untrust { ` + pol9584("p1", "permit") + ` } global { ` + pol9584("p1", "deny") + ` } } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lenientHier9571(t, tc.text)
			if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
				t.Errorf("#9584 OVER-REJECTION: %v", reasons)
			}
		})
	}
}

// Hand-built snapshots reach the states a config cannot author: an explicit
// duplicate wire rule_id, a synthesized identity, and the policy_id arm, whose
// ids the builder assigns uniquely by construction.
func TestPolicyIdentityRejectionHandBuilt9584(t *testing.T) {
	r := func(ruleID, name string, policyID uint32) PolicyRuleSnapshot {
		return PolicyRuleSnapshot{RuleID: ruleID, Name: name, PolicyID: policyID, FromZone: "lan", ToZone: "wan"}
	}
	for _, tc := range []struct {
		name  string
		rules []PolicyRuleSnapshot
		want  string // "" => no reason
	}{
		{"explicit duplicate rule_id, distinct names", []PolicyRuleSnapshot{r("wire-dup", "alpha", 10), r("wire-dup", "bravo", 11)}, "DuplicateRuleId"},
		{"synthesized identity (empty rule_id)", []PolicyRuleSnapshot{r("", "dup", 1), r("", "dup", 2)}, "DuplicateRuleId"},
		{"duplicate non-zero policy_id", []PolicyRuleSnapshot{r("a", "a", 7), r("b", "b", 7)}, "DuplicatePolicyId"},
		{"three rules, one identity, one reason", []PolicyRuleSnapshot{r("x", "x", 1), r("x", "x", 2), r("x", "x", 3)}, "DuplicateRuleId"},
		{"policy_id 0 repeated (older producer)", []PolicyRuleSnapshot{r("a", "a", 0), r("b", "b", 0)}, ""},
		{"default-policy sentinel repeated", []PolicyRuleSnapshot{r("a", "a", dataplane.DefaultPolicySentinelID), r("b", "b", dataplane.DefaultPolicySentinelID)}, ""},
		{"all distinct", []PolicyRuleSnapshot{r("a", "a", 1), r("b", "b", 2)}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := collectPolicyIdentityRejections(tc.rules)
			if tc.want == "" {
				if len(got) != 0 {
					t.Errorf("#9584 OVER-REJECTION: %v", got)
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], tc.want) {
				t.Errorf("want exactly one %s reason, got %v", tc.want, got)
			}
		})
	}
}

const dupRuleIDFixture9584 = "../../../testdata/policy_duplicate_rule_id_9584.json"

// TestDuplicateRuleIdentityWireFixtureIsFresh9584 pins the exact wire the Go
// builder emits for shape A to a committed file that the Rust cell
// go_built_split_duplicate_wire_is_refused_9584 reads, so the helper's refusal is
// asserted on the builder's own output rather than on a hand transcription. If
// the builder's output changes, regenerate with UPDATE_9584=1 and run both.
func TestDuplicateRuleIdentityWireFixtureIsFresh9584(t *testing.T) {
	cfg := lenientHier9571(t, shapeA9584)
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("UPDATE_9584") == "1" {
		if err := os.WriteFile(dupRuleIDFixture9584, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(dupRuleIDFixture9584)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the Go builder's wire for the split duplicate drifted from %s; the Rust cell asserts the "+
			"helper refuses THAT file, so regenerate with UPDATE_9584=1 and re-run both halves.\ngot:\n%s", dupRuleIDFixture9584, got)
	}
}
