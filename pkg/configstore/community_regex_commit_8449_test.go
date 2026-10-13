package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const commBase8449 = `
system { host-name p; }
routing-options { autonomous-system 65000; }
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } } }
security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }
`

func commCommit8449(member string) error {
	body := "policy-options { community c1 { members " + member + "; } " +
		"policy-statement p1 { term t1 { from community c1; then accept; } } }\n" +
		"protocols { bgp { group g { type external; peer-as 65001; neighbor 10.0.1.2; export p1; } } }"
	_, err := CheckText(commBase8449+body, 0)
	return err
}

// #8449: `65000:[` and `*65000` committed CLEAN and were rendered verbatim into
// frr.conf, where FRR's regcomp failure fails the ENTIRE frr-reload. Bound at
// configstore.CheckText — the real operator commit path.
func TestCommunityRegexRejectedAtCommit_8449(t *testing.T) {
	// QUOTED, because an unquoted `[` is consumed by the bracketed-list lexer
	// (it truncates `65000:[` to `65000:`, a different #2419-class defect) and
	// the cell would then be measuring the lexer, not this gate.
	for _, bad := range []string{`"65000:["`, "*65000", `"*65000"`, `"65000:("`, `"65000:a{3,1}"`} {
		if err := commCommit8449(bad); err == nil {
			t.Errorf("member %q committed clean — it renders into frr.conf and "+
				"poisons the whole reload", bad)
		}
	}
}

// POSITIVE CONTROL. Without these the cell above would pass against a gate that
// rejects everything, and it is a valid-member regression that would hurt most.
func TestCommunityValidMembersStillCommit_8449(t *testing.T) {
	for _, good := range []string{"65000:100", `"65000:100"`, "no-export", "65000:.*", `"65000:1{2,3}"`, `"^65000:"`} {
		if err := commCommit8449(good); err != nil {
			t.Errorf("valid member %q REJECTED: %v", good,
				strings.SplitN(err.Error(), "\n", 2)[0])
		}
	}
}

// #1960 no-brick: a config already persisted with an unrenderable member must
// still LOAD. Bound at the tolerant compile path, not only at the validator —
// a change that made Load strict would leave every pkg/config test green while
// a booting node lost its routing config.
func TestCommunityRegexNoBrickOnTolerantPath_8449(t *testing.T) {
	// The bad member goes into the TREE before the tolerant compile, the way
	// a stored/peer-synced config would carry it. (Compiling a valid tree and
	// overwriting Members afterwards never exercises the tolerant gate: the
	// downgrade branch can be forced strict and such a cell stays green.)
	// QUOTED, as in TestCommunityRegexRejectedAtCommit_8449: an unquoted `[`
	// is consumed by the bracketed-list lexer.
	tree := &config.ConfigTree{}
	for _, s := range []string{
		`set policy-options community c1 members "65000:["`,
	} {
		p, err := config.ParseSetCommand(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", s, err)
		}
	}
	// The predicate must still call it unrenderable...
	if config.ValidCommunityMember("65000:[") == nil {
		t.Fatal("the predicate no longer rejects the member; the belt guards nothing")
	}
	// ...the strict compile of the same tree must refuse it (the gate fires)...
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("strict compile accepted the unrenderable member; the gate does not fire on this tree")
	}
	// ...and the tolerant path must downgrade it to a warning, not refuse to
	// produce a config.
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile bricked on a persisted unrenderable member: %v", err)
	}
	if cfg.PolicyOptions.Communities["c1"] == nil {
		t.Fatal("tolerant compile dropped the community definition entirely")
	}
	foundMember := false
	for _, m := range cfg.PolicyOptions.Communities["c1"].Members {
		if m == "65000:[" {
			foundMember = true
		}
	}
	if !foundMember {
		t.Fatalf("tolerant compile dropped the unrenderable member; members=%v",
			cfg.PolicyOptions.Communities["c1"].Members)
	}
	foundWarning := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "policy community member") && strings.Contains(w, "65000:[") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatalf("tolerant compile produced no downgraded community-member warning; warnings=%v", cfg.Warnings)
	}
}
