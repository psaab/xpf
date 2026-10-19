package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15665: FRR route-map must emit every community action of a term in
// authored order: delete lines whenever CommunityDelete is non-empty, in
// addition to the set/add/none action, and one additive line per repeated
// `community add` value.

func render15665(t *testing.T, cmds []string) string {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return New().generatePolicyOptions(&cfg.PolicyOptions)
}

func TestPolicyCommunityDeletePlusAddRendersBoth15665(t *testing.T) {
	got := render15665(t, []string{
		"set policy-options community C1 members 65000:1",
		"set policy-options community C2 members 65000:2",
		"set policy-options policy-statement P term t1 from protocol bgp",
		"set policy-options policy-statement P term t1 then community delete C1",
		"set policy-options policy-statement P term t1 then community add C2",
		"set policy-options policy-statement P term t1 then accept",
	})
	del := strings.Index(got, " set comm-list C1 delete\n")
	add := strings.Index(got, " set community 65000:2 additive\n")
	if del < 0 {
		t.Fatalf("missing `set comm-list C1 delete` in:\n%s", got)
	}
	if add < 0 {
		t.Fatalf("missing `set community 65000:2 additive` in:\n%s", got)
	}
	if del > add {
		t.Fatalf("delete must render before add (authored order) in:\n%s", got)
	}
}

func TestPolicyCommunityRepeatedAddRendersAll15665(t *testing.T) {
	got := render15665(t, []string{
		"set policy-options policy-statement P term t1 from protocol bgp",
		"set policy-options policy-statement P term t1 then community add 65000:1",
		"set policy-options policy-statement P term t1 then community add 65000:2",
		"set policy-options policy-statement P term t1 then accept",
	})
	// Accumulated adds render as one additive line carrying every value
	// in authored order (FRR `set community <v...> additive`).
	if !strings.Contains(got, " set community 65000:1 65000:2 additive\n") {
		t.Fatalf("repeated add must render both values additive in order in:\n%s", got)
	}
}

func TestPolicyCommunityBracketedAddRendersAll15665(t *testing.T) {
	got := render15665(t, []string{
		"set policy-options community C1 members 65000:1",
		"set policy-options community C2 members 65000:2",
		"set policy-options policy-statement P term t1 from protocol bgp",
		"set policy-options policy-statement P term t1 then community add [ C1 C2 ]",
		"set policy-options policy-statement P term t1 then accept",
	})
	if !strings.Contains(got, " set community 65000:1 65000:2 additive\n") &&
		!(strings.Contains(got, " set community 65000:1 additive\n") && strings.Contains(got, " set community 65000:2 additive\n")) {
		t.Fatalf("bracketed add [ C1 C2 ] must render 65000:1 and 65000:2 additive in:\n%s", got)
	}
}
