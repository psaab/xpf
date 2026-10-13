package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestApplyGroupsRouteFilterRendersMatchClause12529(t *testing.T) {
	const text = `groups { G { policy-options { policy-statement P { term T from route-filter 10.0.0.0/8 upto /24; } } } }
policy-options { apply-groups G; policy-statement P { term T then accept; } }`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	compiled, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	got := New().generatePolicyOptions(&compiled.PolicyOptions, nil)
	for _, want := range []string{
		"route-map P permit 10",
		"match ip address prefix-list",
		"permit 10.0.0.0/8 le 24",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered policy lost inherited clause %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "route-map P permit 10\nexit") {
		t.Fatalf("route-map P rendered permit-all without inherited match:\n%s", got)
	}
}
