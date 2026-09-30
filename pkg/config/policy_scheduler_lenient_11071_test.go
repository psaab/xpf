package config

import (
	"strings"
	"testing"
)

// TestPolicySchedulerRefLenientBoots11071: a dangling scheduler-name must not
// brick tolerant load / peer-sync (#11071, #1960 class) — it warns and the
// policy loads inactive (policyRuleInactive fail-closed). Strict still rejects.
func TestPolicySchedulerRefLenientBoots11071(t *testing.T) {
	build := func() *ConfigTree {
		p := NewParser(`security {
    policies {
        from-zone trust to-zone untrust {
            policy sched-test {
                match { source-address any; destination-address any; application any; }
                then { permit; }
                scheduler-name missing-sched;
            }
        }
    }
}`)
		tree, errs := p.Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		return tree
	}
	if _, err := CompileConfig(build()); err == nil {
		t.Fatal("strict commit must reject a dangling scheduler-name")
	} else if !strings.Contains(err.Error(), "missing-sched") {
		t.Fatalf("strict error must name the scheduler, got: %v", err)
	}
	cfg, err := CompileConfigLenient(build())
	if err != nil {
		t.Fatalf("lenient load must boot through a dangling scheduler-name, got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "missing-sched") {
			found = true
		}
	}
	if !found {
		t.Errorf("lenient load must warn naming missing-sched; warnings=%v", cfg.Warnings)
	}
}
