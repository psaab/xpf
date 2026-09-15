package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9916 F-135 (display half, parent-review follow-up): the gRPC show path must
// skip a nil within clause, not panic. Failing closed in evaluate while crashing
// display on the same corrupt config would be incoherent defense-in-depth.
//
// NOTE (recorded asymmetry, out of F-135 scope): a nil POLICY entry itself
// (cfg.EventOptions[i] == nil) still panics this loop at ep.Name, while
// evaluateEvent nil-guards pol. F-135 covers the nil CLAUSE (the member's named
// mechanism); nil-policy display hardening is a separate, unfiled concern.
func TestShowEventOptionsSkipsNilClause9916(t *testing.T) {
	cfg := &config.Config{
		EventOptions: []*config.EventPolicy{{
			Name:   "p9916",
			Events: []string{"ping_probe_failed"},
			WithinClauses: []*config.EventWithin{
				{Seconds: 60, TriggerOn: 2},
				nil,
			},
		}},
	}
	var buf strings.Builder
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("showEventOptions panicked on nil clause: %v (#9916 F-135)", r)
			}
		}()
		(&Server{}).showEventOptions(cfg, &buf)
	}()
	out := buf.String()
	if !strings.Contains(out, "Policy: p9916") {
		t.Fatalf("policy header missing from show output %q", out)
	}
	if !strings.Contains(out, "Within: 60 seconds") {
		t.Fatalf("valid sibling clause missing from show output %q (over-suppression)", out)
	}
}
