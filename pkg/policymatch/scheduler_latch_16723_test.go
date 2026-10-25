package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #16723: under the snapshot builder's fail-closed latch, a scheduled
// DENY stays eligible (policyRuleInactiveForScheduler), so the
// simulator must NOT skip it: traffic the runtime denies must not be
// certified as permitted by a later active permit. The name-only
// predicate (PolicyInactiveFn) cannot express this — it skips the
// latched deny — which is why the failing
// TestSchedulerInactiveSkipsLikeRuntime case existed: it expected the
// runtime's fall-through while the builder (with the latch the daemon
// publishes during recovery) keeps the deny.
func TestSchedulerLatchedDenyStaysEligible16723(t *testing.T) {
	cfg := withDefinedSchedulers16723(cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust",
				scheduled(deny("block-by-day", config.PolicyMatch{
					Applications: []string{"any"},
				}), "business-hours"),
				permit("allow-rest", config.PolicyMatch{Applications: []string{"any"}})),
		},
	}, config.ApplicationsConfig{}), "business-hours")
	q := Query{
		FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80,
		PolicyInactiveForFn: dpuserspace.PolicyInactiveFnWithLatch(
			cfg, map[string]bool{"business-hours": false}, true),
	}
	res := Match(cfg, q)
	if !res.Matched || res.Action != config.PolicyDeny || res.PolicyName != "block-by-day" {
		t.Fatalf("latched scheduled deny must stay eligible, got Matched=%v Action=%v PolicyName=%q",
			res.Matched, res.Action, res.PolicyName)
	}
}
