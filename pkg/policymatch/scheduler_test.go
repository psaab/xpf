package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// deny builds a deny policy, optionally scheduler-bound.
func deny(name string, m config.PolicyMatch) *config.Policy {
	return &config.Policy{Name: name, Match: m, Action: config.PolicyDeny}
}

func scheduled(p *config.Policy, schedName string) *config.Policy {
	p.SchedulerName = schedName
	return p
}

// inactiveFnFor builds the name-only predicate used by these ordinary
// scheduler-inactive cases. Live match-policies surfaces use the
// action-aware predicate from the applied state/latch pair.
func inactiveFnFor(active map[string]bool) func(string) bool {
	return dpuserspace.PolicyInactiveFn(active)
}

// TestSchedulerInactiveSkipsLikeRuntime covers #3104: the shared simulator must
// agree with the runtime (policy.rs try_match_rule), which drops a
// scheduler-inactive rule BEFORE app/address matching. Reverting the skip in
// ruleMatches makes case #1 (inactive scheduled permit -> default-deny) go RED.
// withDefinedSchedulers16723 defines the schedulers these fixtures
// bind, as a committed config would: the #12244 content-rejection SSOT
// poisons a rule naming an UNDEFINED scheduler (config-wide
// ContentRejected), which otherwise masks the scheduler-inactivity
// verdict under test. Mutating the shared fixture (not cfgWith, whose
// other callers may deliberately use undefined names) keeps the
// subject isolated.
func withDefinedSchedulers16723(cfg *config.Config, names ...string) *config.Config {
	if cfg.Schedulers == nil {
		cfg.Schedulers = make(map[string]*config.SchedulerConfig, len(names))
	}
	for _, n := range names {
		cfg.Schedulers[n] = &config.SchedulerConfig{Name: n}
	}
	return cfg
}

func TestSchedulerInactiveSkipsLikeRuntime(t *testing.T) {
	// Case 1: an inactive scheduled PERMIT must NOT be reported as a match;
	// the verdict falls through to the configured default-policy (deny).
	t.Run("inactive scheduled permit -> default deny", func(t *testing.T) {
		cfg := withDefinedSchedulers16723(cfgWith(config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Policies: []*config.ZonePairPolicies{
				zonePair("trust", "untrust",
					scheduled(permit("night-allow", config.PolicyMatch{
						Applications: []string{"any"},
					}), "after-hours")),
			},
		}, config.ApplicationsConfig{}), "after-hours", "business-hours", "maint")
		q := Query{
			FromZone:         "trust",
			ToZone:           "untrust",
			Protocol:         "tcp",
			DstPort:          PortPtr(80),
			PolicyInactiveFn: inactiveFnFor(map[string]bool{"after-hours": false}),
		}
		res := Match(cfg, q)
		if res.Matched {
			t.Fatalf("inactive scheduled permit matched (PolicyName=%q); want default-deny fall-through", res.PolicyName)
		}
		if !res.DefaultUsed || res.Action != config.PolicyDeny {
			t.Fatalf("want default deny, got Matched=%v DefaultUsed=%v Action=%v",
				res.Matched, res.DefaultUsed, res.Action)
		}
	})

	// Case 2: an inactive scheduled DENY must be skipped so a LATER active
	// permit wins — the runtime would forward such traffic. (Ordinary
	// inactive state, NO fail-closed latch: under the latch the builder
	// keeps the deny eligible and this fall-through must NOT happen —
	// pinned separately by TestSchedulerLatchedDenyStaysEligible16723.
	// This case uses the name-only predicate, which is exactly the
	// ordinary-inactive disposition.)
	t.Run("inactive scheduled deny -> falls through to active permit", func(t *testing.T) {
		cfg := withDefinedSchedulers16723(cfgWith(config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Policies: []*config.ZonePairPolicies{
				zonePair("trust", "untrust",
					scheduled(deny("block-by-day", config.PolicyMatch{
						Applications: []string{"any"},
					}), "business-hours"),
					permit("allow-rest", config.PolicyMatch{Applications: []string{"any"}})),
			},
		}, config.ApplicationsConfig{}), "after-hours", "business-hours", "maint")
		q := Query{
			FromZone:         "trust",
			ToZone:           "untrust",
			Protocol:         "tcp",
			DstPort:          PortPtr(80),
			PolicyInactiveFn: inactiveFnFor(map[string]bool{"business-hours": false}),
		}
		res := Match(cfg, q)
		if !res.Matched || res.Action != config.PolicyPermit || res.PolicyName != "allow-rest" {
			t.Fatalf("want permit by allow-rest, got Matched=%v Action=%v PolicyName=%q",
				res.Matched, res.Action, res.PolicyName)
		}
	})

	// Case 3: a scheduler flip changes the verdict for the same query/config.
	t.Run("scheduler flip changes verdict", func(t *testing.T) {
		cfg := withDefinedSchedulers16723(cfgWith(config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Policies: []*config.ZonePairPolicies{
				zonePair("trust", "untrust",
					scheduled(permit("maint-window", config.PolicyMatch{
						Applications: []string{"any"},
					}), "maint")),
			},
		}, config.ApplicationsConfig{}), "after-hours", "business-hours", "maint")
		baseQ := func(active bool) Query {
			return Query{
				FromZone:         "trust",
				ToZone:           "untrust",
				Protocol:         "tcp",
				DstPort:          PortPtr(443),
				PolicyInactiveFn: inactiveFnFor(map[string]bool{"maint": active}),
			}
		}
		// Active -> the scheduled permit matches.
		if res := Match(cfg, baseQ(true)); !res.Matched || res.Action != config.PolicyPermit {
			t.Fatalf("scheduler active: want permit match, got Matched=%v Action=%v", res.Matched, res.Action)
		}
		// Inactive -> default deny.
		if res := Match(cfg, baseQ(false)); res.Matched || res.Action != config.PolicyDeny {
			t.Fatalf("scheduler inactive: want default deny, got Matched=%v Action=%v", res.Matched, res.Action)
		}
	})

	// Case 4 (no-regression): a NON-scheduled policy's verdict is identical
	// whether or not a PolicyInactiveFn is threaded, and regardless of the
	// active-state map contents. PolicyInactiveFn must never be consulted for a
	// policy with an empty scheduler name.
	t.Run("non-scheduled policy unchanged", func(t *testing.T) {
		cfg := withDefinedSchedulers16723(cfgWith(config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Policies: []*config.ZonePairPolicies{
				zonePair("trust", "untrust",
					permit("plain-allow", config.PolicyMatch{Applications: []string{"any"}})),
			},
		}, config.ApplicationsConfig{}), "after-hours", "business-hours", "maint")
		q := Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)}

		// No PolicyInactiveFn (offline surface / pre-#3104 behavior).
		baseline := Match(cfg, q)
		if !baseline.Matched || baseline.Action != config.PolicyPermit || baseline.PolicyName != "plain-allow" {
			t.Fatalf("baseline: want permit by plain-allow, got Matched=%v Action=%v PolicyName=%q",
				baseline.Matched, baseline.Action, baseline.PolicyName)
		}

		sameVerdict := func(got Result, label string) {
			if got.Matched != baseline.Matched || got.Action != baseline.Action ||
				got.PolicyName != baseline.PolicyName || got.DefaultUsed != baseline.DefaultUsed ||
				got.Global != baseline.Global {
				t.Fatalf("non-scheduled verdict changed (%s): baseline=%+v got=%+v", label, baseline, got)
			}
		}

		// With a PolicyInactiveFn that marks everything inactive: a
		// non-scheduled policy (empty scheduler name) is still active.
		q.PolicyInactiveFn = inactiveFnFor(map[string]bool{})
		sameVerdict(Match(cfg, q), "empty active map")

		// And with a nil active-state map (state published but empty) — same.
		q.PolicyInactiveFn = inactiveFnFor(nil)
		sameVerdict(Match(cfg, q), "nil active map")
	})
}

// TestSchedulerUnavailableStateFailsClosed covers #3414: the live diagnostic
// surfaces (REST/gRPC/CLI match-policies) bind PolicyInactiveFn even when they
// cannot obtain live scheduler state, by passing a nil active-state map. That
// binding MUST be fail-closed — treating a scheduler-bound policy as inactive —
// so the simulator agrees with the dataplane (snapshot builder: nil scheduler
// state => Inactive => dropped) instead of certifying an as-if-active verdict.
//
// RED-on-revert: making dataplane/userspace.PolicyInactiveFn(nil) return false
// for a scheduled policy (the pre-#3414 "as-if-active" fallback) lets the
// scheduled permit match here, so the default-deny assertion fails. This pins
// the simulator side; the dataplane side is pinned by the snapshot builder test
// (pkg/dataplane/userspace: "fail-closed true" with nil scheduler state).
func TestSchedulerUnavailableStateFailsClosed(t *testing.T) {
	cfg := withDefinedSchedulers16723(cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust",
				scheduled(permit("night-allow", config.PolicyMatch{
					Applications: []string{"any"},
				}), "after-hours")),
		},
	}, config.ApplicationsConfig{}), "after-hours", "business-hours", "maint")

	// inactiveFnFor(nil) is exactly what the live surfaces thread when
	// per-scheduler active-state is unavailable (accessor not wired / early
	// boot). The scheduled permit must be skipped -> default deny.
	q := Query{
		FromZone:         "trust",
		ToZone:           "untrust",
		Protocol:         "tcp",
		DstPort:          PortPtr(80),
		PolicyInactiveFn: inactiveFnFor(nil),
	}
	res := Match(cfg, q)
	if res.Matched {
		t.Fatalf("scheduled permit matched with unavailable state (PolicyName=%q); want fail-closed default-deny fall-through", res.PolicyName)
	}
	if !res.DefaultUsed || res.Action != config.PolicyDeny {
		t.Fatalf("want fail-closed default deny, got Matched=%v DefaultUsed=%v Action=%v",
			res.Matched, res.DefaultUsed, res.Action)
	}
}
