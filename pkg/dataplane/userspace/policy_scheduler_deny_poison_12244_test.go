package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12244: an undefined-scheduler DENY/REJECT on the tolerant path must POISON
// (previous-good retained; the content-rejection mirror names policy +
// scheduler) instead of installing inactive — an inactive rule is a Miss on
// every packet, so a scheduled deny silently never denies (fail-open under a
// subsequent permit/default-permit). A defined-but-off-window deny still
// loads inactive, and an undefined-scheduler PERMIT keeps the #11071
// warn-and-load-inactive posture (fail-closed for a permit).
func lenientSchedulerDenyConfig12244(t *testing.T, schedDef, action, schedName string) *config.Config {
	t.Helper()
	text := schedDef + `security {
    zones { security-zone trust { interfaces { ge-0/0/0.0; } } security-zone untrust { interfaces { ge-0/0/1.0; } } }
    policies {
        from-zone trust to-zone untrust {
            policy probe {
                match { source-address any; destination-address any; application any; }
                then { ` + action + `; }
                scheduler-name ` + schedName + `;
            }
        }
    }
}`
	p := config.NewParser(text)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	return cfg
}

func probePolicy12244(t *testing.T, cfg *config.Config) *config.Policy {
	t.Helper()
	for _, zpp := range cfg.Security.Policies {
		for _, pol := range zpp.Policies {
			if pol.Name == "probe" {
				return pol
			}
		}
	}
	t.Fatal("probe policy not found")
	return nil
}

func snapshotHasAppSentinel12244(t *testing.T, snap *ConfigSnapshot) bool {
	t.Helper()
	if len(snap.Policies) != 1 {
		t.Fatalf("len(Policies)=%d, want 1", len(snap.Policies))
	}
	for _, term := range snap.Policies[0].ApplicationTerms {
		if term.Protocol == unsupportedApplicationSentinel || term.Name == unsupportedApplicationSentinel {
			return true
		}
	}
	return false
}

func TestUndefinedSchedulerDenyRejectPoisons12244(t *testing.T) {
	for _, action := range []string{"deny", "reject"} {
		t.Run(action, func(t *testing.T) {
			cfg := lenientSchedulerDenyConfig12244(t, "", action, "missing-sched")
			if pol := probePolicy12244(t, cfg); !pol.LenientContentDropped {
				t.Fatalf("undefined-scheduler %s was NOT poisoned (LenientContentDropped=false) — it installs inactive and silently never denies (#12244)", action)
			}
			snap, err := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 0, map[string]bool{"workhours": true}, nil, nil)
			if err != nil {
				t.Fatalf("buildSnapshot: %v", err)
			}
			if !snapshotHasAppSentinel12244(t, snap) {
				t.Fatalf("undefined-scheduler %s rule lacks the __unsupported__ poison: %+v", action, snap.Policies[0].ApplicationTerms)
			}
			if len(snap.Capabilities.PolicyContentRejected) == 0 {
				t.Fatalf("PolicyContentRejected empty for undefined-scheduler %s; want the fail-closed diagnostic", action)
			}
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if len(reasons) == 0 {
				t.Fatalf("content-rejection mirror empty for undefined-scheduler %s", action)
			}
			joined := strings.Join(reasons, " | ")
			if !strings.Contains(joined, "probe") || !strings.Contains(joined, "missing-sched") {
				t.Fatalf("mirror must name policy + scheduler, got %q", reasons)
			}
		})
	}
}

func TestUndefinedSchedulerPermitStaysInactive11071(t *testing.T) {
	cfg := lenientSchedulerDenyConfig12244(t, "", "permit", "missing-sched")
	if pol := probePolicy12244(t, cfg); pol.LenientContentDropped {
		t.Fatal("undefined-scheduler permit must NOT be poisoned (#11071 warn-and-inactive posture)")
	}
	rules, err := buildPolicySnapshotsWithSchedulerState(cfg, map[string]bool{"workhours": true})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(rules) != 1 || !rules[0].Inactive {
		t.Fatalf("undefined-scheduler permit must load inactive, got %+v", rules)
	}
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
		t.Fatalf("undefined-scheduler permit must not refuse the snapshot: %q", reasons)
	}
}

func TestDefinedOffWindowDenyStaysInactive12244(t *testing.T) {
	const schedDef = `schedulers { scheduler workhours { daily { start-time 09:00:00; stop-time 17:00:00; } } }`
	cfg := lenientSchedulerDenyConfig12244(t, schedDef, "deny", "workhours")
	if pol := probePolicy12244(t, cfg); pol.LenientContentDropped {
		t.Fatal("defined-scheduler deny must NOT be poisoned")
	}
	rules, err := buildPolicySnapshotsWithSchedulerState(cfg, map[string]bool{"workhours": false})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(rules) != 1 || !rules[0].Inactive {
		t.Fatalf("defined-but-off-window deny must load inactive, got %+v", rules)
	}
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
		t.Fatalf("defined-but-off-window deny must not refuse the snapshot: %q", reasons)
	}
}

// F1 (Opus R2): the GlobalPolicies loop of
// poisonUndefinedSchedulerDenyPolicies12244 must be exercised — a
// zone-pair-only walker would silently fail open for every global
// undefined-scheduler deny/reject. RED-on-revert: deleting the GlobalPolicies
// loop flips every cell below from poisoned to inactive-with-clean-mirror.
func TestUndefinedSchedulerGlobalDenyRejectPoisons12244(t *testing.T) {
	for _, tc := range []struct {
		name      string
		action    string
		scope     string
		wantScope string
	}{
		{name: "unscoped-deny", action: "deny", scope: "", wantScope: "global/gprobe"},
		{name: "scoped-reject", action: "reject", scope: "from-zone trust; to-zone untrust;", wantScope: "global(trust->untrust)/gprobe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := `security {
    zones { security-zone trust { interfaces { ge-0/0/0.0; } } security-zone untrust { interfaces { ge-0/0/1.0; } } }
    policies {
        global {
            policy gprobe {
                match { source-address any; destination-address any; application any; ` + tc.scope + ` }
                then { ` + tc.action + `; }
                scheduler-name missing-gsched;
            }
        }
    }
}`
			p := config.NewParser(text)
			tree, errs := p.Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			cfg, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			if len(cfg.Security.GlobalPolicies) != 1 {
				t.Fatalf("GlobalPolicies=%d, want 1", len(cfg.Security.GlobalPolicies))
			}
			if pol := cfg.Security.GlobalPolicies[0]; !pol.LenientContentDropped {
				t.Fatalf("undefined-scheduler global %s was NOT poisoned (LenientContentDropped=false) — it installs inactive and silently never denies (#12244)", tc.action)
			}
			snap, err := buildSnapshotWithSchedulerState(cfg, config.UserspaceConfig{}, 1, 0, nil, nil, nil)
			if err != nil {
				t.Fatalf("buildSnapshot: %v", err)
			}
			if !snapshotHasAppSentinel12244(t, snap) {
				t.Fatalf("undefined-scheduler global %s rule lacks the __unsupported__ poison: %+v", tc.action, snap.Policies[0].ApplicationTerms)
			}
			if len(snap.Capabilities.PolicyContentRejected) == 0 {
				t.Fatalf("PolicyContentRejected empty for undefined-scheduler global %s; want the fail-closed diagnostic", tc.action)
			}
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if len(reasons) == 0 {
				t.Fatalf("content-rejection mirror empty for undefined-scheduler global %s", tc.action)
			}
			joined := strings.Join(reasons, " | ")
			if !strings.Contains(joined, tc.wantScope) || !strings.Contains(joined, "missing-gsched") {
				t.Fatalf("mirror must name scope-qualified policy %q + scheduler, got %q", tc.wantScope, reasons)
			}
			if _, err := config.CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "missing-gsched") {
				t.Fatalf("strict commit must reject the undefined global scheduler, got: %v", err)
			}
		})
	}
}

// F2 (Opus R2): the defined-scheduler guard inside `mark` must be exercised
// while the poison function actually RUNS — an undefined-scheduler PERMIT in
// the same config trips validatePolicySchedulerReferencesStrict so
// poisonUndefinedSchedulerDenyPolicies12244 runs, and the defined-scheduler
// DENY must still come through clean (no poison, snapshot accepted).
// RED-on-revert: deleting the `cfg.Schedulers[...]; ok → return` guard
// poisons b-deny-def and refuses the snapshot (over-poisoning).
func TestDefinedSchedulerDenyWithUndefinedPermitStaysClean12244(t *testing.T) {
	text := `schedulers { scheduler workhours { daily { start-time 09:00:00; stop-time 17:00:00; } } }` + `security {
    zones { security-zone trust { interfaces { ge-0/0/0.0; } } security-zone untrust { interfaces { ge-0/0/1.0; } } }
    policies {
        from-zone trust to-zone untrust {
            policy a-permit-undef {
                match { source-address any; destination-address any; application any; }
                then { permit; }
                scheduler-name missing-sched;
            }
            policy b-deny-def {
                match { source-address any; destination-address any; application any; }
                then { deny; }
                scheduler-name workhours;
            }
        }
    }
}`
	p := config.NewParser(text)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	byName := map[string]*config.Policy{}
	for _, zpp := range cfg.Security.Policies {
		for _, pol := range zpp.Policies {
			byName[pol.Name] = pol
		}
	}
	undef, ok := byName["a-permit-undef"]
	if !ok {
		t.Fatal("a-permit-undef not found")
	}
	if undef.LenientContentDropped {
		t.Fatal("undefined-scheduler permit must NOT be poisoned (#11071 warn-and-inactive posture)")
	}
	def, ok := byName["b-deny-def"]
	if !ok {
		t.Fatal("b-deny-def not found")
	}
	if def.LenientContentDropped {
		t.Fatal("defined-scheduler deny must NOT be poisoned even while the poison function runs (guard over-poisoning)")
	}
	rules, err := buildPolicySnapshotsWithSchedulerState(cfg, map[string]bool{"workhours": true})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("len(rules)=%d, want 2", len(rules))
	}
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
		t.Fatalf("defined-scheduler deny alongside an undefined-scheduler permit must not refuse the snapshot: %q", reasons)
	}
}

// F3 (Opus R2): only DENY/REJECT scheduler poison is a reported scheduler
// cause. A separately poisoned PERMIT with an undefined scheduler can still
// arise from another dropped constraint; do not attribute that rejection to
// the scheduler.
func TestUndefinedSchedulerPermitOtherPoisonDoesNotNameScheduler12244(t *testing.T) {
	cfg := &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{},
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust":   {Name: "trust"},
				"untrust": {Name: "untrust"},
			},
			Policies: []*config.ZonePairPolicies{{
				FromZone: "trust",
				ToZone:   "untrust",
				Policies: []*config.Policy{{
					Name:                  "bad-destination",
					Match:                 config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"missing-destination"}, Applications: []string{"any"}},
					Action:                config.PolicyPermit,
					SchedulerName:         "missing-sched",
					LenientContentDropped: true,
				}},
			}},
		},
	}
	reasons := PolicyContentRejectionReasons(cfg, nil)
	if len(reasons) != 1 {
		t.Fatalf("rejection reasons=%q, want one policy reason", reasons)
	}
	if !strings.Contains(reasons[0], `destination-address "missing-destination"`) {
		t.Fatalf("rejection reason does not name the dropped destination: %q", reasons[0])
	}
	if strings.Contains(reasons[0], "scheduler") || strings.Contains(reasons[0], "missing-sched") {
		t.Fatalf("undefined scheduler on a separately poisoned permit must not be reported as the cause: %q", reasons[0])
	}
}
