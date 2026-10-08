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
