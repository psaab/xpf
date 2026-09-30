package config_test

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileStrictTree11305(t *testing.T, tree *config.ConfigTree) *config.Config {
	t.Helper()
	if err := config.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func compileHierStrict11305(t *testing.T, input string) *config.Config {
	t.Helper()
	tree, errs := config.NewParser(input).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return compileStrictTree11305(t, tree)
}

func compileFlatStrict11305(t *testing.T, commands ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, command := range commands {
		path, err := config.ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", command, err)
		}
	}
	return compileStrictTree11305(t, tree)
}

const junosSchedulerPolicyConfig11305 = `schedulers {
    scheduler permit-window {
        daily {
            start-time 08:30;
            stop-time 09:00;
        }
    }
    scheduler deny-window {
        start-date 2026-10-01.08:30;
        stop-date 2026-10-01.09:00;
    }
}
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy scheduled-permit {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { permit; }
                scheduler-name permit-window;
            }
            policy scheduled-deny {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
                scheduler-name deny-window;
            }
        }
    }
}`

func policyByName11305(t *testing.T, cfg *config.Config, name string) *config.Policy {
	t.Helper()
	for _, zonePair := range cfg.Security.Policies {
		for _, policy := range zonePair.Policies {
			if policy.Name == name {
				return policy
			}
		}
	}
	t.Fatalf("policy %q was not compiled", name)
	return nil
}

func TestCompileJunosNativeSchedulerFormatsAndPolicyBindings11305(t *testing.T) {
	cfg := compileHierStrict11305(t, junosSchedulerPolicyConfig11305)

	permitWindow := cfg.Schedulers["permit-window"]
	if permitWindow == nil || !permitWindow.Daily ||
		permitWindow.StartTime != "08:30" || permitWindow.StopTime != "09:00" {
		t.Fatalf("HH:MM daily window did not compile: %+v", permitWindow)
	}
	denyWindow := cfg.Schedulers["deny-window"]
	if denyWindow == nil || denyWindow.StartDate != "2026-10-01.08:30" ||
		denyWindow.StopDate != "2026-10-01.09:00" {
		t.Fatalf("Junos date-time window did not compile: %+v", denyWindow)
	}

	for _, tc := range []struct {
		name      string
		action    config.PolicyAction
		scheduler string
	}{
		{"scheduled-permit", config.PolicyPermit, "permit-window"},
		{"scheduled-deny", config.PolicyDeny, "deny-window"},
	} {
		policy := policyByName11305(t, cfg, tc.name)
		if policy.Action != tc.action || policy.SchedulerName != tc.scheduler {
			t.Errorf("policy %q = action %v, scheduler %q; want action %v, scheduler %q",
				tc.name, policy.Action, policy.SchedulerName, tc.action, tc.scheduler)
		}
	}
}

func TestCompileJunosNativeSchedulerFormatsFlatSet11305(t *testing.T) {
	cfg := compileFlatStrict11305(t,
		"set schedulers scheduler permit-window daily start-time 08:30",
		"set schedulers scheduler permit-window daily stop-time 09:00",
		"set schedulers scheduler deny-window start-date 2026-10-01.08:30",
		"set schedulers scheduler deny-window stop-date 2026-10-01.09:00",
	)
	permitWindow := cfg.Schedulers["permit-window"]
	if permitWindow == nil || permitWindow.StartTime != "08:30" || permitWindow.StopTime != "09:00" {
		t.Fatalf("flat-set HH:MM window did not compile: %+v", permitWindow)
	}
	denyWindow := cfg.Schedulers["deny-window"]
	if denyWindow == nil || denyWindow.StartDate != "2026-10-01.08:30" ||
		denyWindow.StopDate != "2026-10-01.09:00" {
		t.Fatalf("flat-set date-time window did not compile: %+v", denyWindow)
	}
}

func TestMalformedJunosSchedulerFormatsStillRejectStrictly11305(t *testing.T) {
	for _, value := range []struct {
		name  string
		leaf  string
		value string
	}{
		{"out-of-range time", "start-time", "24:00"},
		{"out-of-range date-time clock", "start-date", "2026-10-01.24:00"},
		{"out-of-range date-time date", "start-date", "2026-13-01.08:30"},
		{"date-time with unsupported seconds", "start-date", "2026-10-01.08:30:00"},
	} {
		t.Run(value.name, func(t *testing.T) {
			text := "schedulers { scheduler bad { " + value.leaf + " " + value.value + "; } }"
			tree, errs := config.NewParser(text).Parse()
			if len(errs) != 0 {
				t.Fatalf("parse fixture: %v", errs)
			}
			if err := config.SchemaValidate(tree, nil); err == nil {
				t.Fatalf("SchemaValidate accepted %s %q", value.leaf, value.value)
			}
		})
	}
}
