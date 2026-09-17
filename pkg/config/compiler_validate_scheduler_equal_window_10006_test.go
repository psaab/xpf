package config_test

// #10006: start==stop MEANS always-active (the runtime wraparound branch is
// true for every clock time on equal bounds), and ValidateConfig must say so
// at commit: a WARNING naming the scheduler, stating the always-active
// semantic, and directing the operator to the matching explicit all-day form
// (`daily all-day` or `<weekday> all-day`).
// Normal windows, overnight wraparound (start>stop), half-specified windows,
// and explicit all-day/exclude windows must NOT warn. Invalid and
// whitespace-padded direct-config controls must also stay silent because the
// runtime parser fails closed on those raw values.
//
// RED-on-revert: dropping the equality check in ValidateConfig makes the
// want-warning cases below fire zero warnings and
// TestSchedulerEqualWindowWarns goes RED.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// schedulerEqualWindowWarnings returns the subset of ValidateConfig warnings
// that concern a start==stop always-active window.
func schedulerEqualWindowWarnings(cfg *config.Config) []string {
	var got []string
	for _, w := range config.ValidateConfig(cfg) {
		if strings.HasPrefix(w, "scheduler ") && strings.Contains(w, "start-time == stop-time") {
			got = append(got, w)
		}
	}
	return got
}

// directSchedulerConfig deliberately bypasses the strict schema gate so the
// warning helper can be tested with raw malformed/whitespace bounds. The
// commit path rejects those values before ValidateConfig; this fixture covers
// the helper's fail-closed defensive behavior on already-compiled state.
func directSchedulerConfig(s *config.SchedulerConfig) *config.Config {
	return &config.Config{Schedulers: map[string]*config.SchedulerConfig{s.Name: s}}
}

func TestSchedulerEqualWindowWarns(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.Config
		wantWarn  bool
		wantNamed string // scheduler name expected in the warning text
		wantForm  string // matching explicit always-active form
	}{
		{
			name: "daily equal window warns",
			cfg: compileHier(t, "schedulers {\n    scheduler eq {\n        daily {\n"+
				"            start-time 09:00:00;\n            stop-time 09:00:00;\n        }\n    }\n}"),
			wantWarn:  true,
			wantNamed: "eq",
			wantForm:  "daily all-day",
		},
		{
			name: "daily mixed-spelling equal window warns",
			cfg: compileHier(t, "schedulers {\n    scheduler mixed {\n        daily {\n"+
				"            start-time 9:00:00;\n            stop-time 09:00:00;\n        }\n    }\n}"),
			wantWarn:  true,
			wantNamed: "mixed",
			wantForm:  "daily all-day",
		},
		{
			name: "per-day equal window warns",
			cfg: compileHier(t, "schedulers {\n    scheduler eqday {\n        monday {\n"+
				"            start-time 14:00:00;\n            stop-time 14:00:00;\n        }\n    }\n}"),
			wantWarn:  true,
			wantNamed: "eqday",
			wantForm:  "monday all-day",
		},
		{
			name: "per-day overnight does not warn",
			cfg: compileHier(t, "schedulers {\n    scheduler daynight {\n        monday {\n"+
				"            start-time 22:00:00;\n            stop-time 06:00:00;\n        }\n    }\n}"),
			wantWarn: false,
		},
		{
			name: "equal window via flat set warns",
			cfg: compileFlat(t,
				"set schedulers scheduler flateq start-time 09:00:00",
				"set schedulers scheduler flateq stop-time 09:00:00"),
			wantWarn:  true,
			wantNamed: "flateq",
			wantForm:  "daily all-day",
		},
		{
			name: "normal daily window does not warn",
			cfg: compileHier(t, "schedulers {\n    scheduler biz {\n        daily {\n"+
				"            start-time 09:00:00;\n            stop-time 17:00:00;\n        }\n    }\n}"),
			wantWarn: false,
		},
		{
			name: "overnight wraparound does not warn",
			cfg: compileHier(t, "schedulers {\n    scheduler night {\n        daily {\n"+
				"            start-time 22:00:00;\n            stop-time 06:00:00;\n        }\n    }\n}"),
			wantWarn: false,
		},
		{
			name:     "daily all-day does not warn",
			cfg:      compileHier(t, "schedulers {\n    scheduler always {\n        daily all-day;\n    }\n}"),
			wantWarn: false,
		},
		{
			name: "per-day all-day plus equal bounds does not warn",
			cfg: compileHier(t, "schedulers {\n    scheduler dayallwithtimes {\n        monday {\n"+
				"            all-day;\n            start-time 09:00:00;\n            stop-time 09:00:00;\n        }\n    }\n}"),
			wantWarn: false,
		},
		{
			name: "daily all-day plus equal bounds does not warn",
			cfg: compileHier(t, "schedulers {\n    scheduler allwithtimes {\n        daily {\n"+
				"            all-day;\n            start-time 09:00:00;\n            stop-time 09:00:00;\n        }\n    }\n}"),
			wantWarn: false,
		},
		{
			name: "per-day exclude plus equal bounds does not warn",
			cfg: compileHier(t, "schedulers {\n    scheduler excluded-eq {\n        monday {\n"+
				"            exclude;\n            start-time 09:00:00;\n            stop-time 09:00:00;\n        }\n    }\n}"),
			wantWarn: false,
		},
		{
			name: "per-day half-specified window does not warn",
			cfg: compileHier(t, "schedulers {\n    scheduler dayhalf {\n        monday {\n"+
				"            start-time 09:00:00;\n        }\n    }\n}"),
			wantWarn: false,
		},
		{
			name: "half-specified window does not warn",
			cfg: compileHier(t, "schedulers {\n    scheduler half {\n        daily {\n"+
				"            start-time 09:00:00;\n        }\n    }\n}"),
			wantWarn: false,
		},
		{
			name: "per-day exclude does not warn",
			cfg: compileHier(t, "schedulers {\n    scheduler hols {\n        friday {\n"+
				"            exclude;\n        }\n    }\n}"),
			wantWarn: false,
		},
		{
			name: "multi-equal-arm warning chooses sorted arm",
			cfg: compileHier(t, "schedulers {\n    scheduler multi {\n        wednesday {\n"+
				"            start-time 14:00:00;\n            stop-time 14:00:00;\n        }\n        monday {\n            start-time 11:00:00;\n            stop-time 11:00:00;\n        }\n    }\n}"),
			wantWarn:  true,
			wantNamed: "multi",
			wantForm:  "monday all-day",
		},
		{
			name: "invalid equal bounds stay silent",
			cfg: directSchedulerConfig(&config.SchedulerConfig{
				Name:      "invalid-eq",
				StartTime: "not-a-time",
				StopTime:  "not-a-time",
			}),
			wantWarn: false,
		},
		{
			name: "whitespace daily bounds stay silent",
			cfg: directSchedulerConfig(&config.SchedulerConfig{
				Name:      "space-eq",
				StartTime: " 09:00:00",
				StopTime:  " 09:00:00",
			}),
			wantWarn: false,
		},
		{
			name: "whitespace per-day bounds stay silent",
			cfg: directSchedulerConfig(&config.SchedulerConfig{
				Name: "space-day-eq",
				Days: map[string]*config.SchedulerDayWindow{
					"monday": {
						StartTime: "09:00:00 ",
						StopTime:  "09:00:00 ",
					},
				},
			}),
			wantWarn: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := schedulerEqualWindowWarnings(tc.cfg)
			if tc.wantWarn {
				if len(got) == 0 {
					t.Fatalf("expected a start==stop warning, got none")
				}
				joined := strings.Join(got, "\n")
				if !strings.Contains(joined, "\""+tc.wantNamed+"\"") {
					t.Errorf("warning does not name scheduler %q: %q", tc.wantNamed, joined)
				}
				if tc.wantForm != "" && !strings.Contains(joined, "`"+tc.wantForm+"`") {
					t.Errorf("warning does not direct the operator to %q: %q", tc.wantForm, joined)
				}
				if !strings.Contains(joined, "always-active") {
					t.Errorf("warning does not state the always-active semantic: %q", joined)
				}
				if !strings.Contains(joined, "time-of-day arm always-active") {
					t.Errorf("warning does not scope always-active behavior to the time-of-day arm: %q", joined)
				}
				if !strings.Contains(joined, "all-day") {
					t.Errorf("warning does not mention the explicit all-day form: %q", joined)
				}
			} else if len(got) != 0 {
				t.Errorf("unexpected start==stop warning(s): %q", got)
			}
		})
	}
}
