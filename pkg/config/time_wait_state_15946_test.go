package config

import (
	"strings"
	"testing"
)

// #15946 H14-02: RenderFlowTimeouts must show the effective TIME_WAIT
// (time-wait-state session-timeout override), matching buildFlowSnapshot.
func TestRenderFlowTimeoutsTimeWaitOverride15946(t *testing.T) {
	cfg := &Config{}
	cfg.Security.Flow.TCPSession = &TCPSessionConfig{TimeWaitTimeout: 30, TimeWaitStateSessionTimeout: 99}
	var sb strings.Builder
	RenderFlowTimeouts(&sb, cfg)
	if !strings.Contains(sb.String(), "99s") {
		t.Fatalf("render must show override 99s:\n%s", sb.String())
	}
	cfg2 := &Config{}
	cfg2.Security.Flow.TCPSession = &TCPSessionConfig{TimeWaitTimeout: 30}
	var sb2 strings.Builder
	RenderFlowTimeouts(&sb2, cfg2)
	if !strings.Contains(sb2.String(), "30s") {
		t.Fatalf("render must show base 30s:\n%s", sb2.String())
	}
}

func TestCompileTimeWaitStateFlags15946(t *testing.T) {
	// #16485: session-ageout + session-timeout is rejected at strict
	// commit, so the combined-flags compile is exercised on the
	// tolerant path (which keeps both flags; ageout wins at runtime).
	tree := buildTree(t, []string{
		"set security flow tcp-session time-wait-state session-ageout",
		"set security flow tcp-session time-wait-state apply-to-half-closed-state",
		"set security flow tcp-session time-wait-state session-timeout 99",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	ts := cfg.Security.Flow.TCPSession
	if ts == nil || !ts.TimeWaitStateSessionAgeout || !ts.TimeWaitStateApplyToHalfClosed || ts.TimeWaitStateSessionTimeout != 99 {
		t.Fatalf("time-wait-state flags not compiled: %+v", ts)
	}
}

// #16485: RenderFlowTimeouts must derive the closing and TIME_WAIT rows
// from the same selector as the Rust tcp_close_window_ns_with_app, so
// the four probe cases render the dataplane-effective window while the
// 40s and 90s controls are unchanged.
//
// FAIL-ON-REVERT: restoring the pre-#16485 rows (closing-timeout /
// effectiveTimeWait only) turns the ageout and half-closed cases RED.
func TestRenderFlowTimeoutsTimeWaitState16485(t *testing.T) {
	row := func(out, label string) string {
		t.Helper()
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, label) {
				return line
			}
		}
		t.Fatalf("no %q row in:\n%s", label, out)
		return ""
	}
	render := func(ts *TCPSessionConfig) string {
		t.Helper()
		cfg := &Config{}
		cfg.Security.Flow.TCPSession = ts
		var sb strings.Builder
		RenderFlowTimeouts(&sb, cfg)
		return sb.String()
	}
	for _, tc := range []struct {
		name string
		ts   *TCPSessionConfig
		want map[string]string
	}{
		{
			name: "control time-wait-timeout 40 unchanged",
			ts:   &TCPSessionConfig{TimeWaitTimeout: 40},
			want: map[string]string{"TCP time-wait timeout:": "40s"},
		},
		{
			name: "control session-timeout 90 unchanged",
			ts:   &TCPSessionConfig{TimeWaitTimeout: 40, TimeWaitStateSessionTimeout: 90},
			want: map[string]string{"TCP time-wait timeout:": "90s"},
		},
		{
			name: "ageout renders established window not 40s",
			ts:   &TCPSessionConfig{TimeWaitTimeout: 40, TimeWaitStateSessionAgeout: true},
			want: map[string]string{
				"TCP time-wait timeout:": "1800s (default) (service/established timeout (session-ageout))",
			},
		},
		{
			name: "ageout renders configured established window",
			ts:   &TCPSessionConfig{EstablishedTimeout: 600, TimeWaitTimeout: 40, TimeWaitStateSessionAgeout: true},
			want: map[string]string{
				"TCP time-wait timeout:": "600s (service/established timeout (session-ageout))",
			},
		},
		{
			name: "half-closed closing renders time-wait window",
			ts:   &TCPSessionConfig{ClosingTimeout: 10, TimeWaitStateSessionTimeout: 120, TimeWaitStateApplyToHalfClosed: true},
			want: map[string]string{
				"TCP closing timeout:":   "120s (time-wait window (apply-to-half-closed-state))",
				"TCP time-wait timeout:": "120s",
			},
		},
		{
			name: "half-closed closing renders default time-wait window",
			ts:   &TCPSessionConfig{ClosingTimeout: 10, TimeWaitStateApplyToHalfClosed: true},
			want: map[string]string{
				"TCP closing timeout:": "30s (default) (time-wait window (apply-to-half-closed-state))",
			},
		},
		{
			name: "ageout wins over session-timeout on lenient render",
			ts:   &TCPSessionConfig{TimeWaitStateSessionTimeout: 120, TimeWaitStateSessionAgeout: true},
			want: map[string]string{
				"TCP time-wait timeout:": "1800s (default) (service/established timeout (session-ageout))",
			},
		},
		{
			name: "ageout plus half-closed closing renders established window",
			ts:   &TCPSessionConfig{ClosingTimeout: 10, TimeWaitStateSessionTimeout: 120, TimeWaitStateSessionAgeout: true, TimeWaitStateApplyToHalfClosed: true},
			want: map[string]string{
				"TCP closing timeout:":   "1800s (default) (service/established timeout (session-ageout))",
				"TCP time-wait timeout:": "1800s (default) (service/established timeout (session-ageout))",
			},
		},
		{
			name: "no flags closing control unchanged",
			ts:   &TCPSessionConfig{ClosingTimeout: 10, TimeWaitTimeout: 40},
			want: map[string]string{
				"TCP closing timeout:":   "10s",
				"TCP time-wait timeout:": "40s",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := render(tc.ts)
			for label, want := range tc.want {
				if got := row(out, label); !strings.Contains(got, want) {
					t.Fatalf("%s row = %q, want substring %q\nfull output:\n%s", label, got, want, out)
				}
			}
		})
	}
}

// #16485: `session-ageout` together with `session-timeout` is rejected
// at strict commit and warned (not bricked) on the tolerant path.
//
// FAIL-ON-REVERT: delete validateTimeWaitStateAgeoutStrict (or its
// dispatch in runUniformGatesClusterZone) and the strict cells below
// go GREEN on the forbidden combination.
func TestTimeWaitStateAgeoutSessionTimeoutExclusion16485(t *testing.T) {
	cmds := []string{
		"set security flow tcp-session time-wait-state session-ageout",
		"set security flow tcp-session time-wait-state session-timeout 120",
	}
	if _, err := CompileConfig(buildTree(t, cmds)); err == nil ||
		!strings.Contains(err.Error(), "session-ageout") ||
		!strings.Contains(err.Error(), "session-timeout") {
		t.Fatalf("strict commit must reject session-ageout + session-timeout, got err=%v", err)
	}

	cfg, err := CompileConfigLenient(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("lenient load must not brick on session-ageout + session-timeout: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "session-ageout") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient load must warn on session-ageout + session-timeout, warnings=%v", cfg.Warnings)
	}
	// The leniently loaded combination still compiles both flags, and
	// the renderer reports the dataplane's ageout-wins window.
	ts := cfg.Security.Flow.TCPSession
	if ts == nil || !ts.TimeWaitStateSessionAgeout || ts.TimeWaitStateSessionTimeout != 120 {
		t.Fatalf("lenient compile lost flags: %+v", ts)
	}
	var sb strings.Builder
	RenderFlowTimeouts(&sb, cfg)
	if !strings.Contains(sb.String(), "1800s (default) (service/established timeout (session-ageout))") {
		t.Fatalf("lenient render must show ageout window:\n%s", sb.String())
	}

	// Controls: each leaf alone still commits.
	for _, name := range []string{"ageout alone", "session-timeout alone"} {
		var lines []string
		if name == "ageout alone" {
			lines = []string{"set security flow tcp-session time-wait-state session-ageout"}
		} else {
			lines = []string{"set security flow tcp-session time-wait-state session-timeout 120"}
		}
		if _, err := CompileConfig(buildTree(t, lines)); err != nil {
			t.Fatalf("%s must still compile: %v", name, err)
		}
	}

	// The lenient flag must be registered or the tolerant path bricks.
	if !lenientCompileOpts().lenientTimeWaitStateAgeout16485 {
		t.Fatal("lenientTimeWaitStateAgeout16485 is NOT registered in lenientCompileOpts() — a persisted or peer-synced config carrying session-ageout + session-timeout would fail to boot (#1960)")
	}
}
