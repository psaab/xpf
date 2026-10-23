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
	cfg := compileSetLines(t, []string{
		"set security flow tcp-session time-wait-state session-ageout",
		"set security flow tcp-session time-wait-state apply-to-half-closed-state",
		"set security flow tcp-session time-wait-state session-timeout 99",
	})
	ts := cfg.Security.Flow.TCPSession
	if ts == nil || !ts.TimeWaitStateSessionAgeout || !ts.TimeWaitStateApplyToHalfClosed || ts.TimeWaitStateSessionTimeout != 99 {
		t.Fatalf("time-wait-state flags not compiled: %+v", ts)
	}
}
