package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5804: `show security flow` must not render gre-performance-acceleration as a
// bare "enabled". The flag reaches ForwardingState.gre_acceleration and no
// packet path reads it, so an unqualified "enabled" tells an operator a
// tunnel-aware session identity is in force when GRE sessions are still keyed
// on the bare 5-tuple and two tunnels between the same outer endpoints share
// one session.
//
// This is the surface an operator reads AFTER committing, so the commit-time
// advisory does not cover it: a box configured by someone else, or before an
// upgrade, shows this text and nothing else.
//
// RED-on-revert: restore `"  GRE acceleration:     enabled\n"` and both
// assertions fail.
func TestShowFlowGREAccelerationIsQualified_5804(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Flow.GREPerformanceAcceleration = true

	var buf strings.Builder
	(&Server{}).showFlowTimeouts(cfg, &buf)
	got := buf.String()

	line := ""
	for _, l := range strings.Split(got, "\n") {
		if strings.Contains(l, "gre-performance-acceleration") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatalf("no GRE acceleration line rendered at all; the operator surface vanished.\n%s", got)
	}
	// #15649/#7188: stale #5804 "remain 5-tuple keyed" wording replaced by
	// the shared SSOT line (partial; discriminator-keyed locally, not HA).
	if strings.Contains(line, "#5804") || strings.Contains(line, "remain 5-tuple") || strings.Contains(line, "accepted-only") {
		t.Errorf("stale #5804 GRE wording: %q", line)
	}
	if !strings.Contains(line, "#7188") || !strings.Contains(line, "RFC 2890") {
		t.Errorf("GRE line does not carry #7188 partial wording: %q", line)
	}
	if strings.TrimSpace(line) == "gre-performance-acceleration: enabled" {
		t.Errorf("bare enabled: %q", line)
	}

	// Negative control: an unset knob renders no line.
	var off strings.Builder
	(&Server{}).showFlowTimeouts(&config.Config{}, &off)
	if strings.Contains(off.String(), "gre-performance-acceleration") {
		t.Errorf("a config that never sets the knob must render no GRE line:\n%s", off.String())
	}
}
