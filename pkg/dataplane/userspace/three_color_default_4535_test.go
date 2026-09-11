// #4535: a `three-color-policer` with NEITHER `color-blind` nor `color-aware`
// configured must NOT disarm the whole dataplane. The Go compiler now defaults
// the unspecified case to COLOR-BLIND (Junos parity), so the compiled snapshot
// carries color_blind=true and deriveUserspaceCapabilities keeps
// ForwardingSupported=true — the color-blind srTCM runtime enforces the policer
// instead of refusing to forward. An explicit color-aware policer is unchanged:
// it still fails closed (userspace only supports color-blind mode).
package userspace

import (
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileThreeColorCfg4535(t *testing.T, colorLine string) *config.Config {
	t.Helper()
	lines := []string{
		"set firewall three-color-policer p1 single-rate committed-information-rate 1m",
		"set firewall three-color-policer p1 single-rate committed-burst-size 15k",
		"set firewall three-color-policer p1 single-rate excess-burst-size 30k",
		"set firewall three-color-policer p1 then discard",
	}
	if colorLine != "" {
		lines = append(lines, colorLine)
	}
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// A three-color policer with no color statement keeps forwarding armed. RED on
// revert: the compiler leaves ColorBlind=false → userspaceSupportsThreeColorPolicers
// returns false → ForwardingSupported=false with the disarm reason.
func TestThreeColorPolicerUnspecifiedKeepsForwarding4535(t *testing.T) {
	cfg := compileThreeColorCfg4535(t, "")
	caps := deriveUserspaceCapabilities(cfg)
	if !caps.ForwardingSupported {
		t.Fatalf("ForwardingSupported = false for unspecified-color three-color policer; want true (color-blind default). Reasons: %+v",
			caps.UnsupportedReasons)
	}
	if slices.Contains(caps.UnsupportedReasons, "userspace three-color policers require color-blind mode and a supported then action") {
		t.Fatalf("unspecified-color policer must not carry the three-color disarm reason: %+v", caps.UnsupportedReasons)
	}
}

// An explicit color-aware policer is the existing documented limitation: it
// still disarms forwarding (userspace supports color-blind mode only).
func TestThreeColorPolicerColorAwareStillDisarms4535(t *testing.T) {
	cfg := compileThreeColorCfg4535(t, "set firewall three-color-policer p1 single-rate color-aware")
	caps := deriveUserspaceCapabilities(cfg)
	if caps.ForwardingSupported {
		t.Fatal("ForwardingSupported = true for explicit color-aware policer; want fail-closed disarm")
	}
	if !slices.Contains(caps.UnsupportedReasons, "userspace three-color policers require color-blind mode and a supported then action") {
		t.Fatalf("color-aware policer must carry the three-color disarm reason, got: %+v", caps.UnsupportedReasons)
	}
}
