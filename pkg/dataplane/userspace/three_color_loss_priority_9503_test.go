package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9503: a color-blind three-color policer with `then loss-priority` must not
// disarm forwarding. The cell follows the config to the FINAL armed decision:
// compile, build the snapshot whose capabilities the helper echoes back into
// lastStatus, then desiredForwardingArmedLocked. The capability alone is one
// hop short of the consequence.
func compileThreeColor9503(t *testing.T, lines ...string) *config.Config {
	t.Helper()
	all := append([]string{
		"set firewall three-color-policer p1 single-rate committed-information-rate 1m",
		"set firewall three-color-policer p1 single-rate committed-burst-size 15k",
		"set firewall three-color-policer p1 single-rate excess-burst-size 30k",
	}, lines...)
	tree := &config.ConfigTree{}
	for _, line := range all {
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

func armedFor9503(t *testing.T, cfg *config.Config) bool {
	t.Helper()
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	m := &Manager{}
	m.lastStatus.Capabilities = snap.Capabilities
	return m.desiredForwardingArmedLocked()
}

func TestThreeColorLossPriorityKeepsForwardingArmed9503(t *testing.T) {
	for _, c := range []struct {
		name  string
		lines []string
		armed bool
	}{
		{"then loss-priority high, color-blind", []string{"set firewall three-color-policer p1 then loss-priority high"}, true},
		{"then discard control", []string{"set firewall three-color-policer p1 then discard"}, true},
		// Colour-aware stays explicitly guarded, with either action.
		{"color-aware then loss-priority", []string{
			"set firewall three-color-policer p1 single-rate color-aware",
			"set firewall three-color-policer p1 then loss-priority high"}, false},
		{"color-aware then discard", []string{
			"set firewall three-color-policer p1 single-rate color-aware",
			"set firewall three-color-policer p1 then discard"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := compileThreeColor9503(t, c.lines...)
			caps := deriveUserspaceCapabilities(cfg)
			if caps.ForwardingSupported != c.armed {
				t.Fatalf("ForwardingSupported = %v, want %v; reasons %v", caps.ForwardingSupported, c.armed, caps.UnsupportedReasons)
			}
			if got := armedFor9503(t, cfg); got != c.armed {
				t.Fatalf("final armed state = %v, want %v", got, c.armed)
			}
		})
	}
}

// The drift guard: an action neither side knows still refuses, so the Go gate
// and the helper's shape check agree.
func TestThreeColorUnknownActionStillRefuses9503(t *testing.T) {
	for action, want := range map[string]bool{
		"": true, "discard": true, "loss-priority high": true, "loss-priority low": true,
		"frobnicate": false, "loss-priority": false,
	} {
		if got := threeColorThenActionSupported(action); got != want {
			t.Errorf("threeColorThenActionSupported(%q) = %v, want %v", action, got, want)
		}
	}
}
