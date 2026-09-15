package userspace

// #9882 — a lone policer `then forwarding-class` compiled to `discard` and
// dropped the excess, contradicting Junos mark-and-forward and the #8445
// message's own "METERS ONLY" remedy text. These cells bind the dataplane half
// of the fix: the single-rate snapshot must NOT set DiscardExcess for the
// marking, and the three-color capability gate must keep forwarding armed for
// it (the #9503 pattern — refusing the marking here disarmed every binding).
import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// A lone single-rate `then forwarding-class` meters only: the snapshot leaves
// DiscardExcess false, so the helper's build_single_rate_policer_state selects
// the no-drop default. `then discard` still sets it.
func TestSingleRateForwardingClassMetersOnly9882(t *testing.T) {
	compile := func(t *testing.T, then string) *config.Config {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, line := range []string{
			"set firewall policer p1 if-exceeding bandwidth-limit 1m",
			"set firewall policer p1 if-exceeding burst-size-limit 15k",
			"set firewall policer p1 then " + then,
		} {
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
	discardExcess := func(t *testing.T, cfg *config.Config) bool {
		t.Helper()
		snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
		if err != nil {
			t.Fatalf("buildSnapshot: %v", err)
		}
		for _, p := range snap.Policers {
			if p.Name == "p1" {
				return p.DiscardExcess
			}
		}
		t.Fatalf("policer p1 missing from snapshot")
		return false
	}

	if got := discardExcess(t, compile(t, "forwarding-class af11")); got {
		t.Errorf("lone forwarding-class sets DiscardExcess — the policer drops " +
			"traffic the operator asked to be marked and forwarded (#9882)")
	}
	if got := discardExcess(t, compile(t, "discard")); !got {
		t.Errorf("then discard must still set DiscardExcess")
	}
}

// A color-blind three-color policer with `then forwarding-class` must not
// disarm forwarding — the #9503 loss-priority admission, second marking
// spelling. Follows the config to the FINAL armed decision like the #9503
// cell; reuses its harness.
func TestThreeColorForwardingClassKeepsForwardingArmed9882(t *testing.T) {
	for _, c := range []struct {
		name  string
		lines []string
		armed bool
	}{
		{"then forwarding-class, color-blind", []string{"set firewall three-color-policer p1 then forwarding-class af11"}, true},
		{"then loss-priority control", []string{"set firewall three-color-policer p1 then loss-priority high"}, true},
		{"then discard control", []string{"set firewall three-color-policer p1 then discard"}, true},
		// Colour-aware stays explicitly guarded, with either marking.
		{"color-aware then forwarding-class", []string{
			"set firewall three-color-policer p1 single-rate color-aware",
			"set firewall three-color-policer p1 then forwarding-class af11"}, false},
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

// The drift guard for the new arm: the forwarding-class marking is admitted
// (with a class value — the bare keyword is not a marking), and an action
// neither side knows still refuses, so the Go gate and the helper's shape
// check agree.
func TestThreeColorForwardingClassShapeGuard9882(t *testing.T) {
	for action, want := range map[string]bool{
		"forwarding-class af11": true, "forwarding-class be": true,
		"forwarding-class": false, "frobnicate": false,
	} {
		if got := threeColorThenActionSupported(action); got != want {
			t.Errorf("threeColorThenActionSupported(%q) = %v, want %v", action, got, want)
		}
	}
}
