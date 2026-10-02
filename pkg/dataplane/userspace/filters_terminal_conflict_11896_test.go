package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11896: #11893's lenient poison overwrites a conflicting term's Action with
// "discard", and this builder propagated term.Action directly — so the
// conflict installed a REAL DROP in the userspace dataplane instead of
// refusing via the no-brick marker flow. A conflicting term must set the
// FromUnrepresentable wire marker (the #9875 channel: the Rust filter
// compiler rejects the WHOLE snapshot and the reconcile preflight keeps the
// previous good filter state) while keeping the latent discard as the
// safe-direction value. Reverting the builder arm makes each assert FAIL.

// filterConflictTree11896 builds a one-term inet filter whose `then` carries
// the given terminating actions in order, plus a surviving `from` match.
func filterConflictTree11896(t *testing.T, actions ...string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := []string{"set firewall family inet filter f term t from protocol tcp"}
	for _, action := range actions {
		cmds = append(cmds, "set firewall family inet filter f term t then "+action)
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestFilterTerminalConflictSetsFromUnrepresentable11896 is the end-to-end
// guard: a leniently-loaded / peer-synced conflicting term must refuse the
// snapshot via the marker — neither a last-wins accept (the pre-#11507
// fail-open) nor a freshly installed drop (the #11893 over-correction) may
// reach the dataplane.
func TestFilterTerminalConflictSetsFromUnrepresentable11896(t *testing.T) {
	for _, tc := range []struct {
		name    string
		compile func(*config.ConfigTree) (*config.Config, error)
		actions []string
	}{
		{
			name:    "load",
			compile: config.CompileConfigLenient,
			actions: []string{"discard", "accept"},
		},
		{
			name: "peer sync",
			compile: func(tree *config.ConfigTree) (*config.Config, error) {
				return config.CompileConfigForNodeLenient(tree, 1)
			},
			actions: []string{"reject", "accept"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tc.compile(filterConflictTree11896(t, tc.actions...))
			if err != nil {
				t.Fatalf("tolerant compile must remain bootable (#1960 no-brick): %v", err)
			}
			foundWarning := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "firewall filter terminal-action conflict") {
					foundWarning = true
					break
				}
			}
			if !foundWarning {
				t.Fatalf("tolerant compile must warn about the conflict; warnings=%v", cfg.Warnings)
			}
			term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]
			if !term.FromUnrepresentable {
				t.Error("a conflicting lenient term must set FromUnrepresentable so the " +
					"snapshot is refused whole (prior-good retained, #11896)")
			}
			if term.Action != "discard" {
				t.Errorf("conflicting terminals %v snapshotted Action=%q; the latent "+
					"safe-direction discard must be retained", tc.actions, term.Action)
			}
			if len(term.Protocols) != 1 || term.Protocols[0] != "tcp" {
				t.Errorf("the surviving match must ride the wire alongside the marker, got %v", term.Protocols)
			}
		})
	}
}

// TestFilterTerminalConflictMarkerUnit11896 pins the builder mapping without
// the compiler: conflicting TerminalActions evidence sets the marker.
func TestFilterTerminalConflictMarkerUnit11896(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name:            "t",
			Action:          "discard",
			TerminalActions: []string{"accept", "discard"},
		}}},
	}
	if term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]; !term.FromUnrepresentable {
		t.Error("conflicting TerminalActions must set FromUnrepresentable (#11896)")
	}
}

// TestFilterTerminalConflictMarkerNegative11896 is the over-refusal guard: a
// single terminal and a repeated SAME terminal (a redundancy, not a conflict
// — #4375) must not set the marker.
func TestFilterTerminalConflictMarkerNegative11896(t *testing.T) {
	for _, tc := range []struct {
		name    string
		actions []string
	}{
		{name: "single terminal", actions: []string{"accept"}},
		{name: "repeated same terminal", actions: []string{"discard", "discard"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.CompileConfigLenient(filterConflictTree11896(t, tc.actions...))
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			if term := buildFirewallFilterSnapshots(cfg)[0].Terms[0]; term.FromUnrepresentable {
				t.Errorf("actions %v carry no conflict and must not set FromUnrepresentable", tc.actions)
			}
		})
	}
}
