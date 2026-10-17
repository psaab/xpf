package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8445 — a policer `then` carrying BOTH `discard` and a marking action keeps
// only the last one, and with `discard` written first the compiled policer
// METERS AND DROPS NOTHING. The rate limit the operator authored is entirely
// unenforced and the commit reports success.
//
// Measured before the gate was written, by dumping the compiled struct:
//
//	then { discard; loss-priority high; }  ThenAction "loss-priority high"
//	then { loss-priority high; discard; }  ThenAction "discard"
//
// Same intent, two behaviours, decided by SOURCE ORDER — and only one of them
// enforces anything. `filters.go` sets DiscardExcess only for "discard", and
// the Rust `build_single_rate_policer_state` then selects
// `ThreeColorTreatments::default()` (no drop) for everything else.
//
// These cells bind the gate at `CheckText`, the real operator commit path.

const polBase8445 = `
system { host-name p; }
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } } }
security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }
`

func polCommit8445(t *testing.T, firewall string) error {
	t.Helper()
	_, err := CheckText(polBase8445+"firewall {\n"+firewall+"\n}\n", 0)
	return err
}

// A policer whose rate config is complete, so a refusal can only come from the
// `then` gate and never from the #5299 rate validator.
func pol8445(then string) string {
	return "policer p1 { if-exceeding { bandwidth-limit 10m; burst-size-limit 15k; } then { " +
		then + " } }"
}

// REJECT. Both orders, because the defect is order-dependent and a cell that
// only wrote one of them would leave the other free to regress — and the
// dangerous order (discard first) is the one a "make discard win" fix would
// have made pass while still losing the marking statement.
func TestPolicerThenConflictRejected_8445(t *testing.T) {
	for _, tc := range []struct {
		name string
		then string
	}{
		{"discard-then-marking (the no-op order)", "discard; loss-priority high;"},
		{"marking-then-discard", "loss-priority high; discard;"},
		{"discard with forwarding-class", "discard; forwarding-class af11;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := polCommit8445(t, pol8445(tc.then))
			if err == nil {
				t.Fatalf("policer `then { %s }` committed CLEAN. The single-valued "+
					"ThenAction keeps only the last statement; with `discard` first "+
					"that leaves a policer that meters and drops nothing, so the "+
					"authored rate limit is entirely unenforced (#8445)", tc.then)
			}
			// The message must name BOTH actions — a rejection that named only the
			// survivor would leave the operator looking at the statement that
			// worked.
			for _, want := range []string{"discard", "policer", "p1"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("rejection must mention %q, got: %v", want, err)
				}
			}
			if !strings.Contains(err.Error(), "loss-priority") &&
				!strings.Contains(err.Error(), "forwarding-class") {
				t.Errorf("rejection must name the marking action too, got: %v", err)
			}
		})
	}
}

// REJECT: the three-color-policer arm, whose `then` loop is the identical
// last-wins switch. A fix wired only into the policer arm passes every cell
// above.
func TestThreeColorPolicerThenConflictRejected_8445(t *testing.T) {
	fw := "three-color-policer t1 { single-rate { committed-information-rate 10m; " +
		"committed-burst-size 15k; excess-burst-size 15k; } then { discard; loss-priority high; } }"
	err := polCommit8445(t, fw)
	if err == nil {
		t.Fatalf("three-color-policer `then { discard; loss-priority high; }` committed CLEAN (#8445)")
	}
	if !strings.Contains(err.Error(), "three-color-policer") {
		t.Errorf("rejection must name the three-color-policer, got: %v", err)
	}
}

// POSITIVE CONTROLS. A gate that rejects everything passes every cell above.
//
// The third row is the one that stops this becoming "at most one action": the
// SAME action twice is a redundancy, not a contradiction, and mirrors #4375's
// treatment of a repeated terminal.
func TestPolicerThenValidFormsStillCommit_8445(t *testing.T) {
	for _, tc := range []struct {
		name string
		then string
	}{
		{"discard alone — the enforcing form", "discard;"},
		{"loss-priority alone — meter-only, but valid", "loss-priority high;"},
		{"forwarding-class alone", "forwarding-class af11;"},
		{"discard repeated is redundancy, not conflict", "discard; discard;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := polCommit8445(t, pol8445(tc.then)); err != nil {
				t.Fatalf("valid policer `then { %s }` must still commit, got: %v", tc.then, err)
			}
		})
	}
}

// THE HARM, and the #1960 no-brick doctrine, in one cell.
//
// On the TOLERANT path the contradictory config must still boot — and before
// #14443 this is where the defect was visible in the compiled output: the two
// orders produced DIFFERENT ThenAction values, and only "discard" makes
// `filters.go` set DiscardExcess. So the same authored intent was a rate
// limit in one order and a no-op in the other.
//
// After #14443 the lenient path poisons both orders to "discard"
// (failClosedPolicerThenConflicts): the config still boots and warns, but
// excess traffic is dropped in both orders. The authored set still records
// both actions, which is what the strict gate reads.
func TestPolicerThenConflictHarmIsOrderDependent_8445(t *testing.T) {
	compile := func(then string) *config.PolicerConfig {
		t.Helper()
		tree := &config.ConfigTree{}
		for _, cmd := range []string{
			"set firewall policer p1 if-exceeding bandwidth-limit 10m",
			"set firewall policer p1 if-exceeding burst-size-limit 15k",
		} {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath: %v", err)
			}
		}
		for _, cmd := range strings.Split(then, "\n") {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("parse %q: %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		cfg, err := config.CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("the TOLERANT path must still boot a contradictory policer "+
				"(#1960 no-brick), got: %v", err)
		}
		if len(cfg.Warnings) == 0 {
			t.Errorf("the tolerant path must WARN about the conflict, not swallow it")
		}
		pol := cfg.Firewall.Policers["p1"]
		if pol == nil {
			t.Fatalf("policer p1 not compiled")
		}
		return pol
	}

	discardFirst := compile("set firewall policer p1 then discard\n" +
		"set firewall policer p1 then loss-priority high")
	markingFirst := compile("set firewall policer p1 then loss-priority high\n" +
		"set firewall policer p1 then discard")

	if discardFirst.ThenAction != "discard" {
		t.Errorf("with `discard` written FIRST the lenient poison must force "+
			"\"discard\" (#14443), got %q", discardFirst.ThenAction)
	}
	if markingFirst.ThenAction != "discard" {
		t.Errorf("fixture: with `discard` written LAST it must survive, got %q",
			markingFirst.ThenAction)
	}
	if discardFirst.ThenAction != markingFirst.ThenAction {
		t.Fatalf("after #14443 both orders must poison to the same fail-closed "+
			"survivor: %q vs %q", discardFirst.ThenAction, markingFirst.ThenAction)
	}

	// And the authored set — the thing the gate reads — sees both in both orders.
	for _, pol := range []*config.PolicerConfig{discardFirst, markingFirst} {
		if len(pol.ThenActions) != 2 {
			t.Errorf("ThenActions must record BOTH authored actions regardless of "+
				"order; that is the only place the conflict is visible, got %v",
				pol.ThenActions)
		}
	}
}
