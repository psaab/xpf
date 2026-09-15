package configstore

// #9882 — an unknown policer `then` token was dropped on every path (strict
// included) while ThenAction kept its "discard" default, so a typo over-dropped
// with zero diagnostic; and a lone `forwarding-class` — Junos mark-and-forward,
// and "METERS ONLY" per the #8445 message's own remedy text — compiled to
// `discard` and dropped the excess.
//
// These cells bind the fix at `CheckText`, the real operator commit path, and
// pin BOTH the commit outcome AND the compiled ThenAction per spelling. Where
// the strict path rejects, the ThenAction is asserted on the tolerant path
// (after a gate, the strict path has no compiled output to inspect — the #8445
// harm-cell doctrine).
import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const polBase9882 = `
system { host-name p; }
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } } }
security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }
`

func polCommit9882(t *testing.T, firewall string) (*config.Config, error) {
	t.Helper()
	return CheckText(polBase9882+"firewall {\n"+firewall+"\n}\n", 0)
}

// A policer whose rate config is complete, so a refusal can only come from a
// `then` gate and never from the #5299 rate validator.
func pol9882(then string) string {
	return "policer p1 { if-exceeding { bandwidth-limit 10m; burst-size-limit 15k; } then { " +
		then + " } }"
}

func tcp9882(then string) string {
	return "three-color-policer t1 { single-rate { committed-information-rate 10m; " +
		"committed-burst-size 15k; excess-burst-size 15k; } then { " + then + " } }"
}

// Unbraced (packed) forms: the statement is spliced directly, with no
// `then { }` wrapper — wrapping a packed statement would nest a second `then`
// inside the first.
func pol9882packed(thenStmt string) string {
	return "policer p1 { if-exceeding { bandwidth-limit 10m; burst-size-limit 15k; } " +
		thenStmt + " }"
}

func tcp9882packed(thenStmt string) string {
	return "three-color-policer t1 { single-rate { committed-information-rate 10m; " +
		"committed-burst-size 15k; excess-burst-size 15k; } " + thenStmt + " }"
}

// REJECT. The typo, the unknown token, and the unknown token alongside a valid
// action (which proves the token is seen even when a valid action is present —
// a gate reading only ThenAction would miss it, since ThenAction is "discard"
// either way).
func TestPolicerThenUnknownRejected_9882(t *testing.T) {
	for _, tc := range []struct {
		name  string
		then  string
		token string
	}{
		{"typo of discard", "discrad;", "discrad"},
		{"unknown token", "foo;", "foo"},
		{"unknown token alongside discard", "discard; foo;", "foo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := polCommit9882(t, pol9882(tc.then))
			if err == nil {
				t.Fatalf("policer `then { %s }` committed CLEAN with ThenAction=%q. "+
					"An unrecognized token must not silently select the most "+
					"destructive action (#9882)", tc.then, cfg.Firewall.Policers["p1"].ThenAction)
			}
			for _, want := range []string{tc.token, "policer", "p1", "supported"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("rejection must mention %q, got: %v", want, err)
				}
			}
		})
	}
}

// REJECT: the three-color-policer arm, whose `then` loop is the identical
// silent-drop switch. A fix wired only into the policer arm passes every cell
// above.
func TestThreeColorPolicerThenUnknownRejected_9882(t *testing.T) {
	cfg, err := polCommit9882(t, tcp9882("foo;"))
	if err == nil {
		t.Fatalf("three-color-policer `then { foo; }` committed CLEAN with ThenAction=%q (#9882)",
			cfg.Firewall.ThreeColorPolicers["t1"].ThenAction)
	}
	for _, want := range []string{"foo", "three-color-policer", "t1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("rejection must mention %q, got: %v", want, err)
		}
	}
}

// REJECT: tokens fused past a known action's arity. `then { discard foo; }`
// must not swallow `foo` any more than `then { foo; }` does (the #8971 shape
// for filter terms). Runs on the hoisted siblings, so a DECLARED trailing
// action was already split into its own statement — see the flat-set chain
// cell — and only genuinely extra tokens land here.
func TestPolicerThenTrailingTokenRejected_9882(t *testing.T) {
	for _, tc := range []struct {
		name  string
		then  string
		token string
	}{
		{"trailing unknown after discard", "discard foo;", "foo"},
		{"trailing unknown after loss-priority", "loss-priority high foo;", "foo"},
		{"trailing unknown after forwarding-class", "forwarding-class af11 foo;", "foo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := polCommit9882(t, pol9882(tc.then))
			if err == nil {
				t.Fatalf("policer `then { %s }` committed CLEAN — the trailing token was swallowed (#9882)", tc.then)
			}
			if !strings.Contains(err.Error(), tc.token) {
				t.Errorf("rejection must name the trailing token %q, got: %v", tc.token, err)
			}
		})
	}
}

// THE MATRIX. One row per spelling, pinning commit outcome AND compiled
// ThenAction. For rows the strict path rejects, the ThenAction is pinned on
// the tolerant path (which must boot with a warning — #1960 no-brick) rather
// than the strict one, which has no output after the gate.
func TestPolicerThenSpellingMatrix_9882(t *testing.T) {
	for _, tc := range []struct {
		name       string
		then       string
		commit     bool
		thenAction string
	}{
		{"discard alone — the enforcing form", "discard;", true, "discard"},
		{"loss-priority alone — meter-only", "loss-priority high;", true, "loss-priority high"},
		// THE FIX, second half: lone forwarding-class is Junos
		// mark-and-forward — meter-only on this dataplane, exactly what the
		// #8445 message promises. Before #9882 this row compiled to "discard"
		// and dropped the excess.
		{"forwarding-class alone — meter-only, not discard", "forwarding-class af11;", true, "forwarding-class af11"},
		// THE FIX, first half: the typo is refused instead of becoming a
		// silent discard. Tolerant ThenAction stays "discard" (the pre-gate
		// behavior — no worse off).
		{"typo — rejected", "discrad;", false, "discard"},
		{"discard+forwarding-class — rejected by #8445", "discard; forwarding-class af11;", false, "forwarding-class af11"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := polCommit9882(t, pol9882(tc.then))
			if tc.commit {
				if err != nil {
					t.Fatalf("policer `then { %s }` must commit, got: %v", tc.then, err)
				}
				if got := cfg.Firewall.Policers["p1"].ThenAction; got != tc.thenAction {
					t.Errorf("ThenAction = %q, want %q", got, tc.thenAction)
				}
				return
			}
			if err == nil {
				t.Fatalf("policer `then { %s }` committed CLEAN, want rejection", tc.then)
			}
			pol, warnings := polLenient9882(t, tc.then)
			if got := pol.ThenAction; got != tc.thenAction {
				t.Errorf("tolerant ThenAction = %q, want %q", got, tc.thenAction)
			}
			if len(warnings) == 0 {
				t.Errorf("tolerant path must WARN about `then { %s }`, not swallow it", tc.then)
			}
		})
	}
}

// polLenient9882 compiles the policer on the TOLERANT path via flat-set lines
// (the #8445 harm-cell pattern), returning the compiled policer and warnings.
func polLenient9882(t *testing.T, then string) (*config.PolicerConfig, []string) {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := []string{
		"set firewall policer p1 if-exceeding bandwidth-limit 10m",
		"set firewall policer p1 if-exceeding burst-size-limit 15k",
	}
	for _, stmt := range strings.Split(then, ";") {
		if stmt = strings.TrimSpace(stmt); stmt != "" {
			cmds = append(cmds, "set firewall policer p1 then "+stmt)
		}
	}
	for _, cmd := range cmds {
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
		t.Fatalf("tolerant path must boot `then { %s }` (#1960 no-brick), got: %v", then, err)
	}
	pol := cfg.Firewall.Policers["p1"]
	if pol == nil {
		t.Fatalf("policer p1 not compiled")
	}
	return pol, cfg.Warnings
}

// The flat-set spelling reaches the same gate: `set ... then foo` is kept as
// an undeclared leaf under `then` by SetPath, so the strict compile must
// refuse it, and lone forwarding-class must compile to the marking — not to
// the discard default — on that shape too.
func TestPolicerThenUnknownFlatSetStrict_9882(t *testing.T) {
	compile := func(t *testing.T, thenCmds ...string) (*config.Config, error) {
		t.Helper()
		tree := &config.ConfigTree{}
		cmds := append([]string{
			"set firewall policer p1 if-exceeding bandwidth-limit 10m",
			"set firewall policer p1 if-exceeding burst-size-limit 15k",
		}, thenCmds...)
		for _, cmd := range cmds {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("parse %q: %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		return config.CompileConfig(tree)
	}

	if _, err := compile(t, "set firewall policer p1 then foo"); err == nil {
		t.Fatalf("flat-set `then foo` committed CLEAN at strict compile (#9882)")
	} else if !strings.Contains(err.Error(), "foo") {
		t.Errorf("flat-set rejection must name the token, got: %v", err)
	}

	cfg, err := compile(t, "set firewall policer p1 then forwarding-class af11")
	if err != nil {
		t.Fatalf("flat-set lone forwarding-class must commit, got: %v", err)
	}
	if got := cfg.Firewall.Policers["p1"].ThenAction; got != "forwarding-class af11" {
		t.Errorf("flat-set lone-FC ThenAction = %q, want %q", got, "forwarding-class af11")
	}
}

// GATE ORDER. A `then` carrying both an unknown token and the #8445 conflict
// reports the unknown token: an unknown token means the intent cannot be fully
// characterized, so it is reported first (same order as the filter side, where
// #2399 unknown-actions runs before #4375 terminal-conflict).
func TestPolicerThenUnknownBeforeConflict_9882(t *testing.T) {
	_, err := polCommit9882(t, pol9882("discard; loss-priority high; foo;"))
	if err == nil {
		t.Fatalf("`then { discard; loss-priority high; foo; }` committed CLEAN")
	}
	if !strings.Contains(err.Error(), "foo") || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("combined defect must report the unknown token first, got: %v", err)
	}
}

// THE TOLERANT CONTRACT. An already-persisted or peer-synced config carrying
// an unknown policer token still boots (#1960 no-brick) — with a warning
// naming the token, and the pre-gate "discard" behavior so it is no worse off
// than before the gate.
func TestPolicerThenUnknownLenientWarnsAndKeepsDiscard_9882(t *testing.T) {
	pol, warnings := polLenient9882(t, "foo;")
	if pol.ThenAction != "discard" {
		t.Errorf("tolerant ThenAction = %q, want the pre-gate %q", pol.ThenAction, "discard")
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"foo", "p1", "downgraded to warning"} {
		if !strings.Contains(joined, want) {
			t.Errorf("tolerant warning must mention %q, got: %v", want, warnings)
		}
	}
}

// THREE-COLOR MIRROR of the matrix's behavior rows: lone forwarding-class
// compiles to the marking (which the capability gate and the Rust shape check
// admit as meter-only — the #9503 pattern), and the #9503 advisory already
// warns that it is inert.
func TestThreeColorPolicerThenSpellingMatrix_9882(t *testing.T) {
	for _, tc := range []struct {
		name       string
		then       string
		thenAction string
		wantWarn   bool
	}{
		{"discard alone — the enforcing form", "discard;", "discard", false},
		{"loss-priority alone — meter-only", "loss-priority high;", "loss-priority high", true},
		{"forwarding-class alone — meter-only, not discard", "forwarding-class af11;", "forwarding-class af11", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := polCommit9882(t, tcp9882(tc.then))
			if err != nil {
				t.Fatalf("three-color-policer `then { %s }` must commit, got: %v", tc.then, err)
			}
			if got := cfg.Firewall.ThreeColorPolicers["t1"].ThenAction; got != tc.thenAction {
				t.Errorf("ThenAction = %q, want %q", got, tc.thenAction)
			}
			joined := strings.Join(cfg.Warnings, "\n")
			hasMarkingWarn := strings.Contains(joined, "t1") && strings.Contains(joined, "meters only")
			if hasMarkingWarn != tc.wantWarn {
				t.Errorf("marking advisory present = %v, want %v (warnings: %v)",
					hasMarkingWarn, tc.wantWarn, cfg.Warnings)
			}
		})
	}
}

// PACKED PARITY. The hierarchical unbraced spellings compile exactly like
// their braced twins. The compact fold only fires when the head names a
// DECLARED child (normalizeCompactNodes), so `then foo;` stays a leaf with no
// children and a children-only walk sees nothing — the packed typo bypassed
// the gate while the braced one was refused. The compiler's leaf-form reader
// (mirroring compileFilterThen's #2399 leaf path) walks the Keys tail, so
// packed and braced agree on outcome AND on the compiled action. Without that
// reader every reject row below commits clean in its packed form.
func TestPolicerThenPackedParity_9882(t *testing.T) {
	for _, tc := range []struct {
		name       string
		packed     string
		braced     string
		commit     bool
		thenAction string
		wantInErr  string
	}{
		// packed is the FULL unbraced statement; braced is the INNER content
		// (pol9882 wraps it in `then { }`).
		{"lone forwarding-class marks on both shapes",
			"then forwarding-class af11;", "forwarding-class af11;",
			true, "forwarding-class af11", ""},
		{"lone loss-priority marks on both shapes",
			"then loss-priority high;", "loss-priority high;",
			true, "loss-priority high", ""},
		{"lone discard enforces on both shapes",
			"then discard;", "discard;",
			true, "discard", ""},
		{"packed typo is refused like the braced one",
			"then foo;", "foo;",
			false, "", "foo"},
		{"unknown after a valid action is refused on both shapes",
			"then discard foo;", "discard; foo;",
			false, "", "foo"},
		{"packed discard+marking conflicts like the braced form",
			"then discard forwarding-class af11;", "discard; forwarding-class af11;",
			false, "", "discard"},
		{"packed discard+loss-priority conflicts like the braced form",
			"then discard loss-priority high;", "discard; loss-priority high;",
			false, "", "discard"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packedCfg, packedErr := polCommit9882(t, pol9882packed(tc.packed))
			bracedCfg, bracedErr := polCommit9882(t, pol9882(tc.braced))
			if (packedErr == nil) != (bracedErr == nil) {
				t.Fatalf("packed/braced OUTCOME diverged: packed %q err=%v, braced %q err=%v",
					tc.packed, packedErr, tc.braced, bracedErr)
			}
			if tc.commit {
				if packedErr != nil {
					t.Fatalf("both shapes must commit, packed got: %v", packedErr)
				}
				pg, bg := packedCfg.Firewall.Policers["p1"], bracedCfg.Firewall.Policers["p1"]
				if pg.ThenAction != tc.thenAction || bg.ThenAction != tc.thenAction {
					t.Errorf("ThenAction packed=%q braced=%q, want %q",
						pg.ThenAction, bg.ThenAction, tc.thenAction)
				}
				return
			}
			if packedErr == nil {
				t.Fatalf("packed %q committed CLEAN (braced twin rejects)", tc.packed)
			}
			if !strings.Contains(packedErr.Error(), tc.wantInErr) {
				t.Errorf("packed rejection must mention %q, got: %v", tc.wantInErr, packedErr)
			}
		})
	}
	// The forwarding-class-head multi-statement run folds (FC is declared) and
	// is refused by the #8437 fused-statement guard — a different gate than the
	// braced twin's #8445, but the same outcome: never a silent commit.
	if _, err := polCommit9882(t, pol9882packed("then forwarding-class af11 discard;")); err == nil {
		t.Fatalf("packed `then forwarding-class af11 discard;` committed CLEAN")
	}
}

// PACKED PARITY, three-color arm: the unbraced typo is refused and the unbraced
// marking compiles to the marking, exactly like the braced twins.
func TestThreeColorPolicerThenPackedParity_9882(t *testing.T) {
	if _, err := polCommit9882(t, tcp9882packed("then foo;")); err == nil {
		t.Fatalf("three-color-policer packed `then foo;` committed CLEAN (#9882)")
	} else if !strings.Contains(err.Error(), "foo") {
		t.Errorf("packed rejection must name the token, got: %v", err)
	}
	cfg, err := polCommit9882(t, tcp9882packed("then forwarding-class af11;"))
	if err != nil {
		t.Fatalf("three-color-policer packed lone forwarding-class must commit, got: %v", err)
	}
	if got := cfg.Firewall.ThreeColorPolicers["t1"].ThenAction; got != "forwarding-class af11" {
		t.Errorf("packed lone-FC ThenAction = %q, want %q", got, "forwarding-class af11")
	}
}

// FLAT-SET CHAIN. One `set` command naming two `then` actions nests the
// second under the first, where a children-only walk keeps just the head.
// The reader expands the run (hoistAndSplitRun8939), so the single-command
// spelling reads exactly what the two-command spelling does — including the
// #8445 conflict. Without the expansion the tail is silently lost (the #9156
// row this fix clears).
func TestPolicerThenFlatSetChainReadsTail_9882(t *testing.T) {
	compile := func(t *testing.T, thenCmds ...string) (*config.Config, error) {
		t.Helper()
		tree := &config.ConfigTree{}
		cmds := append([]string{
			"set firewall policer p1 if-exceeding bandwidth-limit 10m",
			"set firewall policer p1 if-exceeding burst-size-limit 15k",
		}, thenCmds...)
		for _, cmd := range cmds {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("parse %q: %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		return config.CompileConfig(tree)
	}

	// Two markings: last-wins on both spellings, tail not lost.
	one, err := compile(t, "set firewall policer p1 then forwarding-class af11 loss-priority high")
	if err != nil {
		t.Fatalf("single-command two markings must commit, got: %v", err)
	}
	two, err := compile(t,
		"set firewall policer p1 then forwarding-class af11",
		"set firewall policer p1 then loss-priority high")
	if err != nil {
		t.Fatalf("two-command two markings must commit, got: %v", err)
	}
	if one.Firewall.Policers["p1"].ThenAction != two.Firewall.Policers["p1"].ThenAction {
		t.Fatalf("single-command ThenAction=%q, two-command ThenAction=%q — the tail was lost",
			one.Firewall.Policers["p1"].ThenAction, two.Firewall.Policers["p1"].ThenAction)
	}
	if got := one.Firewall.Policers["p1"].ThenAction; got != "loss-priority high" {
		t.Errorf("single-command ThenAction = %q, want last-wins %q", got, "loss-priority high")
	}

	// Terminal + marking in one command: the #8445 conflict, not a silent
	// discard that drops the marking.
	if _, err := compile(t, "set firewall policer p1 then discard loss-priority high"); err == nil {
		t.Fatalf("single-command discard+marking committed CLEAN — the tail was silently lost (#8445/#9882)")
	} else if !strings.Contains(err.Error(), "discard") || !strings.Contains(err.Error(), "loss-priority") {
		t.Errorf("rejection must name both actions, got: %v", err)
	}
}
