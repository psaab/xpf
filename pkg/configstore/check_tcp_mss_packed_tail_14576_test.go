package configstore

import (
	"strings"
	"testing"
)

// #14576 (Y03-01): the decisive regression instrument named by the
// re-reviewers — strict CheckText (the real commit gate) on the four
// defect rows from the probe. Each packed a second kind or trailing
// tokens into one tcp-mss kind node and committed clean with the tail
// silently dropped (selected value compiled, the rest lost). Each must
// now fail strict CheckText; the two-line and braced controls must
// still compile both kinds. The value-level assertions live in
// pkg/config (TestTCPMSSPackedTail*14576).
func TestCheckTextTCPMSSPackedTail14576(t *testing.T) {
	// Defect rows (hierarchical text, as the probe ran them).
	for _, c := range []struct {
		name, text string
		// wantTail: the rejection must be the #14576 tail gate. One row
		// is intercepted earlier by the sibling-statement gate (#8437),
		// which already refuses fused sibling kinds in hierarchical
		// text — that still satisfies "fails strict CheckText", and the
		// flat-set spelling of the same fusion IS the #14576 row (it
		// nests instead of fusing visibly, so only this gate sees it).
		wantTail bool
	}{
		{"second kind packed (sibling-fused, #8437 gate)", "security { flow { tcp-mss { gre-out mss 1300 all-tcp mss 1350; } } }", false},
		{"fully-packed second kind", "security { flow { tcp-mss gre-out mss 1300 all-tcp mss 1350; } }", true},
		{"trailing junk", "security { flow { tcp-mss { all-tcp mss 1350 bogus 7; } } }", true},
		{"trailing value", "security { flow { tcp-mss { all-tcp 1350 9999; } } }", true},
		{"junk inside braced child", "security { flow { tcp-mss { all-tcp { mss 1350 bogus 7; } } } }", true},
	} {
		cfg, err := CheckText(c.text, -1)
		if err == nil {
			t.Errorf("%s: CheckText ACCEPTED %q (all=%d greOut=%d). Tokens past the selected "+
				"MSS value must not be silently dropped (#14576)",
				c.name, c.text, cfg.Security.Flow.TCPMSSAllTCP, cfg.Security.Flow.TCPMSSGreOut)
		} else if c.wantTail && (!strings.Contains(err.Error(), "tcp-mss") || !strings.Contains(err.Error(), "unexpected")) {
			t.Errorf("%s: CheckText rejection must name the tcp-mss tail, got: %v", c.name, err)
		} else if !c.wantTail && !strings.Contains(err.Error(), "all-tcp") {
			t.Errorf("%s: CheckText rejection must name the dropped kind, got: %v", c.name, err)
		}
	}

	// Controls: two separate statements compile BOTH kinds.
	cfg, err := CheckText("security { flow { tcp-mss { gre-out mss 1300; all-tcp mss 1350; } } }", -1)
	if err != nil {
		t.Fatalf("control (two packed statements) must pass CheckText: %v", err)
	}
	if cfg.Security.Flow.TCPMSSGreOut != 1300 || cfg.Security.Flow.TCPMSSAllTCP != 1350 {
		t.Errorf("control -> greOut=%d all=%d, want 1300/1350",
			cfg.Security.Flow.TCPMSSGreOut, cfg.Security.Flow.TCPMSSAllTCP)
	}
	cfg, err = CheckText("security { flow { tcp-mss { gre-out { mss 1300; } all-tcp { mss 1350; } } } }", -1)
	if err != nil {
		t.Fatalf("control (braced kinds) must pass CheckText: %v", err)
	}
	if cfg.Security.Flow.TCPMSSGreOut != 1300 || cfg.Security.Flow.TCPMSSAllTCP != 1350 {
		t.Errorf("braced control -> greOut=%d all=%d, want 1300/1350",
			cfg.Security.Flow.TCPMSSGreOut, cfg.Security.Flow.TCPMSSAllTCP)
	}

	// Prior refusals still refuse through the same gate (typo + range).
	for _, text := range []string{
		"security { flow { tcp-mss { all-tcp msss 1350; } } }",
		"security { flow { tcp-mss { gre-in 70000; } } }",
	} {
		if _, err := CheckText(text, -1); err == nil {
			t.Errorf("prior refusal must stay refused via CheckText: %q", text)
		}
	}
}
