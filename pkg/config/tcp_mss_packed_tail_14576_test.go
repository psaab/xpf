package config

import (
	"strings"
	"testing"
)

// #14576 (Y03-01): a tcp-mss kind node read only its selected MSS token and
// silently dropped everything packed after it in the same node.
//
//	selectMSSToken picks Keys[1] (or Keys[2] after the `mss` keyword) and
//	no caller ever inspects the rest, and the kinds are closedWorldOpaque
//	so SchemaValidate never sees the tail either.
//
// Measured at origin/master a615690ed (probe, CompileConfig):
//
//	set security flow tcp-mss gre-out mss 1300 all-tcp mss 1350
//	    -> ok, TCPMSSGreOut=1300 TCPMSSAllTCP=0   (second kind LOST)
//	security { flow { tcp-mss { gre-out mss 1300 all-tcp mss 1350; } } }
//	    -> ok, same loss
//	set security flow tcp-mss all-tcp mss 1350 bogus 7   -> ok, all=1350
//	set security flow tcp-mss all-tcp 1350 9999          -> ok, all=1350
//
// Junos rejects these spellings, so the only acceptable outcomes are
// "compile every kind it names" or "reject". This fix rejects: the gate
// (validateTCPMSSRanges, via checkTCPMSSKind) refuses any token past the
// selected value — strict is a hard error, lenient warns and the compiler
// still applies only the selected (first) value. It deliberately does NOT
// split a packed run into several kinds: Junos has no such statement, and
// inventing one would silently reinterpret operator error.
//
// The flat-set shapes above NEST under the kind (SetPath), so the tail
// lives on the `mss`/value child; the hierarchical packed shapes carry it
// on the kind node itself. Both, plus junk after a braced child's value,
// are covered below.
//
// FAIL-ON-REVERT: drop the mssLeftoverTokens check in checkTCPMSSKind (or
// the tail accounting in selectMSSValueEnd) and the defect rows accept
// again while the controls stay green.

// compileTCPMSS14576 compiles a hierarchical tcp-mss body through the strict
// compiler and reports the three enforceable clamp values plus rejection.
func compileTCPMSS14576(t *testing.T, body string) (all, greIn, greOut int, rejected bool, errStr string) {
	t.Helper()
	tree, perrs := NewParser(`security { flow { tcp-mss { ` + body + ` } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil || cfg == nil {
		return 0, 0, 0, true, errStrOr(err)
	}
	return cfg.Security.Flow.TCPMSSAllTCP, cfg.Security.Flow.TCPMSSGreIn, cfg.Security.Flow.TCPMSSGreOut, false, ""
}

func errStrOr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestTCPMSSPackedTailRejected14576(t *testing.T) {
	// THE DEFECT ROWS (hierarchical spellings). Each packs extra tokens
	// into one kind node; each must fail strict instead of dropping them.
	for _, c := range []struct{ name, body string }{
		{"second kind packed after mss keyword", `gre-out mss 1300 all-tcp mss 1350;`},
		{"second kind packed after bare value", `gre-out 1300 all-tcp 1350;`},
		{"second kind packed, value-first kind order", `all-tcp mss 1350 gre-out mss 1300;`},
		{"trailing junk after mss keyword value", `all-tcp mss 1350 bogus 7;`},
		{"trailing value after bare value", `all-tcp 1350 9999;`},
		{"junk packed inside braced mss child", `all-tcp { mss 1350 bogus 7; }`},
		{"second statement packed inside braced mss child", `all-tcp { mss 1350 9999; }`},
		{"extra child after braced mss child", `all-tcp { mss 1350; bogus 7; }`},
		{"leftover after unparseable-child fallback", `gre-in 1400 bogus { mss bogus; }`},
		{"ipsec tail does not hide behind ipsec rejection", `ipsec-vpn 1400 bogus;`},
	} {
		if _, _, _, rejected, errStr := compileTCPMSS14576(t, c.body); !rejected {
			t.Errorf("%s (%s) was ACCEPTED. Tokens past the selected MSS value must not "+
				"be silently dropped (#14576): Junos rejects this spelling, so xpf must "+
				"compile every kind it names or reject", c.name, c.body)
		} else if !strings.Contains(errStr, "tcp-mss") {
			t.Errorf("%s (%s): rejection must name tcp-mss, got: %s", c.name, c.body, errStr)
		}
		if _, _, _, rejected, errStr := compileTCPMSS14576(t, c.body); rejected && !strings.Contains(errStr, "unexpected") {
			t.Errorf("%s (%s): rejection must call the tail unexpected, got: %s", c.name, c.body, errStr)
		}
	}

	// THE DEFECT ROWS (flat set spellings). SetPath nests the tail under
	// the kind's `mss`/value child node, but it is the same silent drop.
	for _, c := range []struct{ name, cmd string }{
		{"flat second kind", "set security flow tcp-mss gre-out mss 1300 all-tcp mss 1350"},
		{"flat trailing junk after mss keyword", "set security flow tcp-mss all-tcp mss 1350 bogus 7"},
		{"flat trailing value after bare value", "set security flow tcp-mss all-tcp 1350 9999"},
		{"flat fully-packed tcp-mss leaf", "set security flow tcp-mss all-tcp mss 1350 bogus 7 extra"},
	} {
		tree := &ConfigTree{}
		path, err := ParseSetCommand(c.cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c.cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", c.cmd, err)
		}
		if _, err := CompileConfig(tree); err == nil {
			t.Errorf("%s (%s) was ACCEPTED by strict compile. Tokens past the selected "+
				"MSS value must not be silently dropped (#14576)", c.name, c.cmd)
		} else if !strings.Contains(err.Error(), "tcp-mss") {
			t.Errorf("%s (%s): rejection must name tcp-mss, got: %v", c.name, c.cmd, err)
		}
	}
}

// The issue's decisive instrument is strict configstore.CheckText (the
// real commit gate). It lives in the configstore package to avoid an
// import cycle in reverse; the twin there (TestCheckTextTCPMSSPackedTail14576)
// exercises the same rows through CheckText. This test pins the compiled
// values so the acceptance "compiles every kind or fails" is checked on
// the clamp fields, not only on accept/reject.

func TestTCPMSSPackedTailControls14576(t *testing.T) {
	// CONTROLS: every previously-valid spelling still compiles to the same
	// values. This is the regression half — a fix that rejects too much
	// (e.g. treats the discarded tokens of a #1979 mixed shape, or a
	// sibling child, as a tail) fails here.
	for _, c := range []struct {
		name, body         string
		all, greIn, greOut int
	}{
		{"two braced kinds", `gre-out { mss 1300; } all-tcp { mss 1350; }`, 1350, 0, 1300},
		{"two packed kind statements", `gre-out mss 1300; all-tcp mss 1350;`, 1350, 0, 1300},
		{"braced value", `all-tcp { mss 1350; }`, 1350, 0, 0},
		{"flat value", `all-tcp 1350;`, 1350, 0, 0},
		{"packed keyword", `all-tcp mss 1350;`, 1350, 0, 0},
		{"mixed: unparseable child falls back to flat", `gre-in 1400 { mss bogus; }`, 0, 1400, 0},
		{"mixed: wrong-keyword child falls back to flat", `gre-in 1400 { msss 1; }`, 0, 1400, 0},
		{"mixed: child wins when it parses", `gre-in 70000 { mss 1360; }`, 0, 1360, 0},
		{"empty body", `all-tcp { }`, 0, 0, 0},
	} {
		all, greIn, greOut, rejected, errStr := compileTCPMSS14576(t, c.body)
		if rejected || all != c.all || greIn != c.greIn || greOut != c.greOut {
			t.Errorf("%s (%s) -> all=%d greIn=%d greOut=%d rejected=%v (%s), want %d/%d/%d accepted",
				c.name, c.body, all, greIn, greOut, rejected, errStr, c.all, c.greIn, c.greOut)
		}
	}

	// The two-set-line control: the same two kinds as two commands compile
	// both clamps. This is the correct way to write what the packed defect
	// row attempted, and it must stay equivalent.
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security flow tcp-mss gre-out mss 1300",
		"set security flow tcp-mss all-tcp mss 1350",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("two-line control must compile: %v", err)
	}
	if cfg.Security.Flow.TCPMSSAllTCP != 1350 || cfg.Security.Flow.TCPMSSGreOut != 1300 {
		t.Errorf("two-line control -> all=%d greOut=%d, want 1350/1300",
			cfg.Security.Flow.TCPMSSAllTCP, cfg.Security.Flow.TCPMSSGreOut)
	}

	// Prior typo/range refusals keep their shape: the tail gate must not
	// swallow or replace them.
	for _, c := range []struct{ name, body string }{
		{"packed typo keyword", `all-tcp msss 1350;`},
		{"braced typo keyword", `all-tcp { msss 1350; }`},
		{"keyword with no value", `all-tcp mss;`},
		{"out of range", `gre-in 70000;`},
	} {
		if _, _, _, rejected, _ := compileTCPMSS14576(t, c.body); !rejected {
			t.Errorf("%s (%s) must stay rejected", c.name, c.body)
		}
	}
}

func TestTCPMSSPackedTailLenient14576(t *testing.T) {
	// Lenient (boot/peer-sync): the packed-tail config must WARN, never
	// silently load, and the compiler keeps the selected (first) value —
	// the tail is not reinterpreted as a second kind on any path.
	for _, c := range []struct{ name, body string }{
		{"second kind packed", `gre-out mss 1300 all-tcp mss 1350;`},
		{"trailing junk", `all-tcp mss 1350 bogus 7;`},
	} {
		tree, perrs := NewParser(`security { flow { tcp-mss { ` + c.body + ` } } }`).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("%s: lenient must warn-load, got error: %v", c.name, err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "tcp-mss") && strings.Contains(w, "unexpected") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: lenient load must warn about the dropped tcp-mss tail, got: %v",
				c.name, cfg.Warnings)
		}
		if c.name == "second kind packed" {
			if cfg.Security.Flow.TCPMSSGreOut != 1300 || cfg.Security.Flow.TCPMSSAllTCP != 0 {
				t.Errorf("%s: lenient keeps selected gre-out=1300 and does not invent all-tcp, got greOut=%d all=%d",
					c.name, cfg.Security.Flow.TCPMSSGreOut, cfg.Security.Flow.TCPMSSAllTCP)
			}
		}
	}

	// Flat lenient twin.
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set security flow tcp-mss all-tcp 1350 9999")
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("flat lenient must warn-load: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "tcp-mss") && strings.Contains(w, "unexpected") {
			found = true
		}
	}
	if !found {
		t.Errorf("flat lenient load must warn about the dropped tcp-mss tail, got: %v", cfg.Warnings)
	}
	if cfg.Security.Flow.TCPMSSAllTCP != 1350 {
		t.Errorf("flat lenient keeps selected all-tcp=1350, got %d", cfg.Security.Flow.TCPMSSAllTCP)
	}
}
