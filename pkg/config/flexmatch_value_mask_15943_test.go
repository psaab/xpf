package config

import (
	"strings"
	"testing"
)

// #15943 (H12-01): a flexible-match-range with no match-value must not
// compile into a live match on value 0, an explicit `match-mask 0x0` must
// not be overwritten by the full-width default, and a value/mask carrying
// bits outside bit-length must not be silently truncated. Strict commit
// rejects the first and third; the second is preserved as authored. The
// tolerant path fails the term closed via FlexMatchValid in the snapshot
// and lo0 builders (same channel as UnknownFlexMatch).
//
// RED-on-revert: drop ValueSet/MaskSet tracking and the zero-mask term
// gets Mask=0xFF again; drop the FlexMatchValid strict check and the
// missing-value / out-of-width terms commit clean with a live match.

func flexTerm15943(t *testing.T, cmds ...string) (*Config, error) {
	t.Helper()
	return CompileConfig(buildTree(t, cmds))
}

func TestFlexMatchMissingValueRejected_15943(t *testing.T) {
	_, err := flexTerm15943(t,
		"set firewall family inet filter f1 term missing-val from flexible-match-range range r1 bit-length 8",
		"set firewall family inet filter f1 term missing-val from flexible-match-range range r1 byte-offset 12",
		"set firewall family inet filter f1 term missing-val then discard",
	)
	if err == nil {
		t.Fatal("value-less flexible-match-range compiled clean — it would live-match value 0 with a full mask (#15943)")
	}
	if !strings.Contains(err.Error(), "15943") {
		t.Errorf("reject does not cite #15943: %v", err)
	}
	// Lenient must also not invent the match: the compiled term (if any)
	// must be FlexMatchValid==false so builders poison it.
	cfg, lerr := CompileConfigLenient(buildTree(t, []string{
		"set firewall family inet filter f1 term missing-val from flexible-match-range range r1 bit-length 8",
		"set firewall family inet filter f1 term missing-val from flexible-match-range range r1 byte-offset 12",
		"set firewall family inet filter f1 term missing-val then discard",
	}))
	if lerr != nil {
		t.Fatalf("lenient compile must not hard-fail: %v", lerr)
	}
	term := firstInetTerm(t, cfg, "f1")
	if FlexMatchValid(term.FlexMatch) {
		t.Errorf("lenient value-less term is FlexMatchValid — builders would emit a live 0x0 match: %+v", term.FlexMatch)
	}
}

func TestFlexMatchExplicitZeroMaskPreserved_15943(t *testing.T) {
	cfg, err := flexTerm15943(t,
		"set firewall family inet filter f1 term zero-mask from flexible-match-range range r1 bit-length 8",
		"set firewall family inet filter f1 term zero-mask from flexible-match-range range r1 byte-offset 12",
		"set firewall family inet filter f1 term zero-mask from flexible-match-range range r1 range 0x40/0x0",
		"set firewall family inet filter f1 term zero-mask then discard",
	)
	if err != nil {
		t.Fatalf("explicit zero-mask term must commit: %v", err)
	}
	term := firstInetTerm(t, cfg, "f1")
	if term.FlexMatch == nil {
		t.Fatal("no FlexMatch compiled")
	}
	if term.FlexMatch.Mask != 0 || !term.FlexMatch.MaskSet {
		t.Errorf("explicit match-mask 0x0 overwritten: %+v (want Mask=0, MaskSet=true)", term.FlexMatch)
	}
	if term.FlexMatch.Value != 0x40 || !FlexMatchValid(term.FlexMatch) {
		t.Errorf("zero-mask term must stay valid with its authored value: %+v", term.FlexMatch)
	}

	// Same via the standalone match-mask leaf.
	cfg2, err2 := flexTerm15943(t,
		"set firewall family inet filter f1 term zm2 from flexible-match-range range r1 bit-length 8",
		"set firewall family inet filter f1 term zm2 from flexible-match-range range r1 range 0x40",
		"set firewall family inet filter f1 term zm2 from flexible-match-range range r1 match-mask 0x0",
		"set firewall family inet filter f1 term zm2 then discard",
	)
	if err2 != nil {
		t.Fatalf("match-mask-leaf zero-mask term must commit: %v", err2)
	}
	term2 := firstInetTerm(t, cfg2, "f1")
	if term2.FlexMatch.Mask != 0 || !term2.FlexMatch.MaskSet {
		t.Errorf("match-mask leaf 0x0 overwritten: %+v", term2.FlexMatch)
	}
}

func TestFlexMatchOutOfWidthRejected_15943(t *testing.T) {
	// Value 0x40 needs 7 bits; bit-length 4 cannot represent it.
	_, err := flexTerm15943(t,
		"set firewall family inet filter f1 term trunc from flexible-match-range range r1 bit-length 4",
		"set firewall family inet filter f1 term trunc from flexible-match-range range r1 byte-offset 12",
		"set firewall family inet filter f1 term trunc from flexible-match-range range r1 range 0x40",
		"set firewall family inet filter f1 term trunc then discard",
	)
	if err == nil {
		t.Fatal("out-of-width match-value (0x40 in 4 bits) compiled clean — it would be silently truncated (#15943)")
	}
	// Control: an in-width value commits clean.
	cfg, err := flexTerm15943(t,
		"set firewall family inet filter f1 term ok from flexible-match-range range r1 bit-length 4",
		"set firewall family inet filter f1 term ok from flexible-match-range range r1 range 0x4",
		"set firewall family inet filter f1 term ok then discard",
	)
	if err != nil {
		t.Fatalf("in-width term must commit: %v", err)
	}
	if term := firstInetTerm(t, cfg, "f1"); !FlexMatchValid(term.FlexMatch) {
		t.Errorf("in-width control term must be valid: %+v", term.FlexMatch)
	}
}
