package config

import (
	"strings"
	"testing"
)

// #15943 (H12-01) / #16849: a flexible-match-range with no match-value must not
// compile into a live match on value 0, an explicit `match-mask 0x0` must
// not be overwritten by the full-width default, and a value/mask carrying
// bits outside bit-length must not be silently truncated. Strict commit
// rejects a value-less discard/reject term and every out-of-width term; a
// value-less accept/next-term term stays strict-accepted (packed/fused
// controls) and is refused at the dataplane. The tolerant path warns and
// builders refuse the candidate via FlexMatchValid.
//
// RED-on-revert: drop ValueSet/MaskSet tracking and the zero-mask term
// gets Mask=0xFF again; drop the FlexMatchValid strict check and the
// missing-value discard / out-of-width terms commit clean with a live match.

func flexTerm15943(t *testing.T, cmds ...string) (*Config, error) {
	t.Helper()
	return CompileConfig(buildTree(t, cmds))
}

func TestFlexMatchMissingValueRejected_15943(t *testing.T) {
	// #16849: a value-less discard (and reject) term must hard-reject at
	// strict commit — poisoning it to match-nothing would let its traffic
	// fall through to later terms or the implicit accept.
	for _, action := range []string{"discard", "reject"} {
		_, err := flexTerm15943(t,
			"set firewall family inet filter f1 term missing-val from flexible-match-range range r1 bit-length 8",
			"set firewall family inet filter f1 term missing-val from flexible-match-range range r1 byte-offset 12",
			"set firewall family inet filter f1 term missing-val then "+action,
		)
		if err == nil {
			t.Fatalf("value-less %s term compiled clean — the drop would fall through (#16849)", action)
		}
		if !strings.Contains(err.Error(), "flexible-match-range") {
			t.Errorf("value-less %s rejection must name flexible-match-range, got: %v", action, err)
		}
	}
	// Accept control: a value-less accept term stays strict-accepted
	// (packed/fused controls) with ValueMissing recorded, and is refused
	// at the dataplane rather than widened.
	cfg, err := flexTerm15943(t,
		"set firewall family inet filter f1 term missing-val from flexible-match-range range r1 bit-length 8",
		"set firewall family inet filter f1 term missing-val from flexible-match-range range r1 byte-offset 12",
		"set firewall family inet filter f1 term missing-val then accept",
	)
	if err != nil {
		t.Fatalf("value-less accept term must keep compiling: %v", err)
	}
	term := firstInetTerm(t, cfg, "f1")
	if FlexMatchValid(term.FlexMatch) {
		t.Errorf("value-less term is FlexMatchValid — builders would emit a live 0x0 match: %+v", term.FlexMatch)
	}
	if !term.FlexMatch.ValueMissing {
		t.Errorf("compiler did not record the missing value: %+v", term.FlexMatch)
	}
	// Tolerant control: lenient compile still boots with a warning.
	tree := buildTree(t, []string{
		"set firewall family inet filter f1 term missing-val from flexible-match-range range r1 bit-length 8",
		"set firewall family inet filter f1 term missing-val from flexible-match-range range r1 byte-offset 12",
		"set firewall family inet filter f1 term missing-val then discard",
	})
	lcfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile must boot (#1960): %v", err)
	}
	if !strings.Contains(strings.Join(lcfg.Warnings, "\n"), "no match-value") {
		t.Errorf("tolerant missing-value accepted without warning: %v", lcfg.Warnings)
	}
	// Valued control stays live.
	vcfg, err := flexTerm15943(t,
		"set firewall family inet filter f1 term ok from flexible-match-range range r1 bit-length 8",
		"set firewall family inet filter f1 term ok from flexible-match-range range r1 byte-offset 9",
		"set firewall family inet filter f1 term ok from flexible-match-range range r1 range 0x11",
		"set firewall family inet filter f1 term ok then discard",
	)
	if err != nil {
		t.Fatalf("valued control must commit: %v", err)
	}
	if term := firstInetTerm(t, vcfg, "f1"); !FlexMatchValid(term.FlexMatch) {
		t.Errorf("valued control must be valid: %+v", term.FlexMatch)
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
	// Mask carrying bits outside the field is likewise unrepresentable:
	// builders would truncate it to the load width and enforce a different
	// mask than authored (Opus fold on #16296).
	_, err = flexTerm15943(t,
		"set firewall family inet filter f1 term wide-mask from flexible-match-range range r1 bit-length 4",
		"set firewall family inet filter f1 term wide-mask from flexible-match-range range r1 range 0x4/0x1F",
		"set firewall family inet filter f1 term wide-mask then discard",
	)
	if err == nil {
		t.Fatal("out-of-width match-mask (0x1F in 4 bits) compiled clean — it would be silently truncated (#15943)")
	}
	// Hand-built contract used by snapshot/lo0 builder tests.
	if FlexMatchValid(&FlexMatchConfig{BitLength: 4, Value: 1, Mask: 0xff, ValueSet: true, MaskSet: true}) {
		t.Fatal("FlexMatchValid accepted a 0xff mask in a 4-bit field")
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
