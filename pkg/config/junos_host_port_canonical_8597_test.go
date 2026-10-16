package config

import "testing"

// #8597 (muse-004 K67) — junosHostParsePorts and the commit-time port gate
// disagreed about what a valid port is.
//
// This parser used strconv.Atoi with a `v < 0 || v > 65535` check. Measured
// against validatePortSpec, the gate that runs at commit:
//
//	spec     junosHostParsePorts     validatePortSpec
//	"+80"    rejected                rejected (not a number)
//	"0"      rejected                rejected (single port is ambiguous)
//	"00"     rejected                rejected
//	"0-100"  [{0 100}], true         accepted (explicit range endpoint)
//
// Why the divergence matters rather than being cosmetic: the projection this
// parser feeds sets RenderedPolicyKeys, which is a SUPPRESSION claim — "this
// deny is enforced, so do not warn about it". Explicit ranges include port 0.

// TestJunosHostPortsAgreeWithTheCommitGate_8597 asserts the AGREEMENT rather
// than a table of verdicts. A pinned table here would be a second statement of
// the accepted domain — the thing that drifted.
//
// The space-separated multi-port spelling is excluded because it is this
// parser's documented input shape (strings.Fields) and NOT a divergence to
// close; the next cell pins it.
func TestJunosHostPortsAgreeWithTheCommitGate_8597(t *testing.T) {
	for _, spec := range []string{
		"80", "443", "1", "65535", "80-90", "1-65535",
		"+80", "0", "00", "65536", "-0", "abc", "80-79",
		// A non-canonical token INSIDE a range. Without these the range arm
		// can be reverted to strconv.Atoi and every cell stays green.
		"+80-90", "80-+90", "00-90",
	} {
		_, parserOK := junosHostParsePorts(spec)
		gateOK := validatePortSpec(spec) == nil
		if parserOK != gateOK {
			t.Errorf("spec %q: junosHostParsePorts ok=%v but validatePortSpec ok=%v — the "+
				"parser feeds a SUPPRESSION claim (RenderedPolicyKeys says 'this deny is "+
				"enforced, do not warn'), so a spec the commit gate refuses must not be "+
				"reported as rendered", spec, parserOK, gateOK)
		}
	}
}

// TestJunosHostPortsRejectTheMeasuredDivergences_8597 states the specific
// verdicts, so a future change that made BOTH sides wrong in the same direction
// would still fail here rather than satisfying the agreement cell above.
func TestJunosHostPortsRejectTheMeasuredDivergences_8597(t *testing.T) {
	for _, tc := range []struct {
		spec string
		why  string
	}{
		{"+80", "a leading sign is not a canonical numeric token"},
		{"0", "port 0 is ambiguous without explicit range syntax"},
		{"00", "same, in the spelling that also hides behind Atoi"},
		{"100-0", "and the ordering check must still fire"},
		{"+80-90", "a non-canonical token in the LOW half of a range"},
		{"80-+90", "and in the HIGH half — the two arms are separate parses"},
	} {
		if _, ok := junosHostParsePorts(tc.spec); ok {
			t.Errorf("junosHostParsePorts(%q) accepted; %s", tc.spec, tc.why)
		}
	}
}

// TestJunosHostPortsKeepTheirDocumentedShapes_8597 is the OVER-BROAD control.
//
// The ordinary specs, explicit zero-floor range, and SPACE-SEPARATED
// multi-port spelling must remain accepted.
// fix would delete a form this parser exists to accept.
func TestJunosHostPortsKeepTheirDocumentedShapes_8597(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want []PortRange
	}{
		{"0-100", []PortRange{{Lo: 0, Hi: 100}}},
		{"80", []PortRange{{Lo: 80, Hi: 80}}},
		{"80-90", []PortRange{{Lo: 80, Hi: 90}}},
		{"1", []PortRange{{Lo: 1, Hi: 1}}},
		{"65535", []PortRange{{Lo: 65535, Hi: 65535}}},
		{"80 443", []PortRange{{Lo: 80, Hi: 80}, {Lo: 443, Hi: 443}}},
		{"80-90 443", []PortRange{{Lo: 80, Hi: 90}, {Lo: 443, Hi: 443}}},
	} {
		got, ok := junosHostParsePorts(tc.spec)
		if !ok {
			t.Errorf("junosHostParsePorts(%q) refused a documented shape", tc.spec)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("junosHostParsePorts(%q) = %v, want %v", tc.spec, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("junosHostParsePorts(%q)[%d] = %v, want %v", tc.spec, i, got[i], tc.want[i])
			}
		}
	}
	// The empty spec means "all ports" and must stay that way.
	if got, ok := junosHostParsePorts(""); !ok || got != nil {
		t.Errorf("empty spec gave (%v, %v), want (nil, true) — \"\" means all ports", got, ok)
	}
}
