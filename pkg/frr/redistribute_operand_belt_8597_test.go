package frr

import (
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 (muse-004 K87) — the two `redistribute` interpolations in this file
// reached frr.conf with no operand belt.
//
// Every other operand interpolation in pkg/frr goes through sanitizeFRRValue
// (bfd.go's `peer ... vrf`, config_render.go's `vrf`, prefix_list_render.go's
// prefixes). These two did not, and both operands are RAW CONFIG STRINGS:
// `proto` comes from `term.FromProtocols` and `rmName`/`export` from a
// policy-statement or protocol name.
//
// Why it is worth fixing even though the strict validator rejects a bad name:
// resolveRedistribute's own doc says only the LENIENT load / peer-sync path can
// reach it with such a name, which is exactly the ingress every other belt in
// this package exists for. And the completeness claim matters as much as the
// hole — a reviewer auditing "are all FRR interpolations belted" against the
// #4482 inventory would answer yes and stop.
//
// SCOPE, stated so this is not read as stronger than it is: sanitizeFRRValue
// maps control bytes to a SPACE, the sink's own separator — the weaker belt
// this package's README describes under #6796. It closes a newline or NUL
// splitting one statement into two. A protocol ALLOWLIST would be stronger and
// is a separate change with its own over-rejection question.

// TestRedistributeOperandsAreSanitized_8597 is the RED-on-revert core, on the
// site that was actually reachable.
//
// Measured before the fix, one fixture per operand:
//
//	proto  "static\n line two"     -> " redistribute static\n line two route-map exp\n"
//	rmName "exp\nrouter bgp 65000" -> " redistribute static route-map exp\nrouter bgp 65000\n"
//
// Each injects a second frr.conf statement. Two fixtures rather than one
// carrying both, because a single dirty-name-AND-dirty-proto fixture renders
// nothing at all — the first draft of this cell used exactly that and passed
// vacuously, which the belt-removal mutation exposed by killing only the
// census.
func TestRedistributeOperandsAreSanitized_8597(t *testing.T) {
	m := New()

	// #14698: the PROTOCOL-operand dirty token ("static\n line two")
	// is now refused enrollment outright by the knownRedistProtocol
	// allowlist gate — stronger than the #8597 sanitize belt (which
	// remains on the render path for any token that does enrol). So
	// that operand now renders NOTHING, and this cell pins the
	// stronger outcome (no line, hence no injection) instead of the
	// belt's sanitized line. The ROUTE-MAP operand subtest below
	// still exercises the sanitize belt on a clean proto.
	t.Run("control byte in the PROTOCOL operand", func(t *testing.T) {
		po := &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{
				"exp": {Name: "exp", Terms: []*config.PolicyTerm{
					{Name: "t1", FromProtocols: []string{"static\n line two"}, Action: "accept"},
				}},
			},
		}
		got := m.resolveRedistribute("exp", po, "", nil)
		if got != "" {
			t.Errorf("dirty protocol token enrolled and rendered %q; the #14698 allowlist must enrol nothing", got)
		}
	})

	for _, tc := range []struct {
		name   string
		export string
		protos []string
	}{
		{"control byte in the ROUTE-MAP operand", "exp\nrouter bgp 65000", []string{"static"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			po := &config.PolicyOptionsConfig{
				PolicyStatements: map[string]*config.PolicyStatement{
					tc.export: {Name: tc.export, Terms: []*config.PolicyTerm{
						{Name: "t1", FromProtocols: tc.protos, Action: "accept"},
					}},
				},
			}
			got := m.resolveRedistribute(tc.export, po, "", nil)
			if got == "" {
				t.Fatalf("the fixture rendered NOTHING; this cell asserts what a dirty " +
					"operand renders, so an empty result makes it vacuous")
			}
			if n := strings.Count(strings.TrimRight(got, "\n"), "\n"); n > 0 {
				t.Errorf("a control byte in the %s emitted %d extra frr.conf line(s):\n%q",
					tc.name, n, got)
			}
		})
	}
}

// TestBareRedistributeIsAllowlistGated_8597 records WHY the single-operand site
// needs no reachable-hole argument: it sits behind knownRedistProtocol, an
// allowlist, which is the stronger belt. Its sanitize call is parity so the
// file has no unbelted interpolation for a future audit to reason about.
//
// If a future change widens that allowlist, this cell fails and points at the
// belt rather than letting the hole open silently.
func TestBareRedistributeIsAllowlistGated_8597(t *testing.T) {
	for _, dirty := range []string{"static\n x", "connected\nrouter bgp 1", "ospf\x00"} {
		if knownRedistProtocol(dirty) {
			t.Errorf("knownRedistProtocol(%q) is true; the bare-export path is no longer "+
				"allowlist-gated and its sanitize belt is now load-bearing rather than "+
				"parity", dirty)
		}
	}
	// Positive control: the allowlist must accept something, or "rejects every
	// dirty value" is what an always-false predicate returns.
	if !knownRedistProtocol("static") {
		t.Fatal("knownRedistProtocol rejects `static`; the predicate is broken, so the " +
			"rejections above prove nothing")
	}
}

// TestSanitizedRedistributeStillRendersTheOrdinaryCase_8597 is the OVER-BROAD
// control. sanitizeFRRValue is a pass-through for clean input, and this asserts
// it: a belt that mangled ordinary protocol names would break every
// redistribute line in the tree.
func TestSanitizedRedistributeStillRendersTheOrdinaryCase_8597(t *testing.T) {
	m := New()
	if got := m.resolveRedistribute("static", nil, "", nil); got != " redistribute static\n" {
		t.Errorf("bare export rendered %q, want \" redistribute static\\n\"", got)
	}
	// `direct` must still map to FRR's `connected` spelling.
	if got := m.resolveRedistribute("direct", nil, "", nil); !strings.Contains(got, "connected") {
		t.Errorf("`direct` rendered %q; it must map to FRR's `connected`", got)
	}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"exp": {Name: "exp", Terms: []*config.PolicyTerm{
				{Name: "t1", FromProtocols: []string{"static", "direct"}},
			}},
		},
	}
	got := m.resolveRedistribute("exp", po, "", nil)
	for _, want := range []string{"redistribute connected route-map exp", "redistribute static route-map exp"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// TestEveryRedistributeInterpolationIsBelted_8597 is the census, keyed on the
// thing that varies rather than on a count.
//
// The finding named ONE site. There are two, and the completeness claim is what
// a future audit will lean on — so this asserts that no `redistribute` format
// string in this file interpolates a bare operand.
func TestEveryRedistributeInterpolationIsBelted_8597(t *testing.T) {
	src := readFileForCensus(t, "redistribute.go")
	var bare []string
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		// COMMENTS ARE NOT CODE. The first version of this census matched its
		// own explanatory comment — a line saying "the file has no unbelted
		// `redistribute %s` interpolation" was itself reported as an unbelted
		// interpolation. A census that counts a proxy for the property finds
		// what it is looking for whether or not the property holds.
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if !strings.Contains(line, "redistribute %s") {
			continue
		}
		if strings.Contains(line, "sanitizeFRRValue") {
			continue
		}
		// The multi-operand call wraps, so a format-string line with no
		// sanitize on it may have the operands on the NEXT line; treat a line
		// ending in a comma as continued.
		if strings.HasSuffix(trimmed, ",") {
			continue
		}
		bare = append(bare, trimmed)
	}
	if len(bare) > 0 {
		t.Errorf("redistribute interpolation(s) with no operand belt:\n  %s",
			strings.Join(bare, "\n  "))
	}
	// Positive control: the census must be able to SEE an interpolation at all,
	// or "none unbelted" is what a broken pattern returns.
	if !strings.Contains(src, "redistribute %s") {
		t.Fatalf("the census found no %q interpolation in redistribute.go; the pattern "+
			"is wrong, not the file clean", "redistribute %s")
	}
}

func readFileForCensus(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
