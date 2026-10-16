package frr

import (
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7526: the route-map sequence BOUND counted one referenced prefix-list NAME
// while the RENDERER emits one row per IP FAMILY that list holds.
//
// fromPrefixListRefs expands a mixed v4+v6 list into an `ip` ref and an `ipv6`
// ref so both families bind a family-correct match line (#2607).
// RouteMapSequenceCount counted `len(term.PrefixList)` — names, family-blind.
// So a policy referencing mixed-family lists rendered up to TWICE the sequences
// admission had approved, and a config sitting just under
// MaxRouteMapSequences could render past FRR's ceiling — which, per the
// admission error's own words, "poisons the ENTIRE frr-reload".
//
// THE ASSERTION IS THE AGREEMENT, NOT A LITERAL. Pinning the count to a number
// I computed would encode which of the two I decided to trust, and this issue
// is precisely a case where one of them was wrong. So the test RENDERS the
// policy, COUNTS the emitted sequences, and compares that to what the bound
// predicts. Either side drifting fails it, and neither side is privileged.

// renderedSeqCount7526 counts the route-map sequence lines the renderer
// actually emits for one policy, EXCLUDING the trailing default that
// RouteMapSequenceCount documents itself as excluding.
func renderedSeqCount7526(t *testing.T, po *config.PolicyOptionsConfig, name string) uint64 {
	t.Helper()
	m := &Manager{}
	out := m.renderRouteMapForPolicy(po, name, po.PolicyStatements[name], "")
	re := regexp.MustCompile(`(?m)^route-map ` + regexp.QuoteMeta(name) + ` (permit|deny) (\d+)`)
	seqs := re.FindAllStringSubmatch(out, -1)
	if len(seqs) == 0 {
		t.Fatalf("the renderer emitted no route-map sequence lines at all for %q; "+
			"nothing below can be interpreted as a count:\n%s", name, out)
	}
	return uint64(len(seqs))
}

func poWithPrefixLists7526(mixed bool) *config.PolicyOptionsConfig {
	v4 := []string{"10.0.0.0/8", "192.168.0.0/16"}
	pl := &config.PrefixList{Name: "PL", Prefixes: v4}
	if mixed {
		pl.Prefixes = append(append([]string{}, v4...), "2001:db8::/32")
	}
	return &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{"PL": pl},
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{Name: "t1", PrefixList: []string{"PL"}, Action: "accept"},
				},
			},
		},
	}
}

func TestBoundMatchesRenderedSequenceCount7526(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mixed bool
	}{
		{"single-family prefix-list", false},
		{"mixed v4+v6 prefix-list", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			po := poWithPrefixLists7526(tc.mixed)
			predicted := config.RouteMapSequenceCount(po, po.PolicyStatements["P"])
			rendered := renderedSeqCount7526(t, po, "P")
			if predicted != rendered {
				t.Errorf("the admission bound predicts %d sequences and the renderer "+
					"emits %d. A config admitted at the ceiling then renders past FRR's "+
					"maximum sequence number, which poisons the entire frr-reload "+
					"(#7526)", predicted, rendered)
			}
		})
	}
}

// NON-VACUITY: the mixed case must actually produce MORE sequences than the
// single-family one. Without this, both cells above are satisfied by a renderer
// that ignores families entirely — the agreement would be real and the
// behaviour under test absent.
func TestMixedFamilyPrefixListActuallyDoublesTheRows7526(t *testing.T) {
	single := renderedSeqCount7526(t, poWithPrefixLists7526(false), "P")
	mixed := renderedSeqCount7526(t, poWithPrefixLists7526(true), "P")
	if mixed <= single {
		t.Fatalf("a mixed v4+v6 prefix-list rendered %d sequences and a single-family "+
			"one rendered %d. The family expansion this issue is about is not "+
			"happening, so the agreement asserted above is vacuous", mixed, single)
	}
	// And the bound must track it, not just happen to agree at one point.
	if got := config.RouteMapSequenceCount(poWithPrefixLists7526(true), nil); got != 0 {
		t.Errorf("RouteMapSequenceCount(po, nil) = %d, want 0", got)
	}
}

// The family expansion must reach the rendered MATCH LINES, not merely the row
// count — a renderer emitting two identical `ip` rows would satisfy every count
// assertion and bind neither family correctly.
func TestMixedFamilyEmitsBothMatchKeywords7526(t *testing.T) {
	po := poWithPrefixLists7526(true)
	m := &Manager{}
	out := m.renderRouteMapForPolicy(po, "P", po.PolicyStatements["P"], "")
	for _, kw := range []string{"match ip address prefix-list", "match ipv6 address prefix-list"} {
		if !strings.Contains(out, kw) {
			t.Errorf("the render is missing %q; a mixed list must bind BOTH families "+
				"(#2607), and two rows of the same family would pass a count-only "+
				"assertion:\n%s", kw, out)
		}
	}
}

// A term with NO from-prefix-list still renders ONE sequence, so the ref count
// for an empty name list must be 1 — not 0.
//
// This is the most common term shape, and a zero here multiplies the whole
// term's cross-product to zero: the bound would report that a large policy
// expands to no sequences at all and admit anything. The matrix found it as a
// live escape, because every other cell here happens to reference a list.
func TestTermWithNoPrefixListStillCounts7526(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {Name: "P", Terms: []*config.PolicyTerm{
				{Name: "t1", Action: "accept"},
				{Name: "t2", Action: "reject"},
			}},
		},
	}
	predicted := config.RouteMapSequenceCount(po, po.PolicyStatements["P"])
	if predicted == 0 {
		t.Fatal("a policy with two prefix-list-less terms was counted as ZERO " +
			"sequences. That multiplies every term's cross-product to zero and the " +
			"bound admits an arbitrarily large policy (#7526)")
	}
	if rendered := renderedSeqCount7526(t, po, "P"); predicted != rendered {
		t.Errorf("bound predicts %d, renderer emits %d for prefix-list-less terms",
			predicted, rendered)
	}
}

// An UNDEFINED or EMPTY referenced prefix-list was historically rendered as
// one fail-closed NOMATCH match line. #14136 now skips the dangling branch:
// an accept term over it emits no term sequence (only the trailing default,
// excluded here), so the rendered count is 0 while the admission bound still
// counts 1. The bound is an upper bound — over-counting by one is safe (it
// can only refuse earlier), and changing the config-side bound would couple
// it to the renderer's dangling policy.
func TestUndefinedPrefixListCountsAsOneFamily7526(t *testing.T) {
	for _, tc := range []struct {
		name string
		po   *config.PolicyOptionsConfig
	}{
		{"undefined list", &config.PolicyOptionsConfig{
			PolicyStatements: map[string]*config.PolicyStatement{
				"P": {Name: "P", Terms: []*config.PolicyTerm{
					{Name: "t1", PrefixList: []string{"MISSING"}, Action: "accept"}}},
			}}},
		{"defined but empty list", &config.PolicyOptionsConfig{
			PrefixLists: map[string]*config.PrefixList{"EMPTY": {Name: "EMPTY"}},
			PolicyStatements: map[string]*config.PolicyStatement{
				"P": {Name: "P", Terms: []*config.PolicyTerm{
					{Name: "t1", PrefixList: []string{"EMPTY"}, Action: "accept"}}},
			}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			predicted := config.RouteMapSequenceCount(tc.po, tc.po.PolicyStatements["P"])
			if predicted != 1 {
				t.Errorf("bound predicts %d, want 1 (safe upper bound)", predicted)
			}
			m := &Manager{}
			out := m.renderRouteMapForPolicy(tc.po, "P", tc.po.PolicyStatements["P"], "")
			if strings.Contains(out, "address prefix-list") {
				t.Errorf("dangling prefix-list match was emitted:\n%s", out)
			}
			if strings.Contains(out, "route-map P permit") {
				t.Errorf("dangling accept degraded to a permit:\n%s", out)
			}
		})
	}
}
