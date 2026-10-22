package config

import (
	"fmt"
	"testing"
)

// #9012: the BFD and BGP-damping numerics were UNTYPED in setSchema -- no
// valueType, no validator -- while the sibling `retransmit-interval` two lines
// away in the same table carries both. A negative committed clean and rendered
// an FRR-invalid line into the xpf-MANAGED section, where one rejected line
// costs the whole reload.
//
// Typing the leaf is the whole remedy and it reaches BOTH channels at once,
// which is why no compiler change was needed:
//
//	Store.Commit  -> compileTreeStrict -> schemaValidateExpandedTreeForNode  REJECT
//	Store.Load /  -> compileTreeLenient -> same validation, downgraded to a
//	Store.SyncApply                        slog.Warn (#1960 no-brick doctrine)
//
// The bounds are FRR's own grammar, because FRR is the consumer that rejects:
// `receive-interval`/`transmit-interval` are (10-60000), `detect-multiplier` is
// (2-255), and `bgp dampening` takes (1-45) (1-20000) (1-20000) (1-255).

func gate9012(t *testing.T, line string) bool {
	t.Helper()
	tr := &ConfigTree{}
	p, err := ParseSetCommand(line)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", line, err)
	}
	tr.SetPath(p)
	return SchemaValidateWithDefinitions(tr, tr) == nil
}

func TestBFDNumericsAreTyped9012(t *testing.T) {
	const base = "set protocols bgp group G bfd-liveness-detection "
	for _, tc := range []struct {
		line string
		want bool
	}{
		// minimum-interval, FRR (10-60000). BOUNDARIES are included on purpose:
		// a range check that is off by one passes every interior row.
		{base + "minimum-interval 300", true},
		{base + "minimum-interval 10", true},
		{base + "minimum-interval 60000", true},
		{base + "minimum-interval 9", false},
		{base + "minimum-interval 60001", false},
		{base + "minimum-interval -100", false}, // the reported defect
		{base + "minimum-interval abc", false},
		// An explicit 0 is now refused rather than silently becoming the
		// renderer's 300 default. That substitution made an explicit 0
		// indistinguishable from "unset" -- the internal-sentinel collision
		// #9125 reports at another site -- so refusing it tells the operator
		// instead of guessing for them.
		{base + "minimum-interval 0", false},

		// multiplier, FRR (2-255).
		{base + "multiplier 3", true},
		{base + "multiplier 2", true},
		{base + "multiplier 255", true},
		{base + "multiplier 1", false},
		{base + "multiplier 256", false},
		{base + "multiplier -1", false},
	} {
		t.Run(tc.line, func(t *testing.T) {
			if got := gate9012(t, tc.line); got != tc.want {
				t.Errorf("commit gate accepted=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestBGPDampingNumericsAreTyped9012(t *testing.T) {
	const base = "set protocols bgp damping "
	for _, tc := range []struct {
		line string
		want bool
	}{
		{base + "half-life 15", true},
		{base + "half-life 1", true},
		{base + "half-life 45", true},
		{base + "half-life 0", false},
		{base + "half-life 46", false},
		{base + "half-life -3", false},
		{base + "reuse 750", true},
		{base + "reuse 20000", true},
		{base + "reuse 20001", false},
		{base + "reuse -1", false},
		{base + "suppress 3000", true},
		{base + "suppress 0", false},
		{base + "max-suppress 60", true},
		{base + "max-suppress 255", true},
		{base + "max-suppress 256", false},
		{base + "max-suppress -5", false},
	} {
		t.Run(tc.line, func(t *testing.T) {
			if got := gate9012(t, tc.line); got != tc.want {
				t.Errorf("commit gate accepted=%v, want %v", got, tc.want)
			}
		})
	}
}

// TestEveryBFDSiteIsTyped9012 is the POPULATION cell, and it is the one that
// matters. `bfd-liveness-detection` is declared at EIGHT places in
// schema_routing.go -- OSPF, OSPFv3, BGP group, BGP neighbor, IS-IS, and their
// routing-instance twins -- and they were byte-identical, which is exactly how
// a fix lands at one site and leaves seven. Walking the schema instead of
// listing paths means a NINTH declaration added later is covered without anyone
// remembering to extend a list.
func TestEveryBFDSiteIsTyped9012(t *testing.T) {
	var untyped []string
	var seen int
	var walk func(path []string, n *schemaNode, depth int)
	walk = func(path []string, n *schemaNode, depth int) {
		if n == nil || n.children == nil || depth > 12 {
			return
		}
		for name, c := range n.children {
			if c == nil {
				continue
			}
			p := append(append([]string{}, path...), name)
			// #9012: DESCEND THROUGH WILDCARDS. Three of the eight BFD sites
			// and one of the two damping sites live under instance-name
			// containers (`routing-instances <name>`), which are reachable
			// only via `wildcard`. The first version of this walk read
			// `children` alone and reached 14 of 24 leaves -- the positive
			// control below is what caught it, which is the whole reason it is
			// a Fatalf and not a comment.
			if c.wildcard != nil {
				walk(append(append([]string{}, p...), "<*>"), c.wildcard, depth+1)
			}
			if name == "bfd-liveness-detection" || name == "damping" {
				for leaf, lc := range c.children {
					if lc == nil || lc.args == 0 {
						continue
					}
					seen++
					if lc.validator == nil || lc.valueType != ValueInteger {
						untyped = append(untyped, fmt.Sprintf("%s %s (validator=%v valueType=%v)",
							joinPath9012(p), leaf, lc.validator != nil, lc.valueType))
					}
				}
			}
			walk(p, c, depth+1)
		}
	}
	walk(nil, setSchema, 0)

	// Positive control: if the walk found nothing, an empty `untyped` would be
	// a statement about the WALK, not about the schema.
	// `seen` counts leaf OCCURRENCES along schema paths, not distinct nodes: a
	// container reachable both directly and through a wildcard is walked twice,
	// so the number exceeds the 24 declarations. That is fine for this
	// assertion -- more paths is more coverage, and any untyped occurrence
	// errors -- but the floor has to be read as a reachability check, not as a
	// declaration count.
	if seen < 24 {
		t.Fatalf("the walk reached only %d numeric leaf occurrences under "+
			"bfd-liveness-detection/damping; there are 8 BFD sites x 2 leaves + 2 damping "+
			"sites x 4 leaves = 24 declarations and wildcards make the reachable count "+
			"HIGHER, so this census is not reaching the schema and an empty result below "+
			"would be a statement about the walk rather than about the schema", seen)
	}
	for _, u := range untyped {
		t.Errorf("UNTYPED numeric leaf: %s — a negative value commits clean here and "+
			"renders an FRR-invalid line into the managed section (#9012)", u)
	}
	t.Logf("%d numeric leaf occurrences under bfd-liveness-detection/damping, all typed", seen)
}

func joinPath9012(p []string) string {
	out := ""
	for i, s := range p {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}
