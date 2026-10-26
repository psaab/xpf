package config

import (
	"sort"
	"strings"
	"testing"
)

// Every schema node declaring `compoundKey: true` is a "family" container, and
// every node named "family" with children declares it. The two sets are EQUAL.
//
// WHY THIS IS PINNED RATHER THAN COMMENTED. Two instruments built for #8763
// depend on the equivalence and neither states it as an assumption it can check:
//
//   - a fixture builder that renders compound containers as ONE node decides
//     which containers those are BY NAME. The builder relies on the seven
//     current compoundKey containers all being named family.
//   - the traversal-defect diagnosis is scoped to `compoundKey` containers, and
//     its population argument is those same seven containers.
//
// The equivalence holds for family containers in the current schema. A scalar
// leaf named "family" is not a compound-key container (port-mirroring has one),
// so it is outside this equivalence. But an eighth declaration of either
// container kind would invalidate one instrument or the other:
//
//	a `compoundKey` node NOT named "family" -> the fixture builder renders it as
//	                                           two levels, measures the shape the
//	                                           census invents, and reports clean
//	                                           about a spelling nobody writes
//	a "family" container WITHOUT compoundKey -> the builder merges a container the
//	                                            pass traverses correctly, and
//	                                            manufactures a defect that is not there
//
// Both directions produce a plausible number rather than a failure, which is why
// this is a cell and not a note. It costs one schema walk.
func TestCompoundKeyNodesAreExactlyTheFamilyNodes8763(t *testing.T) {
	var compound, named []string
	var walk func(path string, n *schemaNode)
	seen := map[*schemaNode]bool{}
	walk = func(path string, n *schemaNode) {
		if n == nil || seen[n] {
			return
		}
		seen[n] = true
		for name, child := range n.children {
			p := path + "/" + name
			if child == nil {
				continue
			}
			if child.compoundKey {
				compound = append(compound, p)
			}
			// The scalar port-mirroring `family` leaf is a value slot, not a container.
			if name == "family" && child.children != nil {
				named = append(named, p)
			}
			walk(p, child)
			if child.wildcard != nil {
				walk(p+"/*", child.wildcard)
			}
		}
	}
	if setSchema.compoundKey {
		compound = append(compound, "/")
	}
	walk("", setSchema)
	if setSchema.wildcard != nil {
		walk("/*", setSchema.wildcard)
	}
	sort.Strings(compound)
	sort.Strings(named)

	// Degeneracy control: a walk that reaches nothing agrees with itself.
	if len(compound) == 0 {
		t.Fatal("the schema walk found NO compoundKey nodes. That is not a state this " +
			"schema has been in; the walk is not reaching them, and an empty set is " +
			"equal to any other empty set, so the assertion below would pass vacuously (#8763)")
	}

	if strings.Join(compound, "\n") != strings.Join(named, "\n") {
		t.Errorf("the `compoundKey` nodes and `family` containers are no longer the "+
			"same set.\n  compoundKey (%d):\n    %s\n  family containers (%d):\n    %s\n\n"+
			"Two #8763 instruments depend on these being equal. A compoundKey node not "+
			"named \"family\" makes a name-based fixture builder render it as two levels — "+
			"measuring the shape the census invents and reporting clean about a spelling "+
			"nobody writes. A \"family\" container without compoundKey makes that builder "+
			"merge a container the pass traverses correctly, manufacturing a defect that "+
			"is not there. Both produce a plausible number rather than a failure. Re-derive "+
			"the instruments against whichever property actually matters before trusting "+
			"either (#8763)",
			len(compound), strings.Join(compound, "\n    "),
			len(named), strings.Join(named, "\n    "))
	}
	t.Logf("#8763: %d compoundKey nodes, %d family containers, sets equal", len(compound), len(named))
}
