package config

import (
	"strings"
	"testing"
)

// #9743: `show configuration | display inheritance` expanded groups on the RAW
// tree, while both compile cores normalize first. Since #9620 the #8662
// normalizer rewrites a brace-elided routing instance into its braced shape, and
// group expansion binds against that shape — so the display omitted properties
// the commit applied.
//
// Measured at origin/master 766da5332:
//
//	group body elided:  display has `description inherited`?  NO   compiled: yes
//	group body braced:  display has `description inherited`?  yes  compiled: yes
//
// `instance-type forwarding` was omitted too, and that one decides whether the
// daemon creates a VRF at all — so the display was wrong exactly where an
// operator checks what a group contributes.
const (
	elidedGroupBody9743 = `groups { G { routing-instances { blue instance-type forwarding description inherited; } } } ` +
		`apply-groups G; routing-instances { blue { interface ge-0/0/0.0; } }`
	bracedGroupBody9743 = `groups { G { routing-instances { blue { instance-type forwarding; description inherited; } } } } ` +
		`apply-groups G; routing-instances { blue { interface ge-0/0/0.0; } }`
)

func parse9743(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	return tree
}

// The claim is EQUALITY between the two spellings' displays, not merely that the
// properties appear. The two group bodies are the same configuration written two
// ways; a display that renders them differently is the defect, whatever the
// difference happens to be. Measured: identical after this change, and the
// elided one is missing two statements before it.
func TestInheritanceDisplayIsTheSameForBothSpellings9743(t *testing.T) {
	elided := parse9743(t, elidedGroupBody9743).FormatInheritance()
	braced := parse9743(t, bracedGroupBody9743).FormatInheritance()
	if elided != braced {
		t.Fatalf("the two spellings of one config must display alike\n--- elided ---\n%s\n--- braced ---\n%s", elided, braced)
	}
	for _, want := range []string{"description inherited", "instance-type forwarding"} {
		if !strings.Contains(elided, want) {
			t.Fatalf("display must show the inherited %q\n%s", want, elided)
		}
	}
}

// FormatPathInheritance is the `show configuration <path> | display inheritance`
// entry point and expands its own clone, so it needs the same normalization. The
// issue names it explicitly; without this cell it would keep the defect after
// FormatInheritance was fixed.
func TestFormatPathInheritanceIsTheSameForBothSpellings9743(t *testing.T) {
	path := []string{"routing-instances"}
	elided := parse9743(t, elidedGroupBody9743).FormatPathInheritance(path)
	braced := parse9743(t, bracedGroupBody9743).FormatPathInheritance(path)
	if elided != braced {
		t.Fatalf("the two spellings must display alike under a path\n--- elided ---\n%s\n--- braced ---\n%s", elided, braced)
	}
	if !strings.Contains(elided, "description inherited") {
		t.Fatalf("path display must show the inherited description\n%s", elided)
	}
}

// The display must still agree with what the COMMIT does — the property the
// issue is really about. Asserting only that the two displays match would be
// satisfied by a change that broke both in the same way.
func TestInheritanceDisplayAgreesWithTheCompiledConfig9743(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"group body elided", elidedGroupBody9743},
		{"group body braced", bracedGroupBody9743},
	} {
		t.Run(tc.name, func(t *testing.T) {
			display := parse9743(t, tc.text).FormatInheritance()
			cfg, err := CompileConfigLenient(parse9743(t, tc.text))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			var found *RoutingInstanceConfig
			for _, ri := range cfg.RoutingInstances {
				if ri.Name == "blue" {
					found = ri
				}
			}
			if found == nil {
				t.Fatalf("fixture must compile a `blue` instance")
			}
			if found.InstanceType != "forwarding" || found.Description != "inherited" {
				t.Fatalf("the commit inherits both properties; got type=%q description=%q",
					found.InstanceType, found.Description)
			}
			if !strings.Contains(display, "instance-type forwarding") ||
				!strings.Contains(display, "description inherited") {
				t.Fatalf("the display omits what the commit applied\n%s", display)
			}
		})
	}
}

// CONTROL: a config with no group and no elision must render exactly as before.
// It passed at master and pins that normalizing the display clone did not
// disturb the ordinary path.
func TestInheritanceDisplayUnchangedWithoutGroups9743(t *testing.T) {
	const plain = `routing-instances { blue { instance-type virtual-router; interface ge-0/0/0.0; } }`
	got := parse9743(t, plain).FormatInheritance()
	for _, want := range []string{"routing-instances", "blue", "instance-type virtual-router", "interface ge-0/0/0.0"} {
		if !strings.Contains(got, want) {
			t.Fatalf("plain display must still contain %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "inherited from group") {
		t.Fatalf("a config with no groups must carry no inheritance annotation\n%s", got)
	}
}
