package config_test

// #12067 — strict-reject an UNCONSUMED route-filter tail token. The schema
// leaf is args:2 + multi (pkg/config/schema_routing.go), so a trailing token
// past <prefix> <match-type> is absorbed onto the leaf's packed Keys; the
// compiler only consumes that tail for upto / prefix-length-range / through
// (routeFilterTrailingToken), and validateRouteFilterMatchTypesStrict only
// gates through / malformed range. Every tail was previously accepted by the
// schema gate and discarded by route-filter compilation; a non-keyword tail
// (`orlonger foo`) also passes strict compilation as an unconstrained
// orlonger-style permit. The `reject` action can be caught later by the
// independent #11779 unsupported-from gate, but it is still not represented
// as a per-filter action and that gate runs after compilation. This validator
// rejects the unconsumed token at schema walk, before that lossy interpretation.
//
// These cells require the schema error to NAME the route-filter leaf. The
// trailing controls pin that supported consumed tails keep their current
// acceptance behavior.

import (
	"strings"
	"testing"
)

const rfSetPrefix12067 = "set policy-options policy-statement P term T from route-filter "

func TestSchemaValidate_RouteFilter_UnconsumedTailRejected_12067(t *testing.T) {
	reject := []string{
		// The issue's probe: a per-filter action after a tail-less match-type.
		rfSetPrefix12067 + "10.0.0.0/8 orlonger reject",
		rfSetPrefix12067 + "10.0.0.0/8 exact reject",
		rfSetPrefix12067 + "10.0.0.0/8 longer accept",
		// A non-keyword tail is not caught by #11779's UnknownFrom gate;
		// it commits and compiles to a bare orlonger-style permit today.
		rfSetPrefix12067 + "10.0.0.0/8 orlonger foo",
		rfSetPrefix12067 + "10.0.0.0/8 exact 17",
		// A second token past a CONSUMED upto trailer: the compiler reads
		// only Keys[3] / Children[0].Keys[0], so `extra` is silent.
		rfSetPrefix12067 + "10.0.0.0/8 upto /24 extra",
		// A malformed upto length parses to UptoLen 0 and degrades to the
		// open-ended `le maxLen` — an orlonger-style widening of `upto`.
		rfSetPrefix12067 + "10.0.0.0/8 upto foo",
	}
	for _, cmd := range reject {
		err := flatSchemaCheck(t, cmd,
			"set policy-options policy-statement P term T then accept")
		if err == nil {
			t.Errorf("flat reject %q: expected commit-check error, got nil", cmd)
			continue
		}
		if !strings.Contains(err.Error(), "route-filter") {
			t.Errorf("flat reject %q: error must name the route-filter leaf: %v", cmd, err)
		}
	}
}

func TestSchemaValidate_RouteFilter_UnconsumedTailRejectedHierarchical_12067(t *testing.T) {
	reject := []string{
		`policy-options {
    policy-statement P {
        term T {
            from {
                route-filter 10.0.0.0/8 orlonger reject;
            }
            then accept;
        }
    }
}`,
		`policy-options {
    policy-statement P {
        term T {
            from {
                route-filter 10.0.0.0/8 orlonger foo;
            }
            then accept;
        }
    }
}`,
		`policy-options {
    policy-statement P {
        term T {
            from route-filter 10.0.0.0/8 orlonger foo;
            then accept;
        }
    }
}`,
		`policy-options {
    policy-statement P {
        term T {
            from {
                route-filter 10.0.0.0/8 orlonger {
                    reject;
                }
            }
            then accept;
        }
    }
}`,
		`policy-options {
    policy-statement P {
        term T {
            from {
                route-filter 10.0.0.0/8 { orlonger; }
            }
            then accept;
        }
    }
}`,
		`policy-options {
    policy-statement P {
        term T {
            from route-filter 10.0.0.0/8;
            then accept;
        }
    }
}`,
		`policy-options {
    policy-statement P {
        term T {
            from {
                route-filter 10.0.0.0/8 upto /24 extra;
            }
            then accept;
        }
    }
}`,
		`policy-options {
    policy-statement P {
        term T {
            from {
                route-filter 10.0.0.0/8 upto foo;
            }
            then accept;
        }
    }
}`,
	}
	for i, src := range reject {
		err := schemaCheck(t, src)
		if err == nil {
			t.Errorf("hierarchical reject case %d: expected commit-check error, got nil", i)
			continue
		}
		if !strings.Contains(err.Error(), "route-filter") {
			t.Errorf("hierarchical reject case %d: error must name the route-filter leaf: %v", i, err)
		}
	}
}

// The acceptance criterion's second half: consumed tails stay byte-identical.
// Every form the compiler reads — tail-less match-types, upto /24,
// prefix-length-range /16-/24 (and its bare keyword form, admitted by #2105),
// through (keyword admitted at the schema gate, rejected later by the #2525
// semantic gate) — must keep committing through BOTH AST shapes.
func TestSchemaValidate_RouteFilter_ConsumedTailAccepted_12067(t *testing.T) {
	accept := []string{
		rfSetPrefix12067 + "10.0.0.0/8 exact",
		rfSetPrefix12067 + "10.0.0.0/8 longer",
		rfSetPrefix12067 + "10.0.0.0/8 orlonger",
		rfSetPrefix12067 + "10.0.0.0/8 upto /24",
		rfSetPrefix12067 + "10.0.0.0/8 upto 24",
		rfSetPrefix12067 + "10.0.0.0/8 prefix-length-range /16-/24",
		rfSetPrefix12067 + "10.0.0.0/8 prefix-length-range",
		rfSetPrefix12067 + "10.0.0.0/8 through",
	}
	for _, cmd := range accept {
		if err := flatSchemaCheck(t, cmd,
			"set policy-options policy-statement P term T then accept"); err != nil {
			t.Errorf("flat accept %q: unexpected error: %v", cmd, err)
		}
	}
	hier := `policy-options {
    policy-statement P {
        term T {
            from {
                route-filter 10.0.0.0/8 exact;
                route-filter 10.0.0.0/8 longer;
                route-filter 10.0.0.0/8 orlonger;
                route-filter 10.0.0.0/8 upto /24;
                route-filter 172.16.0.0/12 upto { /24; }
                route-filter 10.0.0.0/8 prefix-length-range /16-/24;
                route-filter 10.0.0.0/8 through 10.0.0.0/16;
            }
            then accept;
        }
    }
}`
	if err := schemaCheck(t, hier); err != nil {
		t.Errorf("hierarchical consumed tails rejected: %v", err)
	}

	compact := `policy-options {
    policy-statement P {
        term T {
            from route-filter 10.0.0.0/8 upto /24;
            then accept;
        }
    }
}`
	if err := schemaCheck(t, compact); err != nil {
		t.Errorf("compact from route-filter consumed tail rejected: %v", err)
	}
}
