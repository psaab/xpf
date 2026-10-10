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

	"github.com/psaab/xpf/pkg/config"
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
		// Invalid lengths parse to UptoLen 0 and degrade to the open-ended
		// `le maxLen` — an orlonger-style widening of `upto`.
		rfSetPrefix12067 + "10.0.0.0/8 upto foo",
		rfSetPrefix12067 + "10.0.0.0/8 upto /129",
		// A missing length has the same UptoLen==0 widening as a malformed one.
		rfSetPrefix12067 + "10.0.0.0/8 upto",
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
		`policy-options {
    policy-statement P {
        term T {
            from {
                route-filter 10.0.0.0/8 upto;
            }
            then accept;
        }
    }
}`,
		`policy-options {
    policy-statement P {
        term T {
            from route-filter 10.0.0.0/8 upto;
            then accept;
        }
    }
}`,
		`policy-options {
    policy-statement P {
        term T {
            from route-filter 10.0.0.0/8 upto protocol static;
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

func policyTermFrom12067(body string) string {
	return `policy-options { policy-statement P { term T { from { ` + body +
		` } then accept; } } }`
}

func TestSchemaValidate_RouteFilter_PreservesSiblingDiagnostics_12067(t *testing.T) {
	cases := []struct {
		name, body, token string
	}{
		{"orlonger then protocol", "route-filter 10.0.0.0/8 orlonger protocol static;", "protocol"},
		{"upto then protocol", "route-filter 10.0.0.0/8 upto /24 protocol static;", "protocol"},
		{"orlonger then prefix-list", "route-filter 10.0.0.0/8 orlonger prefix-list PL;", "prefix-list"},
		{"range then protocol", "route-filter 10.0.0.0/8 prefix-length-range protocol static;", "protocol"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := schemaCheck(t, policyTermFrom12067(tc.body))
			if err == nil || !strings.Contains(err.Error(), "#8437") ||
				!strings.Contains(err.Error(), "missing semicolon") ||
				!strings.Contains(err.Error(), tc.token) {
				t.Fatalf("diagnostic = %v, want actionable #8437 error naming %q", err, tc.token)
			}
		})
	}

	tree, parseErrs := config.NewParser(policyTermFrom12067(
		"route-filter 10.0.0.0/8 exact route-filter 10.1.0.0/16 exact;",
	)).Parse()
	if len(parseErrs) > 0 {
		t.Fatalf("parse self-repeat case: %v", parseErrs[0])
	}
	if _, err := config.CompileConfig(tree); err == nil ||
		!strings.Contains(err.Error(), "repeats its own keyword") || !strings.Contains(err.Error(), "#9027") {
		t.Fatalf("self-repeat diagnostic = %v, want the #9027 ambiguity error", err)
	}
}

func TestSchemaValidate_RouteFilterPackedRunDoesNotDeferRepeatedFrom_12067(t *testing.T) {
	const text = `policy-options { policy-statement P { term T {
from route-filter 10.0.0.0/8 exact from protocol static; then accept;
} } }`
	err := schemaCheck(t, text)
	if err == nil || !strings.Contains(err.Error(), `unconsumed route-filter token "from"`) {
		t.Fatalf("schema error = %v, want the route-filter gate to reject its packed `from` repeat", err)
	}
}

func TestSchemaValidate_RouteFilter_ChildDiagnosticsNameOffendingToken_12067(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"extra after child trailer", "route-filter 10.0.0.0/8 upto { /24 extra; }", `"extra"`},
		{"second child trailer", "route-filter 10.0.0.0/8 upto { /24; /16; }", `"/16"`},
		{"match-type in child form", "route-filter 10.0.0.0/8 { orlonger; }", "match-type must be on the statement line"},
		{"child after orlonger", "route-filter 10.0.0.0/8 orlonger { reject; }", `"reject"`},
		{"child after upto", "route-filter 10.0.0.0/8 upto /24 { reject; }", `"reject"`},
		{"malformed upto token", "route-filter 10.0.0.0/8 upto foo;", "invalid route-filter `upto` length"},
		{"out-of-range upto token", "route-filter 10.0.0.0/8 upto /129;", "invalid route-filter `upto` length"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := schemaCheck(t, policyTermFrom12067(tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("diagnostic = %v, want it to name %s", err, tc.want)
			}
		})
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
