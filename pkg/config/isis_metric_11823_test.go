package config

import (
	"strings"
	"testing"
)

// #11823: the IS-IS interface `metric` was untyped, so its compiler's
// strconv.Atoi failure path silently left Metric=0 ("unset"). Garbage,
// negative values, and out-of-range integers therefore committed and rendered
// no valid cost. FRR defaults to wide metrics and accepts 0..16777215.
//
// Channel split (the #1319/#1960 doctrine): SchemaValidate is strict ONLY on
// the operator commit path — Store.compileTreeLenient downgrades a typed-leaf
// violation to a warning — so the compiler layer must ALSO gate: strict commit
// rejects, tolerant load warns, and the renderer omits out-of-domain values.

func isisMetricTree11823(t *testing.T, metric string) *ConfigTree {
	t.Helper()
	return flatTreeFromSets(t,
		"set protocols isis net 49.0001.0100.0000.0001.00",
		"set protocols isis interface ge-0/0/0.0 metric "+metric)
}

// The typed leaf rejects garbage, a named token, negatives, and values beyond
// FRR's wide metric ceiling at commit-check in both hierarchical and flat-set
// spellings; zero and both range boundaries remain valid.
func TestISISMetricSchemaGate11823(t *testing.T) {
	bad := []string{"banana", "default", "-5", "16777216", "9223372036854775808"}
	for _, tok := range bad {
		t.Run("reject-"+tok, func(t *testing.T) {
			if err := SchemaValidate(isisMetricTree11823(t, tok), nil); err == nil {
				t.Fatalf("SchemaValidate accepted isis metric %q; want commit rejection", tok)
			} else if !strings.Contains(err.Error(), "metric") {
				t.Fatalf("rejection for metric %q must name the metric slot: %v", tok, err)
			}
			src := `protocols { isis { net 49.0001.0100.0000.0001.00; interface ge-0/0/0.0 { metric ` + tok + `; } } }`
			tree, perrs := NewParser(src).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture did not parse: %v", perrs)
			}
			if err := SchemaValidate(tree, nil); err == nil {
				t.Fatalf("hierarchical: SchemaValidate accepted isis metric %q; want commit rejection", tok)
			} else if !strings.Contains(err.Error(), "metric") {
				t.Fatalf("hierarchical: rejection for metric %q must name the metric slot: %v", tok, err)
			}
		})
	}
	for _, tok := range []string{"0", "1", "10", "16777215"} {
		t.Run("accept-"+tok, func(t *testing.T) {
			if err := SchemaValidate(isisMetricTree11823(t, tok), nil); err != nil {
				t.Fatalf("SchemaValidate rejected valid isis metric %q: %v", tok, err)
			}
		})
	}
}

// The strict compile path rejects malformed/out-of-range metrics even when
// the config bypasses SchemaValidate (the flat AST helper models that path),
// naming the interface and metric slot. Before the gate, Atoi failures became
// Metric 0 and representable but invalid values reached FRR verbatim.
func TestISISMetricStrictCompileRejects11823(t *testing.T) {
	for _, tok := range []string{"banana", "default", "-5", "16777216", "9223372036854775808"} {
		t.Run("reject-"+tok, func(t *testing.T) {
			_, err := CompileConfig(isisMetricTree11823(t, tok))
			if err == nil {
				t.Fatal("CompileConfig accepted a malformed isis metric; want strict rejection")
			}
			if !strings.Contains(err.Error(), "ge-0/0/0.0") {
				t.Fatalf("strict error must name the interface: %v", err)
			}
			if !strings.Contains(err.Error(), "metric") {
				t.Fatalf("strict error must name the metric slot: %v", err)
			}
		})
	}
}

// Control: zero keeps its documented default meaning and valid integer
// metrics compile and bind exactly as authored, including the 24-bit maximum.
func TestISISMetricValidBinds11823(t *testing.T) {
	for _, tc := range []struct {
		tok  string
		want int
	}{{"0", 0}, {"1", 1}, {"10", 10}, {"16777215", 16777215}} {
		t.Run("metric-"+tc.tok, func(t *testing.T) {
			cfg, err := CompileConfig(isisMetricTree11823(t, tc.tok))
			if err != nil {
				t.Fatalf("CompileConfig rejected valid isis metric %q: %v", tc.tok, err)
			}
			if cfg.Protocols.ISIS == nil || len(cfg.Protocols.ISIS.Interfaces) != 1 {
				t.Fatalf("expected one compiled isis interface, got %+v", cfg.Protocols.ISIS)
			}
			if got := cfg.Protocols.ISIS.Interfaces[0].Metric; got != tc.want {
				t.Fatalf("Metric = %d, want %d", got, tc.want)
			}
		})
	}
}

// The tolerant load / peer-sync path warns (naming the interface) instead of
// hard-erroring (#1960 no-brick); malformed metrics do not reach the renderer.
func TestISISMetricLenientWarns11823(t *testing.T) {
	for _, tok := range []string{"banana", "16777216", "9223372036854775808"} {
		t.Run("warn-"+tok, func(t *testing.T) {
			cfg, err := CompileConfigLenient(isisMetricTree11823(t, tok))
			if err != nil {
				t.Fatalf("CompileConfigLenient hard-rejected isis metric %q (want warn): %v", tok, err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "ge-0/0/0.0") && strings.Contains(w, "metric") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("lenient compile produced no isis metric warning naming the interface; got %v", cfg.Warnings)
			}
		})
	}
}

// The RI copy shares the SAME isis schema pointer as the global one (#9351),
// so a validator on the global node reaches it — but this cell pins the
// routing-instances verdict directly so a future split reds loud.
func TestISISMetricReachesTheRoutingInstanceCopy11823(t *testing.T) {
	src := `routing-instances { VRF-A { protocols { isis { net 49.0001.0100.0000.0001.00; interface ge-0/0/0.0 { metric banana; } } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatal("SchemaValidate accepted an RI isis metric banana; want commit rejection")
	} else if !strings.Contains(err.Error(), "metric") {
		t.Fatalf("RI rejection must name the metric slot: %v", err)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted an RI isis metric banana; want strict rejection")
	}
}
