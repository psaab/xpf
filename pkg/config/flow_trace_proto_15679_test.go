package config

import (
	"strings"
	"testing"
)

// #15679 regression: packet-filter protocol lacked validation (bogus/empty/0/256
// committed verbatim), a bare filter with no selector widened to match-all, and
// SchemaValidate treated the leaf as opaque. Strict must reject, lenient must
// warn + mark InvalidPrefix (match-none), and valid named/numeric protocols must
// still commit. RED on base: every strict case returned nil error.
func TestFlowTraceProto15679StrictRejects(t *testing.T) {
	cases := []struct{ name, set, want string }{
		{"empty-protocol", `set security flow traceoptions packet-filter pf1 protocol ""`, "protocol"},
		{"bogus-protocol", "set security flow traceoptions packet-filter pf1 protocol bogus", "bogus"},
		{"out-of-range", "set security flow traceoptions packet-filter pf1 protocol 256", "256"},
		{"zero-protocol", "set security flow traceoptions packet-filter pf1 protocol 0", "protocol"},
		{"no-selector", "set security flow traceoptions packet-filter pf1", "packet-filter pf1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, []string{tc.set}))
			if err == nil {
				t.Fatalf("strict must reject %s", tc.set)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %q want %q", err, tc.want)
			}
		})
	}
	// SchemaValidate must also reject bogus/empty/0/256 and accept valid.
	for _, bad := range []string{"bogus", `""`, "0", "256"} {
		tree := buildTree(t, []string{"set security flow traceoptions packet-filter pf1 protocol " + bad})
		if err := SchemaValidate(tree, nil); err == nil {
			t.Fatalf("SchemaValidate must reject protocol %s", bad)
		}
	}
	for _, good := range []string{"tcp", "ospf", "47", "255"} {
		tree := buildTree(t, []string{"set security flow traceoptions packet-filter pf1 protocol " + good})
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("SchemaValidate rejected valid protocol %s: %v", good, err)
		}
	}
	// Hierarchical (braced) spelling must be gated the same as flat set.
	hier := "security { flow { traceoptions { packet-filter pf1 { protocol bogus; } } } }"
	hp := NewParser(hier)
	htree, errs := hp.Parse()
	if errs != nil {
		t.Fatalf("parse hierarchical: %v", errs)
	}
	if _, err := CompileConfig(htree); err == nil {
		t.Fatalf("hierarchical bogus protocol must be rejected")
	}
	if err := SchemaValidate(htree, nil); err == nil {
		t.Fatalf("SchemaValidate must reject hierarchical bogus protocol")
	}
}

func TestFlowTraceProto15679ValidAndLenient(t *testing.T) {
	for _, proto := range []string{"tcp", "udp", "ospf", "47", "89", "255", "gre"} {
		cfg, err := CompileConfig(buildTree(t, []string{"set security flow traceoptions packet-filter pf1 protocol " + proto}))
		if err != nil {
			t.Fatalf("valid %s rejected: %v", proto, err)
		}
		if cfg.Security.Flow.Traceoptions.PacketFilters[0].InvalidPrefix {
			t.Fatalf("valid %s marked invalid", proto)
		}
	}
	// lenient: bogus -> warning + InvalidPrefix
	cfg, err := CompileConfigLenient(buildTree(t, []string{"set security flow traceoptions packet-filter pf1 protocol bogus"}))
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "bogus") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient warnings %v want bogus", cfg.Warnings)
	}
	if !cfg.Security.Flow.Traceoptions.PacketFilters[0].InvalidPrefix {
		t.Fatalf("lenient bogus not InvalidPrefix")
	}
	// lenient: no-selector -> warning + InvalidPrefix
	cfg2, err := CompileConfigLenient(buildTree(t, []string{"set security flow traceoptions packet-filter pf1"}))
	if err != nil {
		t.Fatalf("lenient2: %v", err)
	}
	if !cfg2.Security.Flow.Traceoptions.PacketFilters[0].InvalidPrefix {
		t.Fatalf("lenient bare filter not InvalidPrefix")
	}
}
