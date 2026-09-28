package config

import (
	"strings"
	"testing"
)

func TestDynamicAddressShrinkGuardThresholdsAreValidatedAndCompiled11059(t *testing.T) {
	prefix := "set security dynamic-address feed-server threat"
	cases := []struct {
		leaf string
		good []string
		bad  []string
		want func(*FeedServer) int
	}{
		{
			leaf: "shrink-guard-min-old-count",
			good: []string{"1", "32", "50000", "1048576"},
			bad:  []string{"0", "-1", "1048577", "fast", "999999999999999999999"},
			want: func(fs *FeedServer) int { return fs.ShrinkGuardMinOldCount },
		},
		{
			leaf: "shrink-guard-min-retain-percent",
			good: []string{"1", "50", "100"},
			bad:  []string{"0", "-1", "101", "half", "999999999999999999999"},
			want: func(fs *FeedServer) int { return fs.ShrinkGuardMinRetainPercent },
		},
		{
			leaf: "shrink-guard-min-drop",
			good: []string{"1", "16", "1048575"},
			bad:  []string{"0", "-1", "1048576", "many", "999999999999999999999"},
			want: func(fs *FeedServer) int { return fs.ShrinkGuardMinDrop },
		},
	}

	for _, tc := range cases {
		t.Run(tc.leaf, func(t *testing.T) {
			for _, value := range tc.bad {
				tree := flatTreeFromSets(t, prefix+" "+tc.leaf+" "+value)
				if err := SchemaValidate(tree, nil); err == nil {
					t.Errorf("SchemaValidate accepted invalid %s %q", tc.leaf, value)
				}
			}
			for _, value := range tc.good {
				tree := flatTreeFromSets(t, prefix+" "+tc.leaf+" "+value)
				if err := SchemaValidate(tree, nil); err != nil {
					t.Errorf("SchemaValidate rejected valid %s %q: %v", tc.leaf, value, err)
				}
			}
		})
	}

	tree := flatTreeFromSets(t,
		"set security dynamic-address feed-server threat url https://feeds.example/list",
		"set security dynamic-address feed-server threat shrink-guard-min-old-count 128",
		"set security dynamic-address feed-server threat shrink-guard-min-retain-percent 65",
		"set security dynamic-address feed-server threat shrink-guard-min-drop 24",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("valid runtime-tunable shrink thresholds failed to compile: %v", err)
	}
	fs := cfg.Security.DynamicAddress.FeedServers["threat"]
	if fs == nil {
		t.Fatal("compiled config omitted feed-server threat")
	}
	for _, tc := range cases {
		if got := tc.want(fs); got == 0 {
			t.Errorf("compiled %s did not reach FeedServer", tc.leaf)
		}
	}
	if fs.ShrinkGuardMinOldCount != 128 || fs.ShrinkGuardMinRetainPercent != 65 || fs.ShrinkGuardMinDrop != 24 {
		t.Fatalf("compiled shrink thresholds = (%d,%d,%d), want (128,65,24)",
			fs.ShrinkGuardMinOldCount, fs.ShrinkGuardMinRetainPercent, fs.ShrinkGuardMinDrop)
	}
}

func TestDynamicAddressShrinkGuardInvalidConfigRejected11059(t *testing.T) {
	for _, command := range []string{
		"set security dynamic-address feed-server threat shrink-guard-min-old-count 0",
		"set security dynamic-address feed-server threat shrink-guard-min-retain-percent 101",
		"set security dynamic-address feed-server threat shrink-guard-min-drop 1048576",
	} {
		tree := flatTreeFromSets(t,
			"set security dynamic-address feed-server threat url https://feeds.example/list",
			command,
		)
		if err := SchemaValidate(tree, nil); err == nil {
			t.Errorf("SchemaValidate accepted invalid threshold: %s", command)
		} else if !strings.Contains(err.Error(), strings.Fields(command)[6]) {
			t.Errorf("validation error %q does not identify offending value in %q", err, command)
		}
	}
}
func TestDynamicAddressShrinkGuardCompactTailMatchesBlock11059(t *testing.T) {
	parse := func(t *testing.T, text string) *ConfigTree {
		t.Helper()
		tree, errs := NewParser(text).Parse()
		if len(errs) != 0 {
			t.Fatalf("parse compact feed-server config: %v", errs)
		}
		return tree
	}
	compact := `security { dynamic-address { feed-server threat { url https://feeds.example/list; } feed-server threat shrink-guard-min-old-count 128 shrink-guard-min-retain-percent 65 shrink-guard-min-drop 24; } }`
	block := `security { dynamic-address { feed-server threat { url https://feeds.example/list; shrink-guard-min-old-count 128; shrink-guard-min-retain-percent 65; shrink-guard-min-drop 24; } } }`
	nested := `security { dynamic-address { feed-server threat { url https://feeds.example/list; } feed-server { threat shrink-guard-min-old-count 128 shrink-guard-min-retain-percent 65 shrink-guard-min-drop 24; } } }`
	compile := func(t *testing.T, text string) *FeedServer {
		t.Helper()
		tree := parse(t, text)
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("SchemaValidate rejected valid config: %v", err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected valid config: %v", err)
		}
		if cfg.Security.DynamicAddress.FeedServers["threat"] == nil {
			t.Fatal("compiled config omitted feed-server threat")
		}
		return cfg.Security.DynamicAddress.FeedServers["threat"]
	}
	compactFS := compile(t, compact)
	blockFS := compile(t, block)
	nestedFS := compile(t, nested)
	want := [3]int{128, 65, 24}
	for name, fs := range map[string]*FeedServer{
		"flat compact tail":   compactFS,
		"block":               blockFS,
		"nested compact tail": nestedFS,
	} {
		got := [3]int{fs.ShrinkGuardMinOldCount, fs.ShrinkGuardMinRetainPercent, fs.ShrinkGuardMinDrop}
		if got != want {
			t.Errorf("%s thresholds = %v, want %v", name, got, want)
		}
	}

	for _, invalid := range []string{
		`security { dynamic-address { feed-server threat shrink-guard-min-old-count 0; } }`,
		`security { dynamic-address { feed-server threat shrink-guard-min-retain-percent 101; } }`,
		`security { dynamic-address { feed-server threat shrink-guard-min-drop 1048576; } }`,
	} {
		tree := parse(t, invalid)
		if err := SchemaValidate(tree, nil); err == nil {
			t.Errorf("SchemaValidate accepted invalid compact feed-server tail: %s", invalid)
		}
	}
}
