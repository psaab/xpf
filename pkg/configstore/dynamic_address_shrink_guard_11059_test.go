package configstore

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/feeds"
)

func shrinkGuardConfigText11059(form, leaf, value string) string {
	base := `security { dynamic-address { feed-server threat { url https://192.0.2.1/list; feed-name list; } `
	tail := leaf + " " + value + ";"
	switch form {
	case "flat":
		return base + "feed-server threat " + tail + ` } }`
	case "nested":
		return base + "feed-server { threat " + tail + ` } } }`
	default:
		panic("unknown feed-server spelling: " + form)
	}
}

func TestShrinkGuardInvalidCompactTailsFailStrictValidation11059(t *testing.T) {
	cases := []struct {
		leaf   string
		values []string
	}{
		{"shrink-guard-min-old-count", []string{"0", "-1", "1048577", "fast", "999999999999999999999"}},
		{"shrink-guard-min-retain-percent", []string{"0", "-1", "101", "half", "999999999999999999999"}},
		{"shrink-guard-min-drop", []string{"0", "-1", "1048576", "many", "999999999999999999999"}},
	}
	for _, tc := range cases {
		for _, value := range tc.values {
			for _, form := range []string{"flat", "nested"} {
				t.Run(tc.leaf+"/"+value+"/"+form, func(t *testing.T) {
					text := shrinkGuardConfigText11059(form, tc.leaf, value)
					tree, parseErrs := config.NewParser(text).Parse()
					if len(parseErrs) != 0 {
						t.Fatalf("invalid-threshold fixture failed to parse: %v", parseErrs)
					}
					if err := config.SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), tc.leaf) {
						t.Errorf("SchemaValidate error = %v, want rejection naming %s", err, tc.leaf)
					}
					if _, err := CheckText(text, -1); err == nil || !strings.Contains(err.Error(), tc.leaf) {
						t.Errorf("CheckText error = %v, want strict rejection naming %s", err, tc.leaf)
					}
				})
			}
		}
	}
}

func TestShrinkGuardNestedLenientTailWarnsAndFallsBack11059(t *testing.T) {
	cases := []struct {
		leaf  string
		value string
		want  int
	}{
		{"shrink-guard-min-old-count", "1048577", 1048577},
		{"shrink-guard-min-retain-percent", "101", 101},
		{"shrink-guard-min-drop", "1048576", 1048576},
	}
	for _, tc := range cases {
		t.Run(tc.leaf, func(t *testing.T) {
			text := shrinkGuardConfigText11059("nested", tc.leaf, tc.value)
			tree, parseErrs := config.NewParser(text).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("invalid-threshold fixture failed to parse: %v", parseErrs)
			}
			store := &Store{nodeID: -1}
			cfg, err := store.compileTreeLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile rejected tolerated nested tail: %v", err)
			}
			warning := strings.Join(cfg.Warnings, "\n")
			if !strings.Contains(warning, config.ToleratedTypedLeafWarningPrefix) || !strings.Contains(warning, tc.leaf) {
				t.Fatalf("lenient warnings %q do not identify tolerated %s", warning, tc.leaf)
			}
			fs := cfg.Security.DynamicAddress.FeedServers["threat"]
			if fs == nil {
				t.Fatal("lenient compile omitted feed-server threat")
			}
			var got int
			switch tc.leaf {
			case "shrink-guard-min-old-count":
				got = fs.ShrinkGuardMinOldCount
			case "shrink-guard-min-retain-percent":
				got = fs.ShrinkGuardMinRetainPercent
			case "shrink-guard-min-drop":
				got = fs.ShrinkGuardMinDrop
			}
			if got != tc.want {
				t.Fatalf("lenient compile lost %s value: got %d, want %d", tc.leaf, got, tc.want)
			}

			manager := feeds.New(nil)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			manager.Apply(ctx, &cfg.Security.DynamicAddress)
			info, ok := manager.AllFeeds()["list"]
			manager.StopAll()
			if !ok {
				t.Fatal("runtime manager omitted configured feed list")
			}
			wantDefaults := [3]int{
				config.DefaultDynamicAddressShrinkGuardMinOldCount,
				config.DefaultDynamicAddressShrinkGuardRetainPct,
				config.DefaultDynamicAddressShrinkGuardMinDrop,
			}
			gotDefaults := [3]int{info.ShrinkGuardMinOldCount, info.ShrinkGuardMinRetainPercent, info.ShrinkGuardMinDrop}
			if gotDefaults != wantDefaults {
				t.Fatalf("runtime policy for tolerated %s = %v, want safe defaults %v", tc.leaf, gotDefaults, wantDefaults)
			}
		})
	}
}
