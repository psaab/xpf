package config

import "testing"

// Temporary hostile-review probe on the fold commit — deleted after run.
func TestZZProbeFoldExpandedUndercount17257(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			"typed-visible-container-then-empty",
			`firewall { family inet { filter F {
				term { from { source-address 10.0.0.0/8; } then accept; }
				term { }
			} } }`,
		},
		{
			"nested-named-container-then-empty",
			`firewall { family inet { filter F {
				term { allow-tcp { from { protocol tcp; } then accept; } allow-udp { from { protocol udp; } then accept; } }
				term { }
			} } }`,
		},
		{
			"two-empty-terms",
			`firewall { family inet { filter F {
				term { }
				term { }
			} } }`,
		},
	}
	for _, tc := range cases {
		cfg, err := CompileConfigLenient(hierTree(t, tc.src))
		if err != nil {
			t.Fatalf("%s: lenient: %v", tc.name, err)
		}
		f := cfg.Firewall.FiltersInet["F"]
		if f == nil {
			t.Logf("%s: filter F missing", tc.name)
			continue
		}
		got := []string{}
		for _, tm := range f.Terms {
			got = append(got, tm.Name+"/"+string(tm.Action)+"/"+boolStr(tm.nameless))
		}
		t.Logf("%s -> terms: %v", tc.name, got)
	}
}

func boolStr(b bool) string {
	if b {
		return "Y"
	}
	return "n"
}
