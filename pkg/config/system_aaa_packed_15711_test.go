package config

import (
	"strings"
	"testing"
)

// TestSystemAAARefusalCoversCompactAndPackedSpellings_V42_01 is the
// acceptance regression for #15711: the #10831 refusal of unimplemented
// Junos AAA leaves (radius-server, tacplus-server, authentication-order)
// must fire for brace-elided, packed-run, and nested-run spellings, not
// only for a direct braced child or a Keys[1] head. Strict compile must
// refuse naming the leaf; lenient compile must warn naming the leaf and
// #10831.
func TestSystemAAARefusalCoversCompactAndPackedSpellings_V42_01(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		leaf string
		flat bool
	}{
		{
			name: "brace-elided authentication-order",
			cfg:  `system authentication-order [ radius password ];`,
			leaf: "authentication-order",
		},
		{
			name: "brace-elided radius-server block",
			cfg:  `system radius-server 192.0.2.10 { secret "$9$radius-secret"; }`,
			leaf: "radius-server",
		},
		{
			name: "packed behind host-name on system line",
			cfg:  `system host-name fw1 authentication-order [ tacplus password ];`,
			leaf: "authentication-order",
		},
		{
			name: "packed behind no-redirects inside system block",
			cfg:  `system { no-redirects tacplus-server 192.0.2.20; }`,
			leaf: "tacplus-server",
		},
		// Nested flat-set runs: SetPath nests the AAA leaf under the
		// preceding modelled leaf.
		{
			name: "nested behind host-name flat-set",
			cfg:  "set system host-name fw1 authentication-order tacplus",
			leaf: "authentication-order",
			flat: true,
		},
		{
			name: "nested behind no-redirects flat-set",
			cfg:  "set system no-redirects tacplus-server 192.0.2.20",
			leaf: "tacplus-server",
			flat: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tree *ConfigTree
			if tc.flat {
				tree = aaaTree10831(t, tc.cfg)
			} else {
				var errs []ParseError
				tree, errs = NewParser(tc.cfg).Parse()
				if len(errs) != 0 {
					t.Fatalf("ParseConfig failed: %v", errs)
				}
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), tc.leaf) {
				t.Fatalf("CompileConfig succeeded or missed %q refusal: err=%v", tc.leaf, err)
			}
			compiled, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient failed: %v", err)
			}
			found := false
			for _, w := range compiled.Warnings {
				if strings.Contains(w, tc.leaf) && strings.Contains(w, "#10831") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("CompileConfigLenient missing #10831 warning for %q; got %v", tc.leaf, compiled.Warnings)
			}
		})
	}
}

// TestSystemAAANonStatementValuesNotRefused15711 pins the false-positive
// boundary: an AAA keyword spelled as a VALUE (hostname, domain-search
// entry) or as a deeper identity (login class/user name) is not a direct
// `system` AAA statement and must compile clean in both modes.
func TestSystemAAANonStatementValuesNotRefused15711(t *testing.T) {
	hier := []string{
		`system host-name radius-server;`,
		`system { host-name radius-server; }`,
		`system { host-name tacplus-server; domain-name example.com; }`,
		`system domain-search [ radius-server.example.com ];`,
		`system { domain-search radius-server.example.com; }`,
		`system { login { class radius-server { permissions all; } } }`,
		`system { login { user radius-server { class operator; } } }`,
		`system { host-name fw1; }`,
	}
	for _, src := range hier {
		tree, errs := NewParser(src).Parse()
		if len(errs) != 0 {
			t.Fatalf("parse %q: %v", src, errs)
		}
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("strict compile %q refused a non-statement value: %v", src, err)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile %q: %v", src, err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#10831") {
				t.Fatalf("lenient compile %q emitted AAA refusal for a value: %v", src, cfg.Warnings)
			}
		}
	}
	// Flat-set value control: hostname literally spelled radius-server.
	tree := aaaTree10831(t, "set system host-name radius-server")
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("flat host-name value refused: %v", err)
	}
}
