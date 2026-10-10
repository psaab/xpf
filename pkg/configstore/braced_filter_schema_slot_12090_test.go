package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBracedFilterSchemaSlotsReject12090(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{
			name: "interface-unit-identity",
			text: "interfaces { ge-0/0/0 { unit { 0 filter input f; } } }",
		},
		{
			name: "sampling-instance-identity",
			text: "forwarding-options { sampling { instance { s filter input f; } } }",
		},
		{
			name: "relay-group-identity",
			text: "forwarding-options { dhcp-relay { server-group sg { 10.0.0.1; } group { lan filter input f; lan { active-server-group sg; interface ge-0/0/0.0; } } } }",
		},
		{
			name: "flat-unit-control",
			text: "interfaces { ge-0/0/0 { unit 0 filter input f; } }",
		},
		{
			name: "fully-braced-unit-control",
			text: "interfaces { ge-0/0/0 { unit { 0 { filter input f; } } } }",
		},
		{
			name: "flat-instance-control",
			text: "forwarding-options { sampling { instance s filter input f; } }",
		},
		{
			name: "fully-braced-instance-control",
			text: "forwarding-options { sampling { instance { s { filter input f; } } } }",
		},
		{
			name: "relay-filter-child-control",
			text: "forwarding-options { dhcp-relay { server-group sg { 10.0.0.1; } group lan { active-server-group sg; interface ge-0/0/0.0; filter { input f; } } } }",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CheckText(tc.text, -1); err == nil || !strings.Contains(err.Error(), "#12090") {
				t.Fatalf("CheckText error = %v; want #12090 rejection", err)
			}

			tree, parseErrors := config.NewParser(tc.text).Parse()
			if len(parseErrors) != 0 {
				t.Fatalf("parse test config: %v", parseErrors)
			}
			compiled, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			warned := false
			for _, warning := range compiled.Warnings {
				if strings.Contains(warning, "#12090") {
					warned = true
					break
				}
			}
			if !warned {
				t.Fatalf("lenient compile warnings = %q; want #12090", compiled.Warnings)
			}

			store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			defer store.ExitConfigure()
			if err := store.LoadOverride(tc.text); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			if _, err := store.Commit(); err == nil || !strings.Contains(err.Error(), "#12090") {
				t.Fatalf("Store Commit error = %v; want #12090 rejection", err)
			}
		})
	}
}

func TestBracedUnitIdentityFilterConsumersRetainHooks12090(t *testing.T) {
	for _, iface := range []string{"ge-0/0/0", "lo0"} {
		for _, family := range []string{"inet", "inet6"} {
			for _, shape := range []string{"compound", "split"} {
				t.Run(iface+"/"+family+"/"+shape, func(t *testing.T) {
					var binding string
					if shape == "compound" {
						binding = "family " + family + " { filter { input f; } }"
					} else {
						binding = "family { " + family + " { filter { input f; } } }"
					}
					text := "firewall { family { " + family +
						" { filter f { term t { then accept; } } } } } " +
						"interfaces { " + iface + " { unit { 0 { " + binding + " } } } }"
					compiled, err := CheckText(text, -1)
					if err != nil {
						t.Fatalf("CheckText rejected supported %s/%s filter: %v", iface, family, err)
					}
					ifaceConfig := compiled.Interfaces.Interfaces[iface]
					if ifaceConfig == nil || ifaceConfig.Units[0] == nil {
						t.Fatalf("compiled interface/unit missing: %#v", ifaceConfig)
					}
					unit := ifaceConfig.Units[0]
					got := unit.FilterInputV4
					if family == "inet6" {
						got = unit.FilterInputV6
					}
					if got != "f" {
						t.Fatalf("%s/%s filter hook = %q, want f", iface, family, got)
					}
					for _, warning := range compiled.Warnings {
						if strings.Contains(warning, "#12090") {
							t.Fatalf("supported filter emitted #12090 warning: %q", warning)
						}
					}
				})
			}
		}
	}
}

func TestBracedUnitIdentityFilterListsRejected12090(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		for _, shape := range []string{"compound", "split"} {
			for _, direction := range []string{"input-list", "output-list"} {
				for _, defined := range []bool{true, false} {
					name := family + "/" + shape + "/" + direction + "/undefined"
					value := "missing"
					firewall := ""
					if defined {
						name = family + "/" + shape + "/" + direction + "/defined"
						value = "f"
						firewall = "firewall { family " + family +
							" { filter f { term t { then accept; } } } } "
					}
					t.Run(name, func(t *testing.T) {
						filter := "filter { " + direction + " " + value + "; }"
						var binding string
						if shape == "compound" {
							binding = "family " + family + " { " + filter + " }"
						} else {
							binding = "family { " + family + " { " + filter + " } }"
						}
						text := firewall + "interfaces { lo0 { unit { 0 { " + binding +
							" } } } }"

						if _, err := CheckText(text, -1); err == nil || !strings.Contains(err.Error(), "#12090") {
							t.Fatalf("CheckText error = %v; want #12090 rejection", err)
						}

						tree, parseErrors := config.NewParser(text).Parse()
						if len(parseErrors) != 0 {
							t.Fatalf("parse test config: %v", parseErrors)
						}
						compiled, err := config.CompileConfigLenient(tree)
						if err != nil {
							t.Fatalf("lenient compile: %v", err)
						}
						warned := false
						for _, warning := range compiled.Warnings {
							if strings.Contains(warning, "#12090") {
								warned = true
								break
							}
						}
						if !warned {
							t.Fatalf("lenient compile warnings = %q; want #12090", compiled.Warnings)
						}

						store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
						if err := store.EnterConfigure(); err != nil {
							t.Fatalf("EnterConfigure: %v", err)
						}
						defer store.ExitConfigure()
						if err := store.LoadOverride(text); err != nil {
							t.Fatalf("LoadOverride: %v", err)
						}
						if _, err := store.Commit(); err == nil || !strings.Contains(err.Error(), "#12090") {
							t.Fatalf("Store Commit error = %v; want #12090 rejection", err)
						}
					})
				}
			}
		}
	}
}

func TestBracedUnitIdentityFilterPackedChildRejected12090(t *testing.T) {
	cases := []struct {
		name, text, wantError string
	}{
		{
			name: "defined-filter",
			text: "interfaces { ge-0/0/0 { unit { 0 { family inet { filter input f; } } } } } " +
				"firewall { family inet { filter f { term t { then accept; } } } }",
			wantError: "#12090",
		},
		{
			name:      "undefined-filter",
			text:      "interfaces { ge-0/0/0 { unit { 0 { family inet { filter input f; } } } } }",
			wantError: "#12090",
		},
		{
			name:      "semi-braced-undefined-filter-control",
			text:      "interfaces { ge-0/0/0 { unit 0 { family inet { filter input f; } } } }",
			wantError: "references undefined filter",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CheckText(tc.text, -1); err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("CheckText error = %v; want %q", err, tc.wantError)
			}

			tree, parseErrors := config.NewParser(tc.text).Parse()
			if len(parseErrors) != 0 {
				t.Fatalf("parse test config: %v", parseErrors)
			}
			compiled, err := config.CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			warned := false
			for _, warning := range compiled.Warnings {
				if strings.Contains(warning, tc.wantError) {
					warned = true
					break
				}
			}
			if !warned {
				t.Fatalf("lenient compile warnings = %q; want %q", compiled.Warnings, tc.wantError)
			}

			store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			defer store.ExitConfigure()
			if err := store.LoadOverride(tc.text); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			if _, err := store.Commit(); err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("Store Commit error = %v; want %q", err, tc.wantError)
			}
		})
	}
}

func TestBracedUnitIdentityPackedFilterTailsRemainRejected12090(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		for _, shape := range []string{"compound", "split"} {
			t.Run(family+"/"+shape, func(t *testing.T) {
				var binding string
				if shape == "compound" {
					binding = "family " + family + " filter input f;"
				} else {
					binding = "family { " + family + " filter input f; }"
				}
				text := "interfaces { ge-0/0/0 { unit { 0 { " + binding + " } } } }"
				if _, err := CheckText(text, -1); err == nil || !strings.Contains(err.Error(), "#12090") {
					t.Fatalf("unconsumed packed filter tail error = %v; want #12090", err)
				}
			})
		}
	}
}
