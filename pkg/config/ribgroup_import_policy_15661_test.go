package config

import (
	"strings"
	"testing"
)

// TestRibGroupImportPolicyRejectedAcrossAllASTShapes is the #15661
// regression: validateRibGroupImportPolicyStrict used to walk only the raw
// children of a global `routing-options rib-groups` container, so the
// named-instance spelling (`rib-groups leak { ... }` with no braces around
// the container) and every per-instance definition
// (`routing-instances <name> routing-options rib-groups ...`) committed an
// import-policy the route-leak applier cannot evaluate — an unfiltered
// leak. Every shape below must strict-reject with the targeted
// import-policy diagnostic and warn on the tolerant path; the flat global
// form is the control that already rejected before the fix.
func TestRibGroupImportPolicyRejectedAcrossAllASTShapes(t *testing.T) {
	cases := []struct {
		name string
		tree func(*testing.T) *ConfigTree
		// wantScope is a substring the strict diagnostic must carry so the
		// operator can locate the offending definition.
		wantScope string
		// packed: the single-command packed spelling is rejected earlier
		// by the undefined-import-rib reference gate (its value node packs
		// `import-policy` in as a rib name), exactly as #11314 pinned.
		packed bool
	}{
		{
			name: "flat-global-control",
			tree: func(t *testing.T) *ConfigTree {
				return buildTree(t, []string{
					"set routing-options rib-groups leak import-rib inet.0",
					"set routing-options rib-groups leak import-policy BLOCK",
				})
			},
			wantScope: "routing-options",
		},
		{
			name: "hierarchical-global-braced",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierarchical(t, `routing-options {
					rib-groups { leak { import-rib inet.0; import-policy BLOCK; } }
				}`)
			},
			wantScope: "routing-options",
		},
		{
			name: "hierarchical-global-named-instance",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierarchical(t, `routing-options {
					rib-groups leak { import-rib inet.0; import-policy BLOCK; }
				}`)
			},
			wantScope: "routing-options",
		},
		{
			name: "hierarchical-global-packed-leaf",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierarchical(t, `routing-options {
					rib-groups { leak import-policy BLOCK; }
				}`)
			},
			wantScope: "routing-options",
		},
		{
			name:   "packed-global",
			packed: true,
			tree: func(t *testing.T) *ConfigTree {
				return buildTree(t, []string{
					"set routing-options rib-groups leak import-rib inet.0 import-policy BLOCK",
				})
			},
			wantScope: "routing-options",
		},
		{
			name: "flat-per-instance",
			tree: func(t *testing.T) *ConfigTree {
				return buildTree(t, []string{
					"set routing-instances blue instance-type virtual-router",
					"set routing-instances blue routing-options rib-groups leak import-rib blue.inet.0",
					"set routing-instances blue routing-options rib-groups leak import-policy BLOCK",
				})
			},
			wantScope: "blue",
		},
		{
			name: "hierarchical-per-instance-braced",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierarchical(t, `routing-instances { blue {
					instance-type virtual-router;
					routing-options { rib-groups { leak { import-rib blue.inet.0; import-policy BLOCK; } } }
				} }`)
			},
			wantScope: "blue",
		},
		{
			name: "hierarchical-per-instance-named-instance",
			tree: func(t *testing.T) *ConfigTree {
				return parseHierarchical(t, `routing-instances { blue {
					instance-type virtual-router;
					routing-options { rib-groups leak { import-rib blue.inet.0; import-policy BLOCK; } }
				} }`)
			},
			wantScope: "blue",
		},
		{
			name:   "packed-per-instance",
			packed: true,
			tree: func(t *testing.T) *ConfigTree {
				return buildTree(t, []string{
					"set routing-instances blue instance-type virtual-router",
					"set routing-instances blue routing-options rib-groups leak import-rib blue.inet.0 import-policy BLOCK",
				})
			},
			wantScope: "blue",
		},
		{
			name: "flat-per-instance-packed-single",
			tree: func(t *testing.T) *ConfigTree {
				return buildTree(t, []string{
					"set routing-instances blue instance-type virtual-router",
					"set routing-instances blue routing-options rib-groups leak import-policy BLOCK",
				})
			},
			wantScope: "blue",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.tree(t))
			if err == nil {
				t.Fatal("strict compile accepted an unsupported rib-group import-policy")
			}
			if tc.packed && tc.wantScope == "routing-options" {
				// Global packed: the earlier undefined-import-rib reference
				// gate fires first, exactly as #11314 pinned.
				const packedDiagnostic = `routing-options rib-groups "leak" import-rib "import-policy" references an undefined rib`
				if !strings.Contains(err.Error(), packedDiagnostic) {
					t.Fatalf("strict error = %v, want packed undefined-import-rib diagnostic", err)
				}
			} else if !strings.Contains(err.Error(), "import-policy is not implemented") ||
				!strings.Contains(err.Error(), `"leak"`) ||
				!strings.Contains(err.Error(), tc.wantScope) {
				t.Fatalf("strict error = %v, want targeted import-policy rejection naming leak in %s", err, tc.wantScope)
			}

			cfg, err := CompileConfigLenient(tc.tree(t))
			if err != nil {
				t.Fatalf("tolerant compile rejected a persisted rib-group: %v", err)
			}
			if tc.packed && tc.wantScope == "routing-options" {
				const packedWarning = `routing-options rib-groups "leak" import-rib "import-policy" references an undefined rib`
				if !hasRoutingKnobWarning11314(cfg, packedWarning) {
					t.Fatalf("tolerant warnings do not identify the packed undefined import-rib: %v", cfg.Warnings)
				}
			} else if !hasRoutingKnobWarning11314(cfg, "import-policy", "leak", "not implemented") {
				t.Fatalf("tolerant warnings do not identify the ignored import-policy: %v", cfg.Warnings)
			}
		})
	}

	// Control: a rib-group with no import-policy still commits in both
	// scopes, so the gate did not become a blanket rib-groups rejection.
	t.Run("no-import-policy-commits", func(t *testing.T) {
		for _, tree := range []*ConfigTree{
			buildTree(t, []string{
				"set routing-options rib-groups leak import-rib inet.0",
			}),
			buildTree(t, []string{
				"set routing-instances blue instance-type virtual-router",
				"set routing-instances blue routing-options rib-groups leak import-rib blue.inet.0",
			}),
			parseHierarchical(t, `routing-options {
				rib-groups leak { import-rib inet.0; }
			}`),
		} {
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("rib-group without import-policy rejected: %v", err)
			}
		}
	})
}
