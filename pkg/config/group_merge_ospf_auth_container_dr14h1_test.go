package config

import (
	"slices"
	"testing"
)

// #14414 (DR14-H1): the #4325 cross-shape guard in mergeNodes dropped a
// single-key group CONTAINER when an inline leaf shared only Keys[0].
// That premise ("same key => same content") is false for a packed-tail
// leaf: `authentication md5 1;` carries only the auth TYPE while the
// group container `authentication { md5 1 { key SECRET1; } }` carries
// the KEY. Dropping the container left AuthKey empty and the FRR
// renderer emitted no auth lines while the interface activated
// unauthenticated. The same guard dropped a group policy/firewall
// `from` container beside an inline packed `from ...` leaf
// (DR14-H1-ext), widening the term's match.
//
// The fix exempts packed-tail leaves (len(Keys) > 1) from the guard so
// the container is adopted beside the leaf; compilers already merge
// both siblings (the inline-inline control below proves it). Bare
// leaves (len(Keys) == 1) keep the guard: a genuine duplicate stays
// dropped.

func ospfAuth14388Helper(t *testing.T, text string) *OSPFInterface {
	t.Helper()
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if err := SchemaValidate(tree, cfg); err != nil {
		t.Fatalf("SchemaValidate rejected the fixture: %v", err)
	}
	return ospfIface6818(t, cfg, "group ospf auth")
}

const ospfGroupMain14414 = `
groups { G { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 {
  authentication { md5 1 { key SECRET1; } }
} } } } } }
protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 {
  authentication md5 1;
} } } }
apply-groups G;
`

const ospfInlineControl14414 = `
protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 {
  authentication md5 1;
  authentication { md5 1 { key SECRET1; } }
} } } }
`

func TestGroupOSPFContainerBesidePackedLeaf14414(t *testing.T) {
	for name, text := range map[string]string{
		"group container beside inline packed leaf": ospfGroupMain14414,
		"inline-inline control":                     ospfInlineControl14414,
	} {
		t.Run(name, func(t *testing.T) {
			iface := ospfAuth14388Helper(t, text)
			if iface.AuthType != "md5" {
				t.Fatalf("AuthType = %q, want md5", iface.AuthType)
			}
			if iface.AuthKey.Reveal() != "SECRET1" {
				t.Fatalf("AuthKey = %q, want SECRET1 — group key dropped beside packed leaf (#14414)", iface.AuthKey)
			}
			if iface.AuthKeyID != 1 {
				t.Fatalf("AuthKeyID = %d, want 1", iface.AuthKeyID)
			}
			found := false
			for _, k := range iface.AuthMD5Keys {
				if k.ID == 1 && k.Key.Reveal() == "SECRET1" {
					found = true
				}
			}
			if !found {
				t.Fatalf("AuthMD5Keys = %+v, want {1 SECRET1}", iface.AuthMD5Keys)
			}
		})
	}
}

// The group must also survive when applied at protocols / ospf / area /
// interface level, and when the two halves come from two groups. Group
// bodies mirror the full hierarchy; only the apply point moves.
func TestGroupOSPFContainerApplicationLevels14414(t *testing.T) {
	auth := `authentication { md5 1 { key SECRET1; } }`
	cases := []struct{ name, text string }{
		{"protocols level", `
groups { G { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { ` + auth + ` } } } } } }
protocols { apply-groups G; ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication md5 1; } } } }
`},
		{"ospf level", `
groups { G { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { ` + auth + ` } } } } } }
protocols { ospf { apply-groups G; area 0.0.0.0 { interface ge-0/0/0.0 { authentication md5 1; } } } }
`},
		{"area level", `
groups { G { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { ` + auth + ` } } } } } }
protocols { ospf { area 0.0.0.0 { apply-groups G; interface ge-0/0/0.0 { authentication md5 1; } } } }
`},
		{"interface level", `
groups { G { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { ` + auth + ` } } } } } }
protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { apply-groups G; authentication md5 1; } } } }
`},
		{"two groups", `
groups {
  G1 { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication md5 1; } } } } }
  G2 { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { ` + auth + ` } } } } }
}
protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { } } } }
apply-groups [ G1 G2 ];
`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			iface := ospfAuth14388Helper(t, c.text)
			if iface.AuthType != "md5" || iface.AuthKey.Reveal() != "SECRET1" {
				t.Fatalf("AuthType=%q AuthKey=%q, want md5/SECRET1 (#14414)", iface.AuthType, iface.AuthKey)
			}
		})
	}
}

// Downgrade variant: inline packed simple-password must not suppress a
// group md5 container — the interface must render md5, not cleartext.
func TestGroupOSPFMD5NotDowngradedToSimple14414(t *testing.T) {
	text := `
groups { G { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 {
  authentication { md5 1 { key K2; } }
} } } } } }
protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 {
  authentication simple-password K;
} } } }
apply-groups G;
`
	iface := ospfAuth14388Helper(t, text)
	if iface.AuthType != "md5" {
		t.Fatalf("AuthType = %q, want md5 — group md5 container dropped, simple downgrade (#14414)", iface.AuthType)
	}
	if iface.AuthKey.Reveal() != "K2" {
		t.Fatalf("AuthKey = %q, want K2", iface.AuthKey)
	}
}

// Rollover variant: a second group md5 key must survive beside an
// inline packed key 1.
func TestGroupOSPFRolloverKey14414(t *testing.T) {
	text := `
groups { G { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 {
  authentication { md5 2 { key K2; } }
} } } } } }
protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 {
  authentication md5 1 key K;
} } } }
apply-groups G;
`
	iface := ospfAuth14388Helper(t, text)
	var ids []int
	for _, k := range iface.AuthMD5Keys {
		ids = append(ids, k.ID)
	}
	if !slices.Contains(ids, 1) || !slices.Contains(ids, 2) {
		t.Fatalf("AuthMD5Keys ids = %v, want both 1 and 2 — rollover key dropped (#14414)", ids)
	}
}

// Reverse precedence: inline container key + group type-only packed
// leaf must keep the inline key (leaf branch, inline wins). The group
// leaf `authentication md5 1;` carries type+id but no key; the inline
// container's key must survive.
func TestGroupOSPFReversePrecedence14414(t *testing.T) {
	text := `
groups { G { protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 {
  authentication md5 1;
} } } } } }
protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 {
  authentication { md5 1 { key INLINEK; } }
} } } }
apply-groups G;
`
	iface := ospfAuth14388Helper(t, text)
	if iface.AuthKey.Reveal() != "INLINEK" {
		t.Fatalf("AuthKey = %q, want INLINEK — inline container must win (#14414)", iface.AuthKey.Reveal())
	}
	if iface.AuthType != "md5" {
		t.Fatalf("AuthType = %q, want md5", iface.AuthType)
	}
}

// Genuine-duplicate control: a bare leaf (no packed tail) still
// suppresses the group container exactly as today. `rip;` is bare
// (Keys len 1) and the compiler reads nothing from it, so the group
// rip body stays dropped.
func TestGroupBareLeafDuplicateStillDropped14414(t *testing.T) {
	text := `
groups { G { protocols { rip { authentication-key GROUPKEY; authentication-type md5; } } } }
protocols { rip; }
apply-groups G;
`
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.RIP == nil {
		t.Fatal("RIP config missing")
	}
	if cfg.Protocols.RIP.AuthKey.Reveal() != "" || cfg.Protocols.RIP.AuthType != "" {
		t.Fatalf("bare rip; must still suppress group rip container, got AuthKey=%q AuthType=%q — #4325 guard broken",
			cfg.Protocols.RIP.AuthKey, cfg.Protocols.RIP.AuthType)
	}
}

// DR14-H1-ext (routing): group `from` container beside an inline packed
// `from route-filter ...` leaf — the merged condition bag must survive.
func TestGroupPolicyFromContainerBesidePackedLeaf14414(t *testing.T) {
	text := `
groups { G { policy-options { policy-statement P { term T {
  from { prefix-list PL1; }
} } } } }
policy-options {
  prefix-list PL1 { 10.0.0.0/8; }
  policy-statement P { term T {
    from route-filter 192.168.0.0/16 exact;
    then { accept; }
  } }
}
apply-groups G;
`
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if err := SchemaValidate(tree, cfg); err != nil {
		t.Fatalf("SchemaValidate rejected the fixture: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil || len(ps.Terms) != 1 {
		t.Fatalf("policy P terms = %+v, want one term", ps)
	}
	term := ps.Terms[0]
	if !slices.Contains(term.PrefixList, "PL1") {
		t.Fatalf("PrefixList = %v, want PL1 from group from-container — dropped beside packed from leaf (#14414-ext)", term.PrefixList)
	}
	if len(term.RouteFilters) != 1 || term.RouteFilters[0].Prefix != "192.168.0.0/16" {
		t.Fatalf("RouteFilters = %+v, want inline 192.168.0.0/16 exact", term.RouteFilters)
	}
	if term.Action != "accept" {
		t.Fatalf("Action = %q, want accept", term.Action)
	}
}

// DR14-H1-ext (firewall): group `from` container beside an inline
// packed `from` leaf in a filter term.
func TestGroupFirewallFromContainerBesidePackedLeaf14414(t *testing.T) {
	text := `
groups { G { firewall { family inet { filter F { term T {
  from { destination-address 10.1.0.0/16; }
} } } } } }
firewall { family inet { filter F { term T {
  from is-fragment;
  then { accept; }
} } } }
apply-groups G;
`
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if err := SchemaValidate(tree, cfg); err != nil {
		t.Fatalf("SchemaValidate rejected the fixture: %v", err)
	}
	term := firstInetTerm(t, cfg, "F")
	if !term.IsFragment {
		t.Fatalf("IsFragment = false, want inline packed from is-fragment kept")
	}
	if !slices.Contains(term.DestAddresses, "10.1.0.0/16") {
		t.Fatalf("DestAddresses = %v, want group 10.1.0.0/16 — from container dropped beside packed from leaf (#14414-ext)", term.DestAddresses)
	}
}
