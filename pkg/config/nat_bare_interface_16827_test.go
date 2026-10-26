package config

import (
	"strings"
	"testing"
)

// #16827: a unit-less NAT from/to interface ref on a plain physical
// interface (only unit 0) compiles to the logical-unit name the
// dataplane compares ("ge-0/0/1.0"); a bare ref naming no unit traffic
// reaches it on (no unit, only a non-zero VLAN unit, or an undeclared
// interface) stays inert and is strict-rejected / lenient-warned.
// RED pre-fix: the bare spelling was stored verbatim and the strict
// gate admitted it, so the rule-set never matched.

func bareNATBase16827() []string {
	return []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
		"set security nat source pool pool1 address 192.0.2.10/32",
		"set security nat destination pool P1 address 10.0.30.100/32",
	}
}

func TestNATBareInterfaceCanonicalizes16827(t *testing.T) {
	// Source from+to bare refs fold to unit 0.
	cfg, err := CompileConfig(buildTree(t, append(bareNATBase16827(),
		"set security nat source rule-set snat-ok from interface ge-0/0/0",
		"set security nat source rule-set snat-ok to interface ge-0/0/1",
		"set security nat source rule-set snat-ok rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-ok rule r1 then source-nat pool pool1")))
	if err != nil {
		t.Fatalf("strict must accept bare refs on plain interfaces: %v", err)
	}
	if len(cfg.Security.NAT.Source) != 1 {
		t.Fatalf("source rule-sets = %d, want 1", len(cfg.Security.NAT.Source))
	}
	rs := cfg.Security.NAT.Source[0]
	if rs.FromInterface != "ge-0/0/0.0" || rs.ToInterface != "ge-0/0/1.0" {
		t.Fatalf("bare scopes = from %q to %q, want ge-0/0/0.0 / ge-0/0/1.0", rs.FromInterface, rs.ToInterface)
	}
	// Destination bare ref.
	cfg, err = CompileConfig(buildTree(t, append(bareNATBase16827(),
		"set security nat destination rule-set dnat-ok from interface ge-0/0/1",
		"set security nat destination rule-set dnat-ok rule R1 match destination-address 198.51.100.5/32",
		"set security nat destination rule-set dnat-ok rule R1 then destination-nat pool P1")))
	if err != nil {
		t.Fatalf("strict must accept bare DNAT ref: %v", err)
	}
	if got := cfg.Security.NAT.Destination.RuleSets[0].FromInterface; got != "ge-0/0/1.0" {
		t.Fatalf("DNAT FromInterface = %q, want ge-0/0/1.0", got)
	}
	// Static bare ref.
	cfg, err = CompileConfig(buildTree(t, append(bareNATBase16827(),
		"set security nat static rule-set stat-ok from interface ge-0/0/1",
		"set security nat static rule-set stat-ok rule R1 match destination-address 198.51.100.5/32",
		"set security nat static rule-set stat-ok rule R1 then static-nat prefix 10.0.0.5/32")))
	if err != nil {
		t.Fatalf("strict must accept bare static ref: %v", err)
	}
	if got := cfg.Security.NAT.Static[0].FromInterface; got != "ge-0/0/1.0" {
		t.Fatalf("static FromInterface = %q, want ge-0/0/1.0", got)
	}
	// lo0 bare ref folds to lo0.0.
	cfg, err = CompileConfig(buildTree(t, append(bareNATBase16827(),
		"set security nat source rule-set snat-lo from interface lo0",
		"set security nat source rule-set snat-lo rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-lo rule r1 then source-nat pool pool1")))
	if err != nil {
		t.Fatalf("strict must accept bare lo0 ref: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "lo0.0" {
		t.Fatalf("lo0 FromInterface = %q, want lo0.0", got)
	}
}

func TestNATBareInterfaceControl16827(t *testing.T) {
	// Unit spellings keep compiling to the same name (control cell).
	cfg, err := CompileConfig(buildTree(t, append(bareNATBase16827(),
		"set security nat source rule-set snat-ok from interface ge-0/0/0.0",
		"set security nat source rule-set snat-ok to interface ge-0/0/1.0",
		"set security nat source rule-set snat-ok rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-ok rule r1 then source-nat pool pool1")))
	if err != nil {
		t.Fatalf("unit-spelled control must compile: %v", err)
	}
	rs := cfg.Security.NAT.Source[0]
	if rs.FromInterface != "ge-0/0/0.0" || rs.ToInterface != "ge-0/0/1.0" {
		t.Fatalf("control scopes = from %q to %q", rs.FromInterface, rs.ToInterface)
	}
	// Undefined unit ref still strict-rejects (gate control).
	_, err = CompileConfig(buildTree(t, append(bareNATBase16827(),
		"set security nat source rule-set snat-bad from interface ge-0/0/9",
		"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1")))
	if err == nil {
		t.Fatal("strict must reject bare ref to undeclared interface ge-0/0/9")
	}
	if !strings.Contains(err.Error(), "ge-0/0/9") {
		t.Fatalf("error must name the bare ref, got: %v", err)
	}
}

func TestNATBareInterfaceInertShapes16827(t *testing.T) {
	// No-unit stanza: strict rejects, lenient warns + records, and the
	// stored value stays bare (never widened to a fabricated unit).
	cmds := append(bareNATBase16827(),
		"set interfaces ge-0/0/5 family inet address 10.0.5.1/24",
		"set security nat source rule-set snat-bad from interface ge-0/0/5",
		"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1")
	if _, err := CompileConfig(buildTree(t, cmds)); err == nil {
		t.Fatal("strict must reject bare ref to a unit-less interface stanza")
	}
	cfg, err := CompileConfigLenient(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("lenient must not hard-fail: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "ge-0/0/5" {
		t.Fatalf("inert bare ref must stay bare, got %q", got)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "snat-bad") && strings.Contains(w, "ge-0/0/5") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient must warn naming snat-bad/ge-0/0/5, warnings=%v", cfg.Warnings)
	}
	if !cfg.LenientNATUndefinedScopeRuleSets["source\x00snat-bad"] {
		t.Fatalf("lenient must record snat-bad in undefined-scope set, got %v", cfg.LenientNATUndefinedScopeRuleSets)
	}

	// A valid non-zero-unit-only interface must not widen a bare ref to .0.
	cmds = append(bareNATBase16827(),
		"set interfaces ge-0/0/6 vlan-tagging",
		"set interfaces ge-0/0/6 unit 1 vlan-id 10 family inet address 10.0.6.1/24",
		"set security nat source rule-set snat-bad from interface ge-0/0/6",
		"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1")
	if _, err := CompileConfig(buildTree(t, cmds)); err == nil ||
		!strings.Contains(err.Error(), `source-nat rule-set "snat-bad": from interface "ge-0/0/6" not defined`) {
		t.Fatalf("strict must reject the unresolved non-zero-unit-only scope with its NAT diagnostic, got %v", err)
	}
	cfg, err = CompileConfigLenient(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("lenient must not hard-fail: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "ge-0/0/6" {
		t.Fatalf("multi-unit bare ref must stay bare (no unit-0 widening), got %q", got)
	}

}

// #17883: a unit-0-plus-tagged-sibling interface is valid, but its bare
// name does not identify one logical unit and must be rejected as a NAT
// scope (rather than accepted as the still-bare, inert name). The
// untagged unit-0-only control remains canonicalizable to .0.
func TestNATBareInterfaceUnitZeroTaggedSiblingRejected17883(t *testing.T) {
	base := append(bareNATBase16827(),
		"set interfaces ge-0/0/7 vlan-tagging",
		"set interfaces ge-0/0/7 unit 0 family inet address 10.0.7.1/24",
		"set interfaces ge-0/0/7 unit 1 vlan-id 10 family inet address 10.0.8.1/24",
	)
	// The interface shape is independently valid; a subsequent error must
	// come from the NAT scope, not the unrelated VLAN consistency gate.
	if _, err := CompileConfig(buildTree(t, base)); err != nil {
		t.Fatalf("tagged unit-0-plus-sibling control must compile: %v", err)
	}
	cmds := append(base,
		"set security nat source rule-set snat-bad from interface ge-0/0/7",
		"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1",
	)
	if _, err := CompileConfig(buildTree(t, cmds)); err == nil ||
		!strings.Contains(err.Error(), `source-nat rule-set "snat-bad": from interface "ge-0/0/7" not defined`) {
		t.Fatalf("strict must reject the unresolved bare NAT scope with its NAT diagnostic, got %v", err)
	}
	cfg, err := CompileConfigLenient(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("lenient must not hard-fail: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "ge-0/0/7" {
		t.Fatalf("unresolved bare scope must stay bare, got %q", got)
	}
	if !cfg.LenientNATUndefinedScopeRuleSets["source\x00snat-bad"] {
		t.Fatalf("lenient must record snat-bad in undefined-scope set, got %v", cfg.LenientNATUndefinedScopeRuleSets)
	}
	foundWarning := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "snat-bad") && strings.Contains(warning, "ge-0/0/7") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatalf("lenient must warn naming snat-bad/ge-0/0/7, warnings=%v", cfg.Warnings)
	}

	// A plain unit-0-only interface still folds its bare NAT scope.
	control := append(bareNATBase16827(),
		"set interfaces ge-0/0/8 unit 0 family inet address 10.0.8.1/24",
		"set security nat source rule-set snat-control from interface ge-0/0/8",
		"set security nat source rule-set snat-control rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-control rule r1 then source-nat pool pool1",
	)
	controlCfg, err := CompileConfig(buildTree(t, control))
	if err != nil {
		t.Fatalf("bare unit-0-only control must compile: %v", err)
	}
	if got := controlCfg.Security.NAT.Source[0].FromInterface; got != "ge-0/0/8.0" {
		t.Fatalf("bare unit-0-only control scope = %q, want ge-0/0/8.0", got)
	}
}

// #17883: a materialized secure-tunnel unit must not let a bare st0
// scope skip the ambiguity veto. With authored st0 units 0 and 1 plus
// VPN bindings for both, bare st0 names neither and must strict-reject
// / lenient-warn+record on every NAT interface scope axis.
func boundST0Base17883() []string {
	return append(bareNATBase16827(),
		"set interfaces st0 unit 0 family inet address 10.9.0.1/30",
		"set interfaces st0 unit 1 family inet address 10.9.1.1/30",
		"set security ipsec vpn vpn0 bind-interface st0.0",
		"set security ipsec vpn vpn1 bind-interface st0.1",
	)
}

func TestNATBareInterfaceBoundST0SiblingRejected17883(t *testing.T) {
	base := boundST0Base17883()
	// The tunnel shape alone is independently valid; this excludes an
	// unrelated IPsec gate as the reason for NAT rejection.
	if _, err := CompileConfig(buildBindIfaceTree(t, base...)); err != nil {
		t.Fatalf("bound st0 unit-0-plus-sibling control must compile: %v", err)
	}

	strictCases := []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "source from",
			cmds: []string{
				"set security nat source rule-set snat-from-bad from interface st0",
				"set security nat source rule-set snat-from-bad rule r1 match source-address 10.0.0.0/8",
				"set security nat source rule-set snat-from-bad rule r1 then source-nat pool pool1",
			},
			want: `source-nat rule-set "snat-from-bad": from interface "st0" not defined`,
		},
		{
			name: "source to with valid from zone",
			cmds: []string{
				"set security nat source rule-set snat-to-bad from zone trust",
				"set security nat source rule-set snat-to-bad to interface st0",
				"set security nat source rule-set snat-to-bad rule r1 match source-address 10.0.0.0/8",
				"set security nat source rule-set snat-to-bad rule r1 then source-nat pool pool1",
			},
			want: `source-nat rule-set "snat-to-bad": to interface "st0" not defined`,
		},
		{
			name: "destination from",
			cmds: []string{
				"set security nat destination rule-set dnat-bad from interface st0",
				"set security nat destination rule-set dnat-bad rule R1 match destination-address 198.51.100.5/32",
				"set security nat destination rule-set dnat-bad rule R1 then destination-nat pool P1",
			},
			want: `destination-nat rule-set "dnat-bad": from interface "st0" not defined`,
		},
		{
			name: "static from",
			cmds: []string{
				"set security nat static rule-set stat-bad from interface st0",
				"set security nat static rule-set stat-bad rule R1 match destination-address 198.51.100.5/32",
				"set security nat static rule-set stat-bad rule R1 then static-nat prefix 10.0.0.5/32",
			},
			want: `static-nat rule-set "stat-bad": from interface "st0" not defined`,
		},
	}
	for _, tc := range strictCases {
		t.Run(tc.name, func(t *testing.T) {
			cmds := append(append([]string(nil), base...), tc.cmds...)
			_, err := CompileConfig(buildBindIfaceTree(t, cmds...))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("strict must reject the scope with diagnostic %q, got %v", tc.want, err)
			}
		})
	}

	cmds := append(append([]string(nil), base...),
		"set security nat source rule-set snat-bad from interface st0",
		"set security nat source rule-set snat-bad to interface st0",
		"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1",
		"set security nat destination rule-set dnat-bad from interface st0",
		"set security nat destination rule-set dnat-bad rule R1 match destination-address 198.51.100.5/32",
		"set security nat destination rule-set dnat-bad rule R1 then destination-nat pool P1",
		"set security nat static rule-set stat-bad from interface st0",
		"set security nat static rule-set stat-bad rule R1 match destination-address 198.51.100.5/32",
		"set security nat static rule-set stat-bad rule R1 then static-nat prefix 10.0.0.5/32",
	)

	cfg, err := CompileConfigLenient(buildBindIfaceTree(t, cmds...))
	if err != nil {
		t.Fatalf("lenient must not hard-fail: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "st0" {
		t.Fatalf("source from scope must stay bare, got %q", got)
	}
	if got := cfg.Security.NAT.Source[0].ToInterface; got != "st0" {
		t.Fatalf("source to scope must stay bare, got %q", got)
	}
	if got := cfg.Security.NAT.Destination.RuleSets[0].FromInterface; got != "st0" {
		t.Fatalf("destination from scope must stay bare, got %q", got)
	}
	if got := cfg.Security.NAT.Static[0].FromInterface; got != "st0" {
		t.Fatalf("static from scope must stay bare, got %q", got)
	}
	wantKeys := map[string]string{
		"source\x00snat-bad":      "snat-bad",
		"destination\x00dnat-bad": "dnat-bad",
		"static\x00stat-bad":      "stat-bad",
	}
	for key, name := range wantKeys {
		if !cfg.LenientNATUndefinedScopeRuleSets[key] {
			t.Errorf("lenient must record %s, got %v", name, cfg.LenientNATUndefinedScopeRuleSets)
		}
		found := false
		for _, warning := range cfg.Warnings {
			if strings.Contains(warning, name) && strings.Contains(warning, "st0") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("lenient must warn naming %s/st0, warnings=%v", name, cfg.Warnings)
		}
	}

	// Explicit unit, bind-only, and lo0 controls retain their behavior.
	explicit := append(boundST0Base17883(),
		"set security nat source rule-set snat-explicit from interface st0.0",
		"set security nat source rule-set snat-explicit rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-explicit rule r1 then source-nat pool pool1",
	)
	cfg, err = CompileConfig(buildBindIfaceTree(t, explicit...))
	if err != nil {
		t.Fatalf("explicit st0.0 control must compile: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "st0.0" {
		t.Fatalf("explicit st0.0 scope = %q, want st0.0", got)
	}

	bindOnly := append(bareNATBase16827(),
		"set security ipsec vpn vpn0 bind-interface st0.0",
		"set security nat source rule-set snat-bind-only from interface st0",
		"set security nat source rule-set snat-bind-only rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-bind-only rule r1 then source-nat pool pool1",
	)
	cfg, err = CompileConfig(buildBindIfaceTree(t, bindOnly...))
	if err != nil {
		t.Fatalf("bind-only bare st0 control must compile: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "st0.0" {
		t.Fatalf("bind-only bare st0 scope = %q, want st0.0", got)
	}

	lo0 := append(bareNATBase16827(),
		"set security nat source rule-set snat-lo from interface lo0",
		"set security nat source rule-set snat-lo rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-lo rule r1 then source-nat pool pool1",
	)
	cfg, err = CompileConfig(buildTree(t, lo0))
	if err != nil {
		t.Fatalf("bare lo0 control must compile: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "lo0.0" {
		t.Fatalf("lo0 scope = %q, want lo0.0", got)
	}
}

// #18024: a binding can materialize unit 0 without an authored unit-0 stanza.
// When authored unit 1 is also present, bare st0 is still ambiguous and must
// be rejected/warned on every NAT interface scope axis.
func TestNATBareInterfaceBindingOnlyUnitZeroSiblingRejected18024(t *testing.T) {
	base := append(bareNATBase16827(),
		"set interfaces st0 unit 1 family inet address 10.9.1.1/30",
		"set security ipsec vpn vpn0 bind-interface st0.0",
		"set security ipsec vpn vpn1 bind-interface st0.1",
	)
	control, err := CompileConfig(buildBindIfaceTree(t, base...))
	if err != nil {
		t.Fatalf("binding-only unit-0-plus-authored-unit-1 control must compile: %v", err)
	}
	ifc := control.Interfaces.Interfaces["st0"]
	if ifc == nil || ifc.Units[0] != nil || ifc.Units[1] == nil {
		t.Fatalf("fixture must have only authored st0 unit 1, got %+v", ifc)
	}
	if _, bound := control.SecureTunnelNetdevForRef("st0.0"); !bound {
		t.Fatal("fixture must materialize bound st0.0 without an authored unit-0 stanza")
	}
	if _, bound := control.SecureTunnelNetdevForRef("st0.1"); !bound {
		t.Fatal("fixture must materialize bound st0.1")
	}

	strictCases := []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "source from",
			cmds: []string{
				"set security nat source rule-set snat-from-bad from interface st0",
				"set security nat source rule-set snat-from-bad rule r1 match source-address 10.0.0.0/8",
				"set security nat source rule-set snat-from-bad rule r1 then source-nat pool pool1",
			},
			want: `source-nat rule-set "snat-from-bad": from interface "st0" not defined`,
		},
		{
			name: "source to",
			cmds: []string{
				"set security nat source rule-set snat-to-bad from zone trust",
				"set security nat source rule-set snat-to-bad to interface st0",
				"set security nat source rule-set snat-to-bad rule r1 match source-address 10.0.0.0/8",
				"set security nat source rule-set snat-to-bad rule r1 then source-nat pool pool1",
			},
			want: `source-nat rule-set "snat-to-bad": to interface "st0" not defined`,
		},
		{
			name: "destination from",
			cmds: []string{
				"set security nat destination rule-set dnat-bad from interface st0",
				"set security nat destination rule-set dnat-bad rule R1 match destination-address 198.51.100.5/32",
				"set security nat destination rule-set dnat-bad rule R1 then destination-nat pool P1",
			},
			want: `destination-nat rule-set "dnat-bad": from interface "st0" not defined`,
		},
		{
			name: "static from",
			cmds: []string{
				"set security nat static rule-set stat-bad from interface st0",
				"set security nat static rule-set stat-bad rule R1 match destination-address 198.51.100.5/32",
				"set security nat static rule-set stat-bad rule R1 then static-nat prefix 10.0.0.5/32",
			},
			want: `static-nat rule-set "stat-bad": from interface "st0" not defined`,
		},
	}
	for _, tc := range strictCases {
		t.Run(tc.name, func(t *testing.T) {
			cmds := append(append([]string(nil), base...), tc.cmds...)
			_, err := CompileConfig(buildBindIfaceTree(t, cmds...))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("strict must reject the scope with diagnostic %q, got %v", tc.want, err)
			}
		})
	}

	cmds := append(append([]string(nil), base...),
		"set security nat source rule-set snat-bad from interface st0",
		"set security nat source rule-set snat-bad to interface st0",
		"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1",
		"set security nat destination rule-set dnat-bad from interface st0",
		"set security nat destination rule-set dnat-bad rule R1 match destination-address 198.51.100.5/32",
		"set security nat destination rule-set dnat-bad rule R1 then destination-nat pool P1",
		"set security nat static rule-set stat-bad from interface st0",
		"set security nat static rule-set stat-bad rule R1 match destination-address 198.51.100.5/32",
		"set security nat static rule-set stat-bad rule R1 then static-nat prefix 10.0.0.5/32",
	)
	cfg, err := CompileConfigLenient(buildBindIfaceTree(t, cmds...))
	if err != nil {
		t.Fatalf("lenient must not hard-fail: %v", err)
	}
	if got := cfg.Security.NAT.Source[0].FromInterface; got != "st0" {
		t.Fatalf("source from scope must stay bare, got %q", got)
	}
	if got := cfg.Security.NAT.Source[0].ToInterface; got != "st0" {
		t.Fatalf("source to scope must stay bare, got %q", got)
	}
	if got := cfg.Security.NAT.Destination.RuleSets[0].FromInterface; got != "st0" {
		t.Fatalf("destination from scope must stay bare, got %q", got)
	}
	if got := cfg.Security.NAT.Static[0].FromInterface; got != "st0" {
		t.Fatalf("static from scope must stay bare, got %q", got)
	}
	wantKeys := map[string]string{
		"source\x00snat-bad":      "snat-bad",
		"destination\x00dnat-bad": "dnat-bad",
		"static\x00stat-bad":      "stat-bad",
	}
	for key, name := range wantKeys {
		if !cfg.LenientNATUndefinedScopeRuleSets[key] {
			t.Errorf("lenient must record %s, got %v", name, cfg.LenientNATUndefinedScopeRuleSets)
		}
		found := false
		for _, warning := range cfg.Warnings {
			if strings.Contains(warning, name) && strings.Contains(warning, "st0") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("lenient must warn naming %s/st0, warnings=%v", name, cfg.Warnings)
		}
	}
}
