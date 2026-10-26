package config

import (
	"strings"
	"testing"
)

// #15678: NAT64 rule-set ingress scoping (`from zone|routing-instance`,
// `match source-address[-name]`) compiles into the typed rule-set, and the
// strict gate rejects mixed/undefined/unparsable scoping while the lenient
// path warns. Fail-on-revert: dropping the compileNAT64 scope arms leaves
// every scoped field empty and the first test fails; dropping the gate
// leaves the reject tests green-compiling.

func nat64ScopeLines(extra ...string) []string {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set routing-instances blue instance-type virtual-router",
		"set security address-book global address clients-v6 2001:db8:1::/48",
		"set security nat source pool p64 address 100.64.0.1/32",
		"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set rs1 source-pool p64",
	}
	return append(lines, extra...)
}

func compileNAT64ScopeTree(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	// Build the tree directly: buildTree auto-defines every referenced
	// zone (#15001 helper), which would mask the undefined-zone reject.
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

func compileNAT64Scope(t *testing.T, lines []string) (*Config, error) {
	t.Helper()
	return CompileConfig(compileNAT64ScopeTree(t, lines))
}

func TestNAT64ScopeCompiles15678(t *testing.T) {
	cfg, err := compileNAT64Scope(t, nat64ScopeLines(
		"set security nat nat64 rule-set rs1 from zone trust",
		"set security nat nat64 rule-set rs1 match source-address 2001:db8:1::/48",
		"set security nat nat64 rule-set rs1 match source-address-name clients-v6",
	))
	if err != nil {
		t.Fatalf("scoped NAT64 must compile: %v", err)
	}
	if len(cfg.Security.NAT.NAT64) != 1 {
		t.Fatalf("NAT64 rule-sets = %d, want 1", len(cfg.Security.NAT.NAT64))
	}
	rs := cfg.Security.NAT.NAT64[0]
	if rs.FromZone != "trust" {
		t.Fatalf("FromZone = %q, want trust", rs.FromZone)
	}
	if rs.FromRoutingInstance != "" {
		t.Fatalf("FromRoutingInstance = %q, want empty", rs.FromRoutingInstance)
	}
	if len(rs.SourceAddresses) != 1 || rs.SourceAddresses[0] != "2001:db8:1::/48" {
		t.Fatalf("SourceAddresses = %v, want [2001:db8:1::/48]", rs.SourceAddresses)
	}
	if len(rs.SourceAddressNames) != 1 || rs.SourceAddressNames[0] != "clients-v6" {
		t.Fatalf("SourceAddressNames = %v, want [clients-v6]", rs.SourceAddressNames)
	}
}

func TestNAT64ScopeRoutingInstance15678(t *testing.T) {
	cfg, err := compileNAT64Scope(t, nat64ScopeLines(
		"set security nat nat64 rule-set rs1 from routing-instance blue",
	))
	if err != nil {
		t.Fatalf("RI-scoped NAT64 must compile: %v", err)
	}
	rs := cfg.Security.NAT.NAT64[0]
	if rs.FromRoutingInstance != "blue" || rs.FromZone != "" {
		t.Fatalf("scope = zone %q ri %q, want ri blue", rs.FromZone, rs.FromRoutingInstance)
	}
}

func TestNAT64ScopeUnscopedStaysGlobal15678(t *testing.T) {
	cfg, err := compileNAT64Scope(t, nat64ScopeLines())
	if err != nil {
		t.Fatalf("unscoped NAT64 must compile: %v", err)
	}
	rs := cfg.Security.NAT.NAT64[0]
	if rs.FromZone != "" || rs.FromRoutingInstance != "" || len(rs.SourceAddresses) != 0 {
		t.Fatalf("unscoped rule-set carried scope: %+v", rs)
	}
}

func TestNAT64ScopeStrictRejects15678(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []string
		want  string
	}{
		{"mixed-from", []string{
			"set security nat nat64 rule-set rs1 from zone trust",
			"set security nat nat64 rule-set rs1 from routing-instance blue",
		}, "mixes 2 scope kinds"},
		{"undefined-zone", []string{
			"set security nat nat64 rule-set rs1 from zone nosuchzone",
		}, "from-zone"},
		{"undefined-ri", []string{
			"set security nat nat64 rule-set rs1 from routing-instance nosuchri",
		}, "routing-instance"},
		{"bad-source", []string{
			"set security nat nat64 rule-set rs1 match source-address not-an-ip",
		}, "source-address"},
		{"v4-source", []string{
			"set security nat nat64 rule-set rs1 match source-address 10.0.0.0/24",
		}, "not IPv6"},
		{"undefined-name", []string{
			"set security nat nat64 rule-set rs1 match source-address-name nosuchname",
		}, "source-address-name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileNAT64Scope(t, nat64ScopeLines(tc.extra...))
			if err == nil {
				t.Fatalf("%s must be rejected at strict commit", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
			// Lenient path warns, never bricks (#1960).
			if _, lerr := CompileConfigLenient(buildTree(t, nat64ScopeLines(tc.extra...))); lerr != nil {
				t.Fatalf("lenient path must not brick on %s: %v", tc.name, lerr)
			}
		})
	}
}

// TestNAT64ScopedShadowing15678: two same-prefix rule-sets in DIFFERENT
// zones are not shadowed (each is reachable in its scope); a second
// rule-set in the SAME zone is.
func TestNAT64ScopedShadowing15678(t *testing.T) {
	cfg := &Config{}
	cfg.Security.NAT.NAT64 = []*NAT64RuleSet{
		{Name: "a", Prefix: "64:ff9b::/96", SourcePool: "p1", FromZone: "trust"},
		{Name: "b", Prefix: "64:ff9b::/96", SourcePool: "p2", FromZone: "untrust"},
		{Name: "c", Prefix: "64:ff9b::/96", SourcePool: "p3", FromZone: "trust"},
	}
	shadowed := nat64ShadowedRuleSets(cfg)
	if _, ok := shadowed[cfg.Security.NAT.NAT64[1]]; ok {
		t.Fatal("different-zone rule-set b must not be shadowed by a")
	}
	if _, ok := shadowed[cfg.Security.NAT.NAT64[2]]; !ok {
		t.Fatal("same-zone rule-set c must be shadowed by a")
	}
	a, b := cfg.Security.NAT.NAT64[0], cfg.Security.NAT.NAT64[1]
	ka, _ := nat64PrefixOwnerKeyScoped(cfg, a)
	kb, _ := nat64PrefixOwnerKeyScoped(cfg, b)
	if ka == kb {
		t.Fatalf("scoped owner keys must differ by zone: %q == %q", ka, kb)
	}
}

// #15932: a bracket `from zone [ trust untrust ]` list must UNION on
// the ONE authored rule-set (the pre-fix compiler kept only the last
// zone). Exactly one typed rule-set is emitted — expanding into
// snapshot siblings would give the shared pool one PortAllocator per
// zone and double-mint it. Fail-on-revert: expanding to two rule-sets,
// or keeping only "untrust" in FromZones, fails below.
func TestNAT64ZoneListUnions15932(t *testing.T) {
	cfg, err := compileNAT64Scope(t, nat64ScopeLines(
		"set security nat nat64 rule-set rs1 from zone [ trust untrust ]",
	))
	if err != nil {
		t.Fatalf("bracket zone list must compile: %v", err)
	}
	if len(cfg.Security.NAT.NAT64) != 1 {
		t.Fatalf("NAT64 rule-sets = %d, want 1 (no snapshot expansion)", len(cfg.Security.NAT.NAT64))
	}
	rs := cfg.Security.NAT.NAT64[0]
	if rs.Name != "rs1" || rs.Prefix != "64:ff9b::/96" || rs.SourcePool != "p64" {
		t.Fatalf("rule-set lost identity: %+v", rs)
	}
	if len(rs.FromZones) != 2 || rs.FromZones[0] != "trust" || rs.FromZones[1] != "untrust" {
		t.Fatalf("FromZones = %v, want [trust untrust]", rs.FromZones)
	}
	if rs.FromZone != "trust" {
		t.Fatalf("FromZone = %q, want first authored zone trust", rs.FromZone)
	}
	// Repeated single-value form unions the same way.
	cfg2, err := compileNAT64Scope(t, nat64ScopeLines(
		"set security nat nat64 rule-set rs1 from zone trust",
		"set security nat nat64 rule-set rs1 from zone untrust",
	))
	if err != nil {
		t.Fatalf("repeated zone form must compile: %v", err)
	}
	if len(cfg2.Security.NAT.NAT64) != 1 || len(cfg2.Security.NAT.NAT64[0].FromZones) != 2 {
		t.Fatalf("repeated form = %+v, want one rule-set with two zones", cfg2.Security.NAT.NAT64)
	}
	// An undefined member of the list is still rejected (every value checked).
	if _, err := compileNAT64Scope(t, nat64ScopeLines(
		"set security nat nat64 rule-set rs1 from zone [ trust nosuchzone ]",
	)); err == nil || !strings.Contains(err.Error(), "nosuchzone") {
		t.Fatalf("undefined list member must reject, got %v", err)
	}
	// One authored rule-set over one pool is ONE allocator owner (#5144):
	// the bracket form above compiled clean as a single owner; a mixed
	// zone+RI clause still rejects.
	if _, err := compileNAT64Scope(t, nat64ScopeLines(
		"set security nat nat64 rule-set rs1 from zone trust",
		"set security nat nat64 rule-set rs1 from routing-instance blue",
	)); err == nil || !strings.Contains(err.Error(), "mixes 2 scope kinds") {
		t.Fatalf("mixed zone+RI must reject, got %v", err)
	}
}

// #16049: a bracket `from routing-instance [ a b ]` list must UNION on
// the ONE authored rule-set (the pre-fix compiler kept only the last
// RI, and the strict gate checked only that survivor — a nonexistent
// first member committed clean). Exactly one typed rule-set is
// emitted — expanding into snapshot siblings would give the shared
// pool one PortAllocator per RI and double-mint it. Fail-on-revert:
// keeping only the last RI in FromRoutingInstances, or checking only
// the singular in the strict gate, fails below.
func TestNAT64RoutingInstanceListUnions16049(t *testing.T) {
	lines := func(extra ...string) []string {
		base := []string{
			"set security zones security-zone trust",
			"set routing-instances blue instance-type virtual-router",
			"set routing-instances red instance-type virtual-router",
			"set security nat source pool p64 address 100.64.0.1/32",
			"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
			"set security nat nat64 rule-set rs1 source-pool p64",
		}
		return append(base, extra...)
	}
	cfg, err := compileNAT64Scope(t, lines(
		"set security nat nat64 rule-set rs1 from routing-instance [ blue red ]",
	))
	if err != nil {
		t.Fatalf("bracket RI list must compile: %v", err)
	}
	if len(cfg.Security.NAT.NAT64) != 1 {
		t.Fatalf("NAT64 rule-sets = %d, want 1 (no snapshot expansion)", len(cfg.Security.NAT.NAT64))
	}
	rs := cfg.Security.NAT.NAT64[0]
	if len(rs.FromRoutingInstances) != 2 || rs.FromRoutingInstances[0] != "blue" || rs.FromRoutingInstances[1] != "red" {
		t.Fatalf("FromRoutingInstances = %v, want [blue red]", rs.FromRoutingInstances)
	}
	if rs.FromRoutingInstance != "blue" {
		t.Fatalf("FromRoutingInstance = %q, want first authored RI blue", rs.FromRoutingInstance)
	}
	// Repeated single-value form unions the same way.
	cfg2, err := compileNAT64Scope(t, lines(
		"set security nat nat64 rule-set rs1 from routing-instance blue",
		"set security nat nat64 rule-set rs1 from routing-instance red",
	))
	if err != nil {
		t.Fatalf("repeated RI form must compile: %v", err)
	}
	if len(cfg2.Security.NAT.NAT64) != 1 || len(cfg2.Security.NAT.NAT64[0].FromRoutingInstances) != 2 {
		t.Fatalf("repeated form = %+v, want one rule-set with two RIs", cfg2.Security.NAT.NAT64)
	}
	// Decisive: a nonexistent FIRST member is rejected — pre-fix it
	// was dropped by last-wins and never reached the strict gate.
	if _, err := compileNAT64Scope(t, lines(
		"set security nat nat64 rule-set rs1 from routing-instance [ nosuchri red ]",
	)); err == nil || !strings.Contains(err.Error(), "nosuchri") {
		t.Fatalf("undefined first RI member must reject, got %v", err)
	}
	// A nonexistent LAST member is likewise rejected (order-independent).
	if _, err := compileNAT64Scope(t, lines(
		"set security nat nat64 rule-set rs1 from routing-instance [ blue nosuchri ]",
	)); err == nil || !strings.Contains(err.Error(), "nosuchri") {
		t.Fatalf("undefined last RI member must reject, got %v", err)
	}
	// Lenient path warns, never bricks (#1960).
	if _, lerr := CompileConfigLenient(buildTree(t, lines(
		"set security nat nat64 rule-set rs1 from routing-instance [ nosuchri red ]",
	))); lerr != nil {
		t.Fatalf("lenient path must not brick on undefined RI member: %v", lerr)
	}
	// Mixed zone+RI list clause still rejects.
	if _, err := compileNAT64Scope(t, lines(
		"set security nat nat64 rule-set rs1 from zone trust",
		"set security nat nat64 rule-set rs1 from routing-instance blue",
	)); err == nil || !strings.Contains(err.Error(), "mixes 2 scope kinds") {
		t.Fatalf("mixed zone+RI must reject, got %v", err)
	}
}
