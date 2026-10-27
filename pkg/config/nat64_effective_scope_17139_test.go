package config

import (
	"reflect"
	"testing"
)

// #17139: the NAT64 effective ingress-scope set is single-sourced in
// NAT64EffectiveZones / NAT64EffectiveRoutingInstances with the
// builder's union-and-dedup semantics (FromZones ∪ {FromZone},
// FromRoutingInstances ∪ {FromRoutingInstance}). A hand-built rule-set
// whose singular disagrees with its plural — FromZone="a",
// FromZones=["b"] — must be seen as {a,b} by the exported normaliser,
// the strict gate, and the scoped owner (shadow) key alike, so a future
// relaxation of the compiler's FromZone=FromZones[0] normalisation
// cannot silently split them.
func TestNAT64EffectiveScopeUnion17139(t *testing.T) {
	rs := &NAT64RuleSet{
		Name: "rs1", Prefix: "64:ff9b::/96",
		FromZone: "a", FromZones: []string{"b"},
		FromRoutingInstance: "r1", FromRoutingInstances: []string{"r2"},
	}
	if got := NAT64EffectiveZones(rs); !reflect.DeepEqual(got, []string{"b", "a"}) {
		t.Fatalf("NAT64EffectiveZones = %v, want [b a] (union, list order first)", got)
	}
	if got := NAT64EffectiveRoutingInstances(nil, rs); !reflect.DeepEqual(got, []string{"r2", "r1"}) {
		t.Fatalf("NAT64EffectiveRoutingInstances = %v, want [r2 r1] (union, list order first)", got)
	}
	// Dedup: a singular already in its plural is not repeated.
	dup := &NAT64RuleSet{FromZone: "b", FromZones: []string{"b"}}
	if got := NAT64EffectiveZones(dup); !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("NAT64EffectiveZones(dup) = %v, want [b]", got)
	}
	// Intra-list duplicates: FromZones ["b","b"] collapses to one
	// token (first occurrence wins), and the owner key is the
	// canonical single-token key for ["b"].
	dupList := &NAT64RuleSet{Prefix: "64:ff9b::/96", FromZones: []string{"b", "b"}}
	if got := NAT64EffectiveZones(dupList); !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("NAT64EffectiveZones(dupList) = %v, want [b]", got)
	}
	keyDupList, ok := nat64PrefixOwnerKeyScoped(nil, dupList)
	if !ok {
		t.Fatal("nat64PrefixOwnerKeyScoped(dupList) not ok")
	}
	keySingleZone, ok := nat64PrefixOwnerKeyScoped(nil, &NAT64RuleSet{Prefix: "64:ff9b::/96", FromZones: []string{"b"}})
	if !ok {
		t.Fatal("nat64PrefixOwnerKeyScoped(single [b]) not ok")
	}
	if keyDupList != keySingleZone {
		t.Fatalf("owner key for FromZones [b b] = %q, want canonical [b] key %q", keyDupList, keySingleZone)
	}
	// "default" singular + "" list member + explicit-master flag: both
	// members lower to the same wire token, so the effective set is ONE
	// token (dedup after lowering), and the owner key is the canonical
	// single-token key.
	defaultDup := &NAT64RuleSet{
		Prefix:              "64:ff9b::/96",
		FromRoutingInstance: "default", FromRoutingInstances: []string{""},
		FromRoutingInstanceDefault: true,
	}
	if got := NAT64EffectiveRoutingInstances(nil, defaultDup); !reflect.DeepEqual(got, []string{NATDefaultRoutingInstanceWire}) {
		t.Fatalf("NAT64EffectiveRoutingInstances(default+\"\"+flag) = %q, want [%q] (one token)", got, NATDefaultRoutingInstanceWire)
	}
	keyDup, ok := nat64PrefixOwnerKeyScoped(nil, defaultDup)
	if !ok {
		t.Fatal("nat64PrefixOwnerKeyScoped(default+\"\"+flag) not ok")
	}
	keyCanonical, ok := nat64PrefixOwnerKeyScoped(nil, &NAT64RuleSet{Prefix: "64:ff9b::/96", FromRoutingInstanceDefault: true})
	if !ok {
		t.Fatal("nat64PrefixOwnerKeyScoped(canonical master) not ok")
	}
	if keyDup != keyCanonical {
		t.Fatalf("owner key for default+\"\"+flag = %q, want canonical single-token key %q", keyDup, keyCanonical)
	}
	// nil and unscoped stay empty.
	if got := NAT64EffectiveZones(nil); got != nil {
		t.Fatalf("NAT64EffectiveZones(nil) = %v, want nil", got)
	}
	if got := NAT64EffectiveZones(&NAT64RuleSet{}); len(got) != 0 {
		t.Fatalf("NAT64EffectiveZones(unscoped) = %v, want empty", got)
	}

	// Shadow key: {b} ∪ {a} keys identically however the union is
	// authored (singular+plural vs plural-only in either order), and
	// differently from either member alone.
	keyUnion, ok := nat64PrefixOwnerKeyScoped(nil, rs)
	if !ok {
		t.Fatal("nat64PrefixOwnerKeyScoped(union) not ok")
	}
	for _, alt := range []*NAT64RuleSet{
		{Prefix: "64:ff9b::/96", FromZones: []string{"b", "a"}, FromRoutingInstances: []string{"r2", "r1"}},
		{Prefix: "64:ff9b::/96", FromZone: "b", FromZones: []string{"a"}, FromRoutingInstance: "r2", FromRoutingInstances: []string{"r1"}},
	} {
		k, _ := nat64PrefixOwnerKeyScoped(nil, alt)
		if k != keyUnion {
			t.Fatalf("owner key for %+v = %q, want union key %q", alt, k, keyUnion)
		}
	}
	keyAOnly, _ := nat64PrefixOwnerKeyScoped(nil, &NAT64RuleSet{Prefix: "64:ff9b::/96", FromZone: "a"})
	if keyAOnly == keyUnion {
		t.Fatalf("owner key for {a} alone must differ from union {a,b}: %q", keyAOnly)
	}

	// Strict gate: with only zone b defined, the union member a (present
	// solely as the singular) must still be rejected as undefined; with
	// both defined the same rule-set passes. The RI twin (singular r1
	// undefined beside plural [r2]) must also be rejected, and the
	// mixed zone+RI union must still be rejected as a mixed clause.
	mkCfg := func(zones []string, ris []string, ruleSets ...*NAT64RuleSet) *Config {
		cfg := &Config{}
		cfg.Security.Zones = map[string]*ZoneConfig{}
		for _, z := range zones {
			cfg.Security.Zones[z] = &ZoneConfig{}
		}
		for _, name := range ris {
			cfg.RoutingInstances = append(cfg.RoutingInstances, &RoutingInstanceConfig{Name: name})
		}
		cfg.Security.NAT.NAT64 = ruleSets
		return cfg
	}
	zoneOnly := &NAT64RuleSet{Name: "rs1", Prefix: "64:ff9b::/96", FromZone: "a", FromZones: []string{"b"}}
	if _, err := validateNAT64ScopeStrict(mkCfg([]string{"b"}, nil, zoneOnly), false); err == nil {
		t.Fatal("gate accepted union {a,b} with zone a undefined; singular member escaped validation")
	}
	if _, err := validateNAT64ScopeStrict(mkCfg([]string{"a", "b"}, nil, zoneOnly), false); err != nil {
		t.Fatalf("gate rejected defined union {a,b}: %v", err)
	}
	if _, err := validateNAT64ScopeStrict(mkCfg([]string{"a", "b"}, nil, rs), false); err == nil {
		t.Fatal("gate accepted mixed zone+RI union rule-set; XOR check lost the union")
	}
	riOnly := &NAT64RuleSet{Name: "rs1", Prefix: "64:ff9b::/96", FromRoutingInstance: "r1", FromRoutingInstances: []string{"r2"}}
	if _, err := validateNAT64ScopeStrict(mkCfg(nil, []string{"r2"}, riOnly), false); err == nil {
		t.Fatal("gate accepted RI union {r1,r2} with r1 undefined; singular member escaped validation")
	}
	if _, err := validateNAT64ScopeStrict(mkCfg(nil, []string{"r1", "r2"}, riOnly), false); err != nil {
		t.Fatalf("gate rejected defined RI union {r1,r2}: %v", err)
	}
}
