package config

import (
	"strings"
	"testing"
)

// #16873 (R3-B09-01): NAT64 shadow detection ignored the earlier rule-set's
// `match source-address` scope. A source-scoped earlier rule-set was treated
// as covering every source, so a reachable same-/96 sibling got a false
// UNREACHABLE warning on every commit and was dropped from the #5144
// pool-overlap owner set (a zone-scoped twin sharing a pool was refused,
// the source-scoped twin committed clean).
//
// Acceptance (issue): T2/T4 emit no UNREACHABLE warning, T4 rejects with
// the same #5144 message as the zone-scoped T3, and T1 (true shadow) still
// warns. Fail-on-revert: restoring the pre-fix key-only shadow predicate
// (source ignored) marks b shadowed in T2/T4, so the no-warning assertions
// and the T4 rejection go RED.

// nat64SrcShadowCmds builds the T-cell config: rule-set a then b on the
// same /96, with extra authored lines appended per rule-set.
func nat64SrcShadowCmds(poolA, poolB string, aExtra, bExtra []string) []string {
	cmds := []string{
		"set security nat source pool p1 address 198.51.100.1/32",
		"set security nat source pool p2 address 198.51.100.2/32",
		"set security nat nat64 rule-set a prefix 64:ff9b::/96",
		"set security nat nat64 rule-set a source-pool " + poolA,
		"set security nat nat64 rule-set b prefix 64:ff9b::/96",
		"set security nat nat64 rule-set b source-pool " + poolB,
	}
	cmds = append(cmds, aExtra...)
	cmds = append(cmds, bExtra...)
	return cmds
}

func aSrc(src string) []string {
	return []string{"set security nat nat64 rule-set a match source-address " + src}
}
func bSrc(src string) []string {
	return []string{"set security nat nat64 rule-set b match source-address " + src}
}

// T1 control: both unscoped, same /96 — b is truly unreachable and warns.
func TestNAT64SrcShadowT1TrueShadowStillWarns16873(t *testing.T) {
	acceptedWithUnreachable9555(t, "b",
		nat64SrcShadowCmds("p1", "p2", nil, nil)...)
}

// T2: a is source-scoped, b is unscoped (distinct pools). Sources outside
// a's /64 reach b, so b must NOT be warned unreachable and must compile.
func TestNAT64SrcShadowT2ScopedEarlierDoesNotShadow16873(t *testing.T) {
	cmds := nat64SrcShadowCmds("p1", "p2", aSrc("2001:db8:1::/64"), nil)
	cfg, err := CompileConfig(natOverlapTree(t, cmds...))
	if err != nil {
		t.Fatalf("T2 must compile clean: %v", err)
	}
	if w := unreachableWarning9555(cfg, "b"); w != "" {
		t.Fatalf("T2: b is reachable for sources outside 2001:db8:1::/64, must not warn UNREACHABLE; got %q", w)
	}
}

// T4: a and b have disjoint source prefixes and share ONE pool. Both are
// reachable independent allocators over the same pool address, so strict
// commit must reject with the same #5144 message as the zone twin (T3).
func TestNAT64SrcShadowT4DisjointSourcesSamePoolRejected16873(t *testing.T) {
	cmds := nat64SrcShadowCmds("p1", "p1", aSrc("2001:db8:1::/64"), bSrc("2001:db8:2::/64"))
	assertNATOverlapRejected(t, "independent NAT allocators", cmds...)
	// And no false UNREACHABLE for b on the lenient path.
	cfg, err := CompileConfigLenient(natOverlapTree(t, cmds...))
	if err != nil {
		t.Fatalf("lenient must not brick: %v", err)
	}
	if w := unreachableWarning9555(cfg, "b"); w != "" {
		t.Fatalf("T4: b must not be warned UNREACHABLE; got %q", w)
	}
}

// T3 control: zone-scoped twins sharing one pool — already refused
// pre-fix; pinning it guards the scope-cover generalisation.
func TestNAT64SrcShadowT3ZoneTwinSamePoolRejected16873(t *testing.T) {
	cmds := nat64SrcShadowCmds("p1", "p1",
		[]string{"set security nat nat64 rule-set a from zone trust"},
		[]string{"set security nat nat64 rule-set b from zone dmz"})
	assertNATOverlapRejected(t, "independent NAT allocators", cmds...)
}

// Covering source: a's /48 covers b's /64 — b truly never matches, warns.
func TestNAT64SrcShadowCoveringSourceStillWarns16873(t *testing.T) {
	acceptedWithUnreachable9555(t, "b",
		nat64SrcShadowCmds("p1", "p2", aSrc("2001:db8::/48"), bSrc("2001:db8:0:1::/64"))...)
}

// Partial overlap is not coverage: a /64 vs b /63 (b wider) — b reachable.
func TestNAT64SrcShadowPartialOverlapDoesNotShadow16873(t *testing.T) {
	cmds := nat64SrcShadowCmds("p1", "p2", aSrc("2001:db8:0:1::/64"), bSrc("2001:db8::/63"))
	cfg, err := CompileConfig(natOverlapTree(t, cmds...))
	if err != nil {
		t.Fatalf("partial-overlap pair must compile: %v", err)
	}
	if w := unreachableWarning9555(cfg, "b"); w != "" {
		t.Fatalf("b's /63 is not covered by a's /64; must not warn; got %q", w)
	}
}

// Equal source sets: later is fully covered — warns (unit-level, plus
// combined zone+source coverage).
func TestNAT64SrcShadowUnit16873(t *testing.T) {
	mk := func(srcs []string, zone string) *NAT64RuleSet {
		rs := &NAT64RuleSet{Name: "x", Prefix: "64:ff9b::/96", SourcePool: "p"}
		rs.SourceAddresses = srcs
		if zone != "" {
			rs.FromZone = zone
		}
		return rs
	}
	cases := []struct {
		name    string
		a, b    *NAT64RuleSet
		shadowB bool
	}{
		{"equal-src", mk([]string{"2001:db8:1::/64"}, ""), mk([]string{"2001:db8:1::/64"}, ""), true},
		{"a-wider", mk([]string{"2001:db8::/48"}, ""), mk([]string{"2001:db8:0:1::/64"}, ""), true},
		{"a-narrower", mk([]string{"2001:db8:0:1::/64"}, ""), mk([]string{"2001:db8::/48"}, ""), false},
		{"disjoint", mk([]string{"2001:db8:0:1::/64"}, ""), mk([]string{"2001:db8:0:2::/64"}, ""), false},
		{"a-scoped-b-any", mk([]string{"2001:db8:1::/64"}, ""), mk(nil, ""), false},
		{"a-any-b-scoped", mk(nil, ""), mk([]string{"2001:db8:1::/64"}, ""), true},
		{"both-any", mk(nil, ""), mk(nil, ""), true},
		{"union-covers", mk([]string{"2001:db8:1::/64", "2001:db8:2::/64"}, ""), mk([]string{"2001:db8:2::/64"}, ""), true},
		{"union-misses", mk([]string{"2001:db8:1::/64"}, ""), mk([]string{"2001:db8:1::/64", "2001:db8:2::/64"}, ""), false},
		{"wildcard-a", mk([]string{"::/0"}, ""), mk([]string{"2001:db8:1::/64"}, ""), true},
		{"bare-host-covered", mk([]string{"2001:db8::/48"}, ""), mk([]string{"2001:db8:0:1::5"}, ""), true},
		{"unparseable-a-unknown", mk([]string{"not-an-ip"}, ""), mk([]string{"2001:db8:1::/64"}, ""), false},
		{"unparseable-b-unknown", mk([]string{"2001:db8::/48"}, ""), mk([]string{"not-an-ip"}, ""), false},
		// Zone axis: earlier scoped to trust does not cover an
		// unscoped later (packets from other zones reach it), but an
		// unscoped earlier covers a zone-scoped later, and a wider
		// zone set covers a narrower one.
		{"zone-a-scoped-b-any", mk(nil, "trust"), mk(nil, ""), false},
		{"zone-a-any-b-scoped", mk(nil, ""), mk(nil, "trust"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.a.Name, tc.b.Name = "a", "b"
			cfg := &Config{}
			cfg.Security.NAT.NAT64 = []*NAT64RuleSet{tc.a, tc.b}
			_, shadowed := nat64ShadowedRuleSets(cfg)[tc.b]
			if shadowed != tc.shadowB {
				t.Fatalf("shadow(b) = %v, want %v (a sources %v zone %q, b sources %v zone %q)",
					shadowed, tc.shadowB, tc.a.SourceAddresses, tc.a.FromZone, tc.b.SourceAddresses, tc.b.FromZone)
			}
		})
	}
}

// Name-resolved sources: a name covering b's literal shadows; a disjoint
// name does not. Unresolvable-at-commit-time names (dns without snapshot)
// prove nothing, so no UNREACHABLE claim.
func TestNAT64SrcShadowAddressNames16873(t *testing.T) {
	book := func() *AddressBook {
		return &AddressBook{Addresses: map[string]*Address{
			"wide":   {Name: "wide", Value: "2001:db8::/48"},
			"narrow": {Name: "narrow", Value: "2001:db8:0:9::/64"},
		}, AddressSets: map[string]*AddressSet{}}
	}
	a := &NAT64RuleSet{Name: "a", Prefix: "64:ff9b::/96", SourcePool: "p1", SourceAddressNames: []string{"wide"}}
	b := &NAT64RuleSet{Name: "b", Prefix: "64:ff9b::/96", SourcePool: "p2", SourceAddresses: []string{"2001:db8:0:1::/64"}}
	cfg := &Config{}
	cfg.Security.AddressBook = book()
	cfg.Security.NAT.NAT64 = []*NAT64RuleSet{a, b}
	if _, ok := nat64ShadowedRuleSets(cfg)[b]; !ok {
		t.Fatal("name 'wide' (2001:db8::/48) covers b's /64: b must be shadowed")
	}
	a.SourceAddressNames = []string{"narrow"}
	if _, ok := nat64ShadowedRuleSets(cfg)[b]; ok {
		t.Fatal("name 'narrow' is disjoint from b's /64: b must not be shadowed")
	}
	// Unknown name proves nothing.
	a.SourceAddressNames = []string{"missing"}
	if _, ok := nat64ShadowedRuleSets(cfg)[b]; ok {
		t.Fatal("unresolvable name must not prove shadowing")
	}
}

// F1 (review fold): a wildcard beside a poisoned name matches NOTHING
// at the dataplane (builder resolves all names first; poison wins over
// wildcard), so it must not prove unconstrained coverage. a carries
// `any` (in each wildcard position, names in both orders) plus a
// defined dns-name with no answers; b is unconstrained. Pre-fold the
// early wildcard return marked b shadowed.
func TestNAT64SrcShadowWildcardPoisonedName16873(t *testing.T) {
	dnsLine := "set security address-book global address dns-clients dns-name clients.example.net"
	cases := []struct {
		name   string
		aExtra []string
	}{
		{"literal-any-first", append(aSrc("any"), "set security nat nat64 rule-set a match source-address-name dns-clients")},
		{"slash0-first", append(aSrc("::/0"), "set security nat nat64 rule-set a match source-address-name dns-clients")},
		{"name-any-first", []string{
			"set security nat nat64 rule-set a match source-address-name any",
			"set security nat nat64 rule-set a match source-address-name dns-clients",
		}},
		{"name-any-last", []string{
			"set security nat nat64 rule-set a match source-address-name dns-clients",
			"set security nat nat64 rule-set a match source-address-name any",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmds := append([]string{dnsLine}, nat64SrcShadowCmds("p1", "p2", tc.aExtra, nil)...)
			cfg, err := CompileConfig(natOverlapTree(t, cmds...))
			if err != nil {
				t.Fatalf("wildcard+defined-dns config must compile (dns admitted, #15930): %v", err)
			}
			if w := unreachableWarning9555(cfg, "b"); w != "" {
				t.Fatalf("a matches nothing (poison wins over wildcard), so b is reachable; must not warn UNREACHABLE; got %q", w)
			}
			foundB := false
			for _, o := range natPoolOverlapOwners(cfg) {
				if strings.Contains(o.desc, "rule-set \"b\"") {
					foundB = true
				}
			}
			if !foundB {
				t.Fatalf("b must remain in #5144 owner set, owners = %v", natPoolOverlapOwners(cfg))
			}
		})
	}
	// Control: wildcard beside a VALID name still proves match-any and
	// shadows b (builder lowers it to unconstrained ::/0).
	t.Run("valid-name-control", func(t *testing.T) {
		cmds := append([]string{
			"set security address-book global address clients-v6 2001:db8:1::/48",
		}, nat64SrcShadowCmds("p1", "p2",
			[]string{
				"set security nat nat64 rule-set a match source-address any",
				"set security nat nat64 rule-set a match source-address-name clients-v6",
			}, nil)...)
		acceptedWithUnreachable9555(t, "b", cmds...)
	})
	// A name resolving to ::/0 beside a poisoned name likewise proves
	// nothing (the resolved wildcard is only reached after poison is
	// excluded for every name).
	t.Run("resolves-slash0-plus-poison", func(t *testing.T) {
		cmds := append([]string{
			dnsLine,
			"set security address-book global address all-v6 ::/0",
		}, nat64SrcShadowCmds("p1", "p2",
			[]string{
				"set security nat nat64 rule-set a match source-address-name all-v6",
				"set security nat nat64 rule-set a match source-address-name dns-clients",
			}, nil)...)
		cfg, err := CompileConfig(natOverlapTree(t, cmds...))
		if err != nil {
			t.Fatalf("must compile: %v", err)
		}
		if w := unreachableWarning9555(cfg, "b"); w != "" {
			t.Fatalf("poisoned sibling name defeats resolved ::/0 wildcard; must not warn; got %q", w)
		}
	})
}

// F2 (review fold): an empty NESTED address-set poisons the whole
// runtime closure (expandBookNameRecursive), even when sibling leaves
// survive. The static proof must not flatten it away: `parents`
// (wide + empty-set) must not prove coverage of b. Removing the empty
// member is the positive control and does shadow b.
func TestNAT64SrcShadowNestedEmptySetPoison16873(t *testing.T) {
	bookLines := []string{
		"set security address-book global address wide 2001:db8::/48",
		"set security address-book global address-set empty description none",
		"set security address-book global address-set parents address wide",
		"set security address-book global address-set parents address-set empty",
	}
	aName := []string{"set security nat nat64 rule-set a match source-address-name parents"}
	cmds := append(append([]string{}, bookLines...),
		nat64SrcShadowCmds("p1", "p2", aName, bSrc("2001:db8:0:1::/64"))...)
	cfg, err := CompileConfig(natOverlapTree(t, cmds...))
	if err != nil {
		t.Fatalf("nested-empty-set config must compile (member-definedness gate passes): %v", err)
	}
	if w := unreachableWarning9555(cfg, "b"); w != "" {
		t.Fatalf("a's closure is poisoned by the empty nested set, so b is reachable; must not warn; got %q", w)
	}
	foundB := false
	for _, o := range natPoolOverlapOwners(cfg) {
		if strings.Contains(o.desc, "rule-set \"b\"") {
			foundB = true
		}
	}
	if !foundB {
		t.Fatal("b must remain in #5144 owner set when a's name closure is poisoned")
	}
	// Positive control: same book without the empty member shadows b.
	ctrlLines := []string{
		"set security address-book global address wide 2001:db8::/48",
		"set security address-book global address-set parents address wide",
	}
	ctrl := append(append([]string{}, ctrlLines...),
		nat64SrcShadowCmds("p1", "p2", aName, bSrc("2001:db8:0:1::/64"))...)
	acceptedWithUnreachable9555(t, "b", ctrl...)
}

func nat64OwnerDescs16873(cfg *Config) []string {
	var out []string
	for _, o := range natPoolOverlapOwners(cfg) {
		out = append(out, o.desc)
	}
	return out
}

func nat64HasOwner16873(cfg *Config, rsName string) bool {
	for _, d := range nat64OwnerDescs16873(cfg) {
		if strings.Contains(d, "rule-set \""+rsName+"\"") {
			return true
		}
	}
	return false
}

// Re-review F1: distinct unprovable selectors must never serialise to
// the same owner key. Witness: a references ONE feed binding named
// "left,right"; b references TWO bindings "left" and "right". The old
// comma-joined fallback keyed both "?left,right" and dropped b from
// the #5144 owners over the shared pool. Both must stay owners, so
// strict rejects and lenient warns with #5144; neither is UNREACHABLE.
// The identical-selector control still collapses/shadows.
func TestNAT64UnknownOwnerKeyNoCollision16873(t *testing.T) {
	feedLines := []string{
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name f1 path /f1.txt",
		"set security dynamic-address feed-server threat feed-name f2 path /f2.txt",
		"set security dynamic-address feed-server threat feed-name f3 path /f3.txt",
		"set security dynamic-address address-name left,right profile feed-name f1",
		"set security dynamic-address address-name left profile feed-name f2",
		"set security dynamic-address address-name right profile feed-name f3",
	}
	aExtra := []string{"set security nat nat64 rule-set a match source-address-name left,right"}
	bExtra := []string{
		"set security nat nat64 rule-set b match source-address-name left",
		"set security nat nat64 rule-set b match source-address-name right",
	}
	cmds := append(append([]string{}, feedLines...), nat64SrcShadowCmds("p1", "p1", aExtra, bExtra)...)
	// Strict must reject (both owners over p1); lenient warns #5144.
	assertNATOverlapRejected(t, "independent NAT allocators", cmds...)
	cfg, err := CompileConfigLenient(natOverlapTree(t, cmds...))
	if err != nil {
		t.Fatalf("lenient must not brick: %v", err)
	}
	if !nat64HasOwner16873(cfg, "a") || !nat64HasOwner16873(cfg, "b") {
		t.Fatalf("both unprovable rule-sets must remain owners, got %v", nat64OwnerDescs16873(cfg))
	}
	if w := unreachableWarning9555(cfg, "b"); w != "" {
		t.Fatalf("unprovable a must not shadow b; got %q", w)
	}
	// Namespace-move variant: the SAME token in different namespaces
	// must not collide either. a carries literal 2001:db8:9::/64 plus
	// a poisoned dns name (whole side unprovable); b carries the name
	// "2001:db8:9::/64" (a feed binding with that literal name). Both
	// stay independent owners over the shared pool.
	moveLines := append(append([]string{},
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name f9 path /f9.txt",
		"set security dynamic-address address-name 2001:db8:9::/64 profile feed-name f9",
		"set security address-book global address dns-clients dns-name clients.example.net",
	), nat64SrcShadowCmds("p1", "p1",
		[]string{
			"set security nat nat64 rule-set a match source-address 2001:db8:9::/64",
			"set security nat nat64 rule-set a match source-address-name dns-clients",
		},
		[]string{"set security nat nat64 rule-set b match source-address-name 2001:db8:9::/64"})...)
	assertNATOverlapRejected(t, "independent NAT allocators", moveLines...)
	mcfg, merr := CompileConfigLenient(natOverlapTree(t, moveLines...))
	if merr != nil {
		t.Fatalf("lenient must not brick: %v", merr)
	}
	if !nat64HasOwner16873(mcfg, "a") || !nat64HasOwner16873(mcfg, "b") {
		t.Fatalf("namespace-move pair must both remain owners, got %v", nat64OwnerDescs16873(mcfg))
	}
	// Identical-selector control: both reference the same single
	// binding — b is still not shadowed (feed unprovable), but both
	// stay owners and #5144 still fires over the shared pool.
	same := append(append([]string{}, feedLines...), nat64SrcShadowCmds("p1", "p1",
		[]string{"set security nat nat64 rule-set a match source-address-name left"},
		[]string{"set security nat nat64 rule-set b match source-address-name left"})...)
	assertNATOverlapRejected(t, "independent NAT allocators", same...)
}

// Gate fold (Opus): nat64PrefixOwnerKeyScoped comma-joined the zone/RI
// sets, so a zone literally named "x,y" collided with zones {x, y} and
// the owner dedup dropped a live rule-set. Zones x,y / x / y all
// defined; a is `from zone x,y`, b is `from zone x` + `from zone y`;
// same /96, same pool. The scopes are genuinely disjoint, so both are
// owners: strict rejects #5144, lenient warns, no UNREACHABLE. The
// identical-scope control (both `from zone x,y`) still deduplicates
// (b shadowed, one owner, accepted with the warning).
func TestNAT64CommaZoneOwnerKeyNoCollision16873(t *testing.T) {
	zoneLines := []string{
		"set security zones security-zone x,y",
		"set security zones security-zone x",
		"set security zones security-zone y",
	}
	aXY := []string{"set security nat nat64 rule-set a from zone x,y"}
	bXY := []string{
		"set security nat nat64 rule-set b from zone x",
		"set security nat nat64 rule-set b from zone y",
	}
	cmds := append(append([]string{}, zoneLines...), nat64SrcShadowCmds("p1", "p1", aXY, bXY)...)
	assertNATOverlapRejected(t, "independent NAT allocators", cmds...)
	cfg, err := CompileConfigLenient(natOverlapTree(t, cmds...))
	if err != nil {
		t.Fatalf("lenient must not brick: %v", err)
	}
	if !nat64HasOwner16873(cfg, "a") || !nat64HasOwner16873(cfg, "b") {
		t.Fatalf("comma-zone pair must both remain owners, got %v", nat64OwnerDescs16873(cfg))
	}
	if w := unreachableWarning9555(cfg, "b"); w != "" {
		t.Fatalf("zone x,y does not cover zones {x,y}; must not warn; got %q", w)
	}
	// Unit pin: the scoped keys themselves must differ.
	ka, _ := nat64PrefixOwnerKeyScoped(&NAT64RuleSet{Prefix: "64:ff9b::/96", FromZones: []string{"x,y"}})
	kb, _ := nat64PrefixOwnerKeyScoped(&NAT64RuleSet{Prefix: "64:ff9b::/96", FromZones: []string{"x", "y"}})
	if ka == kb {
		t.Fatalf("scoped keys must differ for zone \"x,y\" vs {x,y}: %q", ka)
	}
	// RI twin: instance "r,s" vs {r, s}.
	kr1, _ := nat64PrefixOwnerKeyScoped(&NAT64RuleSet{Prefix: "64:ff9b::/96", FromRoutingInstances: []string{"r,s"}})
	kr2, _ := nat64PrefixOwnerKeyScoped(&NAT64RuleSet{Prefix: "64:ff9b::/96", FromRoutingInstances: []string{"r", "s"}})
	if kr1 == kr2 {
		t.Fatalf("scoped keys must differ for RI \"r,s\" vs {r,s}: %q", kr1)
	}
	// Identical-scope control: both from zone x,y — b shadowed, one
	// owner, accepted with UNREACHABLE (no #5144 double-owner).
	sameScope := append(append([]string{}, zoneLines...), nat64SrcShadowCmds("p1", "p1", aXY,
		[]string{"set security nat nat64 rule-set b from zone x,y"})...)
	acceptedWithUnreachable9555(t, "b", sameScope...)
}

// Re-review F2: a zoned literal (2001:db8::1%eth0) parses in Go but is
// dropped by Rust, so it enforces no coverage. a = [::1%eth0, ::2],
// b = [::1]: only ::2 is really claimed by a, so b stays reachable.
// The unzoned control ([::1, ::2]) does shadow b.
func TestNAT64ZonedLiteralNoCoverage16873(t *testing.T) {
	zoned := nat64SrcShadowCmds("p1", "p1",
		[]string{
			"set security nat nat64 rule-set a match source-address 2001:db8::1%eth0",
			"set security nat nat64 rule-set a match source-address 2001:db8::2",
		}, bSrc("2001:db8::1"))
	cfg, err := CompileConfig(natOverlapTree(t, zoned...))
	// Strict may reject via #5144 (both owners over p1) — that is the
	// safe outcome; it must NOT accept with a false UNREACHABLE, and
	// the lenient path must keep b as an owner without the warning.
	if err == nil {
		if w := unreachableWarning9555(cfg, "b"); w != "" {
			t.Fatalf("zoned literal must not prove coverage; got %q", w)
		}
	} else if !strings.Contains(err.Error(), "#5144") {
		t.Fatalf("strict outcome must be #5144 rejection or clean accept, got: %v", err)
	}
	lcfg, lerr := CompileConfigLenient(natOverlapTree(t, zoned...))
	if lerr != nil {
		t.Fatalf("lenient must not brick: %v", lerr)
	}
	if w := unreachableWarning9555(lcfg, "b"); w != "" {
		t.Fatalf("lenient: zoned literal must not shadow b; got %q", w)
	}
	if !nat64HasOwner16873(lcfg, "b") {
		t.Fatalf("b must remain a #5144 owner, got %v", nat64OwnerDescs16873(lcfg))
	}
	// Unzoned positive control shadows b.
	acceptedWithUnreachable9555(t, "b", nat64SrcShadowCmds("p1", "p2",
		[]string{
			"set security nat nat64 rule-set a match source-address 2001:db8::1",
			"set security nat nat64 rule-set a match source-address 2001:db8::2",
		}, bSrc("2001:db8::1"))...)
	// Zoned value via an address-book name likewise proves nothing.
	unit := &Config{}
	unit.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{
		"zoned": {Name: "zoned", Value: "2001:db8::1%eth0"},
	}, AddressSets: map[string]*AddressSet{}}
	ua := &NAT64RuleSet{Name: "a", Prefix: "64:ff9b::/96", SourcePool: "p1", SourceAddressNames: []string{"zoned"}}
	ub := &NAT64RuleSet{Name: "b", Prefix: "64:ff9b::/96", SourcePool: "p2", SourceAddresses: []string{"2001:db8::1"}}
	unit.Security.NAT.NAT64 = []*NAT64RuleSet{ua, ub}
	if _, ok := nat64ShadowedRuleSets(unit)[ub]; ok {
		t.Fatal("zoned name value must not prove coverage")
	}
}

// Re-review F3: warm-cache DNS answers are mutable. A dns-name with
// answers at compile time must stay unprovable (a later refresh can
// move the set without re-running tail gates), through nested sets
// too. a (dns clients -> ::1 now) must not shadow literal b (::1),
// and both stay #5144 owners over the shared pool. Control: an
// unconditional earlier rule-set still shadows a dns-scoped later one
// (later unprovable is covered only by unconstrained earlier).
func TestNAT64WarmDNSNoProof16873(t *testing.T) {
	mk := func(dnsAddr *Address, nested bool) *Config {
		cfg := &Config{}
		cfg.Security.AddressBook = &AddressBook{
			Addresses:   map[string]*Address{"clients": dnsAddr},
			AddressSets: map[string]*AddressSet{},
		}
		if nested {
			cfg.Security.AddressBook.AddressSets["grp"] = &AddressSet{Name: "grp", Addresses: []string{"clients"}}
		}
		return cfg
	}
	warm := &Address{Name: "clients", DNSName: "clients.example.net", DNSAddresses: []string{"2001:db8::1"}}
	for _, nested := range []bool{false, true} {
		cfg := mk(warm, nested)
		name := "clients"
		if nested {
			name = "grp"
		}
		a := &NAT64RuleSet{Name: "a", Prefix: "64:ff9b::/96", SourcePool: "p1", SourceAddressNames: []string{name}}
		b := &NAT64RuleSet{Name: "b", Prefix: "64:ff9b::/96", SourcePool: "p1", SourceAddresses: []string{"2001:db8::1"}}
		cfg.Security.NAT.NAT64 = []*NAT64RuleSet{a, b}
		cfg.Security.NAT.SourcePools = map[string]*NATPool{"p1": {Name: "p1", Addresses: []string{"198.51.100.1/32"}}}
		if _, ok := nat64ShadowedRuleSets(cfg)[b]; ok {
			t.Fatalf("nested=%v: warm-cache dns answers must not prove shadowing", nested)
		}
		if !nat64HasOwner16873(cfg, "a") || !nat64HasOwner16873(cfg, "b") {
			t.Fatalf("nested=%v: both must stay #5144 owners, got %v", nested, nat64OwnerDescs16873(cfg))
		}
	}
	// Control: unconstrained earlier shadows a dns-scoped later.
	cfg := mk(warm, false)
	a := &NAT64RuleSet{Name: "a", Prefix: "64:ff9b::/96", SourcePool: "p1"}
	b := &NAT64RuleSet{Name: "b", Prefix: "64:ff9b::/96", SourcePool: "p2", SourceAddressNames: []string{"clients"}}
	cfg.Security.NAT.NAT64 = []*NAT64RuleSet{a, b}
	if _, ok := nat64ShadowedRuleSets(cfg)[b]; !ok {
		t.Fatal("unconstrained earlier must still shadow a dns-scoped later rule-set")
	}
}
