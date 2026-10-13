package config

import (
	"strings"
	"testing"
)

// #12625: a `then static-nat prefix-name <name>` reference whose name (or any
// name traversed while expanding it to its single member) is recorded in
// AddressBook.CollidingNames must NOT resolve to whichever definition won —
// the tolerant path must fail closed to Then=="" so the #4290 empty-target
// warning fires. FAIL-ON-REVERT: dropping the CollidingNames consultation in
// resolveStaticNATThenPrefixName makes the colliding cases resolve to
// 10.0.0.5/32 again.

func collisionBook12625(addresses map[string]string, sets map[string]*AddressSet, colliding ...string) *AddressBook {
	ab := &AddressBook{
		Addresses:      make(map[string]*Address, len(addresses)),
		AddressSets:    sets,
		CollidingNames: make(map[string]struct{}, len(colliding)),
	}
	for name, value := range addresses {
		ab.Addresses[name] = &Address{Name: name, Value: value}
	}
	if ab.AddressSets == nil {
		ab.AddressSets = make(map[string]*AddressSet)
	}
	for _, name := range colliding {
		ab.CollidingNames[name] = struct{}{}
	}
	return ab
}

func TestStaticNATPrefixNameCollidingNames12625(t *testing.T) {
	for _, tc := range []struct {
		name string
		ab   *AddressBook
		ref  string
		want string
	}{
		{
			name: "direct colliding address refused",
			ab:   collisionBook12625(map[string]string{"X": "10.0.0.5/32"}, nil, "X"),
			ref:  "X",
		},
		{
			name: "colliding set name refused",
			ab: collisionBook12625(
				map[string]string{"m": "10.0.0.5/32"},
				map[string]*AddressSet{"grp": {Name: "grp", Addresses: []string{"m"}}},
				"grp"),
			ref: "grp",
		},
		{
			name: "colliding single expanded member refused",
			ab: collisionBook12625(
				map[string]string{"m": "10.0.0.5/32"},
				map[string]*AddressSet{"grp": {Name: "grp", Addresses: []string{"m"}}},
				"m"),
			ref: "grp",
		},
		{
			name: "colliding nested set refused",
			ab: collisionBook12625(
				map[string]string{"m": "10.0.0.5/32"},
				map[string]*AddressSet{
					"inner": {Name: "inner", Addresses: []string{"m"}},
					"outer": {Name: "outer", AddressSets: []string{"inner"}},
				},
				"inner"),
			ref: "outer",
		},
		{
			name: "colliding cross-kind set refused",
			ab: collisionBook12625(
				map[string]string{"m": "10.0.0.5/32"},
				map[string]*AddressSet{
					"inner": {Name: "inner", Addresses: []string{"m"}},
					"outer": {Name: "outer", Addresses: []string{"inner"}},
				},
				"inner"),
			ref: "outer",
		},
		{
			name: "non-colliding direct resolves",
			ab:   collisionBook12625(map[string]string{"X": "10.0.0.5/32"}, nil),
			ref:  "X",
			want: "10.0.0.5/32",
		},
		{
			name: "non-colliding singleton set resolves",
			ab: collisionBook12625(
				map[string]string{"m": "10.0.0.5/32"},
				map[string]*AddressSet{"grp": {Name: "grp", Addresses: []string{"m"}}}),
			ref:  "grp",
			want: "10.0.0.5/32",
		},
		{
			name: "unrelated collision does not refuse",
			ab: collisionBook12625(
				map[string]string{"m": "10.0.0.5/32", "other": "10.0.0.9/32"},
				map[string]*AddressSet{"grp": {Name: "grp", Addresses: []string{"m"}}},
				"other"),
			ref:  "grp",
			want: "10.0.0.5/32",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolveStaticNATThenPrefixName(tc.ab, tc.ref)
			if tc.want == "" {
				if ok || got != "" {
					t.Fatalf("resolveStaticNATThenPrefixName(%q) = %q, %v; want \"\", false (colliding name must fail closed)", tc.ref, got, ok)
				}
				return
			}
			if !ok || got != tc.want {
				t.Fatalf("resolveStaticNATThenPrefixName(%q) = %q, %v; want %q, true", tc.ref, got, ok, tc.want)
			}
		})
	}
}

// Lenient end-to-end: the same-name address + address-set collision is
// warned (not rejected) on the tolerant path, CollidingNames records it,
// and the static-NAT rule must carry Then=="" plus the #4290 warning
// instead of the address winner 10.0.0.5/32.
func TestStaticNATPrefixNameCollisionLenient12625(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []string
		ref     string
	}{
		{
			name: "colliding direct name",
			entries: []string{
				"set security address-book global address X 10.0.0.5/32",
				"set security address-book global address other 10.0.0.6/32",
				"set security address-book global address-set X address other",
			},
			ref: "X",
		},
		{
			name: "colliding singleton member",
			entries: []string{
				"set security address-book global address M 10.0.0.5/32",
				"set security address-book global address other 10.0.0.6/32",
				"set security address-book global address-set M address other",
				"set security address-book global address-set GRP address M",
			},
			ref: "GRP",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmds := append(append([]string{}, tc.entries...),
				"set security nat static rule-set S rule R1 match destination-address 203.0.113.5/32",
				"set security nat static rule-set S rule R1 then static-nat prefix-name "+tc.ref)
			cfg, err := CompileConfigLenient(buildTree(t, cmds))
			if err != nil {
				t.Fatalf("lenient compile must not brick: %v", err)
			}
			if len(cfg.Security.NAT.Static) == 0 || len(cfg.Security.NAT.Static[0].Rules) == 0 {
				t.Fatal("static NAT rule missing")
			}
			rule := cfg.Security.NAT.Static[0].Rules[0]
			if rule.Then != "" {
				t.Fatalf("colliding prefix-name %q resolved Then=%q, want \"\" (ambiguous winner must not install)", tc.ref, rule.Then)
			}
			warned := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "static NAT translation target") {
					warned = true
				}
			}
			if !warned {
				t.Fatalf("lenient compile must emit the #4290 empty-target warning; warnings=%v", cfg.Warnings)
			}
		})
	}
}
