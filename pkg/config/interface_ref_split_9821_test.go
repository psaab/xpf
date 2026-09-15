package config

import (
	"reflect"
	"strings"
	"testing"
)

// TestSplitInterfaceUnitRef9821 pins the centralized 4-step precedence:
// raw-exact declared, then legacy-canon alias, then longest declared
// dot-prefix, then legacy Cut-of-legacy-canon. Every row names the step
// the helper must take, so a precedence regression fails on the row whose
// rule broke rather than on an opaque mismatch.
func TestSplitInterfaceUnitRef9821(t *testing.T) {
	decl := func(names ...string) map[string]*InterfaceConfig {
		m := make(map[string]*InterfaceConfig, len(names))
		for _, n := range names {
			m[n] = &InterfaceConfig{Name: n}
		}
		return m
	}
	tests := []struct {
		name     string
		declared map[string]*InterfaceConfig
		ref      string
		wantBase string
		wantTok  string
		wantUnit bool
		wantLit  string
	}{
		// Step 1: raw exact-declared wins, even dotted or padded.
		{name: "exactUndotted", declared: decl("ge-0/0/0"), ref: "ge-0/0/0", wantBase: "ge-0/0/0", wantLit: "ge-0/0/0"},
		{name: "exactDotted", declared: decl("ge-0/0/5.0"), ref: "ge-0/0/5.0", wantBase: "ge-0/0/5.0", wantLit: "ge-0/0/5.0"},
		{name: "exactPaddedDeclared", declared: decl("p.01"), ref: "p.01", wantBase: "p.01", wantLit: "p.01"},
		{name: "rawWinsOverCanonAlias", declared: decl("p.01", "p.1"), ref: "p.01", wantBase: "p.01", wantLit: "p.01"},
		{name: "bothDeclaredExactWins", declared: decl("p", "p.0"), ref: "p.0", wantBase: "p.0", wantLit: "p.0"},
		{name: "declaredTrailingDotIsBare", declared: decl("p."), ref: "p.", wantBase: "p.", wantLit: "p."},
		// A present-but-nil slot is ABSENT (#5886): it must not outrank a parse.
		{name: "nilSlotIsNotDeclared", declared: map[string]*InterfaceConfig{"p.0": nil}, ref: "p.0", wantBase: "p", wantTok: "0", wantUnit: true, wantLit: "p.0"},

		// Step 2: legacy-canon alias of a declaration.
		{name: "canonAliasBare", declared: decl("ge-0/0/5.0"), ref: "ge-0/0/5.00", wantBase: "ge-0/0/5.0", wantLit: "ge-0/0/5.0"},
		{name: "canonAliasOtherSpelling", declared: decl("p.1"), ref: "p.01", wantBase: "p.1", wantLit: "p.1"},

		// Step 3: longest declared dot-prefix + suffix (suffix NOT validated here).
		{name: "declaredUnit", declared: decl("ge-0/0/0"), ref: "ge-0/0/0.1", wantBase: "ge-0/0/0", wantTok: "1", wantUnit: true, wantLit: "ge-0/0/0.1"},
		{name: "declaredUnitPadded", declared: decl("ge-0/0/0"), ref: "ge-0/0/0.01", wantBase: "ge-0/0/0", wantTok: "01", wantUnit: true, wantLit: "ge-0/0/0.1"},
		{name: "doubleDotUnit", declared: decl("ge-0/0/5.0"), ref: "ge-0/0/5.0.1", wantBase: "ge-0/0/5.0", wantTok: "1", wantUnit: true, wantLit: "ge-0/0/5.0.1"},
		{name: "doubleDotUnitPadded", declared: decl("p.0"), ref: "p.0.01", wantBase: "p.0", wantTok: "01", wantUnit: true, wantLit: "p.0.1"},
		{name: "longestPrefixWins", declared: decl("p", "p.0"), ref: "p.0.1", wantBase: "p.0", wantTok: "1", wantUnit: true, wantLit: "p.0.1"},
		{name: "declaredPrefixMalformedSuffix", declared: decl("p.0"), ref: "p.0.foo", wantBase: "p.0", wantTok: "foo", wantUnit: true, wantLit: "p.0.foo"},
		{name: "declaredPrefixTrailingDot", declared: decl("p.0"), ref: "p.0.", wantBase: "p.0", wantTok: "", wantUnit: true, wantLit: "p.0."},

		// Step 4: legacy Cut-of-legacy-canon (byte-identical to before #9821).
		{name: "legacyUnit", declared: decl("ge-0/0/0"), ref: "ge-0/0/9.1", wantBase: "ge-0/0/9", wantTok: "1", wantUnit: true, wantLit: "ge-0/0/9.1"},
		{name: "legacyPaddedUnit", declared: decl("ge-0/0/0"), ref: "ge-0/0/9.01", wantBase: "ge-0/0/9", wantTok: "1", wantUnit: true, wantLit: "ge-0/0/9.1"},
		{name: "legacyBare", declared: decl("ge-0/0/0"), ref: "ge-0/0/9", wantBase: "ge-0/0/9", wantLit: "ge-0/0/9"},
		{name: "legacyMalformed", declared: decl("ge-0/0/0"), ref: "ge-0/0/0.foo", wantBase: "ge-0/0/0", wantTok: "foo", wantUnit: true, wantLit: "ge-0/0/0.foo"},
		{name: "legacyTrailingDot", declared: decl("ge-0/0/0"), ref: "ge-0/0/0.", wantBase: "ge-0/0/0", wantTok: "", wantUnit: true, wantLit: "ge-0/0/0."},
		{name: "legacyMultiDot", declared: decl("ge-0/0/0"), ref: "ge-0/0/0.1.5", wantBase: "ge-0/0/0", wantTok: "1.5", wantUnit: true, wantLit: "ge-0/0/0.1.5"},
		{name: "legacyLeadingDot", declared: decl("ge-0/0/0"), ref: ".5", wantBase: "", wantTok: "5", wantUnit: true, wantLit: ".5"},
		{name: "legacyEmpty", declared: decl("ge-0/0/0"), ref: "", wantBase: "", wantLit: ""},
		// No central slash/dash aliasing: a dash spelling of a slash-declared
		// dotted interface falls through to legacy (dhcpLeaseKeysForMember
		// resolves it locally, #8829).
		{name: "noCentralDashAlias", declared: decl("ge-0/0/5.0"), ref: "ge-0-0-5.0", wantBase: "ge-0-0-5", wantTok: "0", wantUnit: true, wantLit: "ge-0-0-5.0"},
		{name: "nilMapFallsBack", declared: nil, ref: "ge-0/0/0.01", wantBase: "ge-0/0/0", wantTok: "1", wantUnit: true, wantLit: "ge-0/0/0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Interfaces: InterfacesConfig{Interfaces: tt.declared}}
			got := cfg.SplitInterfaceUnitRef(tt.ref)
			want := InterfaceRefSplit{Base: tt.wantBase, UnitTok: tt.wantTok, HasUnit: tt.wantUnit, Literal: tt.wantLit}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Split(%q) = %+v, want %+v", tt.ref, got, want)
			}
			// The Literal contract: bare → Base; valid suffix → canonical
			// rebuild; anything else → byte-equal to the legacy canon.
			var wantLiteral string
			if !want.HasUnit {
				wantLiteral = want.Base
			} else if _, canon, err := CanonicalLogicalUnit(want.UnitTok); err == nil {
				wantLiteral = want.Base + "." + canon
			} else {
				wantLiteral = CanonicalInterfaceUnitRef(tt.ref)
				// Multi-dot raws survive legacy canon unchanged, and the
				// rebuild spells the same string.
				if rebuilt := want.Base + "." + want.UnitTok; wantLiteral != rebuilt {
					t.Errorf("Split(%q) literal %q != legacy canon %q", tt.ref, want.Literal, wantLiteral)
				}
			}
			if got.Literal != wantLiteral && wantLiteral != "" {
				t.Errorf("Split(%q).Literal = %q, want %q", tt.ref, got.Literal, wantLiteral)
			}
		})
	}
}

// TestSplitInterfaceUnitRefNilReceiver9821 pins the nil-safe degradation: a
// nil *Config behaves exactly like strings.Cut over the legacy canon.
func TestSplitInterfaceUnitRefNilReceiver9821(t *testing.T) {
	var cfg *Config
	for _, ref := range []string{"", "ge-0/0/0", "ge-0/0/0.1", "ge-0/0/0.01", "p.0.01", "x.foo", "trail."} {
		got := cfg.SplitInterfaceUnitRef(ref)
		canon := CanonicalInterfaceUnitRef(ref)
		base, tok, has := strings.Cut(canon, ".")
		var wantLit string
		if !has {
			wantLit = base
		} else if _, canonTok, err := CanonicalLogicalUnit(tok); err == nil {
			wantLit = base + "." + canonTok
		} else {
			wantLit = canon
		}
		want := InterfaceRefSplit{Base: base, UnitTok: tok, HasUnit: has, Literal: wantLit}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("nil.Split(%q) = %+v, want %+v", ref, got, want)
		}
	}
}

// TestSplitInterfaceUnitRefAgreesWithDeclaredSet9821 pins that the *Config
// method and the AST-site free function implement ONE precedence: same
// declared set in, same split out, on every shape in the corpus (incl.
// padded, alias, both-declared and malformed refs).
func TestSplitInterfaceUnitRefAgreesWithDeclaredSet9821(t *testing.T) {
	declared := map[string]*InterfaceConfig{
		"ge-0/0/0":    {Name: "ge-0/0/0"},
		"ge-0/0/5.0":  {Name: "ge-0/0/5.0"},
		"p":           {Name: "p"},
		"p.0":         {Name: "p.0"},
		"p.01":        {Name: "p.01"},
		"nil-slot":    nil,
		"unrelated":   {Name: "unrelated"},
		"unrelated.9": {Name: "unrelated.9"},
	}
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: declared}}
	isDeclared := func(s string) bool {
		ifc, ok := declared[s]
		return ok && ifc != nil
	}
	refs := []string{
		"", "ge-0/0/0", "ge-0/0/0.1", "ge-0/0/0.01", "ge-0/0/5.0", "ge-0/0/5.00",
		"ge-0/0/5.0.1", "ge-0/0/5.0.01", "ge-0/0/9", "ge-0/0/9.2",
		"p", "p.0", "p.1", "p.01", "p.0.0", "p.0.1", "p.0.01", "p.1.2",
		"p.", ".5", "x.foo", "nil-slot", "nil-slot.0", "unrelated.9.3",
		"ge-0-0-5.0", "trail.",
	}
	for _, ref := range refs {
		if got, want := splitInterfaceRefWithDeclared(isDeclared, ref), cfg.SplitInterfaceUnitRef(ref); !reflect.DeepEqual(got, want) {
			t.Errorf("freefunc(%q) = %+v, method = %+v — one precedence, two answers", ref, got, want)
		}
	}
	// A nil predicate degrades to legacy, like a nil receiver.
	for _, ref := range []string{"p.0", "ge-0/0/0.01", "bare"} {
		got := splitInterfaceRefWithDeclared(nil, ref)
		var cfg2 *Config
		if want := cfg2.SplitInterfaceUnitRef(ref); !reflect.DeepEqual(got, want) {
			t.Errorf("freefunc(nil)(%q) = %+v, want %+v", ref, got, want)
		}
	}
}
