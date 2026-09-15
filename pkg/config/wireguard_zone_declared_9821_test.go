package config

import (
	"reflect"
	"strings"
	"testing"
)

// #9821 D22/D26/F-D26: the WireGuard zone index is declared-aware.
//
// The pre-walk has no *Config by design, so it harvests the declared set from
// the interfaces-stanza node names and splits through the shared free-function
// splitter — the same 4-step precedence the *Config method implements. Writer
// keys per member: raw spelling, plus Literal when the member is a UNIT ref,
// plus the declared Base when the member is a bare ALIAS. Lookup: raw exact,
// declared-aware Literal, unit-owner fallback (unit queries only),
// owner-filtered member scan (bare queries only — load-bearing).
//
// All cells drive warnWireGuardPlaintextUnadjudicatedAST directly: strict gates
// own name acceptance, this file owns zone attribution.

// wgIfaceTunnel9821 renders an interface-level WireGuard tunnel: ONE shared TUN.
func wgIfaceTunnel9821(name string) string {
	return name + " { tunnel { mode wireguard; } }\n"
}

// wgUnitTunnel9821 renders a per-unit WireGuard tunnel. unit is raw text so
// padded ("01") and malformed ("foo") spellings survive verbatim.
func wgUnitTunnel9821(name, unit string) string {
	return name + " { unit " + unit + " { tunnel { mode wireguard; } } }\n"
}

// wgZoneMember9821 renders a single-member zone.
func wgZoneMember9821(zone, member string) string {
	return "security-zone " + zone + " { interfaces " + member + "; }\n"
}

// wgAdv9821 parses one hierarchical tree and returns the single aggregated
// advisory it must produce.
func wgAdv9821(t *testing.T, ifaces, zones string) string {
	t.Helper()
	text := "interfaces { " + ifaces + " } security { zones { " + zones + " } }"
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v\n%s", errs, text)
	}
	got := warnWireGuardPlaintextUnadjudicatedAST(tree.Children)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 advisory, got %d: %v\n%s", len(got), got, text)
	}
	return got[0]
}

// wgFindingLine9821 returns the advisory line for one finding ref. The " ("
// suffix keeps "p.0" from matching the "p.0.1" line.
func wgFindingLine9821(t *testing.T, adv, ref string) string {
	t.Helper()
	for _, line := range strings.Split(adv, "\n") {
		if strings.HasPrefix(line, "    "+ref+" (") {
			return line
		}
	}
	t.Fatalf("no finding for %q in advisory:\n%s", ref, adv)
	return ""
}

func wgAssertZoned9821(t *testing.T, adv, ref, zone string) {
	t.Helper()
	line := wgFindingLine9821(t, adv, ref)
	if want := `is assigned to security-zone "` + zone + `"`; !strings.Contains(line, want) {
		t.Errorf("%s: want zone %q, got line:\n%s\nfull advisory:\n%s", ref, zone, line, adv)
	}
}

func wgAssertUnzoned9821(t *testing.T, adv, ref string) {
	t.Helper()
	line := wgFindingLine9821(t, adv, ref)
	if strings.Contains(line, "is assigned to security-zone") {
		t.Errorf("%s: want UNZONED, got line:\n%s\nfull advisory:\n%s", ref, line, adv)
	}
}

// Single-dot padded declaration beside its independently-declared canonical
// spelling: cross-zone non-misassignment in BOTH directions. A blind
// canonicalization keys both members under `p.1` (first-wins) and strands the
// `p.01` tunnel; declared-aware keying keeps each spelling on its own zone.
func TestWGZoneDeclaredSingleDotPaddedVsCanonical9821(t *testing.T) {
	adv := wgAdv9821(t,
		wgIfaceTunnel9821("p.01")+wgIfaceTunnel9821("p.1"),
		wgZoneMember9821("zoneA", "p.01")+wgZoneMember9821("zoneB", "p.1"),
	)
	wgAssertZoned9821(t, adv, "p.01", "zoneA")
	wgAssertZoned9821(t, adv, "p.1", "zoneB")
}

// Alias-bare: member `p.00` is not declared but its legacy canon `p.0` is, so
// the writer keys the declared Base and the tunnel on `p.0` is zoned. The
// unrelated tunnel stays unzoned — the Base key fans to its own declaration,
// not to the world.
func TestWGZoneDeclaredAliasBare9821(t *testing.T) {
	adv := wgAdv9821(t,
		wgIfaceTunnel9821("p.0")+wgIfaceTunnel9821("q"),
		wgZoneMember9821("vpn", "p.00"),
	)
	wgAssertZoned9821(t, adv, "p.0", "vpn")
	wgAssertUnzoned9821(t, adv, "q")
}

// Nested negatives: independently-declared names never acquire each other's
// zone through textual nesting, in EITHER direction. The positive halves prove
// the zones exist and the writer keys them — only the cross-acquisition is
// absent. The dot-free-owner pair is the load-bearing one: the legacy
// bare-branch prefix scan (`p.` over `p.0.2`) and the legacy first-dot Cut
// (`p.0.2` onto `p`) both acquire across the independence boundary.
func TestWGZoneDeclaredNestedNegatives9821(t *testing.T) {
	t.Run("bare_gets_no_nested_zone", func(t *testing.T) {
		adv := wgAdv9821(t,
			wgIfaceTunnel9821("p.0")+wgIfaceTunnel9821("p.0.2"),
			wgZoneMember9821("zoneB", "p.0.2"),
		)
		wgAssertUnzoned9821(t, adv, "p.0")
		wgAssertZoned9821(t, adv, "p.0.2", "zoneB")
	})
	t.Run("nested_gets_no_bare_zone", func(t *testing.T) {
		adv := wgAdv9821(t,
			wgIfaceTunnel9821("p.0")+wgIfaceTunnel9821("p.0.2"),
			wgZoneMember9821("zoneA", "p.0"),
		)
		wgAssertZoned9821(t, adv, "p.0", "zoneA")
		wgAssertUnzoned9821(t, adv, "p.0.2")
	})
	t.Run("dotfree_owner_gets_no_nested_zone", func(t *testing.T) {
		adv := wgAdv9821(t,
			wgIfaceTunnel9821("p")+wgIfaceTunnel9821("p.0.2"),
			wgZoneMember9821("zoneB", "p.0.2"),
		)
		wgAssertUnzoned9821(t, adv, "p")
		wgAssertZoned9821(t, adv, "p.0.2", "zoneB")
	})
	t.Run("nested_gets_no_dotfree_owner_zone", func(t *testing.T) {
		adv := wgAdv9821(t,
			wgIfaceTunnel9821("p")+wgIfaceTunnel9821("p.0.2"),
			wgZoneMember9821("zoneA", "p"),
		)
		wgAssertZoned9821(t, adv, "p", "zoneA")
		wgAssertUnzoned9821(t, adv, "p.0.2")
	})
}

// Multi-dot padded: member `p.0.01` keys raw + Literal `p.0.1`. The padded
// finding hits raw; a differently-padded alias-unit finding (`p.0.001`) meets
// the member through the declared-aware Literal.
func TestWGZoneDeclaredMultiDotPadded9821(t *testing.T) {
	adv := wgAdv9821(t,
		"p.0 { unit 01 { tunnel { mode wireguard; } } unit 001 { tunnel { mode wireguard; } } }\n",
		wgZoneMember9821("vpn", "p.0.01"),
	)
	wgAssertZoned9821(t, adv, "p.0.01", "vpn")
	wgAssertZoned9821(t, adv, "p.0.001", "vpn")
}

// Interface-level shared-TUN fan-out, dotted: a zone on the unit governs the
// interface tunnel (arm 4), and a bare member still fans DOWN onto a unit
// tunnel (arm 3). The undotted shapes keep their legacy outcome; the dotted
// ones gain it (the legacy Cut stranded every dotted query off `"p"`).
func TestWGZoneDeclaredSharedTUNFanout9821(t *testing.T) {
	t.Run("unit_member_zones_iface_tunnel", func(t *testing.T) {
		adv := wgAdv9821(t,
			wgIfaceTunnel9821("p.0"),
			wgZoneMember9821("vpn", "p.0.1"),
		)
		wgAssertZoned9821(t, adv, "p.0", "vpn")
	})
	t.Run("bare_member_zones_unit_tunnel", func(t *testing.T) {
		adv := wgAdv9821(t,
			wgUnitTunnel9821("p.0", "1"),
			wgZoneMember9821("vpn", "p.0"),
		)
		wgAssertZoned9821(t, adv, "p.0.1", "vpn")
	})
}

// First-writer-wins is retained: the same key claimed by two zones reports
// the first in AST order.
func TestWGZoneDeclaredFirstWriterWins9821(t *testing.T) {
	adv := wgAdv9821(t,
		wgUnitTunnel9821("p.0", "1"),
		wgZoneMember9821("zoneA", "p.0.1")+wgZoneMember9821("zoneB", "p.0.1"),
	)
	wgAssertZoned9821(t, adv, "p.0.1", "zoneA")
}

// Undotted controls: `wg0.00` keys raw + `wg0.0`, so both the padded and the
// canonical unit tunnel land zoned — the same outcome as the legacy Canon key,
// with the finding ref preserved exactly as authored (#2463: never coerced at
// write).
func TestWGZoneDeclaredUndottedControls9821(t *testing.T) {
	adv := wgAdv9821(t,
		"wg0 { unit 00 { tunnel { mode wireguard; } } unit 0 { tunnel { mode wireguard; } } }\n",
		wgZoneMember9821("vpn", "wg0.00"),
	)
	wgAssertZoned9821(t, adv, "wg0.00", "vpn")
	wgAssertZoned9821(t, adv, "wg0.0", "vpn")
}

// Malformed path intact: an invalid unit token is stored and reported raw,
// hits its own member's raw key, and otherwise falls through to the unzoned
// warn path — never coerced, never fanned.
func TestWGZoneDeclaredMalformedIntact9821(t *testing.T) {
	t.Run("invalid_token_hits_own_member", func(t *testing.T) {
		adv := wgAdv9821(t,
			wgUnitTunnel9821("wg0", "foo"),
			wgZoneMember9821("vpn", "wg0.foo"),
		)
		wgAssertZoned9821(t, adv, "wg0.foo", "vpn")
	})
	t.Run("invalid_token_without_member_is_unzoned", func(t *testing.T) {
		adv := wgAdv9821(t,
			wgUnitTunnel9821("wg0", "foo")+wgIfaceTunnel9821("q"),
			wgZoneMember9821("vpn", "q"),
		)
		wgAssertUnzoned9821(t, adv, "wg0.foo")
		wgAssertZoned9821(t, adv, "q", "vpn")
	})
}

// Canonical-vs-padded in BOTH directions: member `p.0.1` serves finding
// `p.0.01` through the query Literal, and member `p.0.01` serves finding
// `p.0.1` through the stored Literal key.
func TestWGZoneDeclaredCanonicalVsPaddedBothDirections9821(t *testing.T) {
	t.Run("canonical_member_padded_finding", func(t *testing.T) {
		adv := wgAdv9821(t,
			wgUnitTunnel9821("p.0", "01"),
			wgZoneMember9821("vpn", "p.0.1"),
		)
		wgAssertZoned9821(t, adv, "p.0.01", "vpn")
	})
	t.Run("padded_member_canonical_finding", func(t *testing.T) {
		adv := wgAdv9821(t,
			wgUnitTunnel9821("p.0", "1"),
			wgZoneMember9821("vpn", "p.0.01"),
		)
		wgAssertZoned9821(t, adv, "p.0.1", "vpn")
	})
}

// The WG pre-walk holds node names, not a *Config: the AST predicate and the
// method must implement ONE precedence on every shape in this corpus — padded,
// alias, both-declared, malformed, trailing-dot, empty, undeclared.
func TestWGZoneDeclaredSplitAgreement9821(t *testing.T) {
	declared := map[string]*InterfaceConfig{
		"p": {}, "p.01": {}, "p.1": {}, "p.0": {}, "p.0.2": {},
		"wg0": {}, "ge-0/0/0": {},
	}
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: declared}}
	isDeclared := func(s string) bool {
		ifc, ok := declared[s]
		return ok && ifc != nil
	}
	for _, ref := range []string{
		"p.01", "p.1", "p.0", "p.0.2", "p.0.1", "p.0.01", "p.0.001",
		"p.00", "p.02", "p.0.00", "p.1.2", "wg0.00", "wg0.0", "wg0.foo",
		"ge-0/0/0.01", "ge-0/0/0.1", "p.0.01.02", "trail.", "", "nope",
		"nope.1", "p.", ".5", "wg0.",
	} {
		if got, want := splitInterfaceRefWithDeclared(isDeclared, ref), cfg.SplitInterfaceUnitRef(ref); !reflect.DeepEqual(got, want) {
			t.Errorf("freefunc(%q) = %+v, method = %+v — one precedence, two answers", ref, got, want)
		}
	}
}

// End-to-end through the lenient compile: a padded dotted unit tunnel meets
// its canonical zone member in the advisory the operator actually sees —
// proving the declared-set harvest works on the group-expanded tree, not just
// on hand-parsed fixtures. Lenient, not strict: the strict zone-member
// existence gate still strips the suffix at the FIRST dot
// (validateZoneInterfaceDefinedStrict), so it rejects `p.0.1` before the
// advisory runs — that gate's Split migration belongs to its owning slice,
// and this cell will graduate to strict alongside it.
func TestWGZoneDeclaredLenientEndToEnd9821(t *testing.T) {
	lines := wgTunnel5618("p.0", 1, 51820, wgKeyA, wgKeyB)
	for i := range lines {
		lines[i] = strings.Replace(lines[i], "unit 1 ", "unit 01 ", 1)
	}
	lines = append(lines, "set security zones security-zone vpn interfaces p.0.1")
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
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	for _, w := range plaintextWarnings5618(cfg) {
		if strings.Contains(w, "p.0.01") && strings.Contains(w, `"vpn"`) {
			return
		}
	}
	t.Errorf("padded dotted finding p.0.01 not reported zoned under vpn: %v", plaintextWarnings5618(cfg))
}
