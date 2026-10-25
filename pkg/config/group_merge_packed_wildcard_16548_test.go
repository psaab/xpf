package config

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// #16548 — a brace-elided wildcard group statement
// (`interface <*> authentication md5 1 key K;`) took the leaf arm of
// mergeNodes, which has no wildcard check, and was adopted literally as a
// phantom OSPF interface named `<*>`. The real interfaces stayed
// unauthenticated behind only the indirect #9405 advisory. The braced
// spelling of the same template fanned out correctly. Measured at
// 3027e34128: packed compiled interfaces [<*> ge-0/0/0.0] with the phantom
// carrying md5 and ge-0/0/0.0 carrying no auth; ctl-braced applied md5 to
// ge-0/0/0.0 only once the bare-leaf sibling #16543 landed (4975225633),
// and this fix makes the packed spelling equal it.
//
// Acceptance: def-packed equals ctl-braced, and no compiled instance name
// contains `<`.

const packedWildcardOSPF16548Secret = "ospf-md5-secret-16548"

func packedWildcardOSPF16548(template string) string {
	return `groups { AUTH { protocols { ospf { area 0.0.0.0 { ` + template + ` } } } } }
apply-groups AUTH;
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } } xe-0/0/0 { unit 0 { family inet { address 10.0.2.1/24; } } } }
protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { } interface ge-0/0/1.0 { } interface xe-0/0/0.0 { } } } }
`
}

func ospfIfaces16548(t *testing.T, cfg *Config) map[string]*OSPFInterface {
	t.Helper()
	out := map[string]*OSPFInterface{}
	if cfg.Protocols.OSPF == nil {
		return out
	}
	for _, a := range cfg.Protocols.OSPF.Areas {
		for _, iface := range a.Interfaces {
			out[iface.Name] = iface
		}
	}
	return out
}

func assertNoPhantom16548(t *testing.T, cfg *Config) {
	t.Helper()
	for name := range cfg.Interfaces.Interfaces {
		if strings.ContainsAny(name, "<>") {
			t.Fatalf("compiled a phantom interface %q: a wildcard matched nothing it should invent (#16548, #9423)", name)
		}
	}
	for name := range ospfIfaces16548(t, cfg) {
		if strings.ContainsAny(name, "<>") {
			t.Fatalf("compiled a phantom OSPF interface %q (#16548)", name)
		}
	}
	for name := range cfg.Security.Zones {
		if strings.ContainsAny(name, "<>") {
			t.Fatalf("compiled a phantom zone %q (#16548)", name)
		}
	}
}

func TestPackedWildcardOSPFEqualsBraced16548(t *testing.T) {
	packed := compileWildcard9423(t, packedWildcardOSPF16548(
		`interface <*> authentication md5 1 key "`+packedWildcardOSPF16548Secret+`";`))
	braced := compileWildcard9423(t, packedWildcardOSPF16548(
		`interface <*> { authentication { md5 1 { key "`+packedWildcardOSPF16548Secret+`"; } } }`))

	assertNoPhantom16548(t, packed)
	assertNoPhantom16548(t, braced)

	got := ospfIfaces16548(t, packed)
	want := ospfIfaces16548(t, braced)
	if len(got) != 3 || len(want) != 3 {
		t.Fatalf("compiled OSPF interfaces packed=%v braced=%v, want the three real interfaces", keysOf16548(got), keysOf16548(want))
	}
	for _, name := range []string{"ge-0/0/0.0", "ge-0/0/1.0", "xe-0/0/0.0"} {
		g, w := got[name], want[name]
		if g == nil || w == nil {
			t.Fatalf("missing OSPF interface %q: packed=%v braced=%v", name, keysOf16548(got), keysOf16548(want))
		}
		if g.AuthType != "md5" || len(g.AuthMD5Keys) != 1 || g.AuthMD5Keys[0].ID != 1 ||
			g.AuthMD5Keys[0].Key.Reveal() != packedWildcardOSPF16548Secret {
			t.Fatalf("packed template did not authenticate %q: auth=%q keys=%v — the wildcard body must fan out from the packed spelling exactly as from the braced one (#16548)", name, g.AuthType, g.AuthMD5Keys)
		}
		if !reflect.DeepEqual(g, w) {
			t.Fatalf("packed and braced spellings diverge on %q:\n packed=%+v\n braced=%+v (#16548)", name, g, w)
		}
	}
}

// The issue's verbatim fixture: a single real interface written BARE
// (`interface ge-0/0/0.0;`). At the original base this compiled the
// phantom <*> with md5 and left ge-0/0/0.0 unauthenticated; the packed
// template must now authenticate the real interface with no phantom
// (the braced spelling against a bare destination binds via the
// sibling #16543 rule, merged in 4975225633, and the packed spelling
// must equal it).
func TestPackedWildcardOSPFIssueFixture16548(t *testing.T) {
	text := `groups { AUTH { protocols { ospf { area 0.0.0.0 { interface <*> authentication md5 1 key "` + packedWildcardOSPF16548Secret + `"; } } } } }
apply-groups AUTH;
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0; } } }
`
	cfg := compileWildcard9423(t, text)
	assertNoPhantom16548(t, cfg)
	iface := ospfIfaces16548(t, cfg)["ge-0/0/0.0"]
	if iface == nil || iface.AuthType != "md5" || len(iface.AuthMD5Keys) != 1 ||
		iface.AuthMD5Keys[0].Key.Reveal() != packedWildcardOSPF16548Secret {
		t.Fatalf("the issue fixture must authenticate ge-0/0/0.0 with the group md5 key, got %+v (#16548)", iface)
	}
}

func TestPackedWildcardOSPFGlobSelectsSubset16548(t *testing.T) {
	cfg := compileWildcard9423(t, packedWildcardOSPF16548(
		`interface <ge-*> authentication md5 1 key "`+packedWildcardOSPF16548Secret+`";`))
	assertNoPhantom16548(t, cfg)
	got := ospfIfaces16548(t, cfg)
	for _, name := range []string{"ge-0/0/0.0", "ge-0/0/1.0"} {
		if got[name] == nil || got[name].AuthType != "md5" {
			t.Fatalf("<ge-*> must authenticate %q, got %+v (#16548)", name, got[name])
		}
	}
	if got["xe-0/0/0.0"] == nil || got["xe-0/0/0.0"].AuthType != "" {
		t.Fatalf("<ge-*> must not touch xe-0/0/0.0, got %+v (#16548)", got["xe-0/0/0.0"])
	}
}

func TestPackedWildcardOSPFNoMatchInventsNothing16548(t *testing.T) {
	cfg := compileWildcard9423(t, packedWildcardOSPF16548(
		`interface <fxp*> authentication md5 1 key "`+packedWildcardOSPF16548Secret+`";`))
	assertNoPhantom16548(t, cfg)
	got := ospfIfaces16548(t, cfg)
	if len(got) != 3 {
		t.Fatalf("a non-matching pattern must apply nothing and invent nothing, got %v (#16548, #9423)", keysOf16548(got))
	}
	for name, iface := range got {
		if iface.AuthType != "" {
			t.Fatalf("non-matching <fxp*> authenticated %q (%q) (#16548)", name, iface.AuthType)
		}
	}
}

func TestPackedWildcardInterfacesEqualsBraced16548(t *testing.T) {
	mk := func(template string) string {
		return `groups { G { interfaces { ` + template + ` } } }
apply-groups G;
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } xe-0/0/0 { unit 0 { family inet { address 10.0.2.1/24; } } } }
`
	}
	packed := compileWildcard9423(t, mk(`<ge-*> description FROM-GROUP;`))
	braced := compileWildcard9423(t, mk(`<ge-*> { description FROM-GROUP; }`))
	assertNoPhantom16548(t, packed)
	if got := packed.Interfaces.Interfaces["ge-0/0/0"]; got == nil || got.Description != "FROM-GROUP" {
		t.Fatalf("packed <ge-*> must describe ge-0/0/0, got %+v (#16548)", got)
	}
	if got := packed.Interfaces.Interfaces["xe-0/0/0"]; got == nil || got.Description != "" {
		t.Fatalf("packed <ge-*> must not describe xe-0/0/0, got %+v (#16548)", got)
	}
	if got := braced.Interfaces.Interfaces["ge-0/0/0"]; got == nil || got.Description != "FROM-GROUP" {
		t.Fatalf("braced control must describe ge-0/0/0, got %+v (#16548)", got)
	}
}

// The zone packed spelling (`security-zone <*> tcp-rst;`) is folded to its
// braced shape by the #8662 compact normalizer before group expansion on
// the strict CompileConfig channel (verified: the normalizer rewrites it
// inside the groups body), so this cell goes through the RAW expansion
// channel instead, where #16548's split is the only thing that can keep
// the phantom out: on the raw channel a non-split packed leaf is adopted
// literally and no real zone receives the statement.
func TestPackedWildcardZoneRawExpansion16548(t *testing.T) {
	text := `groups { G { security { zones { security-zone <*> tcp-rst; } } } } apply-groups G; security { zones { security-zone trust { } security-zone untrust { } } }`
	packed := expand9801(t, text)
	// The split's synthesized tcp-rst child is a childless container where
	// the parser's braced spelling is a leaf; both compile to TCPRst, so
	// compare at the compiler, not at Format's leaf/container spelling.
	cfg, err := CompileConfig(packed)
	if err != nil {
		t.Fatalf("compile raw-expanded packed zone template: %v (#16548)", err)
	}
	if len(cfg.Security.Zones) != 2 {
		t.Fatalf("raw expansion must compile exactly the two real zones, got %v (#16548)", keysOfZones16548(cfg))
	}
	for _, name := range []string{"trust", "untrust"} {
		if z := cfg.Security.Zones[name]; z == nil || !z.TCPRst {
			t.Fatalf("packed security-zone <*> must set tcp-rst on %q after raw expansion, got %+v (#16548)", name, z)
		}
	}
}

func keysOfZones16548(cfg *Config) []string {
	out := make([]string, 0, len(cfg.Security.Zones))
	for k := range cfg.Security.Zones {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The split must not reinterpret a wildcard in a MEMBER slot as an
// instance pattern: the zone-member spelling stays loudly refused,
// exactly as the braced form is (#9423/#9802 guard).
func TestPackedWildcardZoneMemberStillRefused16548(t *testing.T) {
	tree, errs := NewParser(`groups { G { security { zones { security-zone trust { interfaces { <ge-*>; } } } } } }
apply-groups G;
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }
`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("a wildcard zone member must stay refused, not be fanned out as an instance pattern (#16548, #9423)")
	} else if !strings.Contains(err.Error(), "<ge-*>") {
		t.Fatalf("refused, but the message does not name the token: %v (#16548)", err)
	}
}

// The packed template must not override an authored inline value: the
// fan-out merges into the destination, where the ordinary inline-wins
// leaf rules decide, exactly as for the braced spelling.
func TestPackedWildcardInlineAuthWins16548(t *testing.T) {
	text := `groups { AUTH { protocols { ospf { area 0.0.0.0 { interface <*> authentication md5 1 key "` + packedWildcardOSPF16548Secret + `"; } } } } }
apply-groups AUTH;
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { authentication { simple-password "inline-secret"; } } } } }
`
	cfg := compileWildcard9423(t, text)
	assertNoPhantom16548(t, cfg)
	iface := ospfIfaces16548(t, cfg)["ge-0/0/0.0"]
	if iface == nil {
		t.Fatalf("missing ge-0/0/0.0 (#16548)")
	}
	if iface.AuthType != "simple" && iface.AuthType != "md5" {
		t.Fatalf("inline interface lost its authentication entirely: %q (#16548)", iface.AuthType)
	}
	// Whichever spelling wins, the group key must not silently replace an
	// authored inline key on the same statement: a simple-password inline
	// value and the group md5 key are different statements, and the
	// braced control below pins the exact outcome.
	braced := compileWildcard9423(t, strings.Replace(text,
		`interface <*> authentication md5 1 key "`+packedWildcardOSPF16548Secret+`";`,
		`interface <*> { authentication { md5 1 { key "`+packedWildcardOSPF16548Secret+`"; } } }`, 1))
	if b := ospfIfaces16548(t, braced)["ge-0/0/0.0"]; !reflect.DeepEqual(iface, b) {
		t.Fatalf("packed and braced diverge beside inline auth:\n packed=%+v\n braced=%+v (#16548)", iface, b)
	}
}

func keysOf16548(m map[string]*OSPFInterface) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
