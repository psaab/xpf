package appid

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestAppIDSkipsDroppedConstraintAppsAndSupportsZeroRangeAndICMPv6 is the
// #14355 regression. On the tolerant load path a dropped constraint (a
// value-less match leaf, a malformed icmp-type, an unimplemented leaf) leaves
// the compiled application looking protocol-wide: DestinationPort="" and
// ICMPType=nil. Before the fix BuildCatalog emitted a protocol-wide
// (0,0) CatalogEntry for it and the AppID-disabled tuple fallback stamped
// every TCP/UDP/ICMP session with its name — contradicting the #9525
// contract ("a leniently-loaded bad app is inert") that the userspace
// policy expansion already enforces via ApplicationMatchDrops.
//
// The same test pins the two parity legs: an explicit 0-N port range is a
// valid spec (strict validatePortSpec allows lo==0 in a range and the
// catalog preserves 0-N), so the tuple fallback must match port 0 inside
// it; and the hyphenated "icmp-v6" spelling that the junos-host projection
// already accepts must resolve to protocol 58 in ProtocolNumber.
func TestAppIDSkipsDroppedConstraintAppsAndSupportsZeroRangeAndICMPv6(t *testing.T) {
	// --- Leg 1a: dropped-constraint apps constructible directly. ---
	droppedApps := map[string]*config.Application{
		"broken-tcp": {
			Name:                   "broken-tcp",
			Protocol:               "tcp",
			IncompleteDirectLeaves: []string{"destination-port"},
		},
		"bad-icmp": {
			Name:        "bad-icmp",
			Protocol:    "icmp",
			UnknownICMP: []string{"bogus"},
		},
	}
	for name, app := range droppedApps {
		if drops := config.ApplicationMatchDrops(app); len(drops) == 0 {
			t.Fatalf("fixture %s carries no match drops; test would be vacuous", name)
		}
	}

	cfg := policyRefConfig(map[string]*config.Application{
		"broken-tcp": droppedApps["broken-tcp"],
		"bad-icmp":   droppedApps["bad-icmp"],
		"good-web":   {Name: "good-web", Protocol: "tcp", DestinationPort: "8443"},
	})
	cfg.Services.ApplicationIdentification = true

	cat, err := BuildCatalog(cfg)
	if err != nil {
		t.Fatalf("BuildCatalog: %v", err)
	}
	for _, name := range []string{"broken-tcp", "bad-icmp"} {
		if got := entriesForName(cat, name); len(got) != 0 {
			t.Fatalf("dropped-constraint app %s shipped %d catalog row(s) %+v; want 0 (protocol-wide false label)", name, len(got), got)
		}
		if _, ok := appIDForName(cat, name); ok {
			t.Fatalf("dropped-constraint app %s must not hold a resolvable AppNames name", name)
		}
	}
	if got := entriesForName(cat, "good-web"); len(got) != 1 {
		t.Fatalf("well-formed neighbor shipped %d rows; want 1", len(got))
	}

	// AppID-disabled tuple fallback: a TCP/8443 session must resolve to the
	// well-formed app, never to the protocol-wide broken-tcp, and an ICMP
	// session must not be stamped bad-icmp.
	offCfg := policyRefConfig(map[string]*config.Application{
		"broken-tcp": droppedApps["broken-tcp"],
		"bad-icmp":   droppedApps["bad-icmp"],
		"good-web":   {Name: "good-web", Protocol: "tcp", DestinationPort: "8443"},
	})
	if got := ResolveSessionName(cat.AppNames, offCfg, 6, 40000, 8443, 0); got != "good-web" {
		t.Fatalf("tuple fallback TCP/8443 = %q; want good-web (broken-tcp must be inert)", got)
	}
	if got := ResolveSessionName(cat.AppNames, offCfg, 1, 0, 0, 0); got == "bad-icmp" {
		t.Fatalf("tuple fallback ICMP = %q; bad-icmp must be inert", got)
	}
	// A session only the dropped app would have matched stays UNKNOWN.
	if got := ResolveSessionName(cat.AppNames, offCfg, 6, 40000, 9999, 0); got == "broken-tcp" {
		t.Fatalf("tuple fallback TCP/9999 = %q; broken-tcp must be inert", got)
	}

	// --- Leg 1b: end-to-end through the tolerant compiler. ---
	tree := &config.ConfigTree{}
	for _, line := range []string{
		"set applications application e2e-broken protocol tcp",
		"set applications application e2e-broken destination-port",
		"set applications application e2e-good protocol tcp",
		"set applications application e2e-good destination-port 8443",
		"set services application-identification",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	lenientCfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must keep the fixture (#1960 no-brick): %v", err)
	}
	broken := lenientCfg.Applications.Applications["e2e-broken"]
	if broken == nil {
		t.Fatal("lenient compile dropped e2e-broken entirely; fixture shape changed")
	}
	if drops := config.ApplicationMatchDrops(broken); len(drops) == 0 {
		t.Fatalf("e2e-broken carries no match drops (%+v); fixture no longer exercises the tolerant path", broken)
	} else if !strings.Contains(strings.Join(drops, " "), "destination-port") {
		t.Fatalf("e2e-broken drops = %v; want a destination-port drop", drops)
	}
	lenientCat, err := BuildCatalog(lenientCfg)
	if err != nil {
		t.Fatalf("BuildCatalog(lenient): %v", err)
	}
	if got := entriesForName(lenientCat, "e2e-broken"); len(got) != 0 {
		t.Fatalf("lenient e2e-broken shipped %d catalog row(s) %+v; want 0", len(got), got)
	}
	if _, ok := appIDForName(lenientCat, "e2e-broken"); ok {
		t.Fatal("lenient e2e-broken must not hold a resolvable AppNames name")
	}

	// --- Leg 2: explicit 0-N range parity between catalog and fallback. ---
	if !portInSpec(0, "0-1023") {
		t.Fatal(`portInSpec(0, "0-1023") = false; catalog and strict gate accept an explicit 0-N range, so port 0 must match`)
	}
	if portInSpec(1024, "0-1023") {
		t.Fatal(`portInSpec(1024, "0-1023") = true; want false (above range)`)
	}
	if portInSpec(0, "0") {
		t.Fatal(`portInSpec(0, "0") = true; a bare 0 is the (0,0) unconstrained sentinel and must never match`)
	}
	zeroCfg := policyRefConfig(map[string]*config.Application{
		"zero-range": {Name: "zero-range", Protocol: "tcp", DestinationPort: "0-1023"},
	})
	zeroCat, err := BuildCatalog(zeroCfg)
	if err != nil {
		t.Fatalf("BuildCatalog(zero-range): %v", err)
	}
	zr := entriesForName(zeroCat, "zero-range")
	if len(zr) != 1 || zr[0].DstPortLow != 0 || zr[0].DstPortHigh != 1023 {
		t.Fatalf("zero-range catalog entry = %+v; want one tcp 0-1023 entry", zr)
	}
	if got := ResolveSessionName(zeroCat.AppNames, zeroCfg, 6, 40000, 0, 0); got != "zero-range" {
		t.Fatalf("tuple fallback TCP dst-port 0 = %q; want zero-range (catalog/fallback parity on 0-N)", got)
	}

	// --- Leg 3: hyphenated icmp-v6 resolves to ICMPv6 (58). ---
	if n, ok := ProtocolNumber("icmp-v6"); !ok || n != 58 {
		t.Fatalf("ProtocolNumber(%q) = (%d, %v); want (58, true)", "icmp-v6", n, ok)
	}
	v6Cfg := policyRefConfig(map[string]*config.Application{
		"v6-icmp": {Name: "v6-icmp", Protocol: "icmp-v6"},
	})
	v6Cfg.Services.ApplicationIdentification = true
	v6Cat, err := BuildCatalog(v6Cfg)
	if err != nil {
		t.Fatalf("BuildCatalog(icmp-v6): %v", err)
	}
	v6 := entriesForName(v6Cat, "v6-icmp")
	if len(v6) != 1 || v6[0].Protocol != 58 {
		t.Fatalf("icmp-v6 catalog entries = %+v; want one protocol-58 entry", v6)
	}
	if got := ResolveSessionName(v6Cat.AppNames, v6Cfg, 58, 0, 0, 0); got != Unknown && got != "v6-icmp" {
		t.Fatalf("unexpected fallback result %q", got)
	}
	// Disabled-path fallback must also match the icmp-v6 app on proto 58.
	v6Off := policyRefConfig(map[string]*config.Application{
		"v6-icmp": {Name: "v6-icmp", Protocol: "icmp-v6"},
	})
	if got := ResolveSessionName(v6Cat.AppNames, v6Off, 58, 0, 0, 0); got != "v6-icmp" {
		t.Fatalf("tuple fallback ICMPv6 = %q; want v6-icmp", got)
	}
}
