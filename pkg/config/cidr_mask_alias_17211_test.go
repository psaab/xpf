package config

import (
	"reflect"
	"strings"
	"testing"
)

// #17211: #15658 cloned the #12507 static-route mask machinery for generate
// routes as three name-swapped function pairs. The three pairs now delegate
// to canonicalizeMaskAliases / appendMaskAlias /
// helperRefusedMaskSpellings in cidr_mask_alias.go, so one doctrine change
// cannot land on one holder and drift the other.
//
// FAIL-ON-REVERT: revert any one of the six wrappers to a hand-rolled copy
// with a behavioural tweak (e.g. drop the empty-string guard, or change the
// message wording in one gate) and the corresponding half below diverges.

func TestMaskAliasParityStaticGenerate17211(t *testing.T) {
	// Same spelling set through both compile paths: helper-supported
	// padding ("/08") and a helper-refused folded alias ("/008") standing
	// behind a parseable survivor ("10.0.0.0/8").
	staticTree := parseHierText(t, `routing-options {
    static {
        route 10.0.0.0/008 { next-hop 192.0.2.1; }
        route 10.0.0.0/8 { next-hop 192.0.2.2; }
    }
}`)
	generateTree := parseHierText(t, `routing-options {
    generate {
        route 10.0.0.0/008 { discard; }
        route 10.0.0.0/8 { discard; }
    }
}`)

	staticCfg, err := CompileConfigLenient(staticTree)
	if err != nil {
		t.Fatalf("tolerant static compile: %v", err)
	}
	generateCfg, err := CompileConfigLenient(generateTree)
	if err != nil {
		t.Fatalf("tolerant generate compile: %v", err)
	}

	if len(staticCfg.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("static routes = %+v, want 1 folded route", staticCfg.RoutingOptions.StaticRoutes)
	}
	if len(generateCfg.RoutingOptions.GenerateRoutes) != 1 {
		t.Fatalf("generate routes = %+v, want 1 folded route", generateCfg.RoutingOptions.GenerateRoutes)
	}
	sr := staticCfg.RoutingOptions.StaticRoutes[0]
	gr := generateCfg.RoutingOptions.GenerateRoutes[0]

	// Identical canonical primary and identical alias list.
	if sr.Destination != gr.Prefix {
		t.Fatalf("canonical primary diverges: static %q vs generate %q", sr.Destination, gr.Prefix)
	}
	if sr.Destination != "10.0.0.0/8" {
		t.Fatalf("canonical primary = %q, want the parseable spelling to survive", sr.Destination)
	}
	if !reflect.DeepEqual(sr.destinationAliases, gr.prefixAliases) {
		t.Fatalf("alias lists diverge: static %v vs generate %v", sr.destinationAliases, gr.prefixAliases)
	}
	if want := []string{"10.0.0.0/008"}; !reflect.DeepEqual(sr.destinationAliases, want) {
		t.Fatalf("aliases = %v, want %v (authored refused spelling retained)", sr.destinationAliases, want)
	}

	// Identical gate messages apart from scope and tag: normalise those
	// two strings away and require byte equality. Call the gates directly
	// (cfg.Warnings would add per-family wrappers around them).
	staticMsgs := staticRouteHelperRefusedMaskSpellings(staticCfg)
	generateMsgs := generateRouteHelperRefusedMaskSpellings(generateCfg)
	if len(staticMsgs) != 1 || len(generateMsgs) != 1 {
		t.Fatalf("gate messages: static %v, generate %v; want exactly 1 each", staticMsgs, generateMsgs)
	}
	normalise := func(msg, scope, tag string) string {
		msg = strings.Replace(msg, scope, "<scope>", 1)
		msg = strings.Replace(msg, "("+tag+")", "(<tag>)", 1)
		return msg
	}
	sNorm := normalise(staticMsgs[0], "routing-options static route", "#12507")
	gNorm := normalise(generateMsgs[0], "routing-options generate route", "#15658")
	if sNorm != gNorm {
		t.Fatalf("gate messages diverge apart from scope/tag:\n static:   %s\n generate: %s", sNorm, gNorm)
	}
	// And each message really carries its own scope and tag (the
	// normalisation above must not have been vacuous).
	if !strings.Contains(staticMsgs[0], "routing-options static route") || !strings.Contains(staticMsgs[0], "(#12507)") {
		t.Fatalf("static message missing its scope/tag: %q", staticMsgs[0])
	}
	if !strings.Contains(generateMsgs[0], "routing-options generate route") || !strings.Contains(generateMsgs[0], "(#15658)") {
		t.Fatalf("generate message missing its scope/tag: %q", generateMsgs[0])
	}
}

// The unified empty-string policy: neither appender records "".
func TestMaskAliasAppendEmptyRefused17211(t *testing.T) {
	sr := &StaticRoute{Destination: "10.0.0.0/8"}
	appendStaticRouteDestinationAlias(sr, "")
	if len(sr.destinationAliases) != 0 {
		t.Fatalf("static appender recorded empty alias: %v", sr.destinationAliases)
	}
	gr := &GenerateRoute{Prefix: "10.0.0.0/8"}
	appendGenerateRoutePrefixAlias(gr, "")
	if len(gr.prefixAliases) != 0 {
		t.Fatalf("generate appender recorded empty alias: %v", gr.prefixAliases)
	}
	// A canonicalize pass must not fabricate an empty alias either: a
	// helper-refused primary with an empty alias keeps the refused
	// primary (no parseable alias to promote).
	primary := "10.0.0.0/008"
	aliases := []string{""}
	canonicalizeMaskAliases(&primary, &aliases)
	if primary != "10.0.0.0/008" {
		t.Fatalf("canonicalize promoted empty alias: primary = %q", primary)
	}
}
