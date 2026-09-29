package config

import (
	"strings"
	"testing"
)

// fable-review-167 NAT parity findings:
//
//   N-1 (#4290): `then static-nat prefix-name <name>` must resolve the named
//     global address-book entry to its literal prefix (rule.Then); an
//     unresolvable prefix-name OR any unhandled/misspelled target that leaves an
//     EMPTY translation target is rejected at strict commit (warn on lenient).
//   N-2 (#4291): `nat source interface port-overloading off` and pool
//     `port-overloading-factor <n>` are typed + accepted-with-advisory (not
//     enforced), so `off` no longer implies silent false hardening.
//   N-3 (#4292): the NAT translation-TARGET routing-instance (then static-nat
//     ... routing-instance, source/destination pool routing-instance) is typed +
//     accepted-with-advisory (not enforced), so it is no longer silently dropped.
//
// All tests drive the production ParseSetCommand + SetPath path (buildTree),
// never NewParser (the flat-set gotcha in CLAUDE.md).

func natWarnContains(cfg *Config, substr string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// --- N-1: then static-nat prefix-name ---------------------------------------

func staticPrefixNameSet(bookPrefix, thenName string) []string {
	cmds := []string{
		"set security nat static rule-set S rule R1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set S rule R1 then static-nat prefix-name " + thenName,
	}
	if bookPrefix != "" {
		cmds = append([]string{
			"set security address-book global address INSIDEHOST " + bookPrefix,
		}, cmds...)
	}
	return cmds
}

// RED on revert: without the prefix-name case + resolver, rule.Then stays ""
// (the target keyword falls through) and the rule installs with an empty
// translation target.
func TestStaticNATThenPrefixNameResolvesToBookPrefix(t *testing.T) {
	tree := buildTree(t, staticPrefixNameSet("10.0.0.5/32", "INSIDEHOST"))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("static NAT with a resolvable then prefix-name must compile, got: %v", err)
	}
	if len(cfg.Security.NAT.Static) == 0 || len(cfg.Security.NAT.Static[0].Rules) == 0 {
		t.Fatal("static NAT rule-set missing after compile")
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.ThenPrefixName != "INSIDEHOST" {
		t.Fatalf("ThenPrefixName = %q, want INSIDEHOST (parse dropped the named target)", rule.ThenPrefixName)
	}
	if rule.Then != "10.0.0.5/32" {
		t.Fatalf("Then = %q, want 10.0.0.5/32 (prefix-name did not resolve to the address-book prefix — empty/broken static NAT)", rule.Then)
	}
}

// RED on revert: without the empty-target guard, an unresolvable prefix-name
// commits cleanly with rule.Then == "".
func TestStaticNATThenPrefixNameUnresolvableRejected(t *testing.T) {
	// Reference a name that is NOT defined under security address-book.
	tree := buildTree(t, staticPrefixNameSet("", "NOSUCH"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a then static-nat prefix-name referencing an undefined address-book entry must be rejected at commit")
	}
	msg := err.Error()
	if !strings.Contains(msg, "prefix-name") || !strings.Contains(msg, "R1") || !strings.Contains(msg, "NOSUCH") {
		t.Fatalf("error must name the rule + the unresolvable prefix-name, got: %v", err)
	}
}

// An address-set with two members cannot be a scalar 1:1 target -> unresolvable.
func TestStaticNATThenPrefixNameMultiMemberSetRejected(t *testing.T) {
	cmds := []string{
		"set security address-book global address a1 10.0.0.5/32",
		"set security address-book global address a2 10.0.0.6/32",
		"set security address-book global address-set grp address a1",
		"set security address-book global address-set grp address a2",
		"set security nat static rule-set S rule R1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set S rule R1 then static-nat prefix-name grp",
	}
	_, err := CompileConfig(buildTree(t, cmds))
	if err == nil {
		t.Fatal("a then static-nat prefix-name resolving to a multi-member address-set must be rejected (no single 1:1 target)")
	}
	if !strings.Contains(err.Error(), "prefix-name") {
		t.Fatalf("error must reference prefix-name, got: %v", err)
	}
}

// RED on revert: without the empty-target guard, a misspelled/unhandled target
// keyword commits cleanly with rule.Then == "".
func TestStaticNATThenEmptyTargetRejected(t *testing.T) {
	cmds := []string{
		"set security nat static rule-set S rule R1 match destination-address 203.0.113.5/32",
		// "prefix-nam" is a typo for "prefix" / "prefix-name" — the free-form
		// static-nat leaf accepts it, and the then switch matches no case.
		"set security nat static rule-set S rule R1 then static-nat prefix-nam 10.0.0.5/32",
	}
	_, err := CompileConfig(buildTree(t, cmds))
	if err == nil {
		t.Fatal("a then static-nat with an unhandled/misspelled target (empty translation target) must be rejected at commit")
	}
	if !strings.Contains(err.Error(), "empty") || !strings.Contains(err.Error(), "R1") {
		t.Fatalf("error must flag the empty translation target for the rule, got: %v", err)
	}
}

// RED on revert: the lenient (load / peer-sync) path must WARN, not brick, and
// on revert there is neither warning nor error (silent).
func TestStaticNATThenPrefixNameUnresolvableLenientWarns(t *testing.T) {
	tree := buildTree(t, staticPrefixNameSet("", "NOSUCH"))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile of an unresolvable prefix-name must not brick, got: %v", err)
	}
	if !natWarnContains(cfg, "static NAT translation target") {
		t.Fatalf("lenient path must emit a downgraded warning for the unresolvable prefix-name; warnings=%v", cfg.Warnings)
	}
}

func TestStaticNATThenPrefixNameMixedAddressFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		target  string
		entries []string
	}{
		{name: "address", target: "INSIDEHOST"},
		{
			name:   "singleton address-set",
			target: "INSIDESET",
			entries: []string{
				"set security address-book global address-set INSIDESET address INSIDEHOST",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmds := append([]string{
				"set security address-book global address INSIDEHOST 10.0.0.5/32",
				"set security address-book global address INSIDEHOST dns-name evil.example",
				"set security nat static rule-set S rule R1 match destination-address 203.0.113.5/32",
				"set security nat static rule-set S rule R1 then static-nat prefix-name " + tc.target,
			}, tc.entries...)
			cfg, err := CompileConfigLenient(buildTree(t, cmds))
			if err != nil {
				t.Fatalf("lenient compile should preserve the mixed address entry: %v", err)
			}
			rule := cfg.Security.NAT.Static[0].Rules[0]
			if rule.Then != "" {
				t.Fatalf("mixed/unimplemented prefix-name resolved to %q, want no translation", rule.Then)
			}
			if !natWarnContains(cfg, "static NAT translation target") {
				t.Fatalf("missing fail-closed prefix-name warning: %v", cfg.Warnings)
			}
		})
	}
}

// A well-formed prefix/inet/nptv6 target must NOT trip the empty-target guard.
func TestStaticNATThenLiteralPrefixStillCompiles(t *testing.T) {
	cmds := []string{
		"set security nat static rule-set S rule R1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set S rule R1 then static-nat prefix 10.0.0.5/32",
	}
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("a literal then static-nat prefix must still compile, got: %v", err)
	}
	if cfg.Security.NAT.Static[0].Rules[0].Then != "10.0.0.5/32" {
		t.Fatalf("literal prefix target regressed: Then=%q", cfg.Security.NAT.Static[0].Rules[0].Then)
	}
}

// --- N-2: port-overloading knobs -------------------------------------------

// RED on revert: `interface port-overloading off` is silently dropped (no field,
// no advisory) so `off` falsely implies hardening.
func TestNATSourceInterfacePortOverloadingOffAdvisory(t *testing.T) {
	cmds := []string{
		"set security nat source interface port-overloading off",
	}
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("nat source interface port-overloading off must compile, got: %v", err)
	}
	if !cfg.Security.NAT.SourceInterfacePortOverloadingOff {
		t.Fatal("SourceInterfacePortOverloadingOff not recorded (knob silently dropped)")
	}
	if !natWarnContains(cfg, "#4291") || !natWarnContains(cfg, "port-overloading off") {
		t.Fatalf("port-overloading off must emit an accepted-only advisory; warnings=%v", cfg.Warnings)
	}
}

// RED on revert: pool port-overloading-factor is silently dropped.
func TestNATSourcePoolPortOverloadingFactorAdvisory(t *testing.T) {
	cmds := []string{
		"set security nat source pool P1 address 203.0.113.10/32",
		"set security nat source pool P1 port-overloading-factor 4",
	}
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("nat source pool port-overloading-factor must compile, got: %v", err)
	}
	p := cfg.Security.NAT.SourcePools["P1"]
	if p == nil || p.PortOverloadingFactor != 4 {
		t.Fatalf("PortOverloadingFactor not recorded (got %+v)", p)
	}
	if !natWarnContains(cfg, "#4291") || !natWarnContains(cfg, "port-overloading-factor") {
		t.Fatalf("port-overloading-factor must emit an accepted-only advisory; warnings=%v", cfg.Warnings)
	}
}

// --- N-3: translation-target routing-instance -------------------------------

// RED on revert: the trailing routing-instance on a static-nat then target is
// silently dropped.
func TestStaticNATThenRoutingInstanceAdvisory(t *testing.T) {
	cmds := []string{
		"set security nat static rule-set S rule R1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set S rule R1 then static-nat prefix 10.0.0.5/32 routing-instance vr-blue",
	}
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("then static-nat prefix ... routing-instance must compile, got: %v", err)
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.Then != "10.0.0.5/32" {
		t.Fatalf("literal prefix regressed alongside routing-instance: Then=%q", rule.Then)
	}
	if rule.ThenRoutingInstance != "vr-blue" {
		t.Fatalf("ThenRoutingInstance = %q, want vr-blue (target RI silently dropped)", rule.ThenRoutingInstance)
	}
	if !natWarnContains(cfg, "#4292") || !natWarnContains(cfg, "vr-blue") {
		t.Fatalf("translation-target routing-instance must emit an accepted-only advisory; warnings=%v", cfg.Warnings)
	}
}

// The inet (NAT64) target must also keep its trailing routing-instance and NOT
// trip the empty-target guard.
func TestStaticNATThenInetRoutingInstanceAdvisory(t *testing.T) {
	cmds := []string{
		"set security nat static rule-set S rule R1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set S rule R1 then static-nat inet routing-instance vr-green",
	}
	tree := buildTree(t, cmds)
	// #5859: `then static-nat inet` (NAT64) is now rejected at strict commit —
	// no dataplane lowering exists and the literal "inet" installed a silently
	// inert rule. The compiler still records the target + its trailing
	// routing-instance advisory; validate that recording on the tolerant
	// (lenient) path, which downgrades the reject to a surfaced warning.
	if _, serr := CompileConfig(tree); serr == nil {
		t.Fatal("strict CompileConfig must REJECT `then static-nat inet` (#5859)")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must not brick on `then static-nat inet routing-instance`, got: %v", err)
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.Then != "inet" {
		t.Fatalf("inet target regressed alongside routing-instance: Then=%q", rule.Then)
	}
	if rule.ThenRoutingInstance != "vr-green" {
		t.Fatalf("ThenRoutingInstance = %q, want vr-green", rule.ThenRoutingInstance)
	}
	if !hasWarningContaining(cfg.Warnings, "inet") {
		t.Fatalf("lenient path must surface a downgrade warning for `static-nat inet`; warnings: %v", cfg.Warnings)
	}
}

// Copilot edge (#4292): the trailing-routing-instance grammar. The RI scan must
// return the LAST "routing-instance" occurrence, not the first — otherwise an
// earlier "routing-instance" token in the collapsed key list wins. The
// pathological case: the address-book entry referenced by prefix-name is itself
// literally NAMED "routing-instance", and the target RI trails at the tail.
//
// RED on revert (first-match scan): ThenRoutingInstance is recorded as the entry
// name "routing-instance" instead of the trailing "MYVRF".
func TestStaticNATThenRoutingInstanceLastOccurrence(t *testing.T) {
	cmds := []string{
		// An address-book entry pathologically NAMED "routing-instance".
		"set security address-book global address routing-instance 10.0.0.9/32",
		"set security nat static rule-set S rule R1 match destination-address 203.0.113.5/32",
		// then static-nat prefix-name <entry=routing-instance> routing-instance MYVRF
		"set security nat static rule-set S rule R1 then static-nat prefix-name routing-instance routing-instance MYVRF",
	}
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("prefix-name entry named routing-instance + trailing routing-instance must compile, got: %v", err)
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.ThenPrefixName != "routing-instance" {
		t.Fatalf("ThenPrefixName = %q, want routing-instance (the pathological entry name)", rule.ThenPrefixName)
	}
	if rule.Then != "10.0.0.9/32" {
		t.Fatalf("Then = %q, want 10.0.0.9/32 (prefix-name must resolve the entry named routing-instance)", rule.Then)
	}
	if rule.ThenRoutingInstance != "MYVRF" {
		t.Fatalf("ThenRoutingInstance = %q, want MYVRF (trailing RI; a first-match scan wrongly returns the entry name %q)", rule.ThenRoutingInstance, "routing-instance")
	}
	if !natWarnContains(cfg, "#4292") || !natWarnContains(cfg, "MYVRF") {
		t.Fatalf("advisory must reference the TRAILING RI MYVRF, not the entry name; warnings=%v", cfg.Warnings)
	}
}

// The normal prefix-name + trailing routing-instance case stays correct.
func TestStaticNATThenPrefixNameRoutingInstanceNormal(t *testing.T) {
	cmds := []string{
		"set security address-book global address FOO 10.0.0.7/32",
		"set security nat static rule-set S rule R1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set S rule R1 then static-nat prefix-name FOO routing-instance MYVRF",
	}
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("prefix-name FOO routing-instance MYVRF must compile, got: %v", err)
	}
	rule := cfg.Security.NAT.Static[0].Rules[0]
	if rule.Then != "10.0.0.7/32" {
		t.Fatalf("Then = %q, want 10.0.0.7/32", rule.Then)
	}
	if rule.ThenRoutingInstance != "MYVRF" {
		t.Fatalf("ThenRoutingInstance = %q, want MYVRF", rule.ThenRoutingInstance)
	}
}

// RED on revert: the DNAT pool routing-instance is silently dropped.
func TestDNATPoolRoutingInstanceAdvisory(t *testing.T) {
	cmds := []string{
		"set security nat destination pool DP address 10.0.0.5/32",
		"set security nat destination pool DP routing-instance vr-red",
	}
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("nat destination pool routing-instance must compile, got: %v", err)
	}
	if cfg.Security.NAT.Destination == nil {
		t.Fatal("destination NAT config missing")
	}
	p := cfg.Security.NAT.Destination.Pools["DP"]
	if p == nil || p.RoutingInstance != "vr-red" {
		t.Fatalf("DNAT pool RoutingInstance not recorded (got %+v)", p)
	}
	if !natWarnContains(cfg, "#4292") || !natWarnContains(cfg, "vr-red") {
		t.Fatalf("DNAT pool routing-instance must emit an accepted-only advisory; warnings=%v", cfg.Warnings)
	}
}

// RED on revert: the source NAT pool routing-instance is silently dropped.
func TestSourceNATPoolRoutingInstanceAdvisory(t *testing.T) {
	cmds := []string{
		"set security nat source pool SP address 203.0.113.10/32",
		"set security nat source pool SP routing-instance vr-orange",
	}
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("nat source pool routing-instance must compile, got: %v", err)
	}
	p := cfg.Security.NAT.SourcePools["SP"]
	if p == nil || p.RoutingInstance != "vr-orange" {
		t.Fatalf("source pool RoutingInstance not recorded (got %+v)", p)
	}
	if !natWarnContains(cfg, "#4292") || !natWarnContains(cfg, "vr-orange") {
		t.Fatalf("source pool routing-instance must emit an accepted-only advisory; warnings=%v", cfg.Warnings)
	}
}
