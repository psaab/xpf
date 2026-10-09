package config

import (
	"strings"
	"testing"
)

// #2142: an `set applications application <name>` with a malformed
// destination-port / source-port or an unknown protocol was only WARNED at
// commit (ValidateConfig), never rejected. Commit succeeded, the dataplane
// app-id compiler recorded the AppID name then skipped the unparsable port (a
// never-match AppID), and a policy referencing the application failed CLOSED on
// a permit rule or fell through OPEN on a deny rule. These tests drive the real
// strict commit path (CompileConfig) and the tolerant load path
// (CompileConfigLenient) through validateApplicationSpecsStrict.
//
// All trees are built from flat `set` commands via flatTreeFromSets (defined in
// compiler_interfaces_unsupported_test.go) — the only correct way to exercise
// the flat-set AST shape.

// referencedBadApp wires the issue's exact trigger: a policy `deny` rule that
// matches a malformed application. baseValid is the same structure with a VALID
// destination-port, proving the reject is caused by the bad spec, not the
// surrounding policy.
func referencedBadApp(destPort string) []string {
	return []string{
		// One leaf per `set` line: a single flat-set line nests each token as a
		// child of the previous, so `protocol tcp destination-port X` would bury
		// destination-port under protocol and the compiler would never see it
		// (see TestMultiTermApplication for the multi-token-chain pitfall).
		"set applications application BAD protocol tcp",
		"set applications application BAD destination-port " + destPort,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application BAD",
		"set security policies from-zone trust to-zone untrust policy p then deny",
	}
}

func TestApplicationSpec_ReferencedBadDestPort_RejectsAtCommit(t *testing.T) {
	// The issue's verbatim trigger: destination-port nope.
	tree := flatTreeFromSets(t, referencedBadApp("nope")...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject application BAD with destination-port nope")
	}
	if !strings.Contains(err.Error(), "BAD") ||
		!strings.Contains(err.Error(), "destination-port") {
		t.Fatalf("error %q must name application BAD and destination-port", err.Error())
	}
}

func TestApplicationSpec_ReferencedOutOfRangeDestPort_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, referencedBadApp("99999")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject application BAD with destination-port 99999")
	}
}

func TestApplicationSpec_ReferencedInvertedRange_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, referencedBadApp("200-100")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject application BAD with inverted range 200-100")
	}
}

func TestApplicationSpec_ReferencedUnknownProtocol_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol bogus",
		"set applications application BAD destination-port 80",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application BAD",
		"set security policies from-zone trust to-zone untrust policy p then deny",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject application BAD with protocol bogus")
	}
	if !strings.Contains(err.Error(), "BAD") ||
		!strings.Contains(err.Error(), "bogus") {
		t.Fatalf("error %q must name application BAD and the bad protocol", err.Error())
	}
}

func TestApplicationSpec_ReferencedBadSourcePort_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol tcp",
		"set applications application BAD source-port nope",
		"set applications application BAD destination-port 80",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application BAD",
		"set security policies from-zone trust to-zone untrust policy p then deny",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject application BAD with source-port nope")
	}
	if !strings.Contains(err.Error(), "source-port") {
		t.Fatalf("error %q must mention source-port", err.Error())
	}
}

// Non-tautological companion: the SAME policy structure with a VALID
// destination-port must commit cleanly, proving the reject above is caused by
// the malformed spec and not the surrounding policy.
func TestApplicationSpec_ReferencedValid_AcceptsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, referencedBadApp("8080-8090")...)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("expected commit to accept application BAD with valid range: %v", err)
	}
}

// A malformed application that is referenced via an application-SET (the policy
// names the set, not the app directly) must also reject at commit.
func TestApplicationSpec_ReferencedViaSet_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol tcp",
		"set applications application BAD destination-port nope",
		"set applications application-set SET application BAD",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application SET",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject application BAD referenced via application-set SET")
	}
}

// The set-with-dangling-member escape (independent review F1): a policy
// references an application-SET that contains BOTH a malformed user app (BAD,
// destination-port "nope") AND an undefined/dangling member (MISSING).
// ExpandApplicationSet bails on the FIRST member it cannot resolve, so before
// the fix the whole expansion errored, applicationsToValidateStrict's addRef
// silently returned, and BAD escaped the strict gate — commit succeeded (the
// exact #2142 fail-closed-on-permit pathology, scoped to a set carrying a
// dangling member). The malformed member must still be hard-rejected; the
// unrelated dangling member must not mask it.
func TestApplicationSpec_SetWithDanglingMember_StillRejectsBadMember(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol tcp",
		"set applications application BAD destination-port nope",
		// SET carries BAD plus an undefined member MISSING; member order in the
		// flat AST follows set-line order, so MISSING-first would make the
		// dangling error fire before BAD is even reached pre-fix.
		"set applications application-set SET application BAD",
		"set applications application-set SET application MISSING",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application SET",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject malformed application BAD even though " +
			"application-set SET also has a dangling member MISSING")
	}
	if !strings.Contains(err.Error(), "BAD") ||
		!strings.Contains(err.Error(), "destination-port") {
		t.Fatalf("error %q must name the malformed member BAD and destination-port "+
			"(the dangling MISSING must not mask the malformed spec)", err.Error())
	}
}

// app-id (services application-identification) enabled: EVERY user application
// compiles into the catalog, so a malformed app must reject at commit even when
// no policy references it.
func TestApplicationSpec_AppIDEnabledUnreferencedBad_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol tcp",
		"set applications application BAD destination-port nope",
		"set services application-identification",
	)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("expected commit to reject unreferenced application BAD when app-id is enabled")
	}
}

// An UNREFERENCED application with app-id DISABLED is not matchable by anything,
// so its malformed spec stays a warning (the explicit referenced-vs-unreferenced
// distinction in #2142). This keeps an operator iterating on a not-yet-wired
// application library unblocked, and preserves existing configs that carry an
// unreferenced app with a port form the policy matcher cannot represent.
func TestApplicationSpec_UnreferencedBad_WarnsNotRejected(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD protocol bogus",
		"set applications application BAD destination-port nope",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("unreferenced bad app must not reject at commit: %v", err)
	}
	// ValidateConfig still surfaces it as a warning (the show paths use this).
	var warned bool
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "BAD") {
			warned = true
		}
	}
	if !warned {
		t.Fatal("expected ValidateConfig to warn about unreferenced bad application BAD")
	}
}

// No-brick (#1960 / #2008 doctrine): a config persisted/synced with a
// policy-referenced malformed application must still LOAD on the tolerant path
// (CompileConfigLenient) — downgraded to a warning — so an upgraded node does
// not fail closed on boot. The runtime #2124 capability gate fails the snapshot
// closed for the referenced app it cannot represent, so the leniently-loaded
// bad app is inert rather than silently mis-matching.
func TestApplicationSpec_ReferencedBad_LenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t, referencedBadApp("nope")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a referenced bad app must not fail: %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "application spec") && strings.Contains(w, "BAD") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected lenient path to record an application-spec downgrade warning, got %v", cfg.Warnings)
	}
}

// #3109: a custom application with a port (or any spec) but NO `protocol` was
// accepted at commit (validateApplicationSpecsStrict only checked a NON-empty
// protocol, compiler_validate_strict_application.go), then was unrepresentable at runtime: the
// Go capability gate (normalizeUserspaceApplicationProtocol("") → ok=false) trips
// #2124's refuse-to-arm and sets ForwardingSupported=false for the WHOLE userspace
// dataplane, so ONE protocol-less app silently disabled security-policy enforcement
// for the entire config (a system-level fail-OPEN to the kernel slow path); the Rust
// snapshot builder likewise hard-errors UnrepresentableApplicationProtocol. Junos
// requires `protocol`, so the fix rejects a protocol-less referenced application at
// COMMIT, naming the one offending app instead of silently disabling everything.

// A referenced protocol-less (port-only) application must reject at commit, naming
// the application and "protocol".
func TestApplicationSpec_ReferencedProtocollessApp_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t,
		// No `protocol` leaf — only a destination-port. This is the issue's exact
		// trigger.
		"set applications application BAD destination-port 443",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application BAD",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject protocol-less application BAD (port-only, no protocol)")
	}
	if !strings.Contains(err.Error(), "BAD") ||
		!strings.Contains(err.Error(), "protocol") {
		t.Fatalf("error %q must name application BAD and mention protocol", err.Error())
	}
}

// Blast-radius containment / non-tautology: a config that references BOTH a
// normal protocol-bearing application (GOOD) AND a protocol-less one (BAD) must
// reject at commit with an error that pinpoints BAD — the failure is isolated to
// the one offending app, NOT a vague global break. The GOOD app's spec is valid,
// proving the reject is caused solely by the protocol-less BAD.
//
// Fail-on-revert: removing the `if app.Protocol == ""` guard in
// validateApplicationSpecsStrict restores the pre-fix whole-table-failure
// behavior — the config COMMITS (BAD passes the strict gate), and at runtime the
// #2124 capability gate sets ForwardingSupported=false for the entire userspace
// dataplane (one protocol-less app disables policy enforcement for GOOD's policy
// too). With the guard removed CompileConfig returns nil, so this test's
// `err == nil` assertion fires and the test goes RED.
func TestApplicationSpec_ProtocollessApp_DoesNotDisableOtherApps(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application GOOD protocol tcp destination-port 80",
		"set applications application BAD destination-port 443",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		// p_good references the well-formed GOOD app.
		"set security policies from-zone trust to-zone untrust policy p_good match source-address any",
		"set security policies from-zone trust to-zone untrust policy p_good match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p_good match application GOOD",
		"set security policies from-zone trust to-zone untrust policy p_good then permit",
		// p_bad references the protocol-less BAD app.
		"set security policies from-zone trust to-zone untrust policy p_bad match source-address any",
		"set security policies from-zone trust to-zone untrust policy p_bad match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p_bad match application BAD",
		"set security policies from-zone trust to-zone untrust policy p_bad then deny",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject protocol-less application BAD so it can " +
			"never reach the runtime and globally disable enforcement (GOOD's policy included)")
	}
	if !strings.Contains(err.Error(), "BAD") {
		t.Fatalf("error %q must pinpoint the protocol-less application BAD (blast radius is one named app)", err.Error())
	}
	// The error must isolate BAD, not implicate the well-formed GOOD app.
	if strings.Contains(err.Error(), "GOOD") {
		t.Fatalf("error %q must not implicate the well-formed application GOOD", err.Error())
	}
}

// The same config, but with GOOD only (no protocol-less app) and BAD given a
// protocol, must commit cleanly — proving the reject above is caused by the
// missing protocol and not the surrounding two-policy structure.
func TestApplicationSpec_BothAppsHaveProtocol_AcceptsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application GOOD protocol tcp destination-port 80",
		"set applications application BAD protocol tcp destination-port 443",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p_good match source-address any",
		"set security policies from-zone trust to-zone untrust policy p_good match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p_good match application GOOD",
		"set security policies from-zone trust to-zone untrust policy p_good then permit",
		"set security policies from-zone trust to-zone untrust policy p_bad match source-address any",
		"set security policies from-zone trust to-zone untrust policy p_bad match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p_bad match application BAD",
		"set security policies from-zone trust to-zone untrust policy p_bad then deny",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("expected commit to accept two protocol-bearing applications: %v", err)
	}
}

// No-brick (#1960): a config persisted/synced with a policy-referenced
// protocol-less application must still LOAD on the tolerant path
// (CompileConfigLenient) — downgraded to a warning — so an upgraded node does
// not fail closed on boot. The #2124 runtime gate keeps that one app's policy
// inert (refuse-to-arm) rather than silently mis-matching.
func TestApplicationSpec_ReferencedProtocollessApp_LenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD destination-port 443",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application BAD",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a referenced protocol-less app must not fail: %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "application spec") && strings.Contains(w, "BAD") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected lenient path to record an application-spec downgrade warning, got %v", cfg.Warnings)
	}
}

// An UNREFERENCED protocol-less application with app-id DISABLED stays a warning
// (the referenced-vs-unreferenced distinction): it is not matchable by anything,
// so it cannot disable a live policy and must not block an operator iterating on
// a not-yet-wired application library.
func TestApplicationSpec_UnreferencedProtocollessApp_WarnsNotRejected(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application BAD destination-port 443",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("unreferenced protocol-less app must not reject at commit: %v", err)
	}
}

// referencedProtoApp wires the issue's exact #3150 trigger: a policy that
// matches an application whose `protocol` leaf is the supplied token. No port is
// attached — these cases exercise protocol RESOLVABILITY only, and the #3373
// gate now rejects a port on a non-port protocol (icmp/gre/numeric), which
// several of these tokens are.
func referencedProtoApp(proto string) []string {
	return []string{
		"set applications application BAD protocol " + proto,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application BAD",
		"set security policies from-zone trust to-zone untrust policy p then deny",
	}
}

// #3150: validateProtocol blanket-accepts ANY "junos-" prefix, so a
// policy-referenced application with `protocol junos-foobar` committed cleanly
// while the dataplane resolver (appid.ProtocolNumber, mirrored by
// filterProtocolResolvable) rejects it — disarming the userspace policy
// capability gate (a commit-succeeds / apply-fails split). The strict gate must
// resolve the protocol through the SAME authority the dataplane uses, so an
// unresolvable junos-* token is rejected at COMMIT.
//
// Fail-on-revert: restoring the broad `strings.HasPrefix("junos-")` accept in
// validateApplicationSpecsStrict makes this commit SUCCEED, turning the test RED.
func TestApplicationSpec_ReferencedUnknownJunosProtocol_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, referencedProtoApp("junos-foobar")...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject application BAD with protocol junos-foobar " +
			"(the dataplane's appid.ProtocolNumber cannot resolve it)")
	}
	if !strings.Contains(err.Error(), "BAD") ||
		!strings.Contains(err.Error(), "junos-foobar") {
		t.Fatalf("error %q must name application BAD and the bad protocol junos-foobar", err.Error())
	}
}

// Non-tautological companion: a RESOLVABLE junos-* alias the catalog actually
// knows (junos-ping → ICMP) must still commit cleanly, proving the #3150 reject
// is scoped to genuinely-unresolvable tokens and does not break legitimate
// junos-* protocol aliases.
func TestApplicationSpec_ReferencedResolvableJunosProtocol_AcceptsAtCommit(t *testing.T) {
	for _, proto := range []string{"junos-ping", "junos-tcp-any", "junos-gre"} {
		tree := flatTreeFromSets(t, referencedProtoApp(proto)...)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("expected commit to accept application BAD with resolvable protocol %q: %v", proto, err)
		}
	}
}

// A numeric protocol referenced by a policy must commit (appid.ProtocolNumber
// resolves any 0..255 numeric, including the deliberate "0" / HOPOPT).
func TestApplicationSpec_ReferencedNumericProtocol_AcceptsAtCommit(t *testing.T) {
	for _, proto := range []string{"0", "47", "255"} {
		tree := flatTreeFromSets(t, referencedProtoApp(proto)...)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("expected commit to accept application BAD with numeric protocol %q: %v", proto, err)
		}
	}
}

// No-brick (#1960): a config persisted/synced with a policy-referenced
// unresolvable junos-* protocol must still LOAD on the tolerant path
// (CompileConfigLenient) — downgraded to a warning — so an upgraded node does
// not fail closed on boot.
func TestApplicationSpec_ReferencedUnknownJunosProtocol_LenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t, referencedProtoApp("junos-foobar")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a referenced bad-protocol app must not fail: %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "application spec") && strings.Contains(w, "junos-foobar") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected lenient path to record an application-spec downgrade warning, got %v", cfg.Warnings)
	}
}

// #3373: a source-port/destination-port is only meaningful on a port-bearing
// transport (TCP/UDP/SCTP). Before this gate validateApplicationSpecsStrict
// checked port SYNTAX and protocol resolvability but never that the port was
// attached to a port-bearing protocol, so `protocol icmp destination-port 80`
// (or gre/ospf/esp + a port) committed. The runtime then compiled a port
// matcher indexed by the protocol number; a non-port protocol always presents
// ports of 0, so the term became a never-match — fail-OPEN for a deny rule,
// fail-CLOSED for a permit rule. The gate rejects such a spec at COMMIT.
//
// referencedNonPortProtoWithPort wires a policy-referenced application whose
// protocol is `proto` (a non-port protocol) carrying `portKind` (destination or
// source) port `port`. Two `set` lines (one leaf each) so the port leaf is not
// buried under protocol (see referencedBadApp).
func referencedNonPortProtoWithPort(proto, portKind, port string) []string {
	return []string{
		"set applications application BAD protocol " + proto,
		"set applications application BAD " + portKind + " " + port,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application BAD",
		"set security policies from-zone trust to-zone untrust policy p then deny",
	}
}

// Fail-on-revert: removing the protocolIsPortBearing gate in
// validateApplicationSpecsStrict makes every one of these commit SUCCEED (the
// port passes validatePortSpec and the protocol passes filterProtocolResolvable),
// turning the test RED.
func TestApplicationSpec_PortOnNonPortProtocol_RejectsAtCommit(t *testing.T) {
	cases := []struct {
		name, proto, portKind, port string
	}{
		{"icmp_dst", "icmp", "destination-port", "80"},
		{"icmpv6_dst", "icmpv6", "destination-port", "80"},
		{"gre_dst", "gre", "destination-port", "47"},
		{"ospf_dst", "ospf", "destination-port", "89"},
		{"esp_src", "esp", "source-port", "4500"},
		{"ah_dst", "ah", "destination-port", "51"},
		{"vrrp_dst", "vrrp", "destination-port", "112"},
		// SCTP HAS ports on the wire but this dataplane never extracts them
		// (ip_proto.rs has_l4_ports = TCP/UDP only), so an sctp+port term is the
		// same #3373 never-match — reject it, fail-closed-correct.
		{"sctp_dst", "sctp", "destination-port", "80"},
		{"numeric_sctp_dst", "132", "destination-port", "80"},
		{"junos_ping_dst", "junos-ping", "destination-port", "8"},
		{"junos_gre_src", "junos-gre", "source-port", "1024"},
		{"numeric_gre_dst", "47", "destination-port", "80"},
		{"numeric_hopopt_dst", "0", "destination-port", "80"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, referencedNonPortProtoWithPort(tc.proto, tc.portKind, tc.port)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject application BAD with %s %s on non-port protocol %q",
					tc.portKind, tc.port, tc.proto)
			}
			if !strings.Contains(err.Error(), "BAD") ||
				!strings.Contains(err.Error(), tc.portKind) ||
				!strings.Contains(err.Error(), tc.proto) {
				t.Fatalf("error %q must name application BAD, the %s, and protocol %q",
					err.Error(), tc.portKind, tc.proto)
			}
		})
	}
}

// Positive controls — these must continue to commit cleanly, proving the #3373
// reject is scoped to (port set) AND (a protocol the dataplane does not extract
// ports for):
//
//   - tcp/udp + a port (the ONLY protocols ip_proto.rs has_l4_ports extracts —
//     SCTP is deliberately excluded and tested as a REJECT above);
//   - a non-port protocol (icmp/gre) with NO port (the port is what makes it
//     unrepresentable — the protocol alone is fine);
//   - the numeric forms of the extracted protocols (6/17).
func TestApplicationSpec_PortBearingProtocolWithPort_AcceptsAtCommit(t *testing.T) {
	for _, proto := range []string{"tcp", "udp", "junos-tcp-any", "junos-udp-any", "6", "17"} {
		tree := flatTreeFromSets(t, referencedNonPortProtoWithPort(proto, "destination-port", "8080")...)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("expected commit to accept port-bearing protocol %q with a port: %v", proto, err)
		}
	}
}

func TestApplicationSpec_NonPortProtocolWithoutPort_AcceptsAtCommit(t *testing.T) {
	for _, proto := range []string{"icmp", "icmpv6", "gre", "ospf", "esp", "ah", "vrrp", "sctp", "junos-ping", "47", "0", "132"} {
		tree := flatTreeFromSets(t, referencedProtoApp(proto)...)
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("expected commit to accept non-port protocol %q with NO port: %v", proto, err)
		}
	}
}

// An ICMP application constrained by an icmp-type but carrying NO port must be
// accepted — the #3373 gate fires only when a port is set, so a type-only ICMP
// app (e.g. the junos-ping shape) is unaffected. Built as a Config directly
// because custom-application icmp-type is a typed-leaf the strict validator
// reads off the Application struct; ApplicationIdentification is enabled so the
// app is in scope for the strict walk without a policy reference.
func TestApplicationSpec_ICMPTypeOnlyNoPort_AcceptsAtCommit(t *testing.T) {
	icmpType := uint8(8)
	cfg := &Config{}
	cfg.Services.ApplicationIdentification = true
	cfg.Applications.Applications = map[string]*Application{
		"PING": {Name: "PING", Protocol: "icmp", ICMPType: &icmpType},
	}
	if err := validateApplicationSpecsStrict(cfg); err != nil {
		t.Fatalf("expected an icmp-type-only application (no port) to pass the strict gate: %v", err)
	}
	// And with a port on the same icmp app, the gate must reject.
	cfg.Applications.Applications["PING"].DestinationPort = "80"
	if err := validateApplicationSpecsStrict(cfg); err == nil {
		t.Fatal("expected an icmp application with a destination-port to be rejected by the #3373 gate")
	}
}

// No-brick (#1960/#3261): a config persisted/synced with a policy-referenced
// port-on-non-port-protocol application must still LOAD on the tolerant path
// (CompileConfigLenient) — downgraded to a warning, NOT a hard fail — so an
// upgraded node (or one peer-syncing from an older binary that accepted the
// spec) does not fail closed on boot. The icmp subcase covers a classic
// non-port protocol; the sctp / numeric-132 subcases pin the contract for the
// EXACT protocol that triggered the #3373 SCTP MAJOR — SCTP has wire ports but
// is not extracted by this dataplane (ip_proto.rs has_l4_ports), so the strict
// gate rejects sctp+port at commit, yet an already-committed sctp+port config
// must still load leniently.
func TestApplicationSpec_PortOnNonPortProtocol_LenientWarns(t *testing.T) {
	cases := []struct {
		name, proto, portKind, port string
	}{
		{"icmp", "icmp", "destination-port", "80"},
		{"sctp", "sctp", "destination-port", "80"},
		{"numeric_sctp", "132", "destination-port", "80"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, referencedNonPortProtoWithPort(tc.proto, tc.portKind, tc.port)...)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient load of a referenced %s+port app must not fail: %v", tc.proto, err)
			}
			if cfg == nil {
				t.Fatalf("lenient load of a referenced %s+port app must return a non-nil config", tc.proto)
			}
			var warned bool
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "application spec") && strings.Contains(w, "BAD") {
					warned = true
				}
			}
			if !warned {
				t.Fatalf("expected lenient path to record an application-spec downgrade warning for %s, got %v",
					tc.proto, cfg.Warnings)
			}
		})
	}
}

// shadowedPredefinedBundleBadMember references the built-in junos-sip bundle
// with a malformed user-defined junos-sip-tcp member.
func shadowedPredefinedBundleBadMember() []string {
	return []string{
		"set applications application junos-sip-tcp protocol tcp",
		"set applications application junos-sip-tcp destination-port nope",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application junos-sip",
		"set security policies from-zone trust to-zone untrust policy p then deny",
	}
}

// AppID is deliberately left disabled here: only the policy's reference to
// the predefined bundle should make the malformed shadowed member strict.
// This regression ensures a shadowed member is rejected by the spec gate, not
// merely by the all-applications AppID path.
func TestApplicationSpec_ShadowedPredefinedBundleMember_AppIDOffRejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, shadowedPredefinedBundleBadMember()...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject malformed user application junos-sip-tcp referenced through predefined bundle junos-sip")
	}
	if !strings.Contains(err.Error(), "junos-sip-tcp") ||
		!strings.Contains(err.Error(), "destination-port") {
		t.Fatalf("error %q must name malformed bundle member junos-sip-tcp and destination-port", err.Error())
	}
}

func TestApplicationSpec_ShadowedPredefinedBundleMember_AppIDOnControl(t *testing.T) {
	lines := append(shadowedPredefinedBundleBadMember(), "set services application-identification")
	tree := flatTreeFromSets(t, lines...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected AppID-on commit to continue rejecting malformed user application junos-sip-tcp")
	}
	if !strings.Contains(err.Error(), "junos-sip-tcp") ||
		!strings.Contains(err.Error(), "destination-port") {
		t.Fatalf("error %q must name malformed application junos-sip-tcp and destination-port", err.Error())
	}
}

// A user application shadows a predefined bundle with the same name: the
// strict walk must check user applications BEFORE predefined sets (matching
// the runtime's ResolveApplication-then-ResolveApplicationSet order). This
// pins that precedence — moving the PredefinedApplicationSets branch ahead of
// the user-app check would expand junos-sip to its predefined members, collect
// nothing user-defined, and commit green while the runtime resolves the
// malformed user app first and poisons at apply.
func TestApplicationSpec_UserAppBeforePredefinedSet_AppIDOffRejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set applications application junos-sip protocol tcp",
		"set applications application junos-sip destination-port nope",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application junos-sip",
		"set security policies from-zone trust to-zone untrust policy p then deny",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject malformed user application junos-sip shadowing the predefined junos-sip bundle")
	}
	if !strings.Contains(err.Error(), "junos-sip") ||
		!strings.Contains(err.Error(), "destination-port") {
		t.Fatalf("error %q must name user application junos-sip and destination-port", err.Error())
	}
}
