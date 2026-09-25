package appid

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestCatalogNamesReferencedOnly(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				"custom-web": {Name: "custom-web", Protocol: "tcp", DestinationPort: "8443"},
			},
			ApplicationSets: map[string]*config.ApplicationSet{
				"web-set": {Name: "web-set", Applications: []string{"junos-http", "custom-web"}},
			},
		},
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{
				{
					Policies: []*config.Policy{
						{Match: config.PolicyMatch{Applications: []string{"web-set"}}},
					},
				},
			},
		},
	}

	got, err := CatalogNames(cfg, false)
	if err != nil {
		t.Fatalf("CatalogNames() error = %v", err)
	}
	want := []string{"custom-web", "junos-http"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CatalogNames() = %v, want %v", got, want)
	}
}

// TestCatalogNamesIncludesNATOnlyAppRefs is the #3626 RED-on-revert proof.
// With application-identification DISABLED, an application referenced ONLY by a
// source- or destination-NAT rule's `match application` — with NO security
// policy referencing it — must still land in the compiled catalog. Before the
// fix CatalogNames walked only policies, so these apps were silently dropped
// and the dataplane could not resolve them. Reverting the NAT walk in
// CatalogNames turns this test RED (the NAT-only names disappear from the
// result). It covers a direct source-NAT ref, a direct destination-NAT ref,
// and a destination-NAT ref via an application-set (member expansion).
func TestCatalogNamesIncludesNATOnlyAppRefs(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				"snat-app":   {Name: "snat-app", Protocol: "tcp", DestinationPort: "2222"},
				"dnat-app":   {Name: "dnat-app", Protocol: "udp", DestinationPort: "3333"},
				"set-member": {Name: "set-member", Protocol: "tcp", DestinationPort: "4444"},
				"unused-app": {Name: "unused-app", Protocol: "tcp", DestinationPort: "9999"},
			},
			ApplicationSets: map[string]*config.ApplicationSet{
				"nat-set": {Name: "nat-set", Applications: []string{"set-member"}},
			},
		},
		Security: config.SecurityConfig{
			NAT: config.NATConfig{
				Source: []*config.NATRuleSet{
					{Name: "srs", Rules: []*config.NATRule{
						{Name: "sr1", Match: config.NATMatch{Application: "snat-app"}},
						// nil rule must be skipped, not panic.
						nil,
					}},
					// nil rule-set must be skipped, not panic.
					nil,
				},
				Destination: &config.DestinationNATConfig{
					RuleSets: []*config.NATRuleSet{
						{Name: "drs", Rules: []*config.NATRule{
							{Name: "dr1", Match: config.NATMatch{Application: "dnat-app"}},
							{Name: "dr2", Match: config.NATMatch{Application: "nat-set"}},
							// "any" / "" are not references.
							{Name: "dr3", Match: config.NATMatch{Application: "any"}},
							{Name: "dr4", Match: config.NATMatch{Application: ""}},
						}},
					},
				},
			},
		},
	}

	got, err := CatalogNames(cfg, false)
	if err != nil {
		t.Fatalf("CatalogNames() error = %v", err)
	}
	// snat-app, dnat-app (direct NAT refs) and set-member (via nat-set) must be
	// present; unused-app (referenced nowhere) and the "any"/"" pseudo-refs must
	// not appear.
	want := []string{"dnat-app", "set-member", "snat-app"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CatalogNames() = %v, want %v", got, want)
	}
}

// TestStrictValidationSetMatchesCatalogNames is the #2185 drift guard
// (independent review check #4). The compiler's commit-time strict-validation
// walk (config.applicationsToValidateStrict, exposed as
// config.ApplicationsToValidateStrict) INLINE-duplicates the policy-reference
// resolution in CatalogNames, because pkg/appid imports pkg/config and the
// compiler cannot call back into appid without an import cycle. This test pins
// the two walks together: for a fixture whose application-sets all resolve, the
// USER-APP subset of CatalogNames(cfg, false) must equal the strict set exactly.
// If a future change to CatalogNames's resolution silently diverges from the
// compiler copy, this fails — turning a silent commit-gate drift into a test
// failure. It is a cross-check TEST, not a runtime coupling.
//
// Scope note (#2187 / #3626): the strict walk collects source/destination-NAT
// `match application` references AND — since #3626 — so does CatalogNames. The
// fixture now carries a NAT-only user-app reference ("nat-app", referenced by a
// destination-NAT rule and by NO security policy) so the equality PINS the NAT
// walk too: before #3626 CatalogNames dropped nat-app and this equality broke;
// after #3626 both walks include it. The compiler-package tests exercise the
// commit-gate side of the same NAT reference.
func TestStrictValidationSetMatchesCatalogNames(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				// referenced directly by a policy
				"direct-app": {Name: "direct-app", Protocol: "tcp", DestinationPort: "8443"},
				// referenced only via an application-set
				"set-app": {Name: "set-app", Protocol: "udp", DestinationPort: "1234"},
				// referenced ONLY by a destination-NAT rule (#3626)
				"nat-app": {Name: "nat-app", Protocol: "tcp", DestinationPort: "2222"},
				// not referenced anywhere — must appear in NEITHER walk
				"unref-app": {Name: "unref-app", Protocol: "tcp", DestinationPort: "9000"},
			},
			ApplicationSets: map[string]*config.ApplicationSet{
				// resolvable set: a predefined junos app + a user app. CatalogNames
				// includes junos-http; the strict walk drops it (predefined specs are
				// not operator-owned), so the user-app subset is what must match.
				"web-set": {Name: "web-set", Applications: []string{"junos-http", "set-app"}},
			},
		},
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{
				{
					Policies: []*config.Policy{
						{Match: config.PolicyMatch{Applications: []string{"direct-app"}}},
						{Match: config.PolicyMatch{Applications: []string{"web-set"}}},
					},
				},
			},
			NAT: config.NATConfig{
				Destination: &config.DestinationNATConfig{
					RuleSets: []*config.NATRuleSet{
						{Name: "rs", Rules: []*config.NATRule{
							{Name: "r1", Match: config.NATMatch{Application: "nat-app"}},
						}},
					},
				},
			},
		},
	}

	catalog, err := CatalogNames(cfg, false)
	if err != nil {
		t.Fatalf("CatalogNames() error = %v", err)
	}
	// User-app subset of CatalogNames: drop predefined junos-* names, which the
	// strict walk never returns (their specs are owned by the predefined table).
	catalogUserSubset := map[string]struct{}{}
	for _, name := range catalog {
		if _, isUser := cfg.Applications.Applications[name]; isUser {
			catalogUserSubset[name] = struct{}{}
		}
	}

	strict := config.ApplicationsToValidateStrict(cfg)

	if !reflect.DeepEqual(strict, catalogUserSubset) {
		t.Fatalf("strict-validation walk and CatalogNames user-app subset have "+
			"drifted:\n  strict        = %v\n  catalog(user) = %v",
			sortedKeys(strict), sortedKeys(catalogUserSubset))
	}
	// Guard against the fixture degenerating to the trivial empty/equal case.
	if _, ok := strict["unref-app"]; ok {
		t.Fatal("unreferenced app must not be in the strict-validation set")
	}
	// nat-app is referenced ONLY by the destination-NAT rule; both walks must
	// carry it (#3626). Before the fix CatalogNames omitted it and the
	// DeepEqual above failed.
	if _, ok := strict["nat-app"]; !ok {
		t.Fatal("NAT-only app reference must be in the strict-validation set")
	}
	if len(strict) != 3 {
		t.Fatalf("expected exactly {direct-app, nat-app, set-app} in strict set, got %v", sortedKeys(strict))
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestResolveSessionNameUsesAppIDWhenEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true

	got := ResolveSessionName(map[uint16]string{7: "junos-http"}, cfg, 6, 40000, 80, 7)
	if got != "junos-http" {
		t.Fatalf("ResolveSessionName() = %q, want junos-http", got)
	}
}

func TestResolveSessionNameUnknownWhenEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true

	got := ResolveSessionName(nil, cfg, 6, 40000, 80, 0)
	if got != Unknown {
		t.Fatalf("ResolveSessionName() = %q, want %q", got, Unknown)
	}
}

func TestResolveSessionNameFallbackWhenDisabled(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				"custom-web": {Name: "custom-web", Protocol: "tcp", DestinationPort: "8443-8445"},
			},
		},
	}

	got := ResolveSessionName(nil, cfg, 6, 40000, 8444, 0)
	if got != "custom-web" {
		t.Fatalf("ResolveSessionName() = %q, want custom-web", got)
	}
}

// TestMatchTupleProtocolOnly is the #2548 fail-on-revert guard. A custom app
// configured with a protocol but NO destination-port (e.g. user-defined
// GRE/ESP/AH) must tuple-match on protocol alone. Before the fix, matchTuple
// returned false on appPort=="", so the protocol-only app never matched and
// its sessions reported UNKNOWN. Reverting the empty-appPort short-circuit to
// `return false` fails the protocol-only-matches assertion below.
func TestMatchTupleProtocolOnly(t *testing.T) {
	const greProto = 47

	// Protocol-only app matches a session of its protocol regardless of port.
	if !matchTuple(greProto, 0, 0, "gre", "", "") {
		t.Error("protocol-only GRE app must match a GRE session (proto match alone) — got no match")
	}
	if !matchTuple(greProto, 0, 1234, "gre", "", "") {
		t.Error("protocol-only GRE app must match regardless of dstPort — got no match")
	}
	// Protocol-only app does NOT match a different protocol.
	if matchTuple(6 /*tcp*/, 0, 0, "gre", "", "") {
		t.Error("protocol-only GRE app must NOT match a TCP session")
	}
	// Numeric protocol token, protocol-only.
	if !matchTuple(greProto, 0, 0, "47", "", "") {
		t.Error("protocol-only numeric-protocol app must match its protocol")
	}
	// Port-based app still requires BOTH protocol AND port — no regression.
	if !matchTuple(6, 0, 8443, "tcp", "", "8443") {
		t.Error("port-based app must match on protocol+port")
	}
	if matchTuple(6, 0, 9999, "tcp", "", "8443") {
		t.Error("port-based app must NOT match on protocol-match/port-mismatch")
	}
	if matchTuple(17 /*udp*/, 0, 8443, "tcp", "", "8443") {
		t.Error("port-based app must NOT match on port-match/protocol-mismatch")
	}
	// Port-range app unchanged.
	if !matchTuple(6, 0, 8444, "tcp", "", "8443-8445") {
		t.Error("port-range app must match a dstPort inside the range")
	}
	if matchTuple(6, 0, 8500, "tcp", "", "8443-8445") {
		t.Error("port-range app must NOT match a dstPort outside the range")
	}
	// Empty appProto must NOT match-all.
	if matchTuple(47, 0, 0, "", "", "") {
		t.Error("app with empty protocol must NOT match-all")
	}
}

// TestResolveSessionNameProtocolOnlyApp proves the protocol-only fix flows
// through resolveTupleFallback so the session reports the configured app name
// rather than UNKNOWN. (#2548)
func TestResolveSessionNameProtocolOnlyApp(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				"custom-gre": {Name: "custom-gre", Protocol: "gre"},
			},
		},
	}

	// AppID disabled → tuple fallback. A GRE session (proto 47) names the app.
	got := ResolveSessionName(nil, cfg, 47, 0, 0, 0)
	if got != "custom-gre" {
		t.Fatalf("ResolveSessionName(GRE) = %q, want custom-gre (protocol-only app)", got)
	}
	// A non-GRE session must not pick up the protocol-only GRE app.
	if got := ResolveSessionName(nil, cfg, 6, 40000, 80, 0); got == "custom-gre" {
		t.Fatalf("ResolveSessionName(TCP/80) = %q, must not match protocol-only GRE app", got)
	}
}

// TestResolveTupleFallbackPrefersPortOverProtocol proves the #2578 specificity
// ordering: when BOTH a port-based app (tcp/8443) and a protocol-only app (tcp)
// match a session, the more-specific port-based app wins deterministically. The
// matching-port session resolves to the port-based app; a non-matching-port TCP
// session falls through to the protocol-only app. Reverting the specificity
// sort in resolveTupleFallback (first-match map iteration) makes the matching-
// port assertion flaky — it picks whichever app the Go map hits first.
func TestResolveTupleFallbackPrefersPortOverProtocol(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				// Named so the port-based app sorts AFTER the protocol-only app
				// alphabetically — a name-only tiebreak would pick the protocol
				// app, so a passing test depends on the port>protocol rule.
				"aaa-proto-only": {Name: "aaa-proto-only", Protocol: "tcp"},
				"zzz-port-8443":  {Name: "zzz-port-8443", Protocol: "tcp", DestinationPort: "8443"},
			},
		},
	}

	// Run many times: map iteration order is randomized per-range, so a
	// first-match implementation would intermittently return the protocol-only
	// app. The specificity sort must make every iteration deterministic.
	for i := 0; i < 256; i++ {
		if got := resolveTupleFallback(6, 0, 8443, cfg, nil); got != "zzz-port-8443" {
			t.Fatalf("iter %d: TCP/8443 = %q, want zzz-port-8443 (port-based beats protocol-only)", i, got)
		}
		if got := resolveTupleFallback(6, 0, 9999, cfg, nil); got != "aaa-proto-only" {
			t.Fatalf("iter %d: TCP/9999 = %q, want aaa-proto-only (only the protocol-only app matches)", i, got)
		}
	}
}

// TestPortInSpecCanonicalRejectsMalformed is the #3725 H02/M05 fail-on-revert
// guard for the tuple-fallback port parser. The old strconv.Atoi parse
// MISLABELED sessions on the tolerant-load path:
//   - H02 (uint16 narrowing): strconv.Atoi("70000")==70000, uint16(70000)==4464,
//     so portInSpec(4464,"70000") was TRUE — a real session to port 4464 matched
//     a spec that strict commit rejects.
//   - M05 (signed acceptance): strconv.Atoi("+80")==80, so "+80" matched port 80.
//
// Reverting portInSpec to strconv.Atoi turns the "must NOT match" assertions RED.
func TestPortInSpecCanonicalRejectsMalformed(t *testing.T) {
	// H02: an out-of-range single port must never match the uint16-narrowed
	// value (4464), and must not match its own numeric value either.
	if portInSpec(4464, "70000") {
		t.Error("portInSpec(4464, \"70000\") = true; out-of-range spec must not uint16-narrow and match port 4464 (H02)")
	}
	if portInSpec(70000&0xFFFF, "70000") {
		t.Error("portInSpec of the narrowed value must be false — a malformed spec must be dropped, not narrowed (H02)")
	}
	// M05: a signed spelling the strict gate rejects must not match here.
	if portInSpec(80, "+80") {
		t.Error("portInSpec(80, \"+80\") = true; the signed spelling must be rejected like strict commit (M05)")
	}
	if portInSpec(0, "+0") {
		t.Error("portInSpec(0, \"+0\") = true; signed / zero spec must not match (M05)")
	}
	// An out-of-range endpoint inside a range must not narrow either.
	if portInSpec(4464, "70000-70001") {
		t.Error("portInSpec(4464, \"70000-70001\") = true; range endpoints must not uint16-narrow (H02)")
	}
	// A reversed range never matches any port (fail closed).
	if portInSpec(150, "200-100") {
		t.Error("portInSpec(150, \"200-100\") = true; a reversed range must never match")
	}
	// Port 0 is out of the valid 1..65535 range and must never match.
	if portInSpec(0, "0") {
		t.Error("portInSpec(0, \"0\") = true; port 0 is invalid and must be dropped")
	}

	// Well-formed specs still parse correctly (no over-rejection / no brick).
	if !portInSpec(80, "80") {
		t.Error("portInSpec(80, \"80\") = false; a well-formed exact port must still match")
	}
	if !portInSpec(8444, "8443-8445") {
		t.Error("portInSpec(8444, \"8443-8445\") = false; a well-formed range must still match")
	}
	if portInSpec(9000, "8443-8445") {
		t.Error("portInSpec(9000, \"8443-8445\") = true; port outside a well-formed range must not match")
	}
	if !portInSpec(65535, "65535") {
		t.Error("portInSpec(65535, \"65535\") = false; the max valid port must match")
	}
	if !portInSpec(1234, "") {
		t.Error("portInSpec(1234, \"\") = false; an empty (unconstrained) spec must always match")
	}
}

// TestResolveTupleFallbackNoMislabelOnMalformedPort proves the H02/M05 fix flows
// through the whole tuple fallback: a custom app carrying an out-of-range or
// signed port spec (admitted by the tolerant-load path, rejected by strict
// commit) must NOT be attributed to a real session whose port equals the
// uint16-narrowed or sign-stripped value. Reverting portInSpec to strconv.Atoi
// makes the session resolve to the malformed app name and fails this test.
func TestResolveTupleFallbackNoMislabelOnMalformedPort(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				// 70000 & 0xFFFF == 4464
				"bad-narrow": {Name: "bad-narrow", Protocol: "tcp", DestinationPort: "70000"},
				"bad-signed": {Name: "bad-signed", Protocol: "udp", DestinationPort: "+80"},
			},
		},
	}
	// AppID disabled → tuple fallback is the active path.
	if got := ResolveSessionName(nil, cfg, 6, 40000, 4464, 0); got == "bad-narrow" {
		t.Fatalf("TCP/4464 = %q, must not be mislabeled as the out-of-range \"70000\" app (H02)", got)
	}
	if got := ResolveSessionName(nil, cfg, 17, 40000, 80, 0); got == "bad-signed" {
		t.Fatalf("UDP/80 = %q, must not be mislabeled as the signed \"+80\" app (M05)", got)
	}
}

// TestSessionMatchesUnknown pins the case-EXACT match of the UNKNOWN sentinel
// (#5820). An unclassified session (app_id 0 with AppID enabled) resolves to the
// upper-case sentinel "UNKNOWN", so only the exact "UNKNOWN" filter selects it —
// a lowercase "unknown" filter no longer folds onto it.
func TestSessionMatchesUnknown(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true
	if !SessionMatches("UNKNOWN", nil, cfg, 6, 40000, 80, 0) {
		t.Fatal("SessionMatches(\"UNKNOWN\") should match the unclassified sentinel when AppID is enabled")
	}
	// #5820: case-exact — the lowercase spelling must NOT fold onto the sentinel.
	if SessionMatches("unknown", nil, cfg, 6, 40000, 80, 0) {
		t.Fatal("SessionMatches(\"unknown\") must NOT match the upper-case UNKNOWN sentinel (case-sensitive, #5820)")
	}
}

// TestResolveSessionNameUnmappedNonzeroUnknown is the #3438 L1 fail-on-revert
// guard. When AppID is enabled, a session carrying a NONZERO app_id that is
// absent from AppNames (a control/dataplane catalog skew, including the H4 id
// wrap) must render UNKNOWN — NOT a port-heuristic tuple guess. The session
// here is TCP dst/22, which the builtin fallback would otherwise name
// "junos-ssh". Reverting the L1 fix (restoring the enabled-path tuple fallback)
// returns "junos-ssh" and fails this test.
func TestResolveSessionNameUnmappedNonzeroUnknown(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.ApplicationIdentification = true

	// app_id 999 is not present in AppNames; tuple would guess junos-ssh.
	got := ResolveSessionName(map[uint16]string{1: "mapped-app"}, cfg, 6, 40000, 22, 999)
	if got != Unknown {
		t.Fatalf("unmapped nonzero app_id with AppID enabled = %q, want %q (honest UNKNOWN, not a tuple guess)", got, Unknown)
	}
}

// TestResolveTupleFallbackHonorsSourcePort is the #3428 fail-on-revert guard.
// An application constrained by BOTH a source-port and a destination-port must
// match a session only when the session's source port also matches; a session
// to the same destination port with a DIFFERENT source port must not be
// mislabeled as that app. With AppID disabled the tuple fallback is the active
// path. Reverting the source-port match (matchTuple ignoring SourcePort) makes
// the wrong-source-port session resolve to backup-control and fails this test.
func TestResolveTupleFallbackHonorsSourcePort(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				"backup-control": {
					Name:            "backup-control",
					Protocol:        "tcp",
					SourcePort:      "12345",
					DestinationPort: "8443",
				},
			},
		},
	}

	// Matching source AND destination port → labeled.
	if got := ResolveSessionName(nil, cfg, 6, 12345, 8443, 0); got != "backup-control" {
		t.Fatalf("matching src+dst port = %q, want backup-control", got)
	}
	// Same destination port, WRONG source port → must NOT be mislabeled.
	if got := ResolveSessionName(nil, cfg, 6, 9999, 8443, 0); got == "backup-control" {
		t.Fatalf("non-matching source port = %q, must not be labeled backup-control", got)
	}
}

// TestResolveTupleFallbackSourcePortRange proves the source-port constraint
// honors an inclusive range spec (mirroring the destination-port range path).
func TestResolveTupleFallbackSourcePortRange(t *testing.T) {
	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				"ranged-src": {
					Name:            "ranged-src",
					Protocol:        "udp",
					SourcePort:      "1024-2048",
					DestinationPort: "5000",
				},
			},
		},
	}
	if got := ResolveSessionName(nil, cfg, 17, 1500, 5000, 0); got != "ranged-src" {
		t.Fatalf("source port inside range = %q, want ranged-src", got)
	}
	if got := ResolveSessionName(nil, cfg, 17, 3000, 5000, 0); got == "ranged-src" {
		t.Fatalf("source port outside range = %q, must not be labeled ranged-src", got)
	}
}

// TestBuildCatalogRejectsAppIDOverflow is the #3438 H4 fail-on-revert guard for
// the catalog shipped to the Rust helper. A config that needs more than 65535
// application ids (the uint16 wire space minus the reserved-0 sentinel) must be
// rejected deterministically rather than wrapping a 65536th id to 0. Reverting
// the cap (uint16 appID with no boundary check) wraps silently and returns no
// error, failing this test. The boundary sibling proves exactly 65535 is
// accepted and never assigns the reserved id 0.
func TestBuildCatalogRejectsAppIDOverflow(t *testing.T) {
	// Reject: 65536 referenced applications.
	if _, err := BuildCatalog(catalogConfigWithNApps(65536)); err == nil {
		t.Fatal("BuildCatalog(65536 apps) returned no error; the uint16 app_id space must be rejected, not wrapped to 0")
	}

	// Accept: exactly 65535 applications, ids 1..65535, none wraps to 0.
	cat, err := BuildCatalog(catalogConfigWithNApps(65535))
	if err != nil {
		t.Fatalf("BuildCatalog(65535 apps) error = %v; the boundary must be accepted", err)
	}
	if _, hasZero := cat.AppNames[0]; hasZero {
		t.Fatal("BuildCatalog assigned the reserved app_id 0 to a real application")
	}
	if len(cat.AppNames) != 65535 {
		t.Fatalf("BuildCatalog(65535 apps) produced %d ids, want 65535", len(cat.AppNames))
	}
}

// TestCatalogNamesNilEntriesFailClosed is the #3622 RED-on-revert proof: a
// config carrying a nil *ZonePairPolicies entry, a nil *Policy entry inside a
// valid zone pair, and a nil *Policy entry in GlobalPolicies — all admitted by
// the tolerant-load path (#1960) — must NOT panic CatalogNames. Before the
// nil-guards in runtime.go this fixture panicked on the zpp.Policies /
// pol.Match deref; the strict walker already skips these nil entries, and
// CatalogNames must fail closed the same way. Reverting either guard turns this
// test's recover() into a re-raise (the deferred t.Fatalf fires the panic
// message), so it is RED-on-revert.
func TestCatalogNamesNilEntriesFailClosed(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CatalogNames panicked on nil zone-pair/policy entries "+
				"(must fail closed like the strict walker): %v", r)
		}
	}()

	cfg := &config.Config{
		Applications: config.ApplicationsConfig{
			Applications: map[string]*config.Application{
				"custom-web": {Name: "custom-web", Protocol: "tcp", DestinationPort: "8443"},
			},
		},
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{
				nil, // nil zone-pair entry — must be skipped, not deref'd
				{
					Policies: []*config.Policy{
						nil, // nil policy entry — must be skipped, not deref'd
						{Match: config.PolicyMatch{Applications: []string{"custom-web"}}},
					},
				},
			},
			GlobalPolicies: []*config.Policy{
				nil, // nil global-policy entry — must be skipped, not deref'd
				{Match: config.PolicyMatch{Applications: []string{"junos-https"}}},
			},
		},
	}

	got, err := CatalogNames(cfg, false)
	if err != nil {
		t.Fatalf("CatalogNames() error = %v, want nil", err)
	}
	// The valid (non-nil) policy entries still resolve; the nil entries are
	// silently skipped, so the surviving apps are exactly those two.
	want := []string{"custom-web", "junos-https"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CatalogNames() = %v, want %v", got, want)
	}
}

// catalogConfigWithNApps builds a config with n distinct TCP/80 applications,
// each referenced by a single policy so CatalogNames(cfg, false) returns exactly
// n names (AppID disabled keeps the catalog at the policy-referenced set rather
// than fanning in the predefined table).
func catalogConfigWithNApps(n int) *config.Config {
	apps := make(map[string]*config.Application, n)
	match := make([]string, 0, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("app-%06d", i)
		apps[name] = &config.Application{Name: name, Protocol: "tcp", DestinationPort: "80"}
		match = append(match, name)
	}
	return &config.Config{
		Applications: config.ApplicationsConfig{Applications: apps},
		Security: config.SecurityConfig{
			Policies: []*config.ZonePairPolicies{
				{Policies: []*config.Policy{{Match: config.PolicyMatch{Applications: match}}}},
			},
		},
	}
}
