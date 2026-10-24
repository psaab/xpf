package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
)

// #16134: validation-first cells for the three string protocol carriers that a
// future u8 conversion would retype —
//
//	filter  FirewallTermSnapshot.Protocols          []string
//	app     PolicyApplicationSnapshot.Protocol      string
//	DNAT    DestinationNATRuleSnapshot.Protocol     string
//
// NO carrier is retyped here. These cells prove, per carrier, the three
// prerequisites the conversion is gated on:
//
//	(a) atomic poison: every poison path that today rides the app carrier's
//	    "__unsupported__" sentinel (unrepresentable term, lenient bad
//	    policy, undefined-scheduler DENY/REJECT) replaces the rule's terms
//	    with the sentinel ALONE, is reported by the Go mirror
//	    (PolicyContentRejectionReasons / collectPolicyContentRejections)
//	    with the offending object named, and lands on the wire verbatim so
//	    the Rust integrity preflight can reject the WHOLE snapshot —
//	    including for a partial-drop DENY ahead of a permit (the cell that
//	    would fail open if a u8 conversion skipped/coerced the bad term).
//	(b) mixed version: the exact-equality ProtocolVersion gate plus the
//	    unconditional required-protocol orchestrator already fence both
//	    skew orders (old helper / newer helper) with disarm+abort before
//	    apply, so a future bump has a rejection cell to stand on; a numeric
//	    field under an UNCHANGED version is precisely what that fence
//	    exists to refuse.
//	(c) protocol-0 semantics: "0" (HOPOPT) is (0,true) in the Go SSOT —
//	    valid and distinct from an unknown token's (0,false) — and no
//	    carrier may default an unknown token to 0. Empty means
//	    unconstrained for the filter list and the DNAT token, while the
//	    app term's ""+port shape stays the TCP default on the DNAT path
//	    and a protocol-less app term is poison, never a match-any u8.
//
// The Rust halves are pinned beside them: policy_tests.rs
// (parse_protocol / dropped_any / fresh-boot deny), filter/tests.rs
// (resolve_term_protocols), nat/tests_dnat_proto.rs (proto_number /
// HOPOPT-vs-wildcard) and main_tests.rs (both version orders).

// carrierCfg16134 builds a minimal zone-pair config whose single policy
// references the named application with the given action.
func carrierCfg16134(action config.PolicyAction, appName, appProto, appDstPort string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Applications.Applications = map[string]*config.Application{
		appName: {Name: appName, Protocol: appProto, DestinationPort: appDstPort},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan", ToZone: "wan",
		Policies: []*config.Policy{{
			Name: "p1",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{appName},
			},
			Action: action,
		}},
	}}
	return cfg
}

func assertPoisoned16134(t *testing.T, cfg *config.Config, wantNamed string) {
	t.Helper()
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		t.Fatalf("policy snapshot build: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("want 1 policy rule, got %d", len(rules))
	}
	terms := rules[0].ApplicationTerms
	if len(terms) != 1 || terms[0].Name != unsupportedApplicationSentinel ||
		terms[0].Protocol != unsupportedApplicationSentinel {
		t.Fatalf("poison must be the __unsupported__ sentinel ALONE (atomic replacement, "+
			"not a skipped/coerced term); got %+v", terms)
	}
	// The sentinel must reach the wire the helper reads — a build-time-only
	// marker would not reject anything.
	wire, err := json.Marshal(rules[0])
	if err != nil {
		t.Fatalf("marshal rule: %v", err)
	}
	if !strings.Contains(string(wire), `"`+unsupportedApplicationSentinel+`"`) {
		t.Fatalf("poison is not on the wire: %s", wire)
	}
	// Go mirror (policies_reject.go) must name the offending object.
	reasons := PolicyContentRejectionReasons(cfg, nil)
	if len(reasons) != 1 || !strings.Contains(reasons[0], wantNamed) {
		t.Fatalf("mirror reasons = %q, want exactly one naming %s", reasons, wantNamed)
	}
	// The full snapshot must carry the same reason (the stamp the manager's
	// keep-armed/disarm decision reads).
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.Capabilities.PolicyContentRejected) == 0 {
		t.Fatal("snapshot PolicyContentRejected empty: the keep-armed diagnostic is missing")
	}
	if !snap.Capabilities.ForwardingSupported {
		t.Fatal("ForwardingSupported=false: unrepresentable content must keep the helper armed (#3261)")
	}
}

// (a) Unrepresentable term: a protocol-less application is poison for BOTH
// actions — a DENY must not collapse to match-nothing and fall through, and
// a PERMIT must not collapse to match-any.
func TestCarrierPoisonUnrepresentableTerm16134(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action config.PolicyAction
	}{
		{"permit", config.PolicyPermit},
		{"deny", config.PolicyDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertPoisoned16134(t,
				carrierCfg16134(tc.action, "bad-app", "", ""), `application "bad-app"`)
		})
	}
}

// (a) Partial-drop DENY: a rule citing one good and one unrepresentable
// application must poison WHOLESALE — emitting only the surviving good term
// would narrow the deny and let the dropped traffic fall through to a later
// permit. This is the exact fail-open a naive u8 skip/coerce introduces.
func TestCarrierPoisonPartialDropDeny16134(t *testing.T) {
	cfg := carrierCfg16134(config.PolicyDeny, "good-tcp", "tcp", "443")
	cfg.Applications.Applications["bad-app"] = &config.Application{Name: "bad-app", Protocol: "bogus-proto"}
	cfg.Security.Policies[0].Policies[0].Match.Applications = []string{"good-tcp", "bad-app"}
	assertPoisoned16134(t, cfg, `application "bad-app"`)
}

// (a) Lenient bad policy: content the tolerant compiler dropped
// (LenientContentDropped) poisons even when every named application is
// individually representable.
func TestCarrierPoisonLenientDropped16134(t *testing.T) {
	cfg := carrierCfg16134(config.PolicyPermit, "good-tcp", "tcp", "443")
	cfg.Security.Policies[0].Policies[0].LenientContentDropped = true
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		t.Fatalf("policy snapshot build: %v", err)
	}
	if len(rules) != 1 || len(rules[0].ApplicationTerms) != 1 ||
		rules[0].ApplicationTerms[0].Protocol != unsupportedApplicationSentinel {
		t.Fatalf("lenient-dropped policy must carry the sentinel alone; got %+v", rules)
	}
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) == 0 {
		t.Fatal("mirror must report the lenient-dropped poison")
	}
}

// (a) Undefined-scheduler DENY/REJECT: poison (never publish as inactive and
// fall through), with the mirror naming the scheduler. The PERMIT control
// stays unpoisoned — it keeps the warn-and-inactive posture, proving the
// poison is action-scoped rather than blanket.
func TestCarrierPoisonUndefinedScheduler16134(t *testing.T) {
	for _, action := range []config.PolicyAction{config.PolicyDeny, config.PolicyReject} {
		cfg := carrierCfg16134(action, "good-tcp", "tcp", "443")
		cfg.Security.Policies[0].Policies[0].SchedulerName = "missing-sched"
		assertPoisoned16134(t, cfg, `scheduler "missing-sched"`)
	}
	cfg := carrierCfg16134(config.PolicyPermit, "good-tcp", "tcp", "443")
	cfg.Security.Policies[0].Policies[0].SchedulerName = "missing-sched"
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		t.Fatalf("policy snapshot build: %v", err)
	}
	if len(rules) != 1 || len(rules[0].ApplicationTerms) != 1 ||
		rules[0].ApplicationTerms[0].Protocol == unsupportedApplicationSentinel {
		t.Fatalf("undefined-scheduler PERMIT must stay unpoisoned; got %+v", rules)
	}
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
		t.Fatalf("undefined-scheduler PERMIT must not be mirror-rejected; got %q", reasons)
	}
}

// (c) Protocol-0 per carrier: the SSOT keeps HOPOPT distinct from unknown,
// and each builder carries "0" as a real exact protocol — never as the
// unknown default and never as the unconstrained empty shape.
func TestCarrierProtocolZeroSemantics16134(t *testing.T) {
	if n, ok := appid.ProtocolNumber("0"); !ok || n != 0 {
		t.Fatalf("ProtocolNumber(\"0\") = (%d,%v), want (0,true): HOPOPT is valid", n, ok)
	}
	if n, ok := appid.ProtocolNumber("bogus-proto"); ok || n != 0 {
		t.Fatalf("ProtocolNumber(\"bogus-proto\") = (%d,%v), want (0,false): unknown must not alias HOPOPT", n, ok)
	}
	if _, ok := appid.ProtocolNumber(unsupportedApplicationSentinel); ok {
		t.Fatal("the poison sentinel must stay unparseable by the SSOT (else it decodes to a real protocol)")
	}
	if _, ok := appid.ProtocolNumber(""); ok {
		t.Fatal("ProtocolNumber(\"\") must be ok=false: empty is unconstrained only by carrier convention, not a protocol")
	}

	// App carrier: an application with protocol "0" lowers to a term whose
	// token still resolves to (0,true) — a real HOPOPT match, not match-any.
	cfg := carrierCfg16134(config.PolicyPermit, "hopopt-app", "0", "")
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		t.Fatalf("policy snapshot build: %v", err)
	}
	if len(rules) != 1 || len(rules[0].ApplicationTerms) != 1 {
		t.Fatalf("hopopt app must lower to one term; got %+v", rules)
	}
	term := rules[0].ApplicationTerms[0]
	if term.Protocol == unsupportedApplicationSentinel || term.Protocol == "" {
		t.Fatalf("hopopt term protocol = %q: must be a concrete token, not poison/empty", term.Protocol)
	}
	if n, ok := appid.ProtocolNumber(term.Protocol); !ok || n != 0 {
		t.Fatalf("hopopt term protocol %q resolves to (%d,%v), want (0,true)", term.Protocol, n, ok)
	}
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
		t.Fatalf("hopopt app must not be mirror-rejected; got %q", reasons)
	}

	// Filter carrier: "0" is emitted verbatim as a one-element constraint
	// (a real protocol bitmap entry in Rust), distinct from the empty
	// unconstrained list.
	fcfg := &config.Config{}
	fcfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"f": {Name: "f", Terms: []*config.FirewallFilterTerm{{
			Name: "hopopt", Protocols: []string{"0"}, Action: config.FilterActionDiscard,
		}, {
			Name: "any-proto", Action: config.FilterActionAccept,
		}}},
	}
	snaps := buildFirewallFilterSnapshots(fcfg)
	if len(snaps) != 1 || len(snaps[0].Terms) != 2 {
		t.Fatalf("want 1 filter with 2 terms, got %+v", snaps)
	}
	if got := snaps[0].Terms[0].Protocols; len(got) != 1 || got[0] != "0" {
		t.Fatalf("filter hopopt protocols = %v, want [\"0\"] verbatim", got)
	}
	if got := snaps[0].Terms[1].Protocols; len(got) != 0 {
		t.Fatalf("filter unconstrained protocols = %v, want empty (unconstrained)", got)
	}

	// DNAT carrier: explicit "0" stays a single exact-HOPOPT row; "" with a
	// port fans out to tcp+udp (the Junos bare-port default); "" with no
	// port stays the single any-protocol row. The three shapes must not
	// alias each other.
	hop := buildDestinationNATSnapshots(dnatPortConfig(config.NATMatch{Protocol: "0"}), nil)
	if len(hop) != 1 || hop[0].Protocol != "0" {
		t.Fatalf("DNAT protocol \"0\" = %+v, want one exact-HOPOPT row", hop)
	}
	bare := buildDestinationNATSnapshots(dnatPortConfig(config.NATMatch{
		DestinationPorts: []int{53}, DestinationPort: 53,
	}), nil)
	protos := map[string]bool{}
	for _, s := range bare {
		protos[s.Protocol] = true
	}
	if len(bare) != 2 || !protos["tcp"] || !protos["udp"] {
		t.Fatalf("DNAT bare-port = %+v, want tcp+udp fan-out (\"\"+port defaults, never HOPOPT)", bare)
	}
	anyRule := buildDestinationNATSnapshots(dnatPortConfig(config.NATMatch{}), nil)
	if len(anyRule) != 1 || anyRule[0].Protocol != "" || anyRule[0].DestinationPort != 0 {
		t.Fatalf("DNAT no-protocol/no-port = %+v, want one any-protocol row", anyRule)
	}
}

// (c) Junos aliases resolve identically through the SSOT the app carrier
// canonicalizes against, so an alias never reaches the wire as an
// unparseable token (which would poison) nor as 0.
func TestCarrierJunosAliases16134(t *testing.T) {
	for alias, want := range map[string]uint8{
		"junos-tcp-any": 6, "junos-udp-any": 17, "junos-ping": 1,
		"junos-pingv6": 58, "junos-gre": 47, "junos-ospf": 89,
		"junos-ip-in-ip": 4,
	} {
		if n, ok := appid.ProtocolNumber(alias); !ok || n != want {
			t.Errorf("ProtocolNumber(%q) = (%d,%v), want (%d,true)", alias, n, ok, want)
		}
	}
	// An alias application lowers to a wire token the Rust parse_protocol
	// accepts (named or canonicalized number) resolving to the same number.
	cfg := carrierCfg16134(config.PolicyPermit, "alias-app", "junos-gre", "")
	rules, err := buildPolicySnapshotsWithSchedulerStateAndFeeds(cfg, nil, nil)
	if err != nil {
		t.Fatalf("policy snapshot build: %v", err)
	}
	if len(rules) != 1 || len(rules[0].ApplicationTerms) != 1 {
		t.Fatalf("alias app must lower to one term; got %+v", rules)
	}
	if n, ok := appid.ProtocolNumber(rules[0].ApplicationTerms[0].Protocol); !ok || n != 47 {
		t.Fatalf("alias wire token %q resolves to (%d,%v), want (47,true)",
			rules[0].ApplicationTerms[0].Protocol, n, ok)
	}
}

// (b) Mixed-version prerequisites for any future bump: the Go gate refuses
// BOTH skew orders through the unconditional orchestrator (rejection/disarm
// before apply), the two version constants agree today, and the historical
// pre-v5 literal stays fenced — so a bumped version has a proven cell in
// each direction instead of an assumed one.
func TestCarrierMixedVersionGate16134(t *testing.T) {
	for _, tc := range []struct {
		name     string
		observed int
		wantErr  bool
	}{
		{"older-helper", ProtocolVersion - 1, true},
		{"matched-helper", ProtocolVersion, false},
		{"newer-helper", ProtocolVersion + 1, true},
		{"pre-v5-literal", preV5SnapshotProtocolVersion, true},
		{"unknown-version-no-brick", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			m.lastStatus.ConfigSnapshotProtocolVersion = tc.observed
			err := m.ensureRequiredSnapshotProtocolLocked(nil)
			if tc.wantErr && err == nil {
				t.Fatalf("helper at version %d accepted through the orchestrator, want refusal before apply", tc.observed)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("helper at version %d refused (%v), want accepted", tc.observed, err)
			}
		})
	}
}
