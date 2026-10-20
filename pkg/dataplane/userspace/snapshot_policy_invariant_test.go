package userspace

import (
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// HARDENING (#15742 follow-up): regression tests for the empty-policy
// snapshot class. 670274c712 dropped `Policies: policies` from the full
// builder literal while Summary.PolicyCount still reported the compiled
// rule count; the helper installed policies=[] and default-denied all
// transit silently. Each layer below independently fails on that shape:
//
//   - builder invariant (validateSnapshotPolicyInvariant via buildSnapshot)
//   - send-site gate (requestApplySnapshotPreparedLocked)
//   - field-coverage census (every ConfigSnapshot literal field populated)
//
// The Rust helper layer is covered by
// apply_snapshot_policy_count_mismatch_is_refused_and_counted in
// userspace-dp/src/server/tests.rs.

// hardeningPolicyCfg is a representative config with zones, interfaces,
// and zone-pair + global security policies.
func hardeningPolicyCfg() *config.Config {
	cfg := &config.Config{Security: config.SecurityConfig{
		Zones: map[string]*config.ZoneConfig{
			"lan": {Name: "lan", Interfaces: []string{"ge-0/0/0.0"}},
			"wan": {Name: "wan", Interfaces: []string{"ge-0/0/1.0"}},
		},
		Policies: []*config.ZonePairPolicies{{
			FromZone: "lan",
			ToZone:   "wan",
			Policies: []*config.Policy{{
				Name:   "allow-all",
				Action: config.PolicyPermit,
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"any"},
				},
			}},
		}},
		GlobalPolicies: []*config.Policy{{
			Name:   "global-deny-log",
			Action: config.PolicyDeny,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
		}},
	}}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"192.0.2.1/24"}},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"198.51.100.1/24"}},
		}},
	}
	cfg.System.HostName = "fw-census"
	cfg.System.DataplaneType = "userspace"
	return cfg
}

// TestBuilderInvariantRejectsDroppedPoliciesField simulates the exact
// 670274c712 regression at the builder layer: a snapshot whose Policies
// slice was dropped (empty) while the compiled config carries rules must
// fail validateSnapshotPolicyInvariant, and a full buildSnapshot of a
// policy-bearing config must succeed with a consistent count. Deleting
// the `Policies: policies` line from builder.go makes buildSnapshot
// itself return this error (the invariant runs inside the builder), so
// this test goes RED on that single-line revert.
func TestBuilderInvariantRejectsDroppedPoliciesField(t *testing.T) {
	cfg := hardeningPolicyCfg()
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 7, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.Policies) == 0 {
		t.Fatal("premise: representative config must publish policies")
	}
	// Simulate the dropped field: Policies emptied post-build, Summary
	// left claiming the compiled count (exactly the 670274c712 wire).
	dropped := *snap
	dropped.Policies = nil
	if err := validateSnapshotPolicyInvariant(&dropped, cfg); !errors.Is(err, errSnapshotPolicyMismatch) {
		t.Fatalf("builder invariant on dropped-field snapshot = %v, want errSnapshotPolicyMismatch", err)
	}
	// Count drift without emptying must also fail.
	drifted := *snap
	drifted.Summary.PolicyCount = len(snap.Policies) + 1
	if err := validateSnapshotPolicyInvariant(&drifted, cfg); !errors.Is(err, errSnapshotPolicyMismatch) {
		t.Fatalf("builder invariant on count-drifted snapshot = %v, want errSnapshotPolicyMismatch", err)
	}
	// A policy-free config legitimately publishes zero policies.
	empty := &config.Config{}
	esnap, err := buildSnapshot(empty, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot(policy-free): %v", err)
	}
	if len(esnap.Policies) != 0 || esnap.Summary.PolicyCount != 0 {
		t.Fatalf("policy-free snapshot = %d policies / count %d, want 0/0", len(esnap.Policies), esnap.Summary.PolicyCount)
	}
	if err := validateSnapshotPolicyInvariant(esnap, empty); err != nil {
		t.Fatalf("builder invariant on policy-free snapshot = %v, want nil", err)
	}
}

// TestSendSiteRefusesPolicyCountMismatch drives the single apply_snapshot
// send site with the dropped-field shape. The gate must refuse BEFORE any
// control request is sent (known-unsent: no generation burn, no retry
// debt), so the recorder must observe zero sends.
func TestSendSiteRefusesPolicyCountMismatch(t *testing.T) {
	cfg := hardeningPolicyCfg()
	good := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	bad := *good
	bad.Policies = nil // Summary.PolicyCount still claims the rules.
	if bad.Summary.PolicyCount == 0 {
		t.Fatal("premise: summary must claim policies for this test to measure the gate")
	}
	rec := &applyRecorder9520{}
	m := newRepublishManager9520(good, rec)
	genBefore := m.generation
	err := m.requestApplySnapshotPreparedLocked(&bad, &ProcessStatus{})
	if !errors.Is(err, errSnapshotPolicyMismatch) {
		t.Fatalf("send-site error = %v, want errSnapshotPolicyMismatch", err)
	}
	if len(rec.sent) != 0 {
		t.Fatalf("mismatched snapshot reached the helper: %d sends, want 0", len(rec.sent))
	}
	if m.generation != genBefore {
		t.Fatalf("known-unsent refusal burned a generation: %d -> %d", genBefore, m.generation)
	}
	if !isKnownUnsentFailure(err) {
		t.Fatalf("mismatch refusal must be known-unsent (no retry debt): %v", err)
	}
	if m.applySnapshotOutcomeUnknown {
		t.Fatal("known-unsent refusal must not mark the apply outcome unknown")
	}
	// A consistent snapshot still sends.
	if err := m.requestApplySnapshotPreparedLocked(good, &ProcessStatus{}); err != nil {
		t.Fatalf("consistent snapshot send: %v", err)
	}
	if len(rec.sent) != 1 {
		t.Fatalf("consistent snapshot sends = %d, want 1", len(rec.sent))
	}
}

// TestSendSiteRefusesBothZeroedPartialPublish is the joint-omission
// shape the triple review required: a partial publisher zeroing BOTH
// Policies and Summary.PolicyCount (0 == 0, self-consistent) must still
// refuse at the send site whenever the manager's stamped expectation
// from the last full Compile is non-zero. A legitimate zero-policy
// expectation (stamped 0) must still send.
func TestSendSiteRefusesBothZeroedPartialPublish(t *testing.T) {
	cfg := hardeningPolicyCfg()
	good := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	zeroed := *good
	zeroed.Policies = nil
	zeroed.Summary.PolicyCount = 0
	// A partial publisher's clone: stripSingleUseCommitMetadata clears
	// provenance (and the clear marker) — model exactly that.
	stripSingleUseCommitMetadata(&zeroed)
	rec := &applyRecorder9520{}
	m := newRepublishManager9520(good, rec)
	m.expectedPolicyCount = len(good.Policies) // as Manager.Compile stamps it
	genBefore := m.generation
	err := m.requestApplySnapshotPreparedLocked(&zeroed, &ProcessStatus{})
	if !errors.Is(err, errSnapshotPolicyMismatch) {
		t.Fatalf("both-zeroed send error = %v, want errSnapshotPolicyMismatch", err)
	}
	if len(rec.sent) != 0 {
		t.Fatalf("both-zeroed snapshot reached the helper: %d sends, want 0", len(rec.sent))
	}
	if m.generation != genBefore {
		t.Fatalf("known-unsent refusal burned a generation: %d -> %d", genBefore, m.generation)
	}
	if !isKnownUnsentFailure(err) {
		t.Fatalf("both-zeroed refusal must be known-unsent: %v", err)
	}
	// Legitimate clear: expectation stamped 0 (e.g. fully-quarantined or
	// policy-free Compile) — a 0/0 publish must send.
	rec2 := &applyRecorder9520{}
	m2 := newRepublishManager9520(good, rec2)
	m2.expectedPolicyCount = 0
	emptySnap := *good
	emptySnap.Policies = nil
	emptySnap.Summary.PolicyCount = 0
	if err := m2.requestApplySnapshotPreparedLocked(&emptySnap, &ProcessStatus{}); err != nil {
		t.Fatalf("legitimate 0/0 send with zero expectation: %v", err)
	}
	if len(rec2.sent) != 1 {
		t.Fatalf("legitimate 0/0 sends = %d, want 1", len(rec2.sent))
	}
}

// TestBuilderFullyQuarantinedConfigPasses pins the post-quarantine
// ground truth: a config whose ONLY policies are scrubbed by zone
// quarantine legitimately publishes zero policies and must NOT trip the
// builder invariant (regression for the review finding against the
// raw-count arm; the production-path twin is
// TestBuildSnapshotDropsDanglingGlobalMatchZone).
func TestBuilderFullyQuarantinedConfigPasses(t *testing.T) {
	if config.StableZoneID("z174") == config.StableZoneID("z214") {
		// keep the premise explicit; the collision pair is fixed upstream
	} else {
		t.Skip("premise: z174/z214 no longer collide")
	}
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"z174": {Name: "z174"},
		"z214": {Name: "z214"},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name:   "g-scoped-quarantined",
		Match:  config.PolicyMatch{FromZones: []string{"z214"}, Applications: []string{"any"}},
		Action: config.PolicyPermit,
	}}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 3, 0)
	if err != nil {
		t.Fatalf("fully-quarantined build must pass the builder invariant: %v", err)
	}
	if len(snap.Policies) != 0 || snap.Summary.PolicyCount != 0 {
		t.Fatalf("fully-quarantined snapshot = %d policies / count %d, want 0/0", len(snap.Policies), snap.Summary.PolicyCount)
	}
	exp, err := expectedPolicyCount(cfg)
	if err != nil || exp != 0 {
		t.Fatalf("expectedPolicyCount(fully-quarantined) = %d, %v; want 0, nil", exp, err)
	}
	// And the surviving-rule twin: one rule survives quarantine, so the
	// expectation is non-zero and a dropped Policies field still fails.
	cfg2 := hardeningPolicyCfg()
	exp2, err := expectedPolicyCount(cfg2)
	if err != nil || exp2 != len(mustBuildSnapshot(t, cfg2, config.UserspaceConfig{}, 1, 0).Policies) {
		t.Fatalf("expectedPolicyCount(representative) = %d, %v; want the built policy count", exp2, err)
	}
}

// TestFullBuilderPopulatesEverySnapshotField is the field-coverage census:
// it catches the NEXT dropped literal field, not just Policies. Every
// exported ConfigSnapshot field must be populated (non-zero) by the full
// builder for a representative config, except fields on the explicit
// exemption list (each with its reason). A new field added to
// ConfigSnapshot without builder population fails here until it is either
// populated or consciously exempted.
func TestFullBuilderPopulatesEverySnapshotField(t *testing.T) {
	cfg := hardeningPolicyCfg()
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 7, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	// Fields the representative config cannot populate. Each entry MUST
	// carry its reason; adding a field here without one defeats the census.
	exempt := map[string]string{
		"PermitEpoch":                   "S4 capture authority, only stamped via CaptureEpochProvider",
		"QueueEpochs":                   "S4 capture authority, only stamped via CaptureEpochProvider",
		"IpsecTunnelRows":               "S4 capture authority, only stamped via CaptureEpochProvider",
		"IpsecTunnelSnapshotGeneration": "S4 capture authority stamp",
		"PMechInventory":                "S4 capture authority, only when tunnels admitted",
		"BindlessSelectorFenceEnabled":  "only with bind-less IPsec VPN selectors",
		"BindlessSelectorRows":          "only with bind-less IPsec VPN selectors",
		"PolicyRenameAncestry":          "only staged by daemon rename commits",
		"PolicySessionRebinds":          "only staged by daemon rename commits",
		"WgSteeredListenPorts":          "only with steered WireGuard tunnels",
		"LearnedRouteImportCapped":      "only when learned-route import hits its cap",
		"DefaultLogSessionInit":         "only with default-policy-log session-init",
		"DefaultLogSessionClose":        "only with default-policy-log session-close",
		"NoIPv6RejectZeroHopLimit":      "only with no-ipv6-reject-zero-hop-limit",
		"DeferWorkers":                  "only on deferred-worker publishes",
		"ColdPathSampleMask":            "only with operator cold-path sampling flags",
		"ContentDigest":                 "stamped at the send site, not by the builder",
		"ClearPolicies":                 "authorized-clear marker set only by Manager.Compile on an empty full build; the representative build is non-empty",
		"DestinationNAT":                "representative config has no destination NAT rules",
		"SourceNAT":                     "representative config has no source NAT rules",
		"StaticNAT":                     "representative config has no static NAT rules",
		"NAT64":                         "representative config has no NAT64 rules",
		"Nptv6":                         "representative config has no NPTv6 rules",
		"Screens":                       "representative config has no screen profiles",
		"ScreenMissingProfiles":         "representative config has no missing screen refs",
		"ScreenInertProfiles":           "representative config has no inert screen refs",
		"SYNCookieMasterKey":            "only with an active SYN-cookie screen",
		"SYNCookieKeyRing":              "only with an active SYN-cookie screen",
		"Filters":                       "representative config has no firewall filters",
		"Policers":                      "representative config has no policers",
		"ThreeColorPolicers":            "representative config has no three-color policers",
		"ClassOfService":                "representative config has no class-of-service",
		"FlowExport":                    "representative config has no flow export",
		"MirrorConfigs":                 "representative config has no port mirroring",
		"MirrorExclusions":              "representative config has no refused mirroring",
		"NodeID":                        "standalone node id is 0",
		"Neighbors":                     "representative config has no static neighbors",
		"Fabrics":                       "representative config has no cluster fabrics",
		"ForwardingTables":              "representative config has no forwarding instances",
		"RouteTableIdentities":          "representative config has no named routing instances",
		"Routes":                        "representative config has no static routes",
		"TunnelEndpoints":               "representative config has no tunnel endpoints",
		"FIBGeneration":                 "test builds with fib_generation 0; Compile stamps the live FIB generation",
		"Flow":                          "representative config sets no security flow options (zero FlowSnapshot is the default)",
		"PolicyRematchExtensive":        "only with policy-rematch extensive configuration",
		"AddressBooks":                  "representative config declares no address-book entries (any is a keyword, not a book)",
		"AppCatalog":                    "representative config uses only the `any` application, which needs no catalog row",
		"Userspace":                     "zero UserspaceConfig is the default dataplane tuning",
	}
	v := reflect.ValueOf(*snap)
	typ := v.Type()
	var missing []string
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		if _, ok := exempt[f.Name]; ok {
			continue
		}
		if v.Field(i).IsZero() {
			missing = append(missing, f.Name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("full builder left ConfigSnapshot fields unpopulated (dropped-field class, #15742): %s\n"+
			"populate the field in the builder, or add it to the exemption list WITH a reason",
			strings.Join(missing, ", "))
	}
	// The census itself must be live: Policies is the #15742 field and
	// must never be exempt or empty for this config.
	if len(snap.Policies) == 0 {
		t.Error("census premise: representative config published no policies")
	}
	// Nested census (GLM fold): reflect into Summary so a dropped literal
	// INSIDE the nested struct (e.g. `PolicyCount: len(policies),` deleted
	// from the Summary composite literal) also fails CI. The fixture has
	// no schedulers and is standalone, so those two Summary fields are
	// legitimately zero; every other field must be populated AND
	// consistent with the snapshot it summarizes.
	summaryExempt := map[string]string{
		"SchedulerCount": "representative config declares no schedulers",
		"HAEnabled":      "representative config is standalone (no chassis cluster)",
	}
	sv := reflect.ValueOf(snap.Summary)
	st := sv.Type()
	var summaryMissing []string
	for i := range st.NumField() {
		f := st.Field(i)
		if _, ok := summaryExempt[f.Name]; !ok && sv.Field(i).IsZero() {
			summaryMissing = append(summaryMissing, f.Name)
		}
	}
	if len(summaryMissing) > 0 {
		t.Errorf("full builder left Summary fields unpopulated (nested dropped-literal class): %s\n"+
			"populate the field in the builder, or add it to the Summary exemption list WITH a reason",
			strings.Join(summaryMissing, ", "))
	}
	if snap.Summary.PolicyCount != len(snap.Policies) {
		t.Errorf("Summary.PolicyCount = %d, want len(Policies) = %d", snap.Summary.PolicyCount, len(snap.Policies))
	}
	if snap.Summary.ZoneCount != len(snap.Zones) {
		t.Errorf("Summary.ZoneCount = %d, want len(Zones) = %d", snap.Summary.ZoneCount, len(snap.Zones))
	}
	if snap.Summary.InterfaceCount != len(cfg.Interfaces.Interfaces) {
		t.Errorf("Summary.InterfaceCount = %d, want %d configured interfaces", snap.Summary.InterfaceCount, len(cfg.Interfaces.Interfaces))
	}
	if snap.Summary.HostName != cfg.System.HostName || snap.Summary.DataplaneType != cfg.System.DataplaneType {
		t.Errorf("Summary identity = %q/%q, want %q/%q from config", snap.Summary.HostName, snap.Summary.DataplaneType, cfg.System.HostName, cfg.System.DataplaneType)
	}
}

// TestCompileClearAllCommitsStampAndMarker is the authorized-clear path:
// a full Compile that empties the policy set must (a) send the snapshot
// WITH ClearPolicies marked (the helper's authorized-clear input),
// (b) commit expectedPolicyCount=0 ONLY after the successful apply, and
// (c) leave the retained snapshot with the marker SPENT, so a later
// partial clone cannot replay it.
func TestCompileClearAllCommitsStampAndMarker(t *testing.T) {
	cfg := hardeningPolicyCfg()
	good := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	rec := &applyRecorder9520{}
	m := newRepublishManager9520(good, rec)
	m.expectedPolicyCount = len(good.Policies) // retained-set expectation

	clearSnap := *good
	clearSnap.Policies = nil
	clearSnap.Summary.PolicyCount = 0
	clearSnap.ClearPolicies = true // as Manager.Compile marks an empty full build
	// clearSnap keeps fullBuild=true: it IS this Compile's build.
	clearSnap.Generation = 8
	if err := m.requestApplySnapshotPreparedLocked(&clearSnap, &ProcessStatus{}); err != nil {
		t.Fatalf("authorized-clear send must pass the gate: %v", err)
	}
	if len(rec.sent) != 1 || !rec.sent[0].ClearPolicies {
		t.Fatalf("sent snapshots = %+v, want exactly one WITH ClearPolicies marked", rec.sent)
	}
	if clearSnap.ClearPolicies {
		t.Fatal("marker must be SPENT after the send (retained clones must not inherit it)")
	}
	// A partial both-zeroed clone of the now-retained snapshot (marker
	// spent) against the still-non-zero stamp must refuse: the stamp
	// only moves after a successful full-Compile apply (see
	// TestRefusedCompileLeavesPriorStamp), never on a partial send.
	partial := *good
	partial.Policies = nil
	partial.Summary.PolicyCount = 0
	partial.Generation = 9
	stripSingleUseCommitMetadata(&partial) // partial clone: provenance + marker stripped
	if err := m.requestApplySnapshotPreparedLocked(&partial, &ProcessStatus{}); !errors.Is(err, errSnapshotPolicyMismatch) {
		t.Fatalf("unmarked both-zeroed partial = %v, want errSnapshotPolicyMismatch", err)
	}
	if len(rec.sent) != 1 {
		t.Fatalf("refused partial reached the helper: %d sends, want still 1", len(rec.sent))
	}
}

// TestFullBuildCountChangeSendsAndCommitsStamp rewrites the round-2
// :423 expectation per Codex3: an ordinary policy-count change arriving
// as a FULL build is ground truth and must SEND (the builder invariant
// already validated it) — gating it on the prior stamp deadlocked every
// policy edit. The stamp commits only after the successful apply; a
// PARTIAL carrying a different count still refuses, and a refused full
// build leaves the prior stamp so retained-count partials still send.
func TestFullBuildCountChangeSendsAndCommitsStamp(t *testing.T) {
	cfg := hardeningPolicyCfg()
	good := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	if !good.fullBuild {
		t.Fatal("premise: builder output must carry full-build provenance")
	}
	rec := &applyRecorder9520{}
	m := newRepublishManager9520(good, rec)
	m.expectedPolicyCount = len(good.Policies)
	prior := m.expectedPolicyCount

	// Full build with a changed count (1->2 rules): bypasses the stamp
	// arm and sends.
	bigger := *good
	bigger.Policies = append(append([]PolicyRuleSnapshot{}, good.Policies...), good.Policies[0])
	bigger.Summary.PolicyCount = len(bigger.Policies)
	bigger.Generation = 8
	if err := m.requestApplySnapshotPreparedLocked(&bigger, &ProcessStatus{}); err != nil {
		t.Fatalf("full-build count change must SEND (builder is ground truth): %v", err)
	}
	if len(rec.sent) != 1 {
		t.Fatalf("full-build count change sends = %d, want 1", len(rec.sent))
	}
	// Simulate Compile's post-success commit (applyErr == nil branch).
	m.expectedPolicyCount = len(bigger.Policies)
	if m.expectedPolicyCount != prior+1 {
		t.Fatalf("stamp after successful full apply = %d, want %d", m.expectedPolicyCount, prior+1)
	}

	// A partial (provenance stripped by the clone path) carrying a
	// count different from the committed stamp still refuses.
	partial := bigger
	partial.Policies = partial.Policies[:1]
	partial.Summary.PolicyCount = 1
	partial.Generation = 9
	stripSingleUseCommitMetadata(&partial)
	if err := m.requestApplySnapshotPreparedLocked(&partial, &ProcessStatus{}); !errors.Is(err, errSnapshotPolicyMismatch) {
		t.Fatalf("partial with wrong count = %v, want errSnapshotPolicyMismatch", err)
	}
	if len(rec.sent) != 1 {
		t.Fatalf("refused partial reached the helper: sends = %d, want still 1", len(rec.sent))
	}

	// Refused FULL build leaves the prior stamp: validate-only against
	// a stamp that was never committed (Compile commits on success
	// only) — model by refusing at the transport and confirming the
	// stamp variable is untouched by the gate itself.
	rec2 := &applyRecorder9520{replies: []error{errors.New("apply_snapshot: helper refused")}}
	m2 := newRepublishManager9520(good, rec2)
	m2.expectedPolicyCount = prior
	full2 := *good
	full2.Generation = 8
	if err := m2.requestApplySnapshotPreparedLocked(&full2, &ProcessStatus{}); err == nil {
		t.Fatal("premise: scripted helper refusal must surface")
	}
	if m2.expectedPolicyCount != prior {
		t.Fatalf("gate moved the stamp on a refused full build: %d -> %d", prior, m2.expectedPolicyCount)
	}
	retainedPartial := *good
	retainedPartial.Generation = 9
	stripSingleUseCommitMetadata(&retainedPartial)
	if err := m2.requestApplySnapshotPreparedLocked(&retainedPartial, &ProcessStatus{}); err != nil {
		t.Fatalf("retained-count partial after refused full build must still send: %v", err)
	}
}

// seedPoliciesForOverlayFixture grows the overlay fixture config with
// `n` zone-pair rules between its zones. The overlay fixture itself is
// route-only (no zones/policies); seed policies so the Compile tests
// below measure policy-count movement on a real Compile.
func seedPoliciesForOverlayFixture(cfg *config.Config, n int) {
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan"},
		"wan": {Name: "wan"},
	}
	rules := []*config.Policy{
		{
			Name:   "base-rule",
			Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
		},
		{
			Name:   "extra-rule",
			Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"junos-https"},
			},
		},
	}
	if n > len(rules) {
		n = len(rules)
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: rules[:n],
	}}
}

// TestCompilePolicyCountChangeEndToEnd drives the REAL Manager.Compile
// (shim hook + REAL fixture config + fake helper recorder, modeled on
// TestCompilePublishesCaptureAuthorityRows10485) for a rule-count
// change: the full build must reach the helper and the stamp must
// commit to the new count after success. Before the Codex3 fix the
// send gate refused this shape known-unsent forever (deadlock).
func TestCompilePolicyCountChangeEndToEnd(t *testing.T) {
	dir := t.TempDir()
	controlSock, reqCh := overlayControlServer(t, dir)
	cfg := overlayTestConfig()
	seedPoliciesForOverlayFixture(cfg, 1)
	cfg.System.UserspaceDataplane = &config.UserspaceConfig{ControlSocket: controlSock}
	ucfg := deriveUserspaceConfig(cfg)
	m := New()
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m.proc = &exec.Cmd{Process: proc}
	m.cfg = ucfg
	m.syncCancel = func() {}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.helperStatusCtrlMapHook = &fakeCtrlMap{}
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.clearHelperHAStateHook = func() error { return nil }
	m.lastStatus = ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion}
	m.helperStatusObserved = true
	m.xskLivenessProven = true
	seed := mustBuildSnapshotWithSchedulerState(t, cfg, ucfg, 7, 0, nil, nil, nil)
	if len(seed.Policies) == 0 {
		t.Fatal("premise: seeded fixture must publish policies")
	}
	m.lastSnapshot = seed
	m.generation = 7
	m.publishedSnapshot = 7
	m.publishedPlanKey = snapshotBindingPlanKey(seed)
	if h, ok := snapshotContentHash(seed); ok {
		m.lastSnapshotHash = h
	}
	m.compileUserspaceShimHook = func(_ *config.Config, preflight func(*dataplane.CompileResult) error) (*dataplane.CompileResult, error) {
		result := &dataplane.CompileResult{}
		if err := preflight(result); err != nil {
			return nil, err
		}
		return result, nil
	}
	m.expectedPolicyCount = len(seed.Policies)
	priorStamp := m.expectedPolicyCount

	// Grow the config by one zone-pair rule (count change via Compile).
	grown := overlayTestConfig()
	seedPoliciesForOverlayFixture(grown, 2)
	grown.System.UserspaceDataplane = cfg.System.UserspaceDataplane
	if _, err := m.Compile(grown); err != nil {
		t.Fatalf("policy-count change via Compile must succeed end-to-end: %v", err)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case req := <-reqCh:
			if req.Type != "apply_snapshot" || req.Snapshot == nil {
				continue
			}
			if len(req.Snapshot.Policies) != priorStamp+1 {
				t.Fatalf("helper received %d policies, want %d (prior %d + 1 grown rule)",
					len(req.Snapshot.Policies), priorStamp+1, priorStamp)
			}
			m.mu.Lock()
			stamp := m.expectedPolicyCount
			m.mu.Unlock()
			if stamp != priorStamp+1 {
				t.Fatalf("stamp after successful count-change Compile = %d, want %d", stamp, priorStamp+1)
			}
			return
		case <-deadline:
			t.Fatal("Compile never reached the helper with an apply_snapshot")
		}
	}
}

// TestCompileClearAllEndToEnd drives the REAL Manager.Compile (same
// fixture) for a delete-all-policies config: the sent snapshot must
// carry ClearPolicies (this test FAILS if the Compile marker line is
// neutered), the helper accepts it, and the stamp commits to 0 only
// after success. A subsequent unmarked partial clone must refuse.
func TestCompileClearAllEndToEnd(t *testing.T) {
	dir := t.TempDir()
	controlSock, reqCh := overlayControlServer(t, dir)
	cfg := overlayTestConfig()
	seedPoliciesForOverlayFixture(cfg, 1)
	cfg.System.UserspaceDataplane = &config.UserspaceConfig{ControlSocket: controlSock}
	ucfg := deriveUserspaceConfig(cfg)
	m := New()
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m.proc = &exec.Cmd{Process: proc}
	m.cfg = ucfg
	m.syncCancel = func() {}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.helperStatusCtrlMapHook = &fakeCtrlMap{}
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.clearHelperHAStateHook = func() error { return nil }
	m.lastStatus = ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion}
	m.helperStatusObserved = true
	m.xskLivenessProven = true
	seed := mustBuildSnapshotWithSchedulerState(t, cfg, ucfg, 7, 0, nil, nil, nil)
	if len(seed.Policies) == 0 {
		t.Fatal("premise: overlay fixture must seed policies")
	}
	m.lastSnapshot = seed
	m.generation = 7
	m.publishedSnapshot = 7
	m.publishedPlanKey = snapshotBindingPlanKey(seed)
	if h, ok := snapshotContentHash(seed); ok {
		m.lastSnapshotHash = h
	}
	m.compileUserspaceShimHook = func(_ *config.Config, preflight func(*dataplane.CompileResult) error) (*dataplane.CompileResult, error) {
		result := &dataplane.CompileResult{}
		if err := preflight(result); err != nil {
			return nil, err
		}
		return result, nil
	}
	m.expectedPolicyCount = len(seed.Policies)

	cleared := overlayTestConfig()
	seedPoliciesForOverlayFixture(cleared, 0)
	cleared.System.UserspaceDataplane = cfg.System.UserspaceDataplane
	if _, err := m.Compile(cleared); err != nil {
		t.Fatalf("clear-all via Compile must succeed end-to-end: %v", err)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case req := <-reqCh:
			if req.Type != "apply_snapshot" || req.Snapshot == nil {
				continue
			}
			if len(req.Snapshot.Policies) != 0 {
				t.Fatalf("clear-all snapshot carries %d policies, want 0", len(req.Snapshot.Policies))
			}
			if !req.Snapshot.ClearPolicies {
				t.Fatal("clear-all snapshot reached the helper WITHOUT the authorized-clear marker (Compile marker neutered?)")
			}
			m.mu.Lock()
			stamp := m.expectedPolicyCount
			m.mu.Unlock()
			if stamp != 0 {
				t.Fatalf("stamp after successful clear-all Compile = %d, want 0", stamp)
			}
			return
		case <-deadline:
			t.Fatal("clear-all Compile never reached the helper")
		}
	}
}

// TestTailErrorStampFollowsAcceptedBuild simulates the round-4 (a)
// path at the accounting level: applyCompiledSnapshot ACCEPTED the
// full build (lastSnapshot/publishedSnapshot advanced) and then its
// tail failed with PublishedSnapshotTailError. Compile's commit rule
// (applyErr == nil || isPublishedSnapshotTailError) must move the
// stamp to the accepted count, and a subsequent PARTIAL sized for the
// accepted set must publish — before the fix it wedged against the
// stale stamp.
func TestTailErrorStampFollowsAcceptedBuild(t *testing.T) {
	cfg := hardeningPolicyCfg()
	good := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	rec := &applyRecorder9520{}
	m := newRepublishManager9520(good, rec)
	m.expectedPolicyCount = 1 // stale: pre-change accepted count

	accepted := *good
	accepted.Policies = append(append([]PolicyRuleSnapshot{}, good.Policies...), good.Policies[0])
	accepted.Summary.PolicyCount = len(accepted.Policies)
	accepted.Generation = 8
	tailErr := &PublishedSnapshotTailError{generation: 8, stage: "helper status sync", err: errors.New("boom")}
	if !isPublishedSnapshotTailError(tailErr) {
		t.Fatal("premise: tail error must classify as landed evidence")
	}
	// Compile's exact commit rule.
	if true { // applyErr != nil but is a tail error -> commit
		m.commitExpectedPolicyCountFromLandedSnapshot(&accepted)
	}
	if m.expectedPolicyCount != len(accepted.Policies) {
		t.Fatalf("stamp after tail-error acceptance = %d, want %d", m.expectedPolicyCount, len(accepted.Policies))
	}
	// Partial sized for the ACCEPTED set publishes.
	partial := accepted
	partial.Generation = 9
	stripSingleUseCommitMetadata(&partial)
	if err := m.requestApplySnapshotPreparedLocked(&partial, &ProcessStatus{}); err != nil {
		t.Fatalf("accepted-count partial after tail error must publish (stale-stamp wedge): %v", err)
	}
	if len(rec.sent) != 1 {
		t.Fatalf("accepted-count partial sends = %d, want 1", len(rec.sent))
	}
	// And a partial sized for the STALE count now refuses.
	stale := *good
	stale.Generation = 10
	stripSingleUseCommitMetadata(&stale)
	if err := m.requestApplySnapshotPreparedLocked(&stale, &ProcessStatus{}); !errors.Is(err, errSnapshotPolicyMismatch) {
		t.Fatalf("stale-count partial = %v, want errSnapshotPolicyMismatch", err)
	}
}

// TestLostResponseLandedStampFollowsStatus simulates round-4 (b): an
// unknown-outcome full retry LANDED (helper status at the retained
// generation with the new count). The status reconciler must move the
// stamp to the helper-proven count so later partials publish.
func TestLostResponseLandedStampFollowsStatus(t *testing.T) {
	cfg := hardeningPolicyCfg()
	good := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	rec := &applyRecorder9520{}
	m := newRepublishManager9520(good, rec)
	m.expectedPolicyCount = 1
	// Retained advanced to the landed build (generation 8, 3 policies);
	// helper status proves the landing.
	landed := *good
	landed.Policies = append(append([]PolicyRuleSnapshot{}, good.Policies...), good.Policies[0], good.Policies[0])
	landed.Summary.PolicyCount = len(landed.Policies)
	landed.Generation = 8
	m.lastSnapshot = &landed
	m.publishedSnapshot = 7 // not yet caught up
	m.lastStatus.LastSnapshotGeneration = 8
	m.lastStatus.LastSnapshotPolicyCount = uint64(len(landed.Policies))
	m.reconcileExpectedPolicyCountFromStatusLocked()
	if m.expectedPolicyCount != len(landed.Policies) {
		t.Fatalf("stamp after status-proven landing = %d, want %d", m.expectedPolicyCount, len(landed.Policies))
	}
	partial := landed
	partial.Generation = 9
	stripSingleUseCommitMetadata(&partial)
	if err := m.requestApplySnapshotPreparedLocked(&partial, &ProcessStatus{}); err != nil {
		t.Fatalf("landed-count partial must publish after status reconciliation: %v", err)
	}
	// Status BELOW the retained generation must not move the stamp.
	m2 := newRepublishManager9520(good, &applyRecorder9520{})
	m2.expectedPolicyCount = 1
	m2.lastSnapshot = &landed
	m2.publishedSnapshot = 7
	m2.lastStatus.LastSnapshotGeneration = 7
	m2.lastStatus.LastSnapshotPolicyCount = 99
	m2.reconcileExpectedPolicyCountFromStatusLocked()
	if m2.expectedPolicyCount != 1 {
		t.Fatalf("stamp moved on stale status: %d, want 1", m2.expectedPolicyCount)
	}
}

// TestSyncRetryRemarksUnlandedClear drives the REAL deferred publish
// path (syncSnapshotLocked) for round-4 (c): a retained full-build
// clear whose first attempt did NOT land (helper still reports the
// old non-empty set) must retry WITH the marker re-marked from its
// own provenance, and the retry must reach the helper marked.
func TestSyncRetryRemarksUnlandedClear(t *testing.T) {
	cfg := hardeningPolicyCfg()
	good := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	rec := &applyRecorder9520{}
	m := newRepublishManager9520(good, rec)
	// Published plan context so the deferred gate classifies this as a
	// same-plan retry (not an XSK-startup deferral).
	// publishedPlanKey is set from the retained snapshot below.
	m.pendingFullSnapshotMetadata = true // Compile's own attempt in debt
	m.applySnapshotOutcomeUnknown = true // lost-response debt: exempt from XSK-startup deferral
	// If the resample classifies this as a plan change, the helper
	// restart branch fires; seam it to a no-op so the publish proceeds
	// (the restart itself is not what this test measures).
	m.restartBringupHook = func(config.UserspaceConfig) error { return nil }
	// Retained: the Compile's clear attempt (full build, empty), spent.
	retained := *good
	retained.Config = nil // config-less retained clone: revalidation keeps author rows (no RG resample under the sync lock)
	retained.Policies = nil
	retained.Summary.PolicyCount = 0
	retained.ClearPolicies = false // spent by the first send
	retained.fullBuild = true      // still the Compile's own build in debt
	retained.Generation = 8
	m.lastSnapshot = &retained
	m.publishedPlanKey = snapshotBindingPlanKey(&retained)
	m.publishedSnapshot = 7
	m.expectedPolicyCount = len(good.Policies) // stamp still at the old set
	// Helper truthfully reports the OLD set (clear did not land).
	m.lastStatus.LastSnapshotGeneration = 7
	m.lastStatus.LastSnapshotPolicyCount = uint64(len(good.Policies))
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	// Drive the deferred publish the way runSync does in the 9337
	// fixture: m.mu held for the sync itself (the revalidation rebuild
	// only re-locks when a row actually moved; our rows are static).
	m.mu.Lock()
	err := m.syncSnapshotLocked()
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("deferred retry of the unlanded clear must publish: %v", err)
	}
	if len(rec.sent) != 1 {
		t.Fatalf("retry sends = %d, want 1", len(rec.sent))
	}
	sent := rec.sent[0]
	if len(sent.Policies) != 0 || !sent.ClearPolicies {
		t.Fatalf("retry snapshot = %d policies, ClearPolicies=%v; want 0 policies WITH marker re-marked",
			len(sent.Policies), sent.ClearPolicies)
	}
	// After the successful retry the stamp follows the accepted clear:
	// sync success commits from the accepted full build.
	if m.expectedPolicyCount != 0 {
		t.Fatalf("stamp after landed clear retry = %d, want 0", m.expectedPolicyCount)
	}
	// A retained empty snapshot WITHOUT full-build provenance must NOT
	// re-mark (partial provenance never mints authorization).
	m2 := newRepublishManager9520(good, &applyRecorder9520{})
	unmarked := retained
	unmarked.fullBuild = false
	unmarked.Generation = 8
	m2.lastSnapshot = &unmarked
	m2.publishedSnapshot = 7
	m2.expectedPolicyCount = len(good.Policies)
	m2.lastStatus.LastSnapshotGeneration = 7
	m2.lastStatus.LastSnapshotPolicyCount = uint64(len(good.Policies))
	// Gate-level: the unmarked empty partial refuses against the stamp.
	clone := unmarked
	if err := m2.validateSnapshotForSend(&clone); !errors.Is(err, errSnapshotPolicyMismatch) {
		t.Fatalf("provenance-less empty retained = %v, want errSnapshotPolicyMismatch", err)
	}
}
