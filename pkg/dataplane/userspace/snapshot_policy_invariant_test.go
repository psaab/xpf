package userspace

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
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
