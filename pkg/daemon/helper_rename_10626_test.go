package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #10626: helper-path rename-rematch unit tests. The helper READ match carries
// the tuple as STRINGS plus the live zone IDs and DNAT inputs the Rust scan
// stamped; rematchRenamedMatch must apply the same verdict the legacy
// rematchRenamedV4/V6 reach on the equivalent store key+value.

func helperRenameBinding10626(t *testing.T, oldCfg, newCfg *config.Config) (uint32, policyRenameBinding) {
	t.Helper()
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok || len(bindings) != 1 {
		t.Fatalf("valid policy rename was rejected: bindings=%v ok=%v", bindings, ok)
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	binding, ok := bindings[oldID]
	if !ok {
		t.Fatalf("missing binding for old policy id %d: %v", oldID, bindings)
	}
	return oldID, binding
}

func helperRenameMatch10626(policyID uint32) dpuserspace.SessionPolicyMatch {
	return dpuserspace.SessionPolicyMatch{
		AddrFamily: 4,
		Tuple: dpuserspace.SessionPolicyTuple{
			AddrFamily: 4, Protocol: 6,
			SrcIP: "10.0.0.10", DstIP: "10.0.0.20",
			// Helper-wire ports are HOST order (Rust SessionKey holds host
			// order and policy_tuple_from_key copies them raw) — unlike the
			// BPF-keyed legacy path. The record passes them through raw.
			SrcPort: 1234,
			DstPort: 443,
		},
		PolicyID:      policyID,
		IngressZoneID: config.StableZoneID("lan"),
		EgressZoneID:  config.StableZoneID("wan"),
	}
}

func TestRematchRenamedMatchPermitted10626(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	oldID, binding := helperRenameBinding10626(t, oldCfg, newCfg)
	match := helperRenameMatch10626(oldID)
	// Non-palindromic dst port: a byte-swap slip rematches the wrong
	// service and reds below.
	match.Tuple.DstPort = 5201
	record, permitted := rematchRenamedMatch(oldCfg, newCfg, binding, match)
	if !permitted {
		t.Fatal("matching renamed helper match was not retained")
	}
	if record.RuleID != "lan->wan/p-new" || record.PolicyID == 0 {
		t.Fatalf("renamed record lost identity: %+v", record)
	}
	if record.IngressZone != config.StableZoneID("lan") ||
		record.EgressZone != config.StableZoneID("wan") {
		t.Fatalf("renamed record lost zones: %+v", record)
	}
	if record.SrcPort != 1234 || record.DstPort != 5201 {
		t.Fatalf("record ports not exact host order: got %d/%d", record.SrcPort, record.DstPort)
	}
	if record.SrcIP != "10.0.0.10" || record.DstIP != "10.0.0.20" || record.Protocol != 6 {
		t.Fatalf("renamed record lost tuple: %+v", record)
	}
}

func TestRematchRenamedMatchGRE0Denied10626(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	oldID, binding := helperRenameBinding10626(t, oldCfg, newCfg)
	match := helperRenameMatch10626(oldID)
	// GRE with a zero discriminator is the legacy-parity deny: the
	// discriminator cannot identify the session, so it is deleted rather
	// than retained.
	match.Tuple.Protocol = 47
	match.Tuple.TunnelDiscriminator = 0
	if _, permitted := rematchRenamedMatch(oldCfg, newCfg, binding, match); permitted {
		t.Fatal("GRE0 helper match was retained, want denied (legacy parity)")
	}
}

func TestRematchRenamedMatchZeroZonesDenied10626(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	oldID, binding := helperRenameBinding10626(t, oldCfg, newCfg)
	match := helperRenameMatch10626(oldID)
	// An older helper omits the additive zone fields: fail closed to the
	// denied bucket rather than retaining on unknown zones.
	match.IngressZoneID, match.EgressZoneID = 0, 0
	if _, permitted := rematchRenamedMatch(oldCfg, newCfg, binding, match); permitted {
		t.Fatal("zero-zone helper match was retained, want fail-closed denied")
	}
}

func TestRematchRenamedMatchDNAT10626(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Security.Policies[1].Policies[0].Match.DestinationAddresses =
			[]string{"10.0.0.1/32", "2001:db8::30/128"}
	}
	// Remove the alternate permit (N3e): permittedRenameResult accepts ANY
	// non-sentinel permit, so with p-alternate present the out-of-scope
	// translation below would retain under the alternate's identity and the
	// negative would stay green for the wrong reason. Default-deny without
	// the alternate isolates the translation verdict (mirrors
	// TestPermittedRenameResultAlternateRemovedDenies10592).
	newCfg.Security.Policies[1].Policies = newCfg.Security.Policies[1].Policies[:1]
	oldID, binding := helperRenameBinding10626(t, oldCfg, newCfg)
	match := helperRenameMatch10626(oldID)
	match.DNAT = true
	match.NATDstIP = "10.0.0.1"
	match.NATDstPort = 8443
	record, permitted := rematchRenamedMatch(oldCfg, newCfg, binding, match)
	if !permitted || record.RuleID != "lan->wan/p-new" {
		t.Fatalf("DNAT row not rematched through renamed permit: %+v permitted=%v", record, permitted)
	}
	// The QUERY consults the translated dst, but the RECORD carries the
	// wire tuple.
	if record.SrcIP != "10.0.0.10" || record.DstIP != "10.0.0.20" {
		t.Fatalf("DNAT record carries translated addrs instead of wire: %+v", record)
	}
	if record.SrcPort != 1234 || record.DstPort != 443 {
		t.Fatalf("DNAT record carries translated ports instead of wire: got %d/%d", record.SrcPort, record.DstPort)
	}
	// Out-of-scope translation denies.
	match.NATDstIP = "10.9.9.9"
	if _, permitted := rematchRenamedMatch(oldCfg, newCfg, binding, match); permitted {
		t.Fatal("out-of-scope DNAT translation was retained, want denied")
	}
}

func TestCaptureRequestedPolicyIDs10626(t *testing.T) {
	deleted := map[uint32]struct{}{7: {}, 9: {}}
	modified := map[uint32]struct{}{11: {}}
	var deflt map[uint32]struct{}
	renameBindings := map[uint32]policyRenameBinding{
		// Binding-only key: included + deduplicated by contract (normally
		// already in `deleted`; the union is defensive, not load-bearing).
		13: {},
		// Overlapping key: must not duplicate the deleted entry.
		7: {},
	}
	ids := captureRequestedPolicyIDs(deleted, modified, deflt, renameBindings)
	seen := make(map[uint32]int, len(ids))
	for _, id := range ids {
		seen[id]++
	}
	for _, want := range []uint32{7, 9, 11, 13} {
		if seen[want] != 1 {
			t.Fatalf("requested IDs %v: want exactly one %d", ids, want)
		}
	}
	if len(ids) != 4 {
		t.Fatalf("requested IDs %v: want exactly 4 entries", ids)
	}
}

// helperRenameDP10626 serves the helper READ from a scripted match list. It
// mirrors the helper's filter chain (requested policy, allowed family —
// collisionDP10512 fidelity minus the legacy fence this path never uses, all
// rows are forward-class) and records deletes for the Step 4 drivability
// proof.
type helperRenameDP10626 struct {
	*policyInvalTestDP
	matches []dpuserspace.SessionPolicyMatch
	reqs    []dpuserspace.SessionPolicyListRequest
	deleted []dpuserspace.SessionPolicyMatch
}

func (f *helperRenameDP10626) ListSessionsByPolicy(req dpuserspace.SessionPolicyListRequest) (dpuserspace.ControlResponse, error) {
	f.reqs = append(f.reqs, req)
	want := make(map[uint32]bool, len(req.PolicyIDs))
	for _, id := range req.PolicyIDs {
		want[id] = true
	}
	var out []dpuserspace.SessionPolicyMatch
	for _, m := range f.matches {
		if !want[m.PolicyID] {
			continue
		}
		if len(req.Families) > 0 {
			ok := false
			for _, fam := range req.Families {
				if fam == m.AddrFamily {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		out = append(out, m)
	}
	return dpuserspace.ControlResponse{
		SessionPolicyMatches:  out,
		SessionPolicyComplete: true,
	}, nil
}

func (f *helperRenameDP10626) DeletePolicySessions(matches []dpuserspace.SessionPolicyMatch) (dpuserspace.PolicyDeleteResult, error) {
	f.deleted = append(f.deleted, matches...)
	return dpuserspace.PolicyDeleteResult{Applied: len(matches)}, nil
}

// TestHelperCaptureRetainsRenamedSession10626 is the RED-first cell for the
// helper-rename defect: a renamed session the new policy still permits must
// be captured into `renamed` (rebound), not into `deleted.policy`. Pre-fix
// the helper loop never consults the rename bindings, so the match lands in
// `deleted.policy` and this test FAILS.
func TestHelperCaptureRetainsRenamedSession10626(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	match := helperRenameMatch10626(oldID)
	match.Tuple.SrcIP = "10.0.0.20"
	match.Tuple.DstIP = "10.0.0.254"
	match.Tuple.DstPort = 5201
	match.ExpectedRTFlowSessionID = 0xA11CE
	match.CreatedSecs = 1_500_000_000
	dp := &helperRenameDP10626{
		policyInvalTestDP: &policyInvalTestDP{
			v4: map[dataplane.SessionKey]dataplane.SessionValue{},
			v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
		},
		matches: []dpuserspace.SessionPolicyMatch{match},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.armPolicyInvalidationPlanWithRename(oldCfg, newCfg, &pendingRenameApply{
		descriptors: []configstore.RenameDescriptor{
			policyRenameDescriptor("p-old", "p-new"),
		},
	})
	d.capturePolicyInvalidationLocked(newCfg)
	capture := d.policyInvalidationCapture
	if capture == nil {
		t.Fatal("rename apply did not produce a pre-publication capture")
	}
	if len(capture.renamed) != 1 {
		t.Fatalf("renamed rows = %d, want 1 (deleted.policy = %d)", len(capture.renamed), len(capture.deleted.policy))
	}
	record := capture.renamed[0]
	if record.RuleID != "lan->wan/p-new" {
		t.Fatalf("renamed record lost identity: %+v", record)
	}
	if record.IngressZone == 0 || record.EgressZone == 0 {
		t.Fatalf("renamed record lost zones: %+v", record)
	}
	if len(capture.deleted.policy) != 0 {
		t.Fatalf("deleted.policy = %d, want 0 (renamed match must not also delete)", len(capture.deleted.policy))
	}
}

// TestHelperCaptureDeniedRenameDeletesOnce10626 pins the denied bucket: a
// renamed session the new policy denies must land EXACTLY ONCE in
// `deleted.policy` (plus its v4 entry — the post-P6 pairing), never in
// `renamed`. Driving deleteInvalidatedSessions then proves the match is
// deletable through the helper path (unlike a legacy v4-only shape, which
// would leave the delete recorder empty).
func TestHelperCaptureDeniedRenameDeletesOnce10626(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Security.Policies[1].Policies[0].Match.DestinationAddresses = []string{"10.0.0.1/32"}
	}
	// Alternate removed from the new generation only (10592 pattern): the
	// 10.0.0.254 session misses the renamed rule and falls to default-deny.
	newCfg.Security.Policies[1].Policies = newCfg.Security.Policies[1].Policies[:1]
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	match := helperRenameMatch10626(oldID)
	match.Tuple.DstIP = "10.0.0.254"
	match.Tuple.DstPort = 5201
	match.ExpectedRTFlowSessionID = 0xA11CE
	match.CreatedSecs = 1_500_000_000
	dp := &helperRenameDP10626{
		policyInvalTestDP: &policyInvalTestDP{
			v4: map[dataplane.SessionKey]dataplane.SessionValue{},
			v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
		},
		matches: []dpuserspace.SessionPolicyMatch{match},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.armPolicyInvalidationPlanWithRename(oldCfg, newCfg, &pendingRenameApply{
		descriptors: []configstore.RenameDescriptor{
			policyRenameDescriptor("p-old", "p-new"),
		},
	})
	d.capturePolicyInvalidationLocked(newCfg)
	capture := d.policyInvalidationCapture
	if capture == nil {
		t.Fatal("rename apply did not produce a pre-publication capture")
	}
	if len(capture.renamed) != 0 {
		t.Fatalf("renamed rows = %d, want 0 (denied match must not retain)", len(capture.renamed))
	}
	if len(capture.deleted.policy) != 1 {
		t.Fatalf("deleted.policy = %d, want exactly 1", len(capture.deleted.policy))
	}
	if len(capture.deleted.v4) != 1 || len(capture.deleted.v6) != 0 {
		t.Fatalf("deleted entries v4/v6 = %d/%d, want 1/0 (post-P6 pairing)", len(capture.deleted.v4), len(capture.deleted.v6))
	}
	if err := d.deleteInvalidatedSessions(capture.deleted, dataplane.DeleteReasonPolicyDeleted, "deleted"); err != nil {
		t.Fatalf("delete drive: %v", err)
	}
	if len(dp.deleted) != 1 || dp.deleted[0].ExpectedRTFlowSessionID != 0xA11CE {
		t.Fatalf("delete recorder = %+v, want exactly the denied match", dp.deleted)
	}
}

// TestHelperCaptureDeniedGRE0DeletesViaPolicy10626 pins denied-GRE0 routing:
// a GRE match with a zero discriminator cannot identify its session, so the
// rematch denies it (legacy parity) and it joins `deleted.policy` like any
// denied rename. Note the deliberate asymmetry this pins: the LEGACY denied
// path flags PurgeTunnelVariants (wildcard — the mirror cannot name GRE rows
// exactly), while the HELPER path deletes by exact key + RT_FLOW identity
// (the match carries live discriminators, and wire-0 under-matches to None
// in policy_key_from_tuple rather than refusing).
func TestHelperCaptureDeniedGRE0DeletesViaPolicy10626(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	match := helperRenameMatch10626(oldID)
	match.Tuple.Protocol = 47
	match.Tuple.TunnelDiscriminator = 0
	// GRE has no L4 ports: the Rust tuple copies the key's zero ports raw.
	match.Tuple.SrcPort = 0
	match.Tuple.DstPort = 0
	match.ExpectedRTFlowSessionID = 0xB22CE
	match.CreatedSecs = 1_500_000_000
	dp := &helperRenameDP10626{
		policyInvalTestDP: &policyInvalTestDP{
			v4: map[dataplane.SessionKey]dataplane.SessionValue{},
			v6: map[dataplane.SessionKeyV6]dataplane.SessionValueV6{},
		},
		matches: []dpuserspace.SessionPolicyMatch{match},
	}
	d := &Daemon{}
	d.setDataplane(dp)
	d.armPolicyInvalidationPlanWithRename(oldCfg, newCfg, &pendingRenameApply{
		descriptors: []configstore.RenameDescriptor{
			policyRenameDescriptor("p-old", "p-new"),
		},
	})
	d.capturePolicyInvalidationLocked(newCfg)
	capture := d.policyInvalidationCapture
	if capture == nil {
		t.Fatal("rename apply did not produce a pre-publication capture")
	}
	if len(capture.renamed) != 0 {
		t.Fatalf("renamed rows = %d, want 0 (GRE0 must deny)", len(capture.renamed))
	}
	if len(capture.deleted.policy) != 1 {
		t.Fatalf("deleted.policy = %d, want exactly 1", len(capture.deleted.policy))
	}
	if err := d.deleteInvalidatedSessions(capture.deleted, dataplane.DeleteReasonPolicyDeleted, "deleted"); err != nil {
		t.Fatalf("delete drive: %v", err)
	}
	if len(dp.deleted) != 1 || dp.deleted[0].ExpectedRTFlowSessionID != 0xB22CE {
		t.Fatalf("delete recorder = %+v, want exactly the GRE0 match", dp.deleted)
	}
}

// #10626 m4: port-sensitive rematch pins the query-port encoding (guards M1:
// a byte-swap slip rematches the wrong service). Distinctive ports on an
// otherwise identical shape: dst 5201 permits, dst 5202 denies.
func TestRematchRenamedMatchPortSensitive10626(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Applications.Applications = map[string]*config.Application{
			"svc-5201": {Name: "svc-5201", Protocol: "tcp", DestinationPort: "5201"},
		}
		for _, pair := range cfg.Security.Policies {
			for _, pol := range pair.Policies {
				if pol.Name == "p-old" || pol.Name == "p-new" {
					pol.Match.Applications = []string{"svc-5201"}
				}
			}
		}
		// Remove the port-agnostic alternate (N3e): with it present the
		// out-of-scope dst would retain under the alternate and the deny
		// half would stay green for the wrong reason.
		for _, pair := range cfg.Security.Policies {
			kept := pair.Policies[:0]
			for _, pol := range pair.Policies {
				if pol.Name != "p-alternate" {
					kept = append(kept, pol)
				}
			}
			pair.Policies = kept
		}
	}
	oldID, binding := helperRenameBinding10626(t, oldCfg, newCfg)
	match := helperRenameMatch10626(oldID)
	match.Tuple.DstPort = 5201
	if record, permitted := rematchRenamedMatch(oldCfg, newCfg, binding, match); !permitted || record.DstPort != 5201 {
		t.Fatalf("in-scope dst port not retained: %+v permitted=%v", record, permitted)
	}
	match.Tuple.DstPort = 5202
	if _, permitted := rematchRenamedMatch(oldCfg, newCfg, binding, match); permitted {
		t.Fatal("out-of-scope dst port was retained, want denied")
	}
}

// #10626 m4: v6 helper rematch — family-6 branch, v4-mapped rejection, v6 DNAT.
func TestRematchRenamedMatchV610626(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	oldID, binding := helperRenameBinding10626(t, oldCfg, newCfg)
	v6match := func() dpuserspace.SessionPolicyMatch {
		m := helperRenameMatch10626(oldID)
		m.AddrFamily = 6
		m.Tuple.AddrFamily = 6
		m.Tuple.Protocol = 6
		m.Tuple.SrcIP = "2001:db8::10"
		m.Tuple.DstIP = "2001:db8::20"
		m.Tuple.SrcPort = 1234
		m.Tuple.DstPort = 443
		return m
	}
	if _, permitted := rematchRenamedMatch(oldCfg, newCfg, binding, v6match()); !permitted {
		t.Fatal("v6 helper match was not retained")
	}
	mapped := v6match()
	mapped.Tuple.SrcIP = "::ffff:10.0.0.10"
	if _, permitted := rematchRenamedMatch(oldCfg, newCfg, binding, mapped); permitted {
		t.Fatal("v4-mapped v6 helper match was retained, want rejected")
	}
	dnat := v6match()
	dnat.DNAT = true
	dnat.NATDstIP = "2001:db8::30"
	dnat.NATDstPort = 8443
	if _, permitted := rematchRenamedMatch(oldCfg, newCfg, binding, dnat); !permitted {
		t.Fatal("v6 DNAT helper match was not retained")
	}
}

// #10626 m4: zone rename drives remappedQueryZones off its no-op path — the
// old-zone query rematches against the NEW zone rule and the record carries
// the remapped zones.
func TestRematchRenamedMatchZoneRename10626(t *testing.T) {
	oldCfg, newCfg := zoneRenameEvaluatorConfigs()
	// Single binding: drop the alternate so the zone fan-out yields exactly
	// the renamed pair under test.
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		for _, pair := range cfg.Security.Policies {
			kept := pair.Policies[:0]
			for _, pol := range pair.Policies {
				if pol.Name != "p-alternate" {
					kept = append(kept, pol)
				}
			}
			pair.Policies = kept
		}
	}
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{{
			SourcePath:      []string{"security", "zones", "security-zone", "lan"},
			DestinationPath: []string{"security", "zones", "security-zone", "lan2"},
		}},
	)
	if !ok || len(bindings) != 1 {
		t.Fatalf("zone rename rejected or fanned out: bindings=%v ok=%v", bindings, ok)
	}
	var oldID uint32
	var binding policyRenameBinding
	for id, b := range bindings {
		oldID, binding = id, b
	}
	match := helperRenameMatch10626(oldID)
	record, permitted := rematchRenamedMatch(oldCfg, newCfg, binding, match)
	if !permitted {
		t.Fatal("zone-renamed helper match was not retained")
	}
	if record.IngressZone != config.StableZoneID("lan2") {
		t.Fatalf("record kept stale ingress zone %d, want lan2", record.IngressZone)
	}
}
