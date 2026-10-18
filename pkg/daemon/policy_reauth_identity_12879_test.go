package daemon

import (
	"context"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/policymatch"
)

// #12879: reauthorizePolicyCandidates must discharge a rollback candidate only
// when the restored config re-authorizes the tuple under the candidate's
// CAPTURED IDENTITY — the recorded stable rule key, or the implicit
// default-policy for a sentinel-attributed orphan. The old verdict tested only
// result.Action == PolicyPermit, which reads the ZERO value of Action as a
// permit for a `to-zone junos-host` query that matched no host policy
// (HostInboundUnmatched: Matched=false, DefaultUsed=false, Action unset —
// pkg/policymatch Result contract), and accepts ANY other permit rule (or a
// default-policy permit) as authorization for a candidate whose own rule no
// longer matches the tuple. Both directions discharge a still-owed delete.

// reauthRule12879 builds one policy rule restricted to the named applications.
func reauthRule12879(name string, action config.PolicyAction, apps ...string) *config.Policy {
	return &config.Policy{
		Name: name, Action: action,
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         apps,
		},
	}
}

// reauthConfig12879 builds a struct config (the same lenient-load shape
// policyRenameEvaluatorConfig uses) over the given zone names and policy sets.
func reauthConfig12879(
	def config.PolicyAction, zoneNames []string, pairs ...*config.ZonePairPolicies,
) *config.Config {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = def
	cfg.Security.Zones = make(map[string]*config.ZoneConfig, len(zoneNames))
	for _, name := range zoneNames {
		cfg.Security.Zones[name] = &config.ZoneConfig{Name: name}
	}
	cfg.Security.Policies = pairs
	return cfg
}

// reauthCandidate12879 builds a tcp v4 helper candidate from trust.
func reauthCandidate12879(dstPort uint16, egress uint16) dpuserspace.SessionPolicyMatch {
	return dpuserspace.SessionPolicyMatch{
		AddrFamily: 4,
		Tuple: dpuserspace.SessionPolicyTuple{
			AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 2077, DstPort: dstPort,
		},
		ExpectedRTFlowSessionID: 77,
		IngressZoneID:           config.StableZoneID("trust"),
		EgressZoneID:            egress,
	}
}

// TestReauthorizeRequiresCapturedIdentityPermit12879 pins the verdict
// contract: each table row is a candidate whose captured key still exists in
// the restored config as a permit policy, but the restored verdict for the
// tuple is issued by a DIFFERENT identity (another rule, the default-policy,
// or the host-inbound fall-through). None of those may discharge the debt.
// The two "identity" rows are the positive controls: a verdict by the captured
// identity itself still discharges.
func TestReauthorizeRequiresCapturedIdentityPermit12879(t *testing.T) {
	untrust := config.StableZoneID("untrust")
	hostEgress := config.StableZoneID("junos-host")
	transit := &config.ZonePairPolicies{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
		reauthRule12879("narrow", config.PolicyPermit, "junos-ssh"),
		reauthRule12879("wide", config.PolicyPermit, "junos-http"),
	}}
	hostPair := &config.ZonePairPolicies{FromZone: "trust", ToZone: "junos-host", Policies: []*config.Policy{
		reauthRule12879("host-allow", config.PolicyPermit, "junos-ssh"),
	}}
	cases := []struct {
		name          string
		cfg           *config.Config
		key           string
		dstPort       uint16
		egress        uint16
		wantPermitted bool
	}{
		{
			// The decisive #12879 witness: rule "narrow" survives as a permit
			// policy but matches only ssh, while sibling "wide" permits tcp/80.
			// Another rule's permit is not authorization under "narrow".
			name: "cross_rule_permit_keeps_candidate",
			cfg:  reauthConfig12879(config.PolicyDeny, []string{"trust", "untrust"}, transit),
			key:  "trust->untrust/narrow", dstPort: 80, egress: untrust,
		},
		{
			// No rule matches tcp/80; a default-policy permit is the
			// default's verdict, not "narrow"'s.
			name: "default_policy_substitute_keeps_candidate",
			cfg: reauthConfig12879(config.PolicyPermit, []string{"trust", "untrust"},
				&config.ZonePairPolicies{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
					reauthRule12879("narrow", config.PolicyPermit, "junos-ssh"),
				}}),
			key: "trust->untrust/narrow", dstPort: 80, egress: untrust,
		},
		{
			// Host-bound fall-through: Matched=false, DefaultUsed=false and
			// Action is the meaningless zero value (PolicyPermit). The zone
			// definition mirrors a leniently-loaded restored target, the only
			// shape whose zone table can resolve the junos-host egress name.
			name: "host_unmatched_zero_action_keeps_candidate",
			cfg:  reauthConfig12879(config.PolicyDeny, []string{"trust", "junos-host"}, hostPair),
			key:  "trust->junos-host/host-allow", dstPort: 80, egress: hostEgress,
		},
		{
			// A sentinel-attributed default-policy candidate is discharged by
			// the restored default-policy verdict only — not by a concrete
			// rule that now matches the tuple.
			name: "default_key_cross_rule_keeps_candidate",
			cfg:  reauthConfig12879(config.PolicyDeny, []string{"trust", "untrust"}, transit),
			key:  dataplane.DefaultPolicyName, dstPort: 80, egress: untrust,
		},
		{
			name: "captured_rule_identity_permits",
			cfg:  reauthConfig12879(config.PolicyDeny, []string{"trust", "untrust"}, transit),
			key:  "trust->untrust/narrow", dstPort: 22, egress: untrust,
			wantPermitted: true,
		},
		{
			name: "default_key_default_verdict_permits",
			cfg: reauthConfig12879(config.PolicyPermit, []string{"trust", "untrust"},
				&config.ZonePairPolicies{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
					reauthRule12879("narrow", config.PolicyPermit, "junos-ssh"),
				}}),
			key: dataplane.DefaultPolicyName, dstPort: 80, egress: untrust,
			wantPermitted: true,
		},
		{
			name: "captured_host_rule_identity_permits",
			cfg:  reauthConfig12879(config.PolicyDeny, []string{"trust", "junos-host"}, hostPair),
			key:  "trust->junos-host/host-allow", dstPort: 22, egress: hostEgress,
			wantPermitted: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			match := reauthCandidate12879(tc.dstPort, tc.egress)
			capture := &policyInvalidationCapture{
				candidateRuleIDs: map[policyInvalidationMatchIdentity]string{
					policyInvalidationMatchID(match): tc.key,
				},
			}
			capture.deleted.policy = append(capture.deleted.policy, match)

			d := &Daemon{}
			kept, permitted := d.reauthorizePolicyCandidates(capture, tc.cfg, false)
			if tc.wantPermitted {
				if permitted == nil || permitted.candidateCount() != 1 || kept.candidateCount() != 0 {
					t.Fatalf("candidate under captured identity %q was not discharged: kept=%d permitted=%d",
						tc.key, kept.candidateCount(), permittedCount12879(permitted))
				}
				return
			}
			if permitted != nil || kept.candidateCount() != 1 {
				t.Fatalf("#12879 fail-open: verdict outside captured identity %q discharged the debt: kept=%d permitted=%d",
					tc.key, kept.candidateCount(), permittedCount12879(permitted))
			}
		})
	}
}

func permittedCount12879(permitted *policyInvalidationCapture) int {
	if permitted == nil {
		return 0
	}
	return permitted.candidateCount()
}

// TestReauthorizeHostUnmatchedActionIsMeaningless12879 pins the matcher
// premise behind the host row above: for a `to-zone junos-host` query that no
// host policy matches, Action is the zero value (PolicyPermit) and carries no
// enforced meaning, so any caller treating Action==PolicyPermit as a permit
// fails open. #6576 kept the ordinary-L4 contract: no frag candidate fires.
func TestReauthorizeHostUnmatchedActionIsMeaningless12879(t *testing.T) {
	cfg := reauthConfig12879(config.PolicyDeny, []string{"trust", "junos-host"},
		&config.ZonePairPolicies{FromZone: "trust", ToZone: "junos-host", Policies: []*config.Policy{
			reauthRule12879("host-allow", config.PolicyPermit, "junos-ssh"),
		}})
	result := policymatch.Match(cfg, policymatch.Query{
		FromZone: "trust", ToZone: "junos-host",
		SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
		Protocol: "tcp", SrcPort: 2077, DstPort: 80, SrcFamily: "v4", DstFamily: "v4",
	})
	if !result.HostInboundUnmatched || result.Matched || result.DefaultUsed {
		t.Fatalf("premise: unmatched host query returned %+v", result)
	}
	if result.Action != config.PolicyPermit {
		t.Fatalf("premise: unmatched host query Action=%d, want the zero value PolicyPermit", result.Action)
	}
}

// #14697: reauthorizePolicyCandidates builds its query with ICMPType nil
// (helper tuples store only the echo identifier in the ports), so an
// icmp-type-constrained deny ordered before the candidate's own permit is
// skipped and the session is wrongly discharged. It also never called
// capturedTunnelDiscriminatorValid, so a GRE session with a zero
// discriminator could be re-authorized the same way.
func TestReauthorizeFailsClosedOnICMPAndGRE14697(t *testing.T) {
	restored := reauthConfig12879(config.PolicyDeny, []string{"trust", "untrust"},
		&config.ZonePairPolicies{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
			{Name: "deny-ping", Action: config.PolicyDeny, Match: config.PolicyMatch{
				SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"},
				Applications: []string{"junos-icmp-ping"},
			}},
			{Name: "wide", Action: config.PolicyPermit, Match: config.PolicyMatch{
				SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"},
				Applications: []string{"junos-icmp-all"},
			}},
			{Name: "gre-wide", Action: config.PolicyPermit, Match: config.PolicyMatch{
				SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"},
				Applications: []string{"junos-gre"},
			}},
		}})
	mk := func(proto uint8, key string) *policyInvalidationCapture {
		match := dpuserspace.SessionPolicyMatch{
			AddrFamily: 4,
			Tuple: dpuserspace.SessionPolicyTuple{
				AddrFamily: 4, Protocol: proto, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: 0x1234, DstPort: 0x1234,
			},
			ExpectedRTFlowSessionID: 97,
			IngressZoneID:           config.StableZoneID("trust"),
			EgressZoneID:            config.StableZoneID("untrust"),
		}
		capture := &policyInvalidationCapture{
			candidateRuleIDs: map[policyInvalidationMatchIdentity]string{
				policyInvalidationMatchID(match): key,
			},
		}
		capture.deleted.policy = append(capture.deleted.policy, match)
		return capture
	}
	d := &Daemon{}
	// ICMP candidate whose captured identity is the broader permit: the
	// earlier deny-ping must block discharge, but nil-type evaluation
	// skips it pre-fix.
	if kept, permitted := d.reauthorizePolicyCandidates(mk(1, "trust->untrust/wide"), restored, false); permitted != nil || kept.candidateCount() != 1 {
		t.Fatalf("ICMP candidate discharged past icmp-type deny: kept=%d permitted=%v", kept.candidateCount(), permitted)
	}
	// ICMPv6-shaped protocol number on the same v4 tuple shape: the
	// guard is protocol-based, so 58 fails closed too.
	if kept, permitted := d.reauthorizePolicyCandidates(mk(58, "trust->untrust/wide"), restored, false); permitted != nil || kept.candidateCount() != 1 {
		t.Fatalf("ICMPv6-protocol candidate discharged: kept=%d permitted=%v", kept.candidateCount(), permitted)
	}
	// GRE with zero discriminator: missing-guard consistency.
	if kept, permitted := d.reauthorizePolicyCandidates(mk(47, "trust->untrust/gre-wide"), restored, false); permitted != nil || kept.candidateCount() != 1 {
		t.Fatalf("GRE0 candidate discharged: kept=%d permitted=%v", kept.candidateCount(), permitted)
	}
	// TCP control: an ordinary candidate under its captured permit still
	// discharges (the guard must not over-block non-lossy protocols).
	tcpMatch := dpuserspace.SessionPolicyMatch{
		AddrFamily: 4,
		Tuple: dpuserspace.SessionPolicyTuple{
			AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 2077, DstPort: 22,
		},
		ExpectedRTFlowSessionID: 98,
		IngressZoneID:           config.StableZoneID("trust"),
		EgressZoneID:            config.StableZoneID("untrust"),
	}
	tcpCapture := &policyInvalidationCapture{
		candidateRuleIDs: map[policyInvalidationMatchIdentity]string{
			policyInvalidationMatchID(tcpMatch): "trust->untrust/wide",
		},
	}
	// "wide" here is junos-icmp-all (ICMP only), so use a dedicated TCP
	// restored config for the control.
	tcpRestored := reauthConfig12879(config.PolicyDeny, []string{"trust", "untrust"},
		&config.ZonePairPolicies{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{
			reauthRule12879("wide", config.PolicyPermit, "junos-http"),
		}})
	tcpMatch.Tuple.DstPort = 80
	tcpCapture.candidateRuleIDs = map[policyInvalidationMatchIdentity]string{
		policyInvalidationMatchID(tcpMatch): "trust->untrust/wide",
	}
	tcpCapture.deleted.policy = append(tcpCapture.deleted.policy, tcpMatch)
	if kept, permitted := d.reauthorizePolicyCandidates(tcpCapture, tcpRestored, false); permitted == nil || permitted.candidateCount() != 1 || kept.candidateCount() != 0 {
		t.Fatalf("TCP control candidate not discharged: kept=%d permitted=%v", kept.candidateCount(), permitted)
	}
}

// TestPolicyInvalidationRollbackCrossRulePermitDoesNotDischarge12879 is the
// end-to-end decisive witness. C0 permits ssh under "narrow" and tcp/80 under
// "wide"; C1 widens "narrow" to any application and admits sessions 7 (tcp/80)
// and 8 (tcp/22) under it; C2 removes "narrow" and the candidate delete fails,
// retaining both as debt keyed to trust->untrust/narrow. Rolling back to C0,
// "narrow" exists and is a permit policy but matches only ssh: session 8 is
// re-authorized under its captured identity and must survive, while session 7
// — authorized on C0 only by the sibling "wide" — must remain a deletion
// obligation instead of being discharged by another rule's permit.
func TestPolicyInvalidationRollbackCrossRulePermitDoesNotDischarge12879(t *testing.T) {
	r, _ := newConvergenceRun12072(t, []string{"p-first"})
	c0, err := r.h.d.store.SyncApply(rulesConfigText12532("cross12879-c0", "deny-all", []rule12532{
		{name: "p-first", app: "junos-telnet"}, {name: "narrow", app: "junos-ssh"}, {name: "wide", app: "junos-http"},
	}), nil)
	if err != nil {
		t.Fatalf("promote C0: %v", err)
	}
	r.dp.applied, r.dp.helperCfg = c0, c0
	r.h.d.store.MarkActiveApplied()
	c1, _, err := publishConfirmedRollbackText12072(t, r, c0, rulesConfigText12532("cross12879-c1", "deny-all", []rule12532{
		{name: "p-first", app: "junos-telnet"}, {name: "narrow", app: "any"},
	}))
	if err != nil {
		t.Fatalf("premise: C0->C1 widen narrow: %v", err)
	}
	narrowID := dpuserspace.PolicyIDsByStableKey(c1)["trust->untrust/narrow"]
	for _, session := range []struct {
		id   uint64
		port uint16
	}{{7, 80}, {8, 22}} {
		r.dp.rows = append(r.dp.rows, dpuserspace.SessionPolicyMatch{
			AddrFamily: 4,
			Tuple: dpuserspace.SessionPolicyTuple{
				AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: uint16(2000 + session.id), DstPort: session.port,
			},
			PolicyID: narrowID, ExpectedRTFlowSessionID: session.id,
			IngressZoneID: config.StableZoneID("trust"),
			EgressZoneID:  config.StableZoneID("untrust"),
		})
		r.dp.ruleBySession[session.id] = "trust->untrust/narrow"
	}
	r.dp.deleteErrOnce = true
	_, gen, err := publishConfirmedRollbackText12072(t, r, c1, rulesConfigText12532("cross12879-c2", "deny-all", []rule12532{
		{name: "p-first", app: "junos-telnet"},
	}))
	if err == nil {
		t.Fatal("C1->C2 failed candidate delete was not surfaced")
	}

	r.h.d.executeConfirmedRollback(gen)

	if r.h.d.store.ActiveConfig() != c0 || r.dp.applied != c0 {
		t.Fatalf("rollback authority: store=%p helper=%p, want C0 %p",
			r.h.d.store.ActiveConfig(), r.dp.applied, c0)
	}
	if !r.hasDeletedSession(7) || r.hasLiveSession(7) {
		t.Errorf("UNDER-DELETION #12879: tcp/80 session 7 was discharged by sibling wide's permit instead of remaining narrow's debt: deleted=%v live=%v",
			r.hasDeletedSession(7), r.hasLiveSession(7))
	}
	if r.hasDeletedSession(8) || !r.hasLiveSession(8) {
		t.Errorf("OVER-DELETION: tcp/22 session 8 is permitted by its captured rule narrow, but was deleted")
	}
}

// TestPolicyInvalidationRollbackDefaultPermitDoesNotDischarge12879 is the
// default-policy arm end to end: C0 keeps "narrow" (ssh-only permit) with a
// permit-all default-policy; after C1 widens and C2 removes "narrow", the
// tcp/80 candidate's restored verdict is the DEFAULT-policy permit, which is
// not "narrow"'s authorization either. The tcp/22 session still discharges.
func TestPolicyInvalidationRollbackDefaultPermitDoesNotDischarge12879(t *testing.T) {
	r, _ := newConvergenceRun12072(t, []string{"p-first"})
	c0, err := r.h.d.store.SyncApply(rulesConfigText12532("defperm12879-c0", "permit-all", []rule12532{
		{name: "p-first", app: "junos-telnet"}, {name: "narrow", app: "junos-ssh"},
	}), nil)
	if err != nil {
		t.Fatalf("promote C0: %v", err)
	}
	r.dp.applied, r.dp.helperCfg = c0, c0
	r.h.d.store.MarkActiveApplied()
	c1, _, err := publishConfirmedRollbackText12072(t, r, c0, rulesConfigText12532("defperm12879-c1", "permit-all", []rule12532{
		{name: "p-first", app: "junos-telnet"}, {name: "narrow", app: "any"},
	}))
	if err != nil {
		t.Fatalf("premise: C0->C1 widen narrow: %v", err)
	}
	narrowID := dpuserspace.PolicyIDsByStableKey(c1)["trust->untrust/narrow"]
	for _, session := range []struct {
		id   uint64
		port uint16
	}{{7, 80}, {8, 22}} {
		r.dp.rows = append(r.dp.rows, dpuserspace.SessionPolicyMatch{
			AddrFamily: 4,
			Tuple: dpuserspace.SessionPolicyTuple{
				AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: uint16(2000 + session.id), DstPort: session.port,
			},
			PolicyID: narrowID, ExpectedRTFlowSessionID: session.id,
			IngressZoneID: config.StableZoneID("trust"),
			EgressZoneID:  config.StableZoneID("untrust"),
		})
		r.dp.ruleBySession[session.id] = "trust->untrust/narrow"
	}
	r.dp.deleteErrOnce = true
	_, gen, err := publishConfirmedRollbackText12072(t, r, c1, rulesConfigText12532("defperm12879-c2", "permit-all", []rule12532{
		{name: "p-first", app: "junos-telnet"},
	}))
	if err == nil {
		t.Fatal("C1->C2 failed candidate delete was not surfaced")
	}

	r.h.d.executeConfirmedRollback(gen)

	if r.h.d.store.ActiveConfig() != c0 || r.dp.applied != c0 {
		t.Fatalf("rollback authority: store=%p helper=%p, want C0 %p",
			r.h.d.store.ActiveConfig(), r.dp.applied, c0)
	}
	if !r.hasDeletedSession(7) || r.hasLiveSession(7) {
		t.Errorf("UNDER-DELETION #12879: tcp/80 session 7 was discharged by the default-policy permit instead of remaining narrow's debt: deleted=%v live=%v",
			r.hasDeletedSession(7), r.hasLiveSession(7))
	}
	if r.hasDeletedSession(8) || !r.hasLiveSession(8) {
		t.Errorf("OVER-DELETION: tcp/22 session 8 is permitted by its captured rule narrow, but was deleted")
	}
}

// variantSetConfigText12879 mirrors policySetConfigText12072's trust->untrust
// stanza but gives every rule a distinct built-in application (#12686
// variants), so a session captured under rule R is matched in the restored
// config by R itself instead of by whichever `application any` sibling the
// stanza walk hits first. Post-#12879 a discharge needs that identity agreement.
func variantSetConfigText12879(host string, names []string) string {
	return rulesConfigText12532(host, "deny-all", variantRules12686(names...))
}

// newLandedVariantRollbackRun12879 is newLandedRollbackRun12072 over
// variantSetConfigText12879, additionally stamping each seeded row's
// destination port to its recorded rule's application so the fixture's
// provenance and the restored config's first-match agree.
func newLandedVariantRollbackRun12879(t *testing.T) (*convergenceRun12072, *config.Config) {
	t.Helper()
	policies := []string{"p-first", "a", "b", "web"}
	r, _ := newConvergenceRun12072(t, policies)
	c0, err := r.h.d.store.SyncApply(variantSetConfigText12879("rollback-c0", policies), nil)
	if err != nil {
		t.Fatalf("promote C0: %v", err)
	}
	r.dp.applied, r.dp.helperCfg = c0, c0
	ids := dpuserspace.PolicyIDsByStableKey(c0)
	for i := range r.dp.rows {
		row := &r.dp.rows[i]
		rule := r.dp.ruleBySession[row.ExpectedRTFlowSessionID]
		row.PolicyID = ids[rule]
		row.IngressZoneID = config.StableZoneID("trust")
		row.EgressZoneID = config.StableZoneID("untrust")
		row.Tuple.DstPort = variantDestinationPort12686(rule)
	}
	r.h.d.store.MarkActiveApplied()
	return r, c0
}

// publishConfirmedVariantTarget12879 is publishConfirmedRollbackTarget12072
// over variantSetConfigText12879.
func publishConfirmedVariantTarget12879(
	t *testing.T, r *convergenceRun12072, c0 *config.Config, host string, policies []string,
) (*config.Config, uint64, error) {
	t.Helper()
	return publishConfirmedRollbackText12072(t, r, c0, variantSetConfigText12879(host, policies))
}

// publishLandedVariantConfig12879 is publishLandedRollbackConfig12072 over
// variantSetConfigText12879.
func publishLandedVariantConfig12879(
	t *testing.T, r *convergenceRun12072, old *config.Config, host string, policies []string,
) (*config.Config, error) {
	t.Helper()
	next, err := r.h.d.store.SyncApply(variantSetConfigText12879(host, policies), nil)
	if err != nil {
		t.Fatalf("promote %s: %v", host, err)
	}
	if err := r.h.d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	_, applyErr := r.h.d.applyAndSyncCommitted(old, next, peerSyncNever)
	r.h.d.applySem.Release(1)
	_, _ = r.h.sender.ApplyQueuedMessagesForTesting(r.h.receiver)
	return next, applyErr
}
