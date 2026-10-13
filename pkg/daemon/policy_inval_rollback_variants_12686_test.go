package daemon

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/policymatch"
)

// wildcardZoneConfigText12686 renders a nonmatching exact p-first policy plus
// policies distinguished by their built-in application tuples.
func wildcardZoneConfigText12686(host string, names []string, from, to string) string {
	var stanza string
	hasZoneMismatch := false
	for _, name := range names {
		if name == "p-first" {
			continue
		}
		if name == "zone-mismatch" {
			hasZoneMismatch = true
			continue
		}
		stanza += `
            policy ` + name + ` {
                match { source-address any; destination-address any; application ` + variantApplication12686(name) + `; }
                then { permit; }
            }`
	}
	var mismatchApp, mismatchPolicy string
	if hasZoneMismatch {
		mismatchApp = `
    applications {
        application mismatch-app {
            protocol udp;
            destination-port 5353;
        }
    }`
		mismatchPolicy = `
        from-zone trust to-zone any {
            policy zone-mismatch {
                match { source-address any; destination-address any; application mismatch-app; }
                then { permit; }
            }
        }`
	}
	return `system { host-name ` + host + `; }
` + mismatchApp + `
security {
    zones { security-zone trust; security-zone untrust; security-zone other; }
    policies {
        from-zone trust to-zone untrust {
            policy p-first {
                match { source-address any; destination-address any; application junos-ftp; }
                then { permit; }
            }
        }
        from-zone ` + from + ` to-zone ` + to + ` {` + stanza + `
        }` + mismatchPolicy + `
    }
}`
}

func variantApplication12686(name string) string {
	name = name[strings.LastIndex(name, "/")+1:]
	switch name {
	case "p-first":
		return "junos-ftp"
	case "a":
		return "junos-ssh"
	case "b":
		return "junos-http"
	case "web":
		return "junos-https"
	case "x":
		return "junos-telnet"
	default:
		panic("unknown #12686 test policy " + name)
	}
}

func variantDestinationPort12686(name string) uint16 {
	name = name[strings.LastIndex(name, "/")+1:]
	switch name {
	case "p-first":
		return 21
	case "a":
		return 22
	case "b":
		return 80
	case "web":
		return 443
	case "x":
		return 23
	default:
		panic("unknown #12686 test policy " + name)
	}
}

func variantRules12686(names ...string) []rule12532 {
	rules := make([]rule12532, 0, len(names))
	for _, name := range names {
		rules = append(rules, rule12532{name: name, app: variantApplication12686(name)})
	}
	return rules
}

func assertVariantRuleMatch12686(
	t *testing.T, cfg *config.Config, name, from, to string, srcPort uint16, ruleZones string,
) {
	t.Helper()
	result := policymatch.Match(cfg, policymatch.Query{
		FromZone: from, ToZone: to,
		SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
		Protocol: "tcp", SrcPort: int(srcPort), DstPort: int(variantDestinationPort12686(name)),
		SrcFamily: "v4", DstFamily: "v4",
	})
	want := ruleZones + "/" + name
	if !result.Matched || result.RuleID != want {
		t.Fatalf("fixture tuple for %s matched %q (matched=%v), want %q", name, result.RuleID, result.Matched, want)
	}
}

func anyZoneConfigText12686(host string, names []string) string {
	return wildcardZoneConfigText12686(host, names, "any", "untrust")
}

func promoteParsedC012686(t *testing.T, r *convergenceRun12072, text string, ruleKeys map[uint64]string) *config.Config {
	t.Helper()
	c0, err := r.h.d.store.SyncApply(text, nil)
	if err != nil {
		t.Fatalf("promote C0: %v", err)
	}
	r.dp.applied, r.dp.helperCfg = c0, c0
	policyIDs := dpuserspace.PolicyIDsByStableKey(c0)
	for i := range r.dp.rows {
		row := &r.dp.rows[i]
		if key, ok := ruleKeys[row.ExpectedRTFlowSessionID]; ok {
			r.dp.ruleBySession[row.ExpectedRTFlowSessionID] = key
			row.PolicyID = policyIDs[key]
		}
		row.IngressZoneID = config.StableZoneID("trust")
		row.EgressZoneID = config.StableZoneID("untrust")
		if key := ruleKeys[row.ExpectedRTFlowSessionID]; key != "" {
			row.Tuple.DstPort = variantDestinationPort12686(key)
		}
	}
	r.h.d.store.MarkActiveApplied()
	return c0
}

func addSession12686(r *convergenceRun12072, id uint64, ruleKey string, cfg *config.Config, srcPort uint16) {
	r.dp.rows = append(r.dp.rows, dpuserspace.SessionPolicyMatch{
		AddrFamily: 4,
		Tuple: dpuserspace.SessionPolicyTuple{
			AddrFamily: 4, Protocol: 6, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: srcPort, DstPort: variantDestinationPort12686(ruleKey),
		},
		PolicyID:                dpuserspace.PolicyIDsByStableKey(cfg)[ruleKey],
		ExpectedRTFlowSessionID: id,
		IngressZoneID:           config.StableZoneID("trust"),
		EgressZoneID:            config.StableZoneID("untrust"),
	})
	r.dp.ruleBySession[id] = ruleKey
}

func addConcreteZoneMismatchSession12686(r *convergenceRun12072, id uint64, cfg *config.Config) {
	ruleKey := "trust->any/zone-mismatch"
	r.dp.rows = append(r.dp.rows, dpuserspace.SessionPolicyMatch{
		AddrFamily: 4,
		Tuple: dpuserspace.SessionPolicyTuple{
			AddrFamily: 4, Protocol: 17, SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 2001, DstPort: 5353,
		},
		PolicyID:                dpuserspace.PolicyIDsByStableKey(cfg)[ruleKey],
		ExpectedRTFlowSessionID: id,
		IngressZoneID:           config.StableZoneID("other"),
		EgressZoneID:            config.StableZoneID("untrust"),
	})
	r.dp.ruleBySession[id] = ruleKey
}

func TestRemoveReauthorizedCandidatesKeepsRecycledSessionID12686(t *testing.T) {
	match := func(srcIP string) dpuserspace.SessionPolicyMatch {
		return dpuserspace.SessionPolicyMatch{
			AddrFamily: 4,
			Tuple: dpuserspace.SessionPolicyTuple{
				AddrFamily: 4, Protocol: 6, SrcIP: srcIP, DstIP: "10.0.0.2",
				SrcPort: 1001, DstPort: 80, RoutingDomain: 7,
			},
			RoutingDomain: 7, ExpectedRTFlowSessionID: 42,
		}
	}
	permittedMatch := match("10.0.0.1")
	freshMatch := match("10.0.0.3")
	permittedEntry, _, err := policyMatchEntries(permittedMatch)
	if err != nil {
		t.Fatal(err)
	}
	freshEntry, _, err := policyMatchEntries(freshMatch)
	if err != nil {
		t.Fatal(err)
	}
	capture := &policyInvalidationCapture{
		deleted: capturedSessions{
			policy: []dpuserspace.SessionPolicyMatch{freshMatch},
			v4:     []dataplane.SessionEntryV4{*freshEntry},
		},
	}
	permitted := &policyInvalidationCapture{
		deflt: capturedSessions{
			policy: []dpuserspace.SessionPolicyMatch{permittedMatch},
			v4:     []dataplane.SessionEntryV4{*permittedEntry},
		},
	}
	removeReauthorizedPolicyCandidates(capture, permitted)
	if len(capture.deleted.policy) != 1 || len(capture.deleted.v4) != 1 ||
		policyInvalidationMatchID(capture.deleted.policy[0]) != policyInvalidationMatchID(freshMatch) {
		t.Fatalf("fresh tuple reusing RT_FLOW session ID was removed with permitted tuple: %+v", capture.deleted)
	}
}

// #12686 P4: rules under from-zone any. C0 permits a/b/web under any->untrust;
// C1 removes a, C2 removes b (deletes fail, debt retained). Timer rollback
// to C0 must preserve those sessions and delete session 99 (rule x absent from
// C0) plus session 100, whose trust->any provenance conflicts with its
// concrete other->untrust zones.
func TestPolicyInvalidationRollbackAnyZone12686(t *testing.T) {
	r, _ := newConvergenceRun12072(t, []string{"p-first", "a", "b", "web"})
	c0 := promoteParsedC012686(t, r, anyZoneConfigText12686("any12686-c0", []string{"p-first", "a", "b", "web", "zone-mismatch"}),
		map[uint64]string{1: "any->untrust/a", 2: "any->untrust/b", 3: "any->untrust/web"})

	for i, name := range []string{"a", "b", "web"} {
		assertVariantRuleMatch12686(t, c0, name, "trust", "untrust", uint16(1001+i), "any->untrust")
	}
	r.dp.deleteErrOnce = true
	c1, _, err := publishConfirmedRollbackText12072(t, r, c0,
		anyZoneConfigText12686("any12686-c1", []string{"p-first", "b", "web", "x", "zone-mismatch"}))
	if err == nil {
		t.Fatal("C0->C1 failed candidate delete was not surfaced")
	}
	addSession12686(r, 99, "any->untrust/x", c1, 1099)
	addConcreteZoneMismatchSession12686(r, 100, c1)
	mismatch := policymatch.Match(c0, policymatch.Query{
		FromZone: "other", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
		Protocol: "udp", SrcPort: 2001, DstPort: 5353,
		SrcFamily: "v4", DstFamily: "v4",
	})
	if mismatch.Action == config.PolicyPermit {
		t.Fatal("zone-mismatch fixture unexpectedly matches the restored trust->any permit")
	}
	assertVariantRuleMatch12686(t, c1, "x", "trust", "untrust", 1099, "any->untrust")
	r.dp.deleteErrOnce = true
	_, gen, err := publishConfirmedRollbackText12072(t, r, c1,
		anyZoneConfigText12686("any12686-c2", []string{"p-first", "web"}))
	if err == nil {
		t.Fatal("C1->C2 failed candidate delete was not surfaced")
	}

	r.h.d.executeConfirmedRollback(gen)

	if r.h.d.store.ActiveConfig() != c0 || r.dp.applied != c0 {
		t.Fatalf("rollback authority: store=%p helper=%p, want C0 %p",
			r.h.d.store.ActiveConfig(), r.dp.applied, c0)
	}
	for _, id := range []uint64{1, 2, 3} {
		if r.hasDeletedSession(id) || !r.hasLiveSession(id) {
			t.Fatalf("OVER-DELETION P4: rollback to C0 deleted any-zone permitted session %d", id)
		}
	}
	if !r.hasDeletedSession(99) || r.hasLiveSession(99) {
		t.Fatalf("UNDER-DELETION P4: session 99's rule x is absent from C0 but it survived")
	}
	if !r.hasDeletedSession(100) || r.hasLiveSession(100) {
		t.Fatal("UNDER-DELETION P4: candidate with trust->any provenance but other->untrust zones survived")
	}
}

// #12686 P9: last confirmed target C2 never published (helper rejects it).
// Debt's newCfg (C2) never landed, so rollback takes the carry branch, not
// the landed branch. Rollback to C0 must still re-authorize: sessions 1/2
// (C0 permits a/b) survive; session 99 (x absent from C0) is deleted.
func TestPolicyInvalidationRollbackRejectedPublish12686(t *testing.T) {
	r, _ := newConvergenceRun12072(t, []string{"p-first", "a", "b", "web"})
	c0 := promoteParsedC012686(t, r,
		rulesConfigText12532("rejected12686-c0", "deny-all", variantRules12686("p-first", "a", "b", "web")),
		map[uint64]string{1: "trust->untrust/a", 2: "trust->untrust/b", 3: "trust->untrust/web"})
	for i, name := range []string{"a", "b", "web"} {
		assertVariantRuleMatch12686(t, c0, name, "trust", "untrust", uint16(1001+i), "trust->untrust")
	}

	r.dp.deleteErrOnce = true
	c1, _, err := publishConfirmedRollbackText12072(t, r, c0,
		rulesConfigText12532("rejected12686-c1", "deny-all", variantRules12686("p-first", "b", "web", "x")))
	if err == nil {
		t.Fatal("C0->C1 failed candidate delete was not surfaced")
	}
	addSession12686(r, 99, "trust->untrust/x", c1, 1099)
	assertVariantRuleMatch12686(t, c1, "x", "trust", "untrust", 1099, "trust->untrust")

	// C2 removes b and x but its publish is definitively rejected.
	r.dp.script = make([]invalDebtOutcome12073, r.dp.applyCalls+1)
	r.dp.script[r.dp.applyCalls] = invalDebtOutcome12073{
		err: errors.New("apply_snapshot rejected by helper (definite)"),
	}
	c2, gen, applyErr := publishConfirmedRollbackText12072(t, r, c1,
		rulesConfigText12532("rejected12686-c2", "deny-all", variantRules12686("p-first", "web")))
	if applyErr == nil {
		t.Fatal("rejected C2 publish was not surfaced")
	}
	if r.dp.applied != c1 || r.h.d.store.ActiveConfig() != c2 {
		t.Fatalf("premise: rejected publish authority helper=%p (want C1 %p) store=%p (want C2 %p)",
			r.dp.applied, c1, r.h.d.store.ActiveConfig(), c2)
	}
	for _, id := range []uint64{1, 2, 3, 99} {
		if !r.hasLiveSession(id) || r.hasDeletedSession(id) {
			t.Fatalf("premise: session %d was not live immediately before rollback", id)
		}
	}

	r.h.d.executeConfirmedRollback(gen)
	if r.h.d.store.ActiveConfig() != c0 || r.dp.applied != c0 {
		t.Fatalf("rollback authority: store=%p helper=%p, want C0 %p",
			r.h.d.store.ActiveConfig(), r.dp.applied, c0)
	}
	for _, id := range []uint64{1, 2, 3} {
		if r.hasDeletedSession(id) || !r.hasLiveSession(id) {
			t.Fatalf("OVER-DELETION P9: rollback to C0 deleted permitted session %d", id)
		}
	}
	if !r.hasDeletedSession(99) || r.hasLiveSession(99) {
		t.Fatalf("UNDER-DELETION P9: session 99's rule x is absent from C0 but it survived")
	}
}

func TestPolicyInvalidationRollbackToAnyZone12686(t *testing.T) {
	for _, zones := range []struct {
		name, from, to string
	}{
		{name: "to-any", from: "trust", to: "any"},
		{name: "both-any", from: "any", to: "any"},
	} {
		t.Run(zones.name, func(t *testing.T) {
			r, _ := newConvergenceRun12072(t, []string{"p-first", "a", "b", "web"})
			prefix := zones.from + "->" + zones.to + "/"
			c0 := promoteParsedC012686(t, r,
				wildcardZoneConfigText12686("toany12686-c0",
					[]string{"p-first", "a", "b", "web"}, zones.from, zones.to),
				map[uint64]string{1: prefix + "a", 2: prefix + "b", 3: prefix + "web"})
			for i, name := range []string{"a", "b", "web"} {
				assertVariantRuleMatch12686(t, c0, name, "trust", "untrust", uint16(1001+i), strings.TrimSuffix(prefix, "/"))
			}
			r.dp.deleteErrOnce = true
			c1, _, err := publishConfirmedRollbackText12072(t, r, c0,
				wildcardZoneConfigText12686("toany12686-c1",
					[]string{"p-first", "b", "web"}, zones.from, zones.to))
			if err == nil {
				t.Fatal("C0->C1 failed candidate delete was not surfaced")
			}
			r.dp.deleteErrOnce = true
			_, gen, err := publishConfirmedRollbackText12072(t, r, c1,
				wildcardZoneConfigText12686("toany12686-c2",
					[]string{"p-first", "web"}, zones.from, zones.to))
			if err == nil {
				t.Fatal("C1->C2 failed candidate delete was not surfaced")
			}
			r.h.d.executeConfirmedRollback(gen)
			for _, id := range []uint64{1, 2, 3} {
				if r.hasDeletedSession(id) || !r.hasLiveSession(id) {
					t.Errorf("OVER-DELETION: rollback to C0 deleted wildcard-permitted session %d", id)
				}
			}
		})
	}
}

// #12686 P7: C0 permits a/b with default deny; C1 removes a; C2 changes
// default to permit while retaining b. The rollback's fresh default-policy
// capture sees the orphaned session 1, which C0 still permits through a.
func TestPolicyInvalidationRollbackDefaultPolicyChange12686(t *testing.T) {
	r, _ := newConvergenceRun12072(t, []string{"p-first", "a", "b", "web"})
	c0 := promoteParsedC012686(t, r,
		rulesConfigText12532("def12686-c0", "deny-all", variantRules12686("p-first", "a", "b", "web")),
		map[uint64]string{1: "trust->untrust/a", 2: "trust->untrust/b", 3: "trust->untrust/web"})
	for i, name := range []string{"a", "b", "web"} {
		assertVariantRuleMatch12686(t, c0, name, "trust", "untrust", uint16(1001+i), "trust->untrust")
	}

	r.dp.deleteErrOnce = true
	c1, _, err := publishConfirmedRollbackText12072(t, r, c0,
		rulesConfigText12532("def12686-c1", "deny-all", variantRules12686("p-first", "b", "web", "x")))
	if err == nil {
		t.Fatal("C0->C1 failed candidate delete was not surfaced")
	}
	addSession12686(r, 99, "trust->untrust/x", c1, 1099)
	assertVariantRuleMatch12686(t, c1, "x", "trust", "untrust", 1099, "trust->untrust")
	r.dp.deleteErrOnce = true
	_, gen, err := publishConfirmedRollbackText12072(t, r, c1,
		rulesConfigText12532("def12686-c2", "permit-all", variantRules12686("p-first", "b", "web", "x")))
	if err == nil {
		t.Fatal("C1->C2 failed default-policy candidate delete was not surfaced")
	}
	for _, id := range []uint64{1, 2, 3, 99} {
		if !r.hasLiveSession(id) || r.hasDeletedSession(id) {
			t.Fatalf("premise: session %d was not live before rollback", id)
		}
	}
	r.h.d.executeConfirmedRollback(gen)

	if r.h.d.store.ActiveConfig() != c0 || r.dp.applied != c0 {
		t.Fatalf("rollback authority: store=%p helper=%p, want C0 %p",
			r.h.d.store.ActiveConfig(), r.dp.applied, c0)
	}
	for _, id := range []uint64{1, 2, 3} {
		if r.hasDeletedSession(id) || !r.hasLiveSession(id) {
			t.Fatalf("OVER-DELETION P7: rollback to C0 deleted permitted session %d", id)
		}
	}
	if !r.hasDeletedSession(99) || r.hasLiveSession(99) {
		t.Fatalf("UNDER-DELETION P7: root-denied x session survived rollback")
	}
	if r.h.d.policyInvalidationDebt != nil || !r.h.d.store.ActiveApplied() {
		t.Fatalf("rollback to C0 did not converge: debt=%+v ActiveApplied=%v",
			r.h.d.policyInvalidationDebt, r.h.d.store.ActiveApplied())
	}
}

func TestPolicyInvalidationRollbackDefaultPolicyRejectedRetry12686(t *testing.T) {
	r, _ := newConvergenceRun12072(t, []string{"p-first", "a", "b", "web"})
	c0 := promoteParsedC012686(t, r,
		rulesConfigText12532("defretry12686-c0", "deny-all", variantRules12686("p-first", "a", "b", "web")),
		map[uint64]string{1: "trust->untrust/a", 2: "trust->untrust/b", 3: "trust->untrust/web"})
	r.dp.deleteErrOnce = true
	c1, _, err := publishConfirmedRollbackText12072(t, r, c0,
		rulesConfigText12532("defretry12686-c1", "deny-all", variantRules12686("p-first", "b", "web", "x")))
	if err == nil {
		t.Fatal("C0->C1 failed candidate delete was not surfaced")
	}
	addSession12686(r, 99, "trust->untrust/x", c1, 1099)
	r.dp.deleteErrOnce = true
	c2, gen, err := publishConfirmedRollbackText12072(t, r, c1,
		rulesConfigText12532("defretry12686-c2", "permit-all", variantRules12686("p-first", "b", "web", "x")))
	if err == nil {
		t.Fatal("C1->C2 failed default-policy candidate delete was not surfaced")
	}
	r.dp.script = make([]invalDebtOutcome12073, r.dp.applyCalls+1)
	r.dp.script[r.dp.applyCalls] = invalDebtOutcome12073{
		err: errors.New("rollback apply rejected by helper"),
	}
	r.h.d.executeConfirmedRollback(gen)
	if r.dp.applied != c2 || r.h.d.store.ActiveConfig() != c0 {
		t.Fatalf("premise: rejected rollback authority helper=%p (C2 %p), store=%p (C0 %p)",
			r.dp.applied, c2, r.h.d.store.ActiveConfig(), c0)
	}
	if !r.hasLiveSession(1) || !r.hasLiveSession(99) {
		t.Fatal("rejected rollback changed retained sessions")
	}

	if err := r.h.d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	err = r.h.d.applyConfigLocked(context.Background(), c0)
	r.h.d.applySem.Release(1)
	if err != nil {
		t.Fatalf("same-target rollback retry: %v", err)
	}
	if r.dp.applied != c0 {
		t.Fatalf("helper authority after retry=%p, want C0 %p", r.dp.applied, c0)
	}
	for _, id := range []uint64{1, 2, 3} {
		if r.hasDeletedSession(id) || !r.hasLiveSession(id) {
			t.Errorf("OVER-DELETION after rollback retry: root-permitted session %d was deleted", id)
		}
	}
	if !r.hasDeletedSession(99) || r.hasLiveSession(99) {
		t.Error("UNDER-DELETION after rollback retry: root-denied x survived")
	}
}
