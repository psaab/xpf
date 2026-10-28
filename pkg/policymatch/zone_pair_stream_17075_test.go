package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17075 (R4-Q45-02) parity table: ONE config feeds Match (transit + host),
// the cross-tier shadow lint, ZoneDetailPolicySummary and a filtered view
// (ZonePairStreamForFilter, the stream every filtered policy view walks), and
// all four must agree on stanza order and quarantine marking. Authored in
// reverse tier order — both-any first, single-wildcard next, exact last —
// with a single-wildcard deny authored before a single-wildcard permit, so a
// passing test proves tier reordering plus config-order merge within tier 1.
func streamParityConfig17075(t *testing.T) *config.Config {
	t.Helper()
	pol := func(name string, action config.PolicyAction) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: action,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
		}
	}
	cfg := zoneQuarantineCfg(t) // zzq17760/zzq8100 collision; zzq8100 quarantined
	cfg.Security.Zones = zones("trust", "untrust", "dmz", "zzq17760", "zzq8100")
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{FromZone: "any", ToZone: "any", Policies: []*config.Policy{pol("both-any-permit", config.PolicyPermit)}},
		{FromZone: "trust", ToZone: "any", Policies: []*config.Policy{pol("to-any-deny", config.PolicyDeny)}},
		{FromZone: "any", ToZone: "untrust", Policies: []*config.Policy{pol("from-any-permit", config.PolicyPermit)}},
		{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{pol("exact-permit", config.PolicyPermit)}},
		{FromZone: "zzq8100", ToZone: "trust", Policies: []*config.Policy{pol("quarantined-pair", config.PolicyPermit)}},
		{FromZone: "trust", ToZone: JunosHostZone, Policies: []*config.Policy{pol("host-exact", config.PolicyPermit)}},
		{FromZone: "any", ToZone: JunosHostZone, Policies: []*config.Policy{pol("host-from-any", config.PolicyPermit)}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{
		{Name: "scoped-permit", Action: config.PolicyPermit, Match: config.PolicyMatch{
			SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"},
			FromZones: []string{"trust"}, ToZones: []string{"untrust"}}},
	}
	return cfg
}

func streamNames17075(refs []StanzaRef) []string {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.Policy.Name)
	}
	return names
}

func TestZonePairStreamParity17075(t *testing.T) {
	cfg := streamParityConfig17075(t)

	// 1. Stream order (transit): exact, single-wildcard in authored order
	// (to-any-deny before from-any-permit), both-any. Quarantined and host
	// stanzas never govern a transit pair.
	var transit []StanzaRef
	for ref := range ZonePairStream(ConfigZonePairStanzas(cfg), "trust", "untrust", StreamTransit) {
		transit = append(transit, ref)
	}
	wantTransit := []string{"exact-permit", "to-any-deny", "from-any-permit", "both-any-permit"}
	if got := streamNames17075(transit); strings.Join(got, ",") != strings.Join(wantTransit, ",") {
		t.Fatalf("transit stream order = %v, want %v", got, wantTransit)
	}
	wantTiers := []int{0, 1, 1, 2}
	for i, ref := range transit {
		if ref.Tier != wantTiers[i] {
			t.Fatalf("transit ref %d tier = %d, want %d", i, ref.Tier, wantTiers[i])
		}
	}

	// 2. Match (transit) follows the same order: exact permit wins for
	// trust->untrust; removing exact, the authored-first single-wildcard
	// deny wins over the later from-any permit.
	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	if !res.Matched || res.PolicyName != "exact-permit" {
		t.Fatalf("Match trust->untrust = %+v, want exact-permit", res)
	}
	cfgNoExact := streamParityConfig17075(t)
	cfgNoExact.Security.Policies = cfgNoExact.Security.Policies[:3] // both-any, to-any, from-any
	// keep host/global out of this sub-check's way irrelevant; transit only
	res = Match(cfgNoExact, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: PortPtr(80)})
	if !res.Matched || res.PolicyName != "to-any-deny" {
		t.Fatalf("Match without exact = %+v, want to-any-deny (authored-first wildcard)", res)
	}

	// 3. Host stream + Match host gate: exact host stanza before from-any;
	// transit to-any/both-any never pulled onto the host path.
	var host []StanzaRef
	for ref := range ZonePairStream(ConfigZonePairStanzas(cfg), "trust", JunosHostZone, StreamHost) {
		host = append(host, ref)
	}
	if got := streamNames17075(host); strings.Join(got, ",") != "host-exact,host-from-any" {
		t.Fatalf("host stream = %v, want [host-exact host-from-any]", got)
	}
	res = Match(cfg, Query{FromZone: "trust", ToZone: JunosHostZone, Protocol: "tcp", DstPort: PortPtr(22)})
	if !res.Matched || res.PolicyName != "host-exact" {
		t.Fatalf("Match host = %+v, want host-exact", res)
	}
	// Host query with to-zone any is a transit query, not a host query.
	// For a literal "any" query axis Match never runs (callers pass concrete
	// zones after the zoneKnown gates); at the stream level a trust->any
	// selection yields the to-any stanza (tier 1) and both-any (tier 2) —
	// crucially, no junos-host stanza is pulled in.
	var toAny []StanzaRef
	for ref := range ZonePairStream(ConfigZonePairStanzas(cfg), "trust", "any", StreamTransit) {
		toAny = append(toAny, ref)
	}
	if got := streamNames17075(toAny); strings.Join(got, ",") != "to-any-deny,both-any-permit" {
		t.Fatalf("transit trust->any stream = %v, want [to-any-deny both-any-permit]", got)
	}
	// 4. Shadow lint: the scoped global's entire scope is covered; first
	// coverer in stream order is exact-permit (same action) -> REDUNDANT
	// naming exact-permit, not the wildcard permit.
	joined := strings.Join(AnalyzePolicyShadowing(cfg), "\n")
	if !strings.Contains(joined, `"scoped-permit" is REDUNDANT`) || !strings.Contains(joined, `"exact-permit"`) {
		t.Fatalf("shadow lint must report scoped-permit REDUNDANT behind exact-permit, got:\n%s", joined)
	}

	// 5. Zone summary for trust: zone-pair lines in stream tier order
	// (exact, single-wildcard authored order, both-any), quarantined stanza
	// marked with the qualifier, host stanza excluded from a transit zone
	// view is NOT expected here (trust->junos-host names trust, so it
	// affects trust and appears as an exact row).
	lines := ZoneDetailPolicySummary(cfg, "trust", nil, false)
	var zp []string
	for _, ln := range lines {
		if strings.Contains(ln, "[zone-pair]") {
			zp = append(zp, ln)
		}
	}
	assertOrder := func(lines []string, names ...string) {
		t.Helper()
		idx := -1
		for _, n := range names {
			found := -1
			for i, ln := range lines {
				if strings.Contains(ln, n) {
					found = i
					break
				}
			}
			if found < 0 {
				t.Fatalf("line for %q missing in %v", n, lines)
			}
			if found < idx {
				t.Fatalf("order violated: %q at %d after %d in %v", n, found, idx, lines)
			}
			idx = found
		}
	}
	assertOrder(zp, "exact-permit", "to-any-deny", "both-any-permit")
	// quarantined-pair names trust on the to side: visible, scrub-marked.
	foundQuarantined := false
	for _, ln := range zp {
		if strings.Contains(ln, "quarantined-pair") {
			foundQuarantined = true
			if !strings.Contains(ln, config.ZoneQuarantinePoliciesQualifier) {
				t.Fatalf("quarantined stanza line lacks qualifier: %q", ln)
			}
		}
	}
	if !foundQuarantined {
		t.Fatalf("quarantined-pair line missing from trust summary: %v", zp)
	}

	// 6. Filtered view stream (the one all 8 views walk): same tier order
	// for trust->untrust, and the quarantined filter shows only its exact
	// authored stanza, marked.
	filter := NewZonePairPolicyFilter(cfg, "trust", "untrust")
	var view []StanzaRef
	for ref := range ZonePairStreamForFilter(ConfigZonePairStanzas(cfg), filter) {
		view = append(view, ref)
	}
	if got := streamNames17075(view); strings.Join(got, ",") != strings.Join(wantTransit, ",") {
		t.Fatalf("view stream order = %v, want %v", got, wantTransit)
	}
	qfilter := NewZonePairPolicyFilter(cfg, "zzq8100", "trust")
	var qview []StanzaRef
	for ref := range ZonePairStreamForFilter(ConfigZonePairStanzas(cfg), qfilter) {
		qview = append(qview, ref)
	}
	if got := streamNames17075(qview); strings.Join(got, ",") != "quarantined-pair" {
		t.Fatalf("quarantined view stream = %v, want [quarantined-pair]", got)
	}
	if len(qview) == 1 && !qview[0].Quarantined {
		t.Fatal("quarantined view ref must carry Quarantined=true")
	}
}

// TestZonePairStreamUnfilteredSinglePass17075 pins the historical passes==1
// behavior: an unfiltered view is ONE config-order pass with no tier
// reordering.
func TestZonePairStreamUnfilteredSinglePass17075(t *testing.T) {
	cfg := streamParityConfig17075(t)
	filter := NewZonePairPolicyFilter(cfg, "", "")
	var names []string
	for ref := range ZonePairStreamForFilter(ConfigZonePairStanzas(cfg), filter) {
		names = append(names, ref.Policy.Name)
	}
	want := "both-any-permit,to-any-deny,from-any-permit,exact-permit,quarantined-pair,host-exact,host-from-any"
	if strings.Join(names, ",") != want {
		t.Fatalf("unfiltered view = %v, want config order %s", names, want)
	}
}

// TestZonePairGroupedNilStanza17075 pins Rev18317 F1: a nil
// *config.ZonePairPolicies (the #16160 fixture shape: nil prepended) must
// not yield a phantom ""->"" stanza into grouped views, while an authored
// empty stanza keeps its header. SetIdx must stay aligned to the source
// slice index for surviving stanzas.
func TestZonePairGroupedNilStanza17075(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = zones("trust", "untrust")
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.Policies = []*config.ZonePairPolicies{
		nil,
		{FromZone: "trust", ToZone: "untrust", Policies: []*config.Policy{{Name: "exact-permit", Action: config.PolicyPermit, Match: config.PolicyMatch{SourceAddresses: []string{"any"}, DestinationAddresses: []string{"any"}, Applications: []string{"any"}}}}},
		{FromZone: "any", ToZone: "any"},
	}
	filter := NewZonePairPolicyFilter(cfg, "", "")
	var got []ZonePairStanza
	for st := range ZonePairStanzasOrdered(ConfigZonePairStanzas(cfg), filter) {
		got = append(got, st)
	}
	if len(got) != 2 {
		t.Fatalf("grouped stanzas = %+v, want 2 (nil skipped, authored empty retained)", got)
	}
	for _, st := range got {
		if st.From == "" && st.To == "" {
			t.Fatalf("phantom empty stanza yielded: %+v", got)
		}
	}
	if got[0].From != "trust" || got[0].To != "untrust" || got[0].SetIdx != 1 || len(got[0].Rules) != 1 {
		t.Fatalf("first stanza = %+v, want trust->untrust SetIdx=1 with 1 rule", got[0])
	}
	if got[1].From != "any" || got[1].To != "any" || got[1].SetIdx != 2 || len(got[1].Rules) != 0 {
		t.Fatalf("second stanza = %+v, want authored empty any->any SetIdx=2 with 0 rules (header retained)", got[1])
	}
}
