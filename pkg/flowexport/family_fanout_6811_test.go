package flowexport

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6811: a sampling instance carrying BOTH families cross-fanned each family's
// flows to the other family's collectors.
//
// The families are separate in config (`SamplingInstance.FamilyInet` /
// `FamilyInet6`, each with its own FlowServers), but
// collectInstanceVersionCollectors merged them into ONE collector slice and
// collapsed family to two per-INSTANCE booleans. `CollectorConfig` had no family
// field, grouping keyed on template alone, and `ServesFamily` was evaluated per
// instance — so with both families configured both booleans were true, the gate
// passed for either family, and the daemon fanned the record to EVERY group of
// that instance.
//
// Result: `family inet { flow-server A }` + `family inet6 { flow-server B }`
// sent IPv4 flows to BOTH A and B.
//
// Why it went unnoticed is worth recording: the strict validator explicitly
// PERMITS one instance holding both families, and the existing isolation tests
// (#2462) use family-DISJOINT instances while the template tests use a single
// family. No test configured the shape that breaks. These cells do.

// bothFamiliesInstance builds the shape the defect needs: one instance, one
// flow-server per family, distinct addresses so a cross-fan is visible.
func bothFamiliesInstance(v4Addr, v6Addr, tmpl string) *config.ForwardingOptionsConfig {
	return &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"both": {
					Name: "both",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: v4Addr, Port: 2055, Version9Template: tmpl, VersionIPFIXTemplate: tmpl},
						},
					},
					FamilyInet6: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: v6Addr, Port: 2055, Version9Template: tmpl, VersionIPFIXTemplate: tmpl},
						},
					},
				},
			},
		},
	}
}

// groupFor returns the single group serving isV6, failing if the collectors of
// the two families were not partitioned.
func groupFor(t *testing.T, groups []*ExportConfig, isV6 bool) *ExportConfig {
	t.Helper()
	var found *ExportConfig
	for _, g := range groups {
		if g.GroupIsV6 != isV6 {
			continue
		}
		if found != nil {
			t.Fatalf("more than one group for isV6=%v", isV6)
		}
		found = g
	}
	if found == nil {
		t.Fatalf("no group serves isV6=%v; the families were not partitioned", isV6)
	}
	return found
}

// TestMultiFamilyInstanceDoesNotCrossFanV9_6811 is the core cell. A single
// instance with one collector per family must produce one group per family, each
// holding ONLY its own family's collector.
//
// The addresses are distinct on purpose: asserting only "two groups exist" would
// pass against a split that put both collectors in both groups, and asserting
// only a count would not catch A and B landing in the wrong ones.
//
// FAIL-ON-REVERT: drop IsV6 from collectorGroupKey (grouping by template alone)
// and this REDS — one group holds both collectors, which is the cross-fan.
func TestMultiFamilyInstanceDoesNotCrossFanV9_6811(t *testing.T) {
	fo := bothFamiliesInstance("10.0.0.1", "2001:db8::9", "t")
	groups := ResolveV9TemplateGroups(v9Svc(), fo)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2 (one per address family). A single group holding "+
			"both families is the cross-fan: every export to it reaches both collectors (#6811)",
			len(groups))
	}

	v4 := groupFor(t, groups, false)
	if len(v4.Collectors) != 1 || v4.Collectors[0].Address != "10.0.0.1:2055" {
		t.Fatalf("inet group collectors = %+v, want exactly the inet collector 10.0.0.1:2055 — "+
			"an IPv6-only collector in the inet group receives IPv4 records", v4.Collectors)
	}
	v6 := groupFor(t, groups, true)
	if len(v6.Collectors) != 1 || v6.Collectors[0].Address != "[2001:db8::9]:2055" {
		t.Fatalf("inet6 group collectors = %+v, want exactly the inet6 collector "+
			"[2001:db8::9]:2055", v6.Collectors)
	}
}

// TestMultiFamilyInstanceDoesNotCrossFanIPFIX_6811 is the IPFIX half. Separate
// cell because ResolveIPFIXTemplateGroups is an independent resolver with its
// own grouping call — one cell covering only v9 would report IPFIX as guarded
// when it is not.
//
// FAIL-ON-REVERT: same mutation; both resolvers must key on family.
func TestMultiFamilyInstanceDoesNotCrossFanIPFIX_6811(t *testing.T) {
	fo := bothFamiliesInstance("10.0.0.1", "2001:db8::9", "t")
	groups := ResolveIPFIXTemplateGroups(ipfixSvc(), fo)
	if len(groups) != 2 {
		t.Fatalf("got %d IPFIX groups, want 2 (one per address family) (#6811)", len(groups))
	}
	v4 := groupFor(t, groups, false)
	if len(v4.Collectors) != 1 || v4.Collectors[0].Address != "10.0.0.1:2055" {
		t.Fatalf("IPFIX inet group collectors = %+v, want only the inet collector", v4.Collectors)
	}
	v6 := groupFor(t, groups, true)
	if len(v6.Collectors) != 1 || v6.Collectors[0].Address != "[2001:db8::9]:2055" {
		t.Fatalf("IPFIX inet6 group collectors = %+v, want only the inet6 collector", v6.Collectors)
	}
}

// TestInstanceFamilyFlagsStayInstanceWide_6811 pins the distinction the fix
// depends on and that a "simplification" would collapse.
//
// ServesInet/ServesInet6 stay per-INSTANCE (their #2462 meaning: does this
// instance serve this family at all) and gate the single sampling DECISION;
// GroupIsV6 is per-GROUP and gates which groups that decision fans out to.
// Collapsing the two would either re-open the cross-fan (if the per-group gate
// went away) or change the sampling denominator (if the instance-level gate
// did): a record of a family the instance does not serve must not consume a
// 1-in-N slot.
//
// FAIL-ON-REVERT: set ServesInet/ServesInet6 from the GROUP's collectors instead
// of the instance aggregate and this REDS.
func TestInstanceFamilyFlagsStayInstanceWide_6811(t *testing.T) {
	fo := bothFamiliesInstance("10.0.0.1", "2001:db8::9", "t")
	groups := ResolveV9TemplateGroups(v9Svc(), fo)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}
	for _, g := range groups {
		if !g.ServesInet || !g.ServesInet6 {
			t.Errorf("group (template=%q isV6=%v) has ServesInet=%v ServesInet6=%v; both must "+
				"stay TRUE because the INSTANCE serves both families. These flags gate the "+
				"per-instance sampling decision, not the per-group fan-out — narrowing them "+
				"to the group would make a record of the other family skip SampledForOpen and "+
				"change the 1-in-N denominator (#6811/#2462)",
				g.TemplateName, g.GroupIsV6, g.ServesInet, g.ServesInet6)
		}
	}
}

// TestSingleFamilyInstanceUnchanged_6811 is the control: the family-disjoint
// shape #2462 already covers must behave exactly as before — one group, one
// collector, and the instance flags narrowed to the configured family.
//
// Without it, a "partition everything" change that split single-family groups or
// broke the #2462 attribution would pass every cell above. A control that only
// counted groups would not catch ServesInet6 wrongly becoming true.
func TestSingleFamilyInstanceUnchanged_6811(t *testing.T) {
	fo := &config.ForwardingOptionsConfig{
		Sampling: &config.SamplingConfig{
			Instances: map[string]*config.SamplingInstance{
				"v4only": {
					Name: "v4only",
					FamilyInet: &config.SamplingFamily{
						FlowServers: []*config.FlowServer{
							{Address: "10.0.0.1", Port: 2055, Version9Template: "t"},
						},
					},
				},
			},
		},
	}
	groups := ResolveV9TemplateGroups(v9Svc(), fo)
	if len(groups) != 1 {
		t.Fatalf("single-family instance produced %d groups, want 1 — the family partition "+
			"must not split a group that only ever had one family", len(groups))
	}
	g := groups[0]
	if g.GroupIsV6 {
		t.Error("inet-only group reports GroupIsV6=true")
	}
	if !g.ServesInet || g.ServesInet6 {
		t.Errorf("inet-only instance: ServesInet=%v ServesInet6=%v, want true/false — the "+
			"#2462 attribution must still narrow an instance to its configured family",
			g.ServesInet, g.ServesInet6)
	}
	if len(g.Collectors) != 1 {
		t.Errorf("got %d collectors, want 1", len(g.Collectors))
	}
}

// TestSameCollectorUnderBothFamiliesKeepsBoth_6811 pins the dedup-key change.
//
// An operator may point BOTH families at one collector address. Family is part
// of a collector's identity, so those are two destinations-with-family, not one
// duplicate — collapsing them would silently drop one family's export to a
// collector explicitly configured for both.
//
// FAIL-ON-REVERT: remove the family component from collectorKey and this REDS —
// dedupeCollectors keeps one entry and one family stops being exported.
func TestSameCollectorUnderBothFamiliesKeepsBoth_6811(t *testing.T) {
	fo := bothFamiliesInstance("10.0.0.1", "10.0.0.1", "t")
	groups := ResolveV9TemplateGroups(v9Svc(), fo)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2: the same address under both families is two "+
			"destinations-with-family, not one duplicate (#6811)", len(groups))
	}
	v4 := groupFor(t, groups, false)
	v6 := groupFor(t, groups, true)
	if len(v4.Collectors) != 1 || len(v6.Collectors) != 1 {
		t.Fatalf("inet=%d inet6=%d collectors, want 1 each — a family was deduped away",
			len(v4.Collectors), len(v6.Collectors))
	}
}
