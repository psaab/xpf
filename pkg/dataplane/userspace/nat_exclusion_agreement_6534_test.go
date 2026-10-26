package userspace

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/natshow"
)

// #6534 builder/renderer AGREEMENT for the NAT fail-closed snapshot exclusions.
//
// The defect: every fail-closed exclusion in this package has a show surface
// that renders the excluded object straight from config, so an operator reads a
// rule that the dataplane is not enforcing and concludes it is.
//
// Testing the renderer alone would not close it. A renderer test pins the
// annotation to whatever the renderer currently believes; if the BUILDER's drop
// condition later moves, the renderer keeps printing its stale opinion and the
// renderer test stays green while the surface resumes lying. So these cases
// drive BOTH halves over the SAME config and assert they reach the same verdict
// — that is the property, and it is what the shared pkg/config predicates
// exist to guarantee.
//
// Reachability: these configs are only constructible through
// CompileConfigLenient. The strict commit gates reject every one of them, so
// the lenient Store.Load / Store.SyncApply path (opts.lenientFirewallRefs,
// #1960 no-brick) is the ONLY way an operator's box holds one — which is
// exactly the state in which they go reading show output.

// natExclusionCase is one config plus the verdict both halves must reach.
type natExclusionCase struct {
	name string
	// site names the builder location under test, so a failure says WHICH of
	// the four exclusion sites diverged rather than just "NAT disagreed".
	site string
	cmds []string
	// rule is the rule name whose disposition is under test.
	rule string
	// wantExcluded is the ground truth: does the dataplane install this rule?
	wantExcluded bool
}

// builderExcluded asks the SNAPSHOT BUILDER whether the named rule reached the
// dataplane. Each family answers differently on purpose: source NAT ships the
// rule with a PoolUnusable marker the Rust side honors, while the other three
// omit the rule from the published collection entirely.
func builderExcluded(t *testing.T, c natExclusionCase, cfg *config.Config) bool {
	t.Helper()
	switch c.site {
	case "buildSourceNATSnapshots":
		for _, s := range buildSourceNATSnapshots(cfg, nil) {
			if s.Name == c.rule {
				return s.PoolUnusable
			}
		}
		t.Fatalf("%s: rule %q absent from the source-NAT snapshot entirely; "+
			"the fixture does not build the rule it claims to test", c.site, c.rule)
	case "buildStaticNATSnapshots":
		for _, s := range buildStaticNATSnapshots(cfg, nil) {
			if s.Name == c.rule {
				return false
			}
		}
		return true
	case "buildDestinationNATSnapshots":
		for _, s := range buildDestinationNATSnapshots(cfg, nil) {
			if s.Name == c.rule {
				return false
			}
		}
		return true
	case "buildNptv6Snapshots":
		for _, s := range buildNptv6Snapshots(cfg) {
			if s.Name == c.rule {
				return false
			}
		}
		return true
	}
	t.Fatalf("unknown builder site %q", c.site)
	return false
}

// rendererExcluded asks the SHOW SURFACE the same question, by rendering every
// NAT topic that can display the rule and looking for the #6534 annotation.
// A nil dataplane Reader reproduces the "not loaded" path, which is what an
// operator sees while the helper is down — the case where a lying surface is
// most likely to be consulted.
func rendererExcluded(t *testing.T, cfg *config.Config) bool {
	t.Helper()
	var buf bytes.Buffer
	natshow.RenderSourceRuleDetail(context.Background(), &buf, cfg, nil, nil)
	natshow.RenderDestRuleDetail(context.Background(), &buf, cfg, nil, nil)
	natshow.RenderStatic(&buf, cfg)
	natshow.RenderStaticRule(&buf, cfg, true)
	natshow.RenderStaticRule(&buf, cfg, false)
	natshow.RenderNPTv6(&buf, cfg)
	return strings.Contains(buf.String(), "NOT INSTALLED")
}

func natExclusionCases() []natExclusionCase {
	return []natExclusionCase{
		// --- source NAT: pool disarm (#6812 / #5457 / #5875) ---
		{
			name: "snat_healthy_pool_installs",
			site: "buildSourceNATSnapshots",
			cmds: []string{
				"set security nat source pool p1 address 203.0.113.10/32",
				"set security nat source rule-set rs1 from zone trust",
				"set security nat source rule-set rs1 to zone untrust",
				"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/24",
				"set security nat source rule-set rs1 rule r1 then source-nat pool p1",
			},
			rule:         "r1",
			wantExcluded: false,
		},
		{
			name: "snat_undefined_pool_is_disarmed",
			site: "buildSourceNATSnapshots",
			cmds: []string{
				"set security nat source rule-set rs1 from zone trust",
				"set security nat source rule-set rs1 to zone untrust",
				"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/24",
				"set security nat source rule-set rs1 rule r1 then source-nat pool nope",
			},
			rule:         "r1",
			wantExcluded: true,
		},
		{
			name: "snat_invalid_pool_port_range_is_disarmed",
			site: "buildSourceNATSnapshots",
			cmds: []string{
				"set security nat source pool p1 address 203.0.113.10/32",
				"set security nat source pool p1 port range 9000 1000",
				"set security nat source rule-set rs1 from zone trust",
				"set security nat source rule-set rs1 to zone untrust",
				"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/24",
				"set security nat source rule-set rs1 rule r1 then source-nat pool p1",
			},
			rule:         "r1",
			wantExcluded: true,
		},
		// --- static NAT: #5859 inet target, #5101 port range ---
		{
			name: "static_healthy_rule_installs",
			site: "buildStaticNATSnapshots",
			cmds: []string{
				"set security nat static rule-set srs from zone untrust",
				"set security nat static rule-set srs rule s1 match destination-address 203.0.113.5/32",
				"set security nat static rule-set srs rule s1 then static-nat prefix 10.0.0.5/32",
			},
			rule:         "s1",
			wantExcluded: false,
		},
		{
			name: "static_inet_nat64_target_is_dropped",
			site: "buildStaticNATSnapshots",
			cmds: []string{
				"set security nat static rule-set srs from zone untrust",
				"set security nat static rule-set srs rule s1 match destination-address 2001:db8::5/128",
				"set security nat static rule-set srs rule s1 then static-nat inet",
			},
			rule:         "s1",
			wantExcluded: true,
		},
		// --- destination NAT: #3450 pool shape ---
		{
			name: "dnat_healthy_rule_installs",
			site: "buildDestinationNATSnapshots",
			cmds: []string{
				"set security nat destination pool dp1 address 10.0.0.9/32",
				"set security nat destination rule-set drs from zone untrust",
				"set security nat destination rule-set drs rule d1 match destination-address 203.0.113.9/32",
				"set security nat destination rule-set drs rule d1 then destination-nat pool dp1",
			},
			rule:         "d1",
			wantExcluded: false,
		},
		{
			name: "dnat_non_host_pool_address_is_dropped",
			site: "buildDestinationNATSnapshots",
			cmds: []string{
				"set security nat destination pool dp1 address 10.0.0.0/24",
				"set security nat destination rule-set drs from zone untrust",
				"set security nat destination rule-set drs rule d1 match destination-address 203.0.113.9/32",
				"set security nat destination rule-set drs rule d1 then destination-nat pool dp1",
			},
			rule:         "d1",
			wantExcluded: true,
		},
		{
			name: "dnat_undefined_pool_is_dropped",
			site: "buildDestinationNATSnapshots",
			cmds: []string{
				"set security nat destination rule-set drs from zone untrust",
				"set security nat destination rule-set drs rule d1 match destination-address 203.0.113.9/32",
				"set security nat destination rule-set drs rule d1 then destination-nat pool nope",
			},
			rule:         "d1",
			wantExcluded: true,
		},
		{
			name: "dnat_protocol_less_only_uses_never_match_row",
			site: "buildDestinationNATSnapshots",
			cmds: []string{
				"set applications application NOPROTO destination-port 80",
				"set security nat destination pool dp1 address 10.0.0.9/32",
				"set security nat destination rule-set drs from zone untrust",
				"set security nat destination rule-set drs rule d1 match destination-address 203.0.113.9/32",
				"set security nat destination rule-set drs rule d1 match application NOPROTO",
				"set security nat destination rule-set drs rule d1 then destination-nat pool dp1",
			},
			rule:         "d1",
			wantExcluded: false,
		},
		// --- NPTv6: #5818 scope widening ---
		{
			name: "nptv6_healthy_rule_installs",
			site: "buildNptv6Snapshots",
			cmds: []string{
				"set security nat static rule-set nrs from zone untrust",
				"set security nat static rule-set nrs rule n1 match destination-address 2602:fd41:70::/48",
				"set security nat static rule-set nrs rule n1 then static-nat nptv6-prefix fd35:1940:27::/48",
			},
			rule:         "n1",
			wantExcluded: false,
		},
		{
			name: "nptv6_source_address_scope_is_dropped",
			site: "buildNptv6Snapshots",
			cmds: []string{
				"set security nat static rule-set nrs from zone untrust",
				"set security nat static rule-set nrs rule n1 match destination-address 2602:fd41:70::/48",
				"set security nat static rule-set nrs rule n1 match source-address 2001:db8::/64",
				"set security nat static rule-set nrs rule n1 then static-nat nptv6-prefix fd35:1940:27::/48",
			},
			rule:         "n1",
			wantExcluded: true,
		},
	}
}

// TestNATExclusionBuilderRendererAgree_6534 is the #6534 binding: for every
// exclusion site, the snapshot builder and the show surface must reach the same
// verdict about whether the dataplane installs the rule.
//
// Reverting EITHER half breaks this. Drop the annotation from a natshow
// renderer and the excluded cases fail with "builder EXCLUDED / renderer says
// ARMED". Delete a builder's drop guard and the same cases fail the other way,
// naming the site.
func TestNATExclusionBuilderRendererAgree_6534(t *testing.T) {
	for _, c := range natExclusionCases() {
		t.Run(c.name, func(t *testing.T) {
			cfg := compileSetLenient5717(t, append([]string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
			}, c.cmds...))

			gotBuilder := builderExcluded(t, c, cfg)
			gotRenderer := rendererExcluded(t, cfg)

			// Pin the fixture to ground truth first. Without this, a fixture
			// that silently stopped constructing the malformed shape (a
			// grammar change, a compiler that now drops the offending leaf)
			// would leave both halves agreeing on "installed" and the cell
			// would pass over an empty set — a vacuous green that argues
			// against anyone re-examining the property.
			if gotBuilder != c.wantExcluded {
				t.Fatalf("%s: builder excluded=%v, want %v — the fixture no longer "+
					"constructs the case it names, so the agreement below would be vacuous",
					c.site, gotBuilder, c.wantExcluded)
			}

			if gotBuilder != gotRenderer {
				verdict := "builder EXCLUDED the rule but the show surface renders it ARMED " +
					"(this is the #6534 defect: the operator is told a rule is enforced " +
					"when the dataplane dropped it)"
				if gotRenderer {
					verdict = "the show surface annotated the rule NOT INSTALLED but the " +
						"builder INSTALLED it (the annotation is crying wolf on a working rule)"
				}
				t.Fatalf("site %s, rule %q: %s", c.site, c.rule, verdict)
			}
		})
	}
}

// TestNATExclusionAnnotationCarriesAReason_6534 pins the second acceptance
// criterion: the drop REASON must reach the operator, not just the fact of the
// drop. An annotation that says only "NOT INSTALLED" leaves them to guess which
// of five conditions fired.
func TestNATExclusionAnnotationCarriesAReason_6534(t *testing.T) {
	for _, c := range natExclusionCases() {
		if !c.wantExcluded {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			cfg := compileSetLenient5717(t, append([]string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
			}, c.cmds...))
			var buf bytes.Buffer
			natshow.RenderSourceRuleDetail(context.Background(), &buf, cfg, nil, nil)
			natshow.RenderDestRuleDetail(context.Background(), &buf, cfg, nil, nil)
			natshow.RenderStaticRule(&buf, cfg, true)
			natshow.RenderNPTv6(&buf, cfg)

			out := buf.String()
			idx := strings.Index(out, "NOT INSTALLED")
			if idx < 0 {
				t.Fatalf("no #6534 annotation rendered at all for %s", c.site)
			}
			// The reason follows the em-dash separator on the same line.
			line := out[idx:]
			if nl := strings.IndexByte(line, '\n'); nl >= 0 {
				line = line[:nl]
			}
			reason := strings.TrimPrefix(line, "NOT INSTALLED")
			reason = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(reason), "—"))
			if reason == "" {
				t.Fatalf("annotation for %s carries no reason: %q", c.site, line)
			}
		})
	}
}

// TestNATHealthyConfigRendersUnannotated_6534 is the anti-false-positive half.
// An annotation helper that fired unconditionally would pass every agreement
// case above that expects exclusion, so this pins the other direction: a
// wholly healthy NAT config must render with no #6534 annotation anywhere.
func TestNATHealthyConfigRendersUnannotated_6534(t *testing.T) {
	cfg := compileSetLenient5717(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source pool p1 address 203.0.113.10/32",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/24",
		"set security nat source rule-set rs1 rule r1 then source-nat pool p1",
		"set security nat destination pool dp1 address 10.0.0.9/32",
		"set security nat destination rule-set drs from zone untrust",
		"set security nat destination rule-set drs rule d1 match destination-address 203.0.113.9/32",
		"set security nat destination rule-set drs rule d1 then destination-nat pool dp1",
		"set security nat static rule-set srs from zone untrust",
		"set security nat static rule-set srs rule s1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set srs rule s1 then static-nat prefix 10.0.0.5/32",
	})
	if rendererExcluded(t, cfg) {
		var buf bytes.Buffer
		natshow.RenderSourceRuleDetail(context.Background(), &buf, cfg, nil, nil)
		natshow.RenderDestRuleDetail(context.Background(), &buf, cfg, nil, nil)
		natshow.RenderStaticRule(&buf, cfg, true)
		t.Fatalf("healthy NAT config rendered a #6534 NOT INSTALLED annotation:\n%s", buf.String())
	}
}
