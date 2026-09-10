package policymatch

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9410 — `show security match-policies` must not certify a verdict for a
// snapshot the dataplane refuses wholesale.
//
// CHANNEL. The configs below are compiled with `config.CompileConfigLenient`,
// and that is the finding rather than a convenience:
//
//	configstore.CheckText        REJECTS an unresolvable policy zone reference
//	config.CompileConfig         REJECTS
//	config.CompileConfigLenient  ACCEPTS (the zone gate is downgraded to a warning)
//
// So an operator cannot commit one of these — and `Store.Load` (booting a
// persisted active config), `Store.SyncApply` (an HA standby receiving from an
// un-upgraded primary) and `cmd/xpfd/upgrade.go` all serve one, which is the
// class the #3402 backstop exists for. A cell that built these with the strict
// compiler could not exist at all, and would be measuring the wrong channel.

func tree9410(t *testing.T, lines ...string) *config.Config {
	t.Helper()
	tr := &config.ConfigTree{}
	for _, l := range lines {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tr.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tr)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	return cfg
}

func zoneBase9410() []string {
	return []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
	}
}

func query9410() Query {
	return Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"),
		Protocol: "tcp", SrcPort: 1234, DstPort: 80,
	}
}

// TestMatchPoliciesRefusesToCertifyAnUnresolvableSnapshot9410 is the fix, on the
// operator-facing surface, with the issue's own two probes.
//
// THE CONTROL IS THE THIRD ROW AND IT IS THE ONE THAT MATTERS. "The simulator
// refuses to answer for a broken config" is satisfiable by refusing to answer
// for every config, which would break `show security match-policies` outright —
// worse than the fabricated verdict being fixed. So a healthy config in the same
// run must still produce its concrete permit.
func TestMatchPoliciesRefusesToCertifyAnUnresolvableSnapshot9410(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lines      []string
		wantReject bool
		wantZone   string
		wantAction config.PolicyAction
		wantPolicy string
	}{
		{
			// PROBE A from the issue: a scoped global naming a typo'd zone, under a
			// default permit-all. Measured before the fix: 0 reasons,
			// Matched=true Global=true Display="deny" Policy="g1" — a concrete DENY
			// certified for a snapshot the helper never loaded.
			name: "scoped global naming a typo'd zone",
			lines: append(zoneBase9410(),
				"set security policies default-policy permit-all",
				"set security policies global policy g1 match from-zone [ trust typo-zone ]",
				"set security policies global policy g1 match source-address any",
				"set security policies global policy g1 match destination-address any",
				"set security policies global policy g1 match application any",
				"set security policies global policy g1 then deny",
			),
			wantReject: true, wantZone: "typo-zone",
		},
		{
			// PROBE B: a healthy rule sitting beside a dangling zone-pair. Measured
			// before the fix: Display="permit" Policy="ok1" — a concrete PERMIT
			// while the box runs previous-good or default-deny. The dangling rule
			// is a DIFFERENT policy from the one that matched, which is what makes
			// the whole-snapshot semantics load-bearing: a per-rule mirror would
			// have reported nothing here.
			name: "healthy rule beside a dangling zone-pair",
			lines: append(zoneBase9410(),
				"set security policies from-zone trust to-zone untrust policy ok1 match source-address any",
				"set security policies from-zone trust to-zone untrust policy ok1 match destination-address any",
				"set security policies from-zone trust to-zone untrust policy ok1 match application any",
				"set security policies from-zone trust to-zone untrust policy ok1 then permit",
				"set security policies from-zone trust to-zone gone policy bad1 match source-address any",
				"set security policies from-zone trust to-zone gone policy bad1 match destination-address any",
				"set security policies from-zone trust to-zone gone policy bad1 match application any",
				"set security policies from-zone trust to-zone gone policy bad1 then permit",
			),
			wantReject: true, wantZone: "gone",
		},
		{
			// THE LOAD-BEARING CONTROL.
			name: "CONTROL: a healthy config still gets its concrete verdict",
			lines: append(zoneBase9410(),
				"set security policies from-zone trust to-zone untrust policy ok1 match source-address any",
				"set security policies from-zone trust to-zone untrust policy ok1 match destination-address any",
				"set security policies from-zone trust to-zone untrust policy ok1 match application any",
				"set security policies from-zone trust to-zone untrust policy ok1 then permit",
			),
			wantReject: false, wantAction: config.PolicyPermit, wantPolicy: "ok1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tree9410(t, tc.lines...)
			res := Match(cfg, query9410())
			if res.ContentRejected != tc.wantReject {
				t.Fatalf("#9410: ContentRejected = %v, want %v\nres = %+v",
					res.ContentRejected, tc.wantReject, res)
			}
			if !tc.wantReject {
				if !res.Matched || res.Action != tc.wantAction || res.PolicyName != tc.wantPolicy {
					t.Fatalf("#9410 OVER-REJECTION: a HEALTHY config no longer gets its "+
						"concrete verdict (Matched=%v Action=%v Policy=%q, want true/%v/%q). "+
						"A simulator that refuses every config is worse than one that "+
						"fabricates a verdict for a broken one.",
						res.Matched, res.Action, res.PolicyName, tc.wantAction, tc.wantPolicy)
				}
				return
			}
			// No fabricated verdict survives the rejection.
			if res.Matched || res.PolicyName != "" || res.Global || res.DefaultUsed {
				t.Errorf("#9410: a content-rejected config still carries an attributed "+
					"verdict (Matched=%v Policy=%q Global=%v DefaultUsed=%v) — that is the "+
					"fabrication this change removes", res.Matched, res.PolicyName,
					res.Global, res.DefaultUsed)
			}
			joined := strings.Join(res.ContentRejectionReasons, "\n")
			if !strings.Contains(joined, `"`+tc.wantZone+`"`) {
				t.Errorf("#9410: no reason names the offending zone %q, so the operator is "+
					"told the config cannot be represented without being told which token "+
					"is wrong:\n%s", tc.wantZone, joined)
			}
		})
	}
}

// TestMatchPoliciesZoneRejectionIsLenientPathOnly9410 pins the CHANNEL claim, so
// the fix's justification cannot go stale silently.
//
// If the strict compiler ever started accepting an unresolvable zone reference,
// these configs would be operator-committable and the severity of #9410 would
// rise from "reachable via Store.Load / SyncApply" to "reachable by typing" —
// which is a different issue, not a harder version of this one. If the LENIENT
// compiler started rejecting them, the fix would be unreachable and these cells
// would be testing nothing.
func TestMatchPoliciesZoneRejectionIsLenientPathOnly9410(t *testing.T) {
	lines := append(zoneBase9410(),
		"set security policies from-zone trust to-zone gone policy bad1 match source-address any",
		"set security policies from-zone trust to-zone gone policy bad1 match destination-address any",
		"set security policies from-zone trust to-zone gone policy bad1 match application any",
		"set security policies from-zone trust to-zone gone policy bad1 then permit",
	)
	tr := &config.ConfigTree{}
	for _, l := range lines {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tr.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	if _, err := config.CompileConfig(tr); err == nil {
		t.Errorf("#9410 CHANNEL CHANGED: config.CompileConfig now ACCEPTS an unresolvable " +
			"policy zone reference. These configs would then be operator-committable, which " +
			"is a severity increase and a different issue — re-measure before editing this.")
	}
	if _, err := config.CompileConfigLenient(tr); err != nil {
		t.Errorf("#9410 CHANNEL CHANGED: config.CompileConfigLenient now REJECTS it (%v), so "+
			"the Store.Load / Store.SyncApply path this fix exists for is unreachable and "+
			"the cells above are measuring nothing.", err)
	}
}
