package userspace

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// junos_host_residual_6612_test.go covers the #6612 warning remainder for
// junos-host policies, including the user-space warning that remains after
// #11065 adds a direct-kernel terminal deny for representable scoped permits.
//
// Each row asserts the intended enforcement shape and a policy-specific #4168
// warning. Unrepresentable rows render no rules. A source- or destination-scoped
// permit instead renders its authored RETURN followed by terminal DROP rules in
// both address families; the user-space `None => deliver` path still requires
// the warning.
//
// Each row also carries a FLIP — the same fixture with the residual attribute
// neutralised — so a failed compile or missing address-book entry cannot
// masquerade as coverage.

// residualBase is the minimal zone/interface/address-book scaffolding. `untrust`
// is the ingress zone under test and owns a non-lifeline interface, so it
// resolves to a real iifname scope — without that every row would render zero
// rules for the uninteresting reason that the zone is unenforceable.
var residualBase = []string{
	"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
	"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	"set security zones security-zone untrust interfaces ge-0/0/1.0",
	"set security zones security-zone untrust host-inbound-traffic system-services ssh",
	"set security zones security-zone trust interfaces ge-0/0/0.0",
	"set security address-book global address bad-host 10.0.0.5/32",
	"set security address-book global address fw-mgmt 10.0.1.1/32",
	"set security address-book global address mgmt-net 10.10.0.0/24",
}

// feedScaffolding binds an address-book name to a dynamic feed, which is the
// "not commit-stable" taint the projection refuses to render.
var feedScaffolding = []string{
	"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
	"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
	"set security dynamic-address address-name feed-bad profile feed-name malware",
}

// schedulerScaffolding defines the scheduler a scheduler-gated policy names —
// without it CompileConfig rejects the reference and the row would exercise the
// undefined-scheduler error rather than the time-window residual.
var schedulerScaffolding = []string{
	"set schedulers scheduler workhours daily start-time 09:00:00",
	"set schedulers scheduler workhours daily stop-time 17:00:00",
}

func residualCfg(t *testing.T, cmds ...[]string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, group := range cmds {
		for _, cmd := range group {
			path, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// residualRuleCount is the number of kernel DROP rules the daemon would render
// for this config — the real consumer path (BuildJunosHostPrograms wraps
// config.BuildJunosHostDenyProjection and is what pkg/daemon feeds to the
// nftables renderer).
func residualRuleCount(cfg *config.Config) int {
	n := 0
	for _, p := range BuildJunosHostPrograms(cfg) {
		n += len(p.RulesV4) + len(p.RulesV6)
	}
	return n
}

// residualWarnings returns the #4146/#4168 junos-host parity warnings naming the
// given policy. Filtering by policy NAME (not merely counting) is what makes the
// assertion "the warning names itself" rather than "some warning fired".
func residualWarnings(cfg *config.Config, policy string) []string {
	var out []string
	want := fmt.Sprintf("security policy %q", policy)
	for _, w := range config.ValidateConfig(cfg) {
		if strings.Contains(w, "to-zone junos-host") && strings.Contains(w, "#4146") &&
			strings.Contains(w, want) {
			out = append(out, w)
		}
	}
	return out
}

// policy builds the four set lines of one `from-zone untrust to-zone junos-host`
// policy, so a row differs from its flip in exactly the field under test.
func policy(name, src, dst, app, action string) []string {
	p := "set security policies from-zone untrust to-zone junos-host policy " + name + " "
	return []string{
		p + "match source-address " + src,
		p + "match destination-address " + dst,
		p + "match application " + app,
		p + "then " + action,
	}
}

// TestJunosHostResidualPathsRemainWarned6612 walks the #6612 remainder.
//
// #9504 removed `then reject` from this remainder because it renders with the
// active reject verdict. #11304 clarifies that `tcp-rst` only affects transit
// session misses, so a host-bound policy deny stays a silent drop; that verdict
// is covered by TestJunosHostRejectAndTCPRstPolicyDeny9504_11304 below.
//
// FAIL-ON-REVERT: each row's residual attribute is the only difference from its
// flip. Unrepresentable rows must remain rule-free and warned; the scoped permit
// rows must keep their RETURN-plus-terminal-DROP shape and userspace warning.
// Changing those behaviors or suppressing the warning turns the assertion RED.
func TestJunosHostResidualPathsRemainWarned6612(t *testing.T) {
	rows := []struct {
		name string
		// policyName is the policy the warning must name.
		policyName string
		// cmds is the residual variant and a warning remains expected.
		cmds []string
		// flip is the same fixture with the residual attribute neutralised.
		flip []string
		// flipRules is whether the neutralised variant renders kernel rules.
		flipRules bool
		// terminalFallback marks scoped permits whose direct kernel rules now
		// include a terminal default deny but still retain a userspace warning.
		terminalFallback bool
	}{
		{
			name:       "scheduler-gated deny (time-windowed, cannot be a static rule)",
			policyName: "sched-deny",
			cmds: concat(residualBase, schedulerScaffolding,
				policy("sched-deny", "bad-host", "any", "any", "deny"),
				[]string{"set security policies from-zone untrust to-zone junos-host policy sched-deny scheduler-name workhours"}),
			flip:      concat(residualBase, schedulerScaffolding, policy("sched-deny", "bad-host", "any", "any", "deny")),
			flipRules: true,
		},
		{
			name:       "feed-bound SOURCE deny (not commit-stable)",
			policyName: "feed-src",
			cmds: concat(residualBase, feedScaffolding,
				policy("feed-src", "feed-bad", "any", "any", "deny")),
			flip:      concat(residualBase, feedScaffolding, policy("feed-src", "bad-host", "any", "any", "deny")),
			flipRules: true,
		},
		{
			name:       "feed-bound DESTINATION deny (not commit-stable)",
			policyName: "feed-dst",
			cmds: concat(residualBase, feedScaffolding,
				policy("feed-dst", "any", "feed-bad", "any", "deny")),
			flip:      concat(residualBase, feedScaffolding, policy("feed-dst", "any", "fw-mgmt", "any", "deny")),
			flipRules: true,
		},
		{
			name:       "ALG-bearing application deny (the ALG path owns the tuple)",
			policyName: "alg-deny",
			cmds: concat(residualBase,
				[]string{
					"set applications application my-ftp protocol tcp",
					"set applications application my-ftp destination-port 21",
					"set applications application my-ftp alg ftp",
				},
				policy("alg-deny", "bad-host", "any", "my-ftp", "deny")),
			flip: concat(residualBase,
				[]string{
					"set applications application my-ftp protocol tcp",
					"set applications application my-ftp destination-port 21",
				},
				policy("alg-deny", "bad-host", "any", "my-ftp", "deny")),
			flipRules: true,
		},
		{
			name:       "application scoped to an IKE exempt tuple (the IPsec passthrough path owns it)",
			policyName: "ike-deny",
			cmds: concat(residualBase,
				[]string{
					"set applications application my-ike protocol udp",
					"set applications application my-ike destination-port 500",
				},
				policy("ike-deny", "bad-host", "any", "my-ike", "deny")),
			flip: concat(residualBase,
				[]string{
					"set applications application my-ike protocol udp",
					"set applications application my-ike destination-port 4444",
				},
				policy("ike-deny", "bad-host", "any", "my-ike", "deny")),
			flipRules: true,
		},
		{
			// #6612: destination-narrowed, source UNSCOPED — the shape that was
			// silent on BOTH halves before the destination clause landed. Source
			// `any` is load-bearing: with a concrete source the row would warn
			// through junosHostPolicySourceScoped and could not tell whether the
			// destination clause exists.
			name:             "destination-scoped permit (return plus terminal default deny)",
			policyName:       "dst-permit",
			cmds:             concat(residualBase, policy("dst-permit", "any", "fw-mgmt", "any", "permit")),
			flip:             concat(residualBase, policy("dst-permit", "any", "any", "any", "permit")),
			flipRules:        false,
			terminalFallback: true,
		},
		{
			// The excluded form must be covered too: a fix catching the named
			// destination and missing `destination-address-excluded` would leave a
			// residual with the same shape as the bug, which is the hardest kind
			// to notice later. The projection gates on both
			// (`junosHostAddrScoped(dest) || DestinationAddressExcluded`) and so
			// does the warning.
			name:       "destination-EXCLUDED permit (same carve, inverted domain)",
			policyName: "dstx-permit",
			// `destination-address any` + excluded, NOT a named destination: that
			// isolates the `DestinationAddressExcluded` disjunct on both the
			// projection and the advisory. Naming an address here would satisfy
			// `junosHostAddrScoped` too, and a mutation dropping one disjunct
			// could not be localised — the other would keep the row green.
			cmds: concat(residualBase, policy("dstx-permit", "any", "any", "any", "permit"),
				[]string{"set security policies from-zone untrust to-zone junos-host policy dstx-permit match destination-address-excluded"}),
			flip:      concat(residualBase, policy("dstx-permit", "any", "any", "any", "permit")),
			flipRules: false,
		},
		{
			name:             "source-restricted permit (return plus terminal default deny)",
			policyName:       "src-permit",
			cmds:             concat(residualBase, policy("src-permit", "bad-host", "any", "any", "permit")),
			flip:             concat(residualBase, policy("src-permit", "any", "any", "any", "permit")),
			flipRules:        false,
			terminalFallback: true,
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			cfg := residualCfg(t, row.cmds)
			if row.terminalFallback {
				progs := BuildJunosHostPrograms(cfg)
				if len(progs) != 1 {
					t.Fatalf("want one representable ingress program, got %+v", progs)
				}
				p := progs[0]
				terminal := func(r config.JunosHostDenyRule) bool {
					return r.Verdict == config.JunosHostDrop && r.SrcAny && r.DstAny
				}
				if len(p.RulesV4) != 2 || p.RulesV4[0].Verdict != config.JunosHostReturn ||
					!terminal(p.RulesV4[1]) {
					t.Errorf("v4 rules = %+v, want the authored permit return then terminal default deny", p.RulesV4)
				}
				if len(p.RulesV6) != 1 || !terminal(p.RulesV6[0]) {
					t.Errorf("v6 rules = %+v, want terminal default deny for the unpermitted family", p.RulesV6)
				}
			} else if n := residualRuleCount(cfg); n != 0 {
				t.Errorf("unrepresentable residual rendered %d kernel rule(s); it must emit NOTHING",
					n)
			}
			if got := residualWarnings(cfg, row.policyName); len(got) != 1 {
				t.Errorf("residual variant produced %d #4168 warnings naming %q, want exactly 1 — got %v",
					len(got), row.policyName, got)
			}

			flip := residualCfg(t, row.flip)
			flipRules := residualRuleCount(flip)
			if row.flipRules && flipRules == 0 {
				t.Errorf("flip variant rendered no kernel rule, so the row proves nothing")
			}
			if !row.flipRules && flipRules != 0 {
				t.Errorf("flip variant rendered %d rule(s); the match-all permit should leave no terminal drop",
					flipRules)
			}
			if got := residualWarnings(flip, row.policyName); len(got) != 0 {
				t.Errorf("flip variant still warns for %q (%d): %v",
					row.policyName, len(got), got)
			}
		})
	}
}

// TestJunosHostRepresentableDenyRendersAndIsSuppressed6612 is the positive
// control for the whole file. Without it, a projection that returned nothing for
// EVERY config and a warning generator that fired on EVERY junos-host policy
// would satisfy every assertion above.
func TestJunosHostRepresentableDenyRendersAndIsSuppressed6612(t *testing.T) {
	cfg := residualCfg(t, residualBase, policy("plain-deny", "bad-host", "any", "any", "deny"))
	if n := residualRuleCount(cfg); n == 0 {
		t.Fatalf("a representable junos-host deny must render a kernel DROP rule; got 0")
	}
	if got := residualWarnings(cfg, "plain-deny"); len(got) != 0 {
		t.Errorf("a deny that IS enforced on the direct host-bound path must have its #4168 warning suppressed; got %v", got)
	}
}

func concat(groups ...[]string) []string {
	var out []string
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// TestJunosHostMultiTermApplicationIsFullyExpanded6612 corrects the record on
// one member of #6612's enumeration and locks the correction.
//
// #6612 item 7 and the "Un-representable remainder" paragraph both list
// "multi-term … applications" as un-representable. Measured, that is not what
// the projection does: a pure `term`-bearing application compiles to an implicit
// application-SET (`compiler_applications.go` — the parent struct is discarded
// and each term is stored as its own application), so
// junosHostResolveApplications takes the set branch and OR-expands it, exactly
// as the issue's own "Representable subset" says application-sets are handled.
// What is genuinely un-representable is a MIXED direct+term application
// (`MixedDirectTermApps`), and that is hard-rejected at commit by the strict
// structure gate before it can reach here.
//
// So the deny IS enforced — which makes the real hazard the opposite of the one
// documented: a PARTIAL expansion would render a kernel deny SILENTLY NARROWER
// than authored (the udp/53 term dropped, its traffic admitted), which is the
// one outcome the projection's "no partial / coarsened kernel rule" rule forbids.
// This asserts every term survives.
//
// FAIL-ON-REVERT: drop the `ExpandApplicationSet` loop's accumulation (keep only
// the first member) and the udp/53 fragment disappears — RED. Make the whole
// app un-representable instead and the rule count goes to 0 — also RED.
func TestJunosHostMultiTermApplicationIsFullyExpanded6612(t *testing.T) {
	cfg := residualCfg(t, residualBase,
		[]string{
			"set applications application multi term t1 protocol tcp destination-port 22",
			"set applications application multi term t2 protocol udp destination-port 53",
		},
		policy("mt-deny", "bad-host", "any", "multi", "deny"))

	progs := BuildJunosHostPrograms(cfg)
	if len(progs) != 1 {
		t.Fatalf("multi-term application deny must render one ingress-zone program; got %d", len(progs))
	}
	var frags []config.JunosHostDenyL4
	for _, r := range progs[0].RulesV4 {
		frags = append(frags, r.L4...)
	}
	// Both authored terms must appear. Asserting the SET (not the count) is what
	// distinguishes "expanded" from "expanded to the same term twice".
	want := map[string]bool{"tcp/22": false, "udp/53": false}
	for _, f := range frags {
		for _, p := range f.Ports {
			switch {
			case f.Proto == config.HostInboundProtoTCP && p.Lo == 22 && p.Hi == 22:
				want["tcp/22"] = true
			case f.Proto == config.HostInboundProtoUDP && p.Lo == 53 && p.Hi == 53:
				want["udp/53"] = true
			}
		}
	}
	for term, seen := range want {
		if !seen {
			t.Errorf("term %s is missing from the projected deny — a partially-expanded multi-term application renders a kernel deny SILENTLY NARROWER than authored; got %+v", term, frags)
		}
	}
	// And, being enforced, it must NOT carry the #4168 unenforced-parity warning.
	if got := residualWarnings(cfg, "mt-deny"); len(got) != 0 {
		t.Errorf("an enforced multi-term deny must have its #4168 warning suppressed; got %v", got)
	}
}

// TestJunosHostDestinationScopedPermitDoesNotWidenALaterDeny6612 is the
// projection half of the #6612 destination-scoped permit class, re-pointed by
// #9504.
//
// Before #9504 a permit could be projected only as a `saddr !=` subtraction of
// later denies, which cannot express a carve that is also destination-scoped, so
// the projection refused to render the WHOLE zone program and this cell asserted
// emptiness. The permit now renders as a return carrying its own destination
// predicate, so the property to hold is the one the emptiness stood in for: the
// deny that follows is exactly as wide as authored, and the permit's carve is
// exactly as narrow.
//
// It needs a CONCRETE source for the same reason it always did: with
// `source-address any` the permit returns every packet and shadows the deny
// outright, so nothing downstream would be observable either way.
func TestJunosHostDestinationScopedPermitDoesNotWidenALaterDeny6612(t *testing.T) {
	followingDeny := policy("blk", "any", "any", "any", "deny")
	for _, tc := range []struct {
		name   string
		permit string
		cmds   []string
	}{
		{
			name:   "destination-scoped permit ahead of a deny",
			permit: "dst-permit",
			cmds: concat(residualBase,
				policy("dst-permit", "mgmt-net", "fw-mgmt", "any", "permit"),
				followingDeny),
		},
		{
			name:   "destination-EXCLUDED permit ahead of a deny",
			permit: "dstx-permit",
			cmds: concat(residualBase,
				policy("dstx-permit", "mgmt-net", "fw-mgmt", "any", "permit"),
				[]string{"set security policies from-zone untrust to-zone junos-host policy dstx-permit match destination-address-excluded"},
				followingDeny),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := residualCfg(t, tc.cmds)
			progs := BuildJunosHostPrograms(cfg)
			if len(progs) != 1 {
				t.Fatalf("want one program for the ingress zone, got %+v", progs)
			}
			v4 := progs[0].RulesV4
			if len(v4) != 3 {
				t.Fatalf("want the permit return, authored deny, and terminal default deny in v4, got %+v", v4)
			}
			if r := v4[0]; r.Verdict != config.JunosHostReturn || r.DstAny || len(r.Dst) != 1 {
				t.Errorf("first v4 rule = %+v, want a return still scoped to the permit's "+
					"destination; dropping that predicate is what would under-deny the "+
					"permitted source to every other firewall address", r)
			}
			if r := v4[1]; r.Verdict != config.JunosHostDrop || !r.DstAny || !r.SrcAny {
				t.Errorf("second v4 rule = %+v, want the authored deny unchanged for every source and destination", r)
			}
			if r := v4[2]; r.Verdict != config.JunosHostDrop || !r.SrcAny || !r.DstAny {
				t.Errorf("third v4 rule = %+v, want the terminal default deny (#11065)", r)
			}
			// The deny is enforced on the direct path now, so its warning is gone. The
			// permit keeps one: no path refuses what it does not match.
			if got := residualWarnings(cfg, "blk"); len(got) != 0 {
				t.Errorf("the deny renders kernel rules yet still warns (%d): %v", len(got), got)
			}
			if got := residualWarnings(cfg, tc.permit); len(got) != 1 {
				t.Errorf("the permit must keep its warning (%d): %v", len(got), got)
			}
		})
	}
	// Non-vacuity: the same builder and fixture render for a lone deny too, so the
	// shapes above are the gate and not an inert fixture.
	if n := residualRuleCount(residualCfg(t, residualBase, followingDeny)); n == 0 {
		t.Fatalf("control: a lone representable deny must render a kernel rule on this fixture; got 0")
	}
}

// TestJunosHostRejectAndTCPRstPolicyDeny9504_11304 keeps explicit `reject`
// active while a plain `deny` remains silent even in a `tcp-rst` zone. The
// option controls transit session-miss resets, not host-bound policy denies.
// Assert the projected verdict so a `tcp-rst`-specific deny answer cannot
// silently reappear in the kernel path.
func TestJunosHostRejectAndTCPRstPolicyDeny9504_11304(t *testing.T) {
	for _, tc := range []struct {
		name    string
		policy  string
		verdict config.JunosHostVerdict
		cmds    []string
	}{
		{
			name:    "then reject",
			policy:  "rej",
			verdict: config.JunosHostReject,
			cmds:    concat(residualBase, policy("rej", "bad-host", "any", "any", "reject")),
		},
		{
			name:    "deny on a tcp-rst ingress zone",
			policy:  "rst-zone",
			verdict: config.JunosHostDrop,
			cmds: concat(residualBase,
				[]string{"set security zones security-zone untrust tcp-rst"},
				policy("rst-zone", "bad-host", "any", "any", "deny")),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := residualCfg(t, tc.cmds)
			n := 0
			for _, p := range BuildJunosHostPrograms(cfg) {
				for _, r := range append(append([]config.JunosHostDenyRule{}, p.RulesV4...), p.RulesV6...) {
					n++
					if r.Verdict != tc.verdict {
						t.Errorf("rule verdict = %v, want %v", r.Verdict, tc.verdict)
					}
				}
			}
			if n == 0 {
				t.Fatal("no kernel rule rendered, so this class is still unenforced")
			}
			if got := residualWarnings(cfg, tc.policy); len(got) != 0 {
				t.Errorf("an enforced policy still warns (%d): %v", len(got), got)
			}
		})
	}
}
