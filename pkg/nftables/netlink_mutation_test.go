package nftables

import (
	"testing"

	"github.com/google/nftables/expr"
)

// netlink_mutation_test.go proves the parity comparison is MUTATION-SENSITIVE
// (#6387 §12.1): a deliberately widened set, a dropped `saddr !=` subtraction, a
// dropped counter, or a weakened verdict MUST change the canonical rule stream
// that the parity diff compares — otherwise the gate would pass vacuously and a
// fail-open could merge. Each class below builds a reference rule and a mutated
// rule and asserts their canonical forms DIFFER. (The kernel-gated T1 test
// applies the same mutations against the `nft` text oracle where `nft` exists;
// this test proves the diff methodology itself catches each class without a
// kernel.)

func mutBuild(t *testing.T, build func(p *nlPlan)) string {
	t.Helper()
	p := newBuildPlan(t, "xpf_mut", hostInboundPriority)
	build(p)
	if p.err != nil {
		t.Fatalf("build error: %v", p.err)

	}
	return canonRules(p)
}

// TestJunosHostIKEAcceptDeleted10524 is the pure-netlink Cell 1 pin. With an
// application-any deny and coarse IKE admission, this ident-disabled fixture
// must queue only the fine-chain jump: an IKE ACCEPT ahead of it would
// terminally bypass the fine chain. Restoring the old netlink shield makes this
// fail with two rules and an ACCEPT verdict in the first rule.
func TestJunosHostIKEAcceptDeleted10524(t *testing.T) {
	p := newBuildPlan(t, "xpf_10524", hostInboundPriority)
	emitJunosHostProgramJumpNetlink(p, 0, JunosHostProgram{
		Zone:                  "untrust",
		IngressIfnames:        []string{"ge-0-0-1"},
		HasApplicationAnyDeny: true,
		CoarseAdmitsIKE:       true,
		IKEExemptNetdevs:      []string{"ge-0-0-1"},
	})
	if p.err != nil {
		t.Fatalf("build error: %v", p.err)
	}
	if len(p.rules) != 1 {
		t.Fatalf("#10524 netlink jump must queue one rule (no IKE accept), got %d:\n%s",
			len(p.rules), canonRules(p))
	}
	v, ok := p.rules[0][len(p.rules[0])-1].(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictJump {
		t.Fatalf("#10524 netlink first rule verdict = %#v, want jump", p.rules[0][len(p.rules[0])-1])
	}
}

func TestMutationSensitivity(t *testing.T) {
	cases := []struct {
		name      string
		reference func(p *nlPlan)
		mutated   func(p *nlPlan)
	}{
		{
			// Widened set: a /32 host daddr broadened to a /24 must change the
			// match (exact cmp -> masked cmp over a wider network).
			name: "widened_daddr_/32_to_/24",
			reference: func(p *nlPlan) {
				p.rule().daddr(famV4, []string{"10.0.1.1"}, false).emit(verdictDrop()...)
			},
			mutated: func(p *nlPlan) {
				p.rule().daddr(famV4, []string{"10.0.1.0/24"}, false).emit(verdictDrop()...)
			},
		},
		{
			// Widened lookup set: an exact host set broadened to include a prefix
			// must change the set contents (exact set -> interval set).
			name: "widened_set_host_to_prefix",
			reference: func(p *nlPlan) {
				p.rule().saddr(famV4, []string{"192.0.2.10", "192.0.2.11"}, false).emit(verdictDrop()...)
			},
			mutated: func(p *nlPlan) {
				p.rule().saddr(famV4, []string{"192.0.2.0/24", "192.0.2.11"}, false).emit(verdictDrop()...)
			},
		},
		{
			// Dropped `saddr !=` subtraction: removing the permit carve-out must
			// change the rule (one fewer predicate) — a fail-open that would let
			// the earlier-permitted source through the deny.
			name: "dropped_saddr_except_subtraction",
			reference: func(p *nlPlan) {
				p.rule().saddr(famV4, []string{"192.0.2.0/24"}, false).
					saddr(famV4, []string{"192.0.2.10"}, true).emit(verdictDrop()...)
			},
			mutated: func(p *nlPlan) {
				p.rule().saddr(famV4, []string{"192.0.2.0/24"}, false).emit(verdictDrop()...)
			},
		},
		{
			// Dropped counter: removing the named counter reference must change
			// the rule (the deny becomes invisible to the metric scraper).
			name: "dropped_counter",
			reference: func(p *nlPlan) {
				p.rule().daddr(famV4, []string{"10.0.8.1"}, false).
					counterRef(HostInboundDenyCounterName("quarantine", "ip")).emit(verdictDrop()...)
			},
			mutated: func(p *nlPlan) {
				p.rule().daddr(famV4, []string{"10.0.8.1"}, false).emit(verdictDrop()...)
			},
		},
		{
			// Weakened verdict: a catch-all drop turned into accept — the core
			// host-inbound fail-open — must change the rule.
			name: "weakened_verdict_drop_to_accept",
			reference: func(p *nlPlan) {
				p.rule().daddr(famV4, []string{"10.0.8.1"}, false).emit(verdictDrop()...)
			},
			mutated: func(p *nlPlan) {
				p.rule().daddr(famV4, []string{"10.0.8.1"}, false).emit(verdictAccept()...)
			},
		},
		{
			// Weakened reject: the reject pair collapsed to a single admin-prohibited
			// (dropping the TCP-RST leg) must change the rule stream.
			name: "weakened_reject_pair_to_single",
			reference: func(p *nlPlan) {
				buildLo0TermNetlink(p, Lo0FilterTerm{Name: "r", Action: "reject"}, famV4)
			},
			mutated: func(p *nlPlan) {
				p.rule().emit(rejectICMPXAdminProhibited()...)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref := mutBuild(t, tc.reference)
			mut := mutBuild(t, tc.mutated)
			if ref == mut {
				t.Errorf("mutation %s NOT detected: reference and mutated canonical forms are identical:\n%s", tc.name, ref)
			}
		})
	}
}

// TestBuildDeterministic asserts a construct-complete build renders identically
// twice, so a parity diff only fires on a real change (no spurious set-ordering
// or map-iteration noise).
func TestBuildDeterministic(t *testing.T) {
	build := func() string {
		p := newBuildPlan(t, "xpf_hostinbound", hostInboundPriority)
		buildHostInboundNetlink(p, hostInboundScenario())
		if p.err != nil {
			t.Fatalf("build error: %v", p.err)
		}
		return canonRules(p)
	}
	a, b := build(), build()
	if a != b {
		t.Errorf("build not deterministic across runs:\n  a=%q\n  b=%q", a, b)
	}
}
