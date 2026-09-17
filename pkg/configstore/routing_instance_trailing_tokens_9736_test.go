package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func checkRoutingInstance9736(t *testing.T, instance string) (*config.Config, error) {
	t.Helper()
	return CheckText("routing-instances { "+instance+" }", -1)
}

// The true one-line twin is the brace-elided run rewritten by #9620 into one
// child carrying the same statement. Both spellings must reject a trailing
// token on a fixed-arity RI leaf; otherwise the token extends the statement,
// commits clean, and the compiler drops it (#9736).
func TestRoutingInstanceTrailingTokensRejectBothTwins9736(t *testing.T) {
	cases := []struct {
		name, elided, braced, want string
	}{
		{
			name:   "description then firewall",
			elided: `ri1 description tenant-a firewall family inet filter f1 term t then discard;`,
			braced: `ri1 { description tenant-a firewall family inet filter f1 term t then discard; }`,
			want:   "description",
		},
		{
			name:   "route-distinguisher then firewall",
			elided: `ri1 route-distinguisher 65000:1 firewall family inet filter f1 term t then discard;`,
			braced: `ri1 { route-distinguisher 65000:1 firewall family inet filter f1 term t then discard; }`,
			want:   "route-distinguisher",
		},
		{
			name:   "vrf-target extra token",
			elided: `ri1 vrf-target export target:65000:1 junk-token foo;`,
			braced: `ri1 { vrf-target export target:65000:1 junk-token foo; }`,
			want:   "vrf-target",
		},
		{
			name:   "vrf-table-label extra token",
			elided: `ri1 vrf-table-label junk-token foo;`,
			braced: `ri1 { vrf-table-label junk-token foo; }`,
			want:   "vrf-table-label",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, eerr := checkRoutingInstance9736(t, tc.elided)
			_, berr := checkRoutingInstance9736(t, tc.braced)
			if eerr == nil || berr == nil {
				t.Fatalf("both spellings must reject the trailing token: elided=%v braced=%v", eerr, berr)
			}
			for spelling, err := range map[string]error{"elided": eerr, "braced": berr} {
				if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "trailing") {
					t.Errorf("%s error must name %q and the trailing token: %v", spelling, tc.want, err)
				}
			}
		})
	}
}
func TestRoutingInstanceVRFTargetBlockHeaderRejectsPackedPrefix9736(t *testing.T) {
	for _, instance := range []string{
		`ri1 vrf-target junk { target:65000:1; }`,
		`ri1 { vrf-target junk { target:65000:1; } }`,
	} {
		if _, err := checkRoutingInstance9736(t, instance); err == nil || !strings.Contains(err.Error(), "vrf-target") {
			t.Errorf("malformed vrf-target block header committed: %q: %v", instance, err)
		}
	}
}

// `vrf-target export target:...` is the control that refuted the naive
// keyword-position walk. It remains valid in both one-line spellings, and the
// documented block/list forms remain valid too.
func TestRoutingInstanceVRFTargetGrammarAndTwinParity9736(t *testing.T) {
	valid := []struct{ name, instance string }{
		{"elided export", `ri1 vrf-target export target:65000:1;`},
		{"braced one-line export", `ri1 { vrf-target export target:65000:1; }`},
		{"elided import", `ri1 vrf-target import target:65000:2;`},
		{"braced block", `ri1 { vrf-target { export target:65000:1; import target:65000:2; } }`},
		{"bracket list", `ri1 { vrf-target [ target:65000:1 target:65000:2 ]; }`},
		{"repeated statements", `ri1 { vrf-target target:65000:1; vrf-target target:65000:2; }`},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := checkRoutingInstance9736(t, tc.instance)
			if err != nil {
				t.Fatalf("valid vrf-target form was rejected: %v", err)
			}
			if cfg == nil || len(cfg.RoutingInstances) != 1 {
				t.Fatalf("valid vrf-target form did not compile one routing instance: %#v", cfg)
			}
		})
	}
}

// The issue's residual boundary is deliberate: routing-options is a body
// bearing keyword with its own grammar, so the RI-level walk must not judge
// bogus-kw inside it.
func TestRoutingInstanceWalkStopsAtABodyBearingKeyword9736(t *testing.T) {
	for _, instance := range []string{
		`ri1 routing-options bogus-kw foo;`,
		`ri1 { routing-options bogus-kw foo; }`,
	} {
		if _, err := checkRoutingInstance9736(t, instance); err != nil {
			t.Errorf("routing-options body boundary was over-closed for %q: %v", instance, err)
		}
	}
}

// The motivating firewall spelling is already rejected by the #9814 typed
// instance-type gate. Keep the issue-level assertion here so a future change
// cannot turn it back into a clean commit that compiles no firewall state.
func TestRoutingInstanceFirewallTrailingRunDoesNotCommitSilently9736(t *testing.T) {
	for _, instance := range []string{
		`ri1 instance-type virtual-router firewall family inet filter f1 term t then discard;`,
		`ri1 { instance-type virtual-router firewall family inet filter f1 term t then discard; }`,
	} {
		if _, err := checkRoutingInstance9736(t, instance); err == nil {
			t.Errorf("firewall trailing run committed clean: %q", instance)
		}
	}
}
