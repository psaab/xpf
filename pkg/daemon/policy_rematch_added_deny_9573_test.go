package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #9573: pin what `policy-rematch` does with a commit that ADDS a deny.
//
// docs/log/9386.md accepted a stated fail-open: the frame-independent #8356
// re-derivation skips a type-constrained ICMP DENY on established sessions.
// Its record named `policy-rematch` at commit as a mitigation. For the most
// direct way to create that situation, a commit that ADDS the deny ahead of an
// unchanged broad permit, the mitigation does not hold:
//
//   - rematch off (the default) and plain `policy-rematch` sweep NOTHING.
//     changedPolicyRuntimeIDs iterates OLD ids only and compares policies
//     present on both sides, and the permit itself did not change.
//   - `extensive` sweeps the shadowed permit only INCIDENTALLY. Inserting the
//     deny shifts the permit's positional policy_id, and the resolved
//     fingerprint hashes the rule including policy_id. An appended deny shifts
//     nothing and sweeps nothing. A permit holding policy_id 0 is excluded by
//     the overloaded-wire-value rule even when the insert shifts it.
//
// These cells pin that table, so a change to either behaviour is deliberate
// rather than silent. They do not claim the table is the right policy; #9573
// records the decision question for `extensive`'s positional sweep.

func addedDenyCfg9573(t *testing.T, lines []string) *config.Config {
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
	cfg, err := config.CompileConfig(tr)
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	return cfg
}

func TestRematchAddedDenyTable9573(t *testing.T) {
	base := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
	}
	pol := func(name, app, action string) []string {
		pfx := "set security policies from-zone trust to-zone untrust policy " + name
		return []string{
			pfx + " match source-address any",
			pfx + " match destination-address any",
			pfx + " match application " + app,
			pfx + " then " + action,
		}
	}
	build := func(mode string, pols ...[]string) *config.Config {
		lines := append([]string{}, base...)
		if mode != "" {
			lines = append(lines, "set security policies "+mode)
		}
		for _, p := range pols {
			lines = append(lines, p...)
		}
		return addedDenyCfg9573(t, lines)
	}
	first := pol("p-first", "junos-http", "permit")
	icmp := pol("p-icmp", "any", "permit")
	deny := pol("d-new", "junos-ping", "deny")
	const icmpKey = "trust->untrust/p-icmp"

	for _, tc := range []struct {
		name  string
		mode  string // "" is rematch off, the default
		sweep bool   // is the shadowed permit swept when the deny is inserted before it
	}{
		{name: "rematch-off", mode: "", sweep: false},
		{name: "policy-rematch", mode: "policy-rematch", sweep: false},
		{name: "policy-rematch-extensive", mode: "policy-rematch extensive", sweep: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := build(tc.mode, first, icmp)
			icmpID := dpuserspace.PolicyIDsByStableKey(old)[icmpKey]
			if icmpID == 0 {
				t.Fatalf("precondition: p-icmp must hold a non-zero id behind p-first; ids=%v",
					dpuserspace.PolicyIDsByStableKey(old))
			}

			// LEVELLING CONTROL. A diff that always reports a change would
			// satisfy the extensive insert cell below while sweeping every
			// session on every commit.
			t.Run("CONTROL identical rebuild sweeps nothing", func(t *testing.T) {
				if got := changedPolicyRuntimeIDs(old, build(tc.mode, first, icmp), nil, nil); len(got) != 0 {
					t.Errorf("#9573: an identical rebuild reported %v changed under %q", got, tc.name)
				}
			})

			t.Run("deny inserted before the permit", func(t *testing.T) {
				newCfg := build(tc.mode, first, deny, icmp)
				if newIDs := dpuserspace.PolicyIDsByStableKey(newCfg); newIDs[icmpKey] == icmpID {
					t.Fatalf("precondition: inserting d-new must shift p-icmp's positional id; old=%d new=%v",
						icmpID, newIDs)
				}
				got := changedPolicyRuntimeIDs(old, newCfg, nil, nil)
				_, swept := got[icmpID]
				if swept != tc.sweep || len(got) != map[bool]int{true: 1, false: 0}[tc.sweep] {
					t.Errorf("#9573: %q with a deny INSERTED before an unchanged permit: got changed=%v, "+
						"want the permit's old id %d swept=%v and nothing else. docs/log/9386.md "+
						"records this table; change it deliberately or not at all.", tc.name, got, icmpID, tc.sweep)
				}
			})

			t.Run("deny appended after the permit sweeps nothing", func(t *testing.T) {
				if got := changedPolicyRuntimeIDs(old, build(tc.mode, first, icmp, deny), nil, nil); len(got) != 0 {
					t.Errorf("#9573: %q with a deny APPENDED after an unchanged permit swept %v; "+
						"an appended deny shifts no policy_id, so nothing is expected", tc.name, got)
				}
			})
		})
	}

	t.Run("policy-rematch-extensive: a permit holding policy_id 0 is not swept even when a deny shifts it", func(t *testing.T) {
		const mode = "policy-rematch extensive"
		old := build(mode, icmp)
		if id := dpuserspace.PolicyIDsByStableKey(old)[icmpKey]; id != 0 {
			t.Fatalf("precondition: the sole policy p-icmp must hold id 0; got %d", id)
		}
		newCfg := build(mode, deny, icmp)
		if dpuserspace.PolicyIDsByStableKey(newCfg)[icmpKey] == 0 {
			t.Fatalf("precondition: the inserted deny must shift p-icmp off id 0; ids=%v",
				dpuserspace.PolicyIDsByStableKey(newCfg))
		}
		if got := changedPolicyRuntimeIDs(old, newCfg, nil, nil); len(got) != 0 {
			t.Errorf("#9573: extensive swept %v for a permit that held policy_id 0; the overloaded "+
				"wire value is excluded, so nothing is expected", got)
		}
	})
}
