package config

import (
	"strings"
	"testing"
)

// #16425 (R3-F05-03): the strict gate for bound ip-monitoring targets.
// Three shapes committed clean before this gate and each left the
// primary's probe unable to ever complete:
//
//   - an IPv6 literal target (or secondary-ip-address) under
//     `family inet` — ip-monitoring compiles only `family inet`, so the
//     probe is udp4 and can never bind/measure it;
//   - a bound target whose unit carries no IPv4 address — the primary
//     has no same-family source to probe from.
//
// FAIL-ON-REVERT: drop the #16425 block in validateChassisClusterStrict
// and every reject case below compiles clean again; drop the cluster
// family selection and the accept cases still pass (that half is pinned
// in pkg/cluster), so this file pins only the commit side.

const ipMon16425Head = `chassis {
	cluster {
	    control-interface em0;
	    peer-address 10.99.0.2;
		cluster-id 1;
		node 0;
		authentication-key aaaaaaaaaaaaaaaa;
		redundancy-group 1 {
			ip-monitoring {
				global-weight 255;
`

const ipMon16425Tail = `
			}
		}
	}
}
interfaces {
	ge-0/0/0 {
		gigether-options { redundant-parent reth0; }
	}
	reth0 {
		redundant-ether-options { redundancy-group 1; }
		unit 0 {
`

const ipMon16425End = `
		}
	}
}
`

func ipMon16425Cfg(t *testing.T, target string, unitFamilies string) error {
	t.Helper()
	src := ipMon16425Head + target + ipMon16425Tail + unitFamilies + ipMon16425End
	_, err := CompileConfig(hierTree(t, src))
	return err
}

func TestIPMonitoringFamilyGate16425(t *testing.T) {
	dualStack := `
			family inet6 { address 2001:db8::2/64; }
			family inet { address 10.0.0.2/24; }
`
	v4Bound := `
				family inet {
					10.0.0.1 {
						weight 255;
						interface reth0.0;
						secondary-ip-address 10.0.0.3;
					}
				}
`
	for _, tc := range []struct {
		name       string
		target     string
		unit       string
		wantReject string // substring; empty means must commit clean
	}{
		{
			name:   "dual-stack unit, inet6 authored first (defect shape now probes, must commit)",
			target: v4Bound, unit: dualStack,
		},
		{
			name: "v6 target under family inet rejects",
			target: `
				family inet {
					2001:db8::1 {
						weight 255;
						interface reth0.0;
					}
				}
`, unit: dualStack, wantReject: "not an IPv4 address",
		},
		{
			name: "v6 secondary-ip-address rejects",
			target: `
				family inet {
					10.0.0.1 {
						weight 255;
						interface reth0.0;
						secondary-ip-address 2001:db8::3;
					}
				}
`, unit: dualStack, wantReject: "secondary-ip-address",
		},
		{
			name:   "bound unit with only inet6 addresses rejects",
			target: v4Bound,
			unit: `
			family inet6 { address 2001:db8::2/64; }
`, wantReject: "no IPv4 address",
		},
		{
			name: "unbound v4 target needs no unit address",
			target: `
				family inet {
					10.0.0.1 {
						weight 255;
					}
				}
`, unit: `
			family inet6 { address 2001:db8::2/64; }
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ipMon16425Cfg(t, tc.target, tc.unit)
			if tc.wantReject == "" {
				if err != nil {
					t.Fatalf("strict compile rejected a valid ip-monitoring config: %v (#16425)", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("strict compile accepted %q case, want rejection mentioning %q (#16425)", tc.name, tc.wantReject)
			}
			if !strings.Contains(err.Error(), tc.wantReject) {
				t.Fatalf("rejection = %q, want it to mention %q (#16425)", err.Error(), tc.wantReject)
			}
		})
	}
}

// TestIPMonitoringFamilyGateUndeclaredInterface16425 pins the abstention:
// a target bound to an interface/unit named nowhere must NOT be rejected
// by the family gate (existence is other gates' concern) — mirroring the
// interface-monitor attribution doctrine.
func TestIPMonitoringFamilyGateUndeclaredInterface16425(t *testing.T) {
	target := `
				family inet {
					10.0.0.1 {
						weight 255;
						interface reth9.0;
						secondary-ip-address 10.0.0.3;
					}
				}
`
	unit := `
			family inet6 { address 2001:db8::2/64; }
			family inet { address 10.0.0.2/24; }
`
	if err := ipMon16425Cfg(t, target, unit); err != nil {
		t.Fatalf("family gate must abstain on an undeclared bound interface, got: %v (#16425)", err)
	}
}
