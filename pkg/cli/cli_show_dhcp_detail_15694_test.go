package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #15694 (V37-04): `show dhcp server detail` omitted compiled pool fields
// that Kea serves — v4 domain-name and static-binding, v6 dns-server,
// domain-name, lease-time and static-binding — iterated Groups in Go map
// order, and never showed the Kea subnet-id a lease's Subnet column refers
// to. The fixture authors groups out of sorted order and a v6
// reservation-only pool (static-binding without address-range) so every
// defect is exercised.
//
// The expected subnet-ids are dhcpserver.SubnetIDAssignments15694 over the
// same committed config the renderer received, so the test binds the
// displayed id to the id the Kea generators assign (stableSubnetID /
// resolveSubnetID), not to a hardcoded hash value.
//
// FAIL-ON-REVERT: restoring the pre-fix renderer drops the Domain/DNS/
// Lease-time/Static-binding lines, returns to map iteration (group order
// flakes or reverses), and removes the Subnet ID lines — all asserted
// below. Dropping termsafe on the hostname makes the raw ESC bytes appear.

const detail15694Config = `
system {
    services {
        dhcp-local-server {
            group zeta {
                interface ge-0-0-1.0;
                pool zp {
                    subnet 10.0.2.0/24;
                    address-range low 10.0.2.100 high 10.0.2.199;
                    router 10.0.2.1;
                    dns-server 10.0.2.53;
                    domain-name zeta.example;
                    lease-time 7200;
                }
            }
            group alpha {
                interface ge-0-0-0.0;
                pool ap {
                    subnet 10.0.1.0/24;
                    address-range low 10.0.1.100 high 10.0.1.199;
                    router 10.0.1.1;
                    dns-server [ 10.0.1.53 10.0.1.54 ];
                    domain-name alpha.example;
                    lease-time 3600;
                    static-binding 00:11:22:33:44:55 {
                        fixed-address 10.0.1.50;
                        host-name printer;
                    }
                    static-binding aa:bb:cc:dd:ee:ff {
                        fixed-address 10.0.1.51;
                    }
                }
            }
        }
        dhcpv6-local-server {
            group zeta6 {
                interface ge-0-0-1.0;
                pool zp6 {
                    subnet 2001:db8:2::/64;
                    address-range low 2001:db8:2::100 high 2001:db8:2::199;
                    dns-server 2001:db8:2::53;
                    domain-name zeta6.example;
                    lease-time 7200;
                }
            }
            group alpha6 {
                interface ge-0-0-0.0;
                pool ap6 {
                    subnet 2001:db8:1::/64;
                    dns-server [ 2001:db8:1::53 2001:db8:1::54 ];
                    domain-name alpha6.example;
                    lease-time 3600;
                    static-binding 00:11:22:33:44:66 {
                        fixed-address 2001:db8:1::50;
                        host-name v6host;
                    }
                }
            }
        }
    }
}
`

func detail15694CLI(t *testing.T) (*CLI, string, string) {
	t.Helper()
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(detail15694Config); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig nil after commit")
	}
	ids4, ids6 := dhcpserver.SubnetIDAssignments15694(&cfg.System.DHCPServer)
	if len(ids4) != 2 || len(ids6) != 2 {
		t.Fatalf("SubnetIDAssignments15694 = v4:%v v6:%v, want 2 subnets each", ids4, ids6)
	}
	// Empty lease files: healthy empty lease set, detail still renders pools.
	leaseFile4 := filepath.Join(dir, "leases4.csv")
	leaseFile6 := filepath.Join(dir, "leases6.csv")
	for _, f := range []string{leaseFile4, leaseFile6} {
		if err := os.WriteFile(f, []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c := &CLI{
		store: store,
		dhcpServerFn: func() *dhcpserver.Manager {
			m := dhcpserver.New()
			m.SetLeaseSyncSeamsForTesting(nil, "", "", leaseFile4, leaseFile6)
			return m
		},
	}
	want4 := fmt.Sprintf("Subnet ID: %d", ids4["10.0.1.0/24"])
	want6 := fmt.Sprintf("Subnet ID: %d", ids6["2001:db8:1::/64"])
	return c, want4, want6
}

func TestShowDHCPServerDetail_LocalCLIRendersPoolFields_15694(t *testing.T) {
	c, wantID4, wantID6 := detail15694CLI(t)

	out := captureStdout(t, func() {
		if err := c.showDHCPServer(true); err != nil {
			t.Fatalf("showDHCPServer(true): %v", err)
		}
	})

	// Sorted group order (fixture authors zeta before alpha).
	if ia, iz := strings.Index(out, "Group: alpha"), strings.Index(out, "Group: zeta"); ia < 0 || iz < 0 || ia > iz {
		t.Errorf("v4 groups not in sorted order (alpha idx %d, zeta idx %d):\n%s", ia, iz, out)
	}
	if ia, iz := strings.Index(out, "Group: alpha6"), strings.Index(out, "Group: zeta6"); ia < 0 || iz < 0 || ia > iz {
		t.Errorf("v6 groups not in sorted order (alpha6 idx %d, zeta6 idx %d):\n%s", ia, iz, out)
	}

	for _, want := range []string{
		// DHCPv4 pool fields previously omitted.
		"Domain: alpha.example",
		"Static binding: 00:11:22:33:44:55 fixed-address 10.0.1.50 hostname printer",
		"Static binding: aa:bb:cc:dd:ee:ff fixed-address 10.0.1.51",
		"Domain: zeta.example",
		// Kea subnet-id beside each pool (computed, not hardcoded).
		wantID4, wantID6,
		// DHCPv6 pool fields previously omitted (only Subnet/Range printed).
		"DNS: 2001:db8:1::53, 2001:db8:1::54",
		"Domain: alpha6.example",
		"Lease time: 3600s",
		"Static binding: 00:11:22:33:44:66 fixed-address 2001:db8:1::50 hostname v6host",
		"DNS: 2001:db8:2::53",
		"Domain: zeta6.example",
		"Lease time: 7200s",
		// Pre-existing fields must not regress.
		"Subnet: 10.0.1.0/24",
		"Range: 10.0.1.100 - 10.0.1.199",
		"Router: 10.0.1.1",
		"DNS: 10.0.1.53, 10.0.1.54",
		"Lease time: 3600s",
		"Subnet: 2001:db8:1::/64",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("local detail output missing %q:\n%s", want, out)
		}
	}
}
