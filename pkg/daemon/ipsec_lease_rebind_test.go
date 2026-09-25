package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ipsec"
)

// leaseRebindConfig builds a config with one IPsec gateway bound to the
// wan0.0 external interface. dhcp marks the unit DHCP-managed (so the
// #2884 scoping gate fires) and addr (CIDR) gives a deterministic
// configured address that PrepareConfig resolves into local_addrs in CI
// without a real lease.
func leaseRebindConfig(dhcp bool, addr string) *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"wan0": {
					Name: "wan0",
					Units: map[int]*config.InterfaceUnit{
						0: {DHCP: dhcp, PrimaryAddress: addr, Addresses: []string{addr}},
					},
				},
			},
		},
		Security: config.SecurityConfig{
			IPsec: config.IPsecConfig{
				Gateways: map[string]*config.IPsecGateway{
					"gw": {Name: "gw", Address: "203.0.113.1", ExternalIface: "wan0.0"},
				},
				VPNs: map[string]*config.IPsecVPN{
					"tun": {Gateway: "gw"},
				},
			},
		},
	}
}

func readSwanctl(t *testing.T, dir string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ipsec.BPFRXConfFile))
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatalf("read swanctl conf: %v", err)
	}
	return string(b), true
}

// TestReapplyIPsecForLeaseChange_RebindsLocalAddr proves the #2884 fix:
// a DHCP lease change on an IPsec-bound interface re-renders swanctl with
// the NEW local_addrs. Fail-on-revert anchor — deleting the
// ipsec.Apply call (or the HasDHCPBoundGateway-gated branch) in
// reapplyIPsecForLeaseChange makes the second assertion go RED because the
// stale address is retained / the file is never written. The swanctl seam
// reports reload success so the assertions inspect a successfully applied
// config rather than the transient file from a failed reload.
func TestReapplyIPsecForLeaseChange_RebindsLocalAddr(t *testing.T) {
	dir := t.TempDir()
	m := ipsec.NewWithConfigDir(dir)
	m.SetSwanctlForTesting(func(args ...string) ([]byte, error) { return nil, nil })
	d := &Daemon{
		ipsec:    m,
		applySem: semaphore.NewWeighted(1),
	}
	d.reapplyIPsecForLeaseChange(leaseRebindConfig(true, "198.51.100.7/24"))
	got, ok := readSwanctl(t, dir)
	if !ok {
		t.Fatal("swanctl config not written on first lease change")
	}
	if !strings.Contains(got, "local_addrs = 198.51.100.7") {
		t.Fatalf("first render missing local_addrs:\n%s", got)
	}

	// DHCP renew to a new lease address.
	d.reapplyIPsecForLeaseChange(leaseRebindConfig(true, "203.0.113.42/24"))
	got, _ = readSwanctl(t, dir)
	if !strings.Contains(got, "local_addrs = 203.0.113.42") {
		t.Fatalf("re-render did not pick up the new lease address:\n%s", got)
	}
	if strings.Contains(got, "local_addrs = 198.51.100.7") {
		t.Fatalf("re-render retained the stale local_addrs:\n%s", got)
	}
}

// TestReapplyIPsecForLeaseChange_NoBoundGatewayIsNoOp proves the scoping
// guard: a lease change on an interface NO IPsec gateway dynamically
// binds to does not touch swanctl (no reload storm, no SA churn).
func TestReapplyIPsecForLeaseChange_NoBoundGatewayIsNoOp(t *testing.T) {
	dir := t.TempDir()
	d := &Daemon{
		ipsec:    ipsec.NewWithConfigDir(dir),
		applySem: semaphore.NewWeighted(1),
	}

	// Gateway exists but its interface is not DHCP-managed, so the lease
	// change is irrelevant to its local bind.
	d.reapplyIPsecForLeaseChange(leaseRebindConfig(false, "198.51.100.7/24"))
	if _, ok := readSwanctl(t, dir); ok {
		t.Fatal("swanctl config written for a lease change on a non-IPsec-bound interface")
	}
}
