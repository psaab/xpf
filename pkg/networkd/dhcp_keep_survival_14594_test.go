package networkd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// #14594 (reopened): the shipped unit test pinned the rendered string
// KeepConfiguration=dhcp, but the acceptance is that the daemon's DHCP
// lease address SURVIVES `networkctl reconfigure`. Live systemd 262
// netns probes proved `dhcp` preserves only finite-lifetime foreign
// addresses and strips a forever-lifetime one (an infinite lease, and
// a zero/expired lifetime, both install as forever via pkg/dhcp
// kernelAddrLifetimes), while `static` does the mirror image — so the
// string test passed while the lease still died. This test exercises
// the decisive check: it renders the real .network files via
// generateNetwork, installs foreign addresses in a private netns in
// exactly the kernel shapes pkg/dhcp applyAddress produces, runs the
// real systemd-networkd 262 `networkctl reconfigure`, and asserts
// survival — with fixed controls (static+forever survives, yes+
// lifetime survives, no-keep+lifetime is stripped) that must pass in
// every run so a vacuous environment cannot green the test.
//
// FAIL-ON-REVERT: revert keepConfigurationValue to emit `dhcp` for
// DHCP-only rows and the DHCP victim loses its forever address here
// (PROBE FAIL), while the string-only test would still need its own
// expectation changed to notice.
//
// Skips (not fails) when the probe cannot run: no root/CAP_SYS_ADMIN
// for unshare, or no systemd-udevd/systemd-networkd/networkctl/ip.
func TestDHCPLeaseSurvivesReconfigureNetns14594(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for unshare netns probe")
	}
	for _, bin := range []string{"unshare", "ip", "networkctl"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("missing %s: %v", bin, err)
		}
	}
	for _, p := range []string{"/lib/systemd/systemd-networkd", "/lib/systemd/systemd-udevd"} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("missing %s: %v", p, err)
		}
	}

	m := New()
	dir := t.TempDir()
	rows := map[string]InterfaceConfig{
		// Victim: daemon-DHCP-only row, the #14594 shape. Its rendered
		// KeepConfiguration value is whatever the fix under test emits.
		"dum0": {Name: "dum0", DHCPv4: true},
		// Fixed controls, independent of the fix:
		"dum1": {Name: "dum1", KeepAddresses: true, Addresses: []string{"192.0.2.10/24"}},
		"dum2": {Name: "dum2", KeepAddresses: true, DHCPv4: true, Addresses: []string{"192.0.2.10/24"}},
		"dum3": {Name: "dum3"},
	}
	for name, ifc := range rows {
		content := m.generateNetwork(ifc)
		// dum2/dum3 controls need fixed keep classes regardless of the
		// DHCP composition under test: force dum2=yes, dum3=none by
		// rewriting only the control files.
		if name == "dum2" {
			content = forceKeep(t, content, "yes")
		}
		if name == "dum3" {
			content = forceKeep(t, content, "")
		}
		if err := os.WriteFile(filepath.Join(dir, "10-xpf-"+name+".network"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		// The victim file is logged so a failure shows the exact value
		// that was live-tested.
		if name == "dum0" {
			t.Logf("victim dum0 .network:\n%s", content)
			if !strings.Contains(content, "KeepConfiguration=") {
				t.Fatalf("DHCP row renders no KeepConfiguration:\n%s", content)
			}
		}
	}

	script := `#!/bin/bash
set -u
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /etc/systemd/network
mkdir -p /run/systemd/network
cp /probe-nets/*.network /etc/systemd/network/
/lib/systemd/systemd-udevd > /probe-nets/udevd.log 2>&1 &
/lib/systemd/systemd-networkd > /probe-nets/networkd.log 2>&1 &
NPID=$!
for i in $(seq 1 30); do [ -S /run/systemd/netif/io.systemd.Network ] && break; sleep 0.5; done
sleep 2
for d in dum0 dum1 dum2 dum3; do ip link add $d type dummy; ip link set $d up; done
sleep 4
for d in dum0 dum1 dum2 dum3; do
  ip addr add 192.0.2.10/24 valid_lft 3600 preferred_lft 3600 dev $d
  ip addr add 2001:db8::10/64 valid_lft 3600 preferred_lft 3600 dev $d
done
ip addr del 192.0.2.10/24 dev dum1; ip addr del 2001:db8::10/64 dev dum1
ip addr add 192.0.2.10/24 dev dum1; ip addr add 2001:db8::10/64 dev dum1
ip addr add 192.0.2.11/24 dev dum0
networkctl --no-pager reconfigure -- dum0 dum1 dum2 dum3 || exit 2
sleep 3
fail=0
check() { d=$1; want=$2; got=$(ip -o addr show dev $d | grep -v fe80 | grep -c inet || true); echo "$d non-LL=$got want=$want"; [ "$got" = "$want" ] || fail=1; }
check dum0 3; check dum1 2; check dum2 2; check dum3 0
kill $NPID 2>/dev/null; pkill systemd-udevd 2>/dev/null; wait 2>/dev/null
exit $fail
`
	scriptPath := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	inner := "mkdir -p /probe-nets; mount --bind " + dir + " /probe-nets; exec /probe-nets/probe.sh"
	cmd := exec.Command("unshare", "-n", "-m", "--propagation", "private", "bash", "-c", inner)
	out, err := cmd.CombinedOutput()
	t.Logf("netns probe output:\n%s", out)
	if err != nil {
		// Controls are asserted inside the probe; any non-zero exit
		// (victim stripped OR control broken OR reconfigure failed)
		// is a test failure, not a skip — the environment was already
		// gated above.
		t.Fatalf("lease survival probe failed: %v", err)
	}
}

// forceKeep rewrites the single KeepConfiguration line in a rendered
// control file to the fixed class ("" removes it).
func forceKeep(t *testing.T, content, val string) string {
	t.Helper()
	lines := strings.Split(content, "\n")
	out := lines[:0]
	seen := false
	for _, ln := range lines {
		if strings.HasPrefix(ln, "KeepConfiguration=") {
			seen = true
			if val != "" {
				out = append(out, "KeepConfiguration="+val)
			}
			continue
		}
		out = append(out, ln)
	}
	if !seen && val != "" {
		// Insert after IPv6AcceptRA to keep [Network] shape.
		res := make([]string, 0, len(out)+1)
		for _, ln := range out {
			res = append(res, ln)
			if ln == "IPv6AcceptRA=no" {
				res = append(res, "KeepConfiguration="+val)
			}
		}
		out = res
	}
	return strings.Join(out, "\n")
}
