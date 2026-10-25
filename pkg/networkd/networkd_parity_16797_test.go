package networkd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// #16797: the decisive parity check. The #14701 fix encoded two
// code-derived semantics that were never checked against real
// systemd-networkd: (1) a run of leading "!" on a Name= word collapses
// to one negation, so Name=!eth0 !eth1 vetoes both names; (2) an
// IP-literal MACAddress= word is dropped. systemd 262 does neither:
// net_condition_test_strv strips exactly one "!" (so the parser-stored
// "!!eth1" is a negated pattern "!eth1" that matches nothing and eth1
// is NOT vetoed), and config_parse_hw_addrs → parse_hw_addr_full(word,
// 0) accepts IPv4/IPv6 literals as 4/16-byte tunnel hardware addresses
// (gre1's local 192.0.2.1, shown by networkctl as c0:00:02:01).
//
// This test installs BOTH probe files from the issue into a private
// netns running the real systemd-udevd + systemd-networkd 262 (the
// dhcp_keep_survival_14594 harness shape), reads networkd's own
// verdict per interface from `networkctl status` ("Network File:"),
// and asserts xpf's FindExternallyManaged verdict for the SAME files
// agrees on every interface: eth0/eth1/eth2 for the negated-Name file,
// gre1/eth9 for the IP-literal file — plus the cross cells, so a
// vacuous probe (nothing configured, or everything configured) cannot
// green it. The interface hardware strings fed to Matches are the
// kernel shapes the production callers pass: netlink
// HardwareAddr.String() — dummy MACs read live inside the netns, and
// the gre tunnel's "192.0.2.1" (HardwareAddr.String() of a 4-byte
// address).
//
// FAIL-ON-REVERT: restoring the "!"-run collapse makes xpf veto eth1
// while networkd configures it; restoring the IP-literal rejection
// makes xpf ignore the MAC file while networkd configures gre1. Both
// flip a cell here (and in negated_match_14701_test.go).
//
// Skips (not fails) when the probe cannot run: no root/CAP_SYS_ADMIN
// for unshare, or no systemd-udevd/systemd-networkd/networkctl/ip.
// Under XPF_REQUIRE_NETNS a missing prerequisite is a failure instead,
// matching the daemon netns cells' contract.
func TestExternalMatchParityWithRealNetworkd16797(t *testing.T) {
	require := os.Getenv("XPF_REQUIRE_NETNS") != ""
	if os.Geteuid() != 0 {
		if require {
			t.Fatal("requires root for unshare netns probe (XPF_REQUIRE_NETNS is set)")
		}
		t.Skip("requires root for unshare netns probe")
	}
	for _, bin := range []string{"unshare", "ip", "networkctl"} {
		if _, err := exec.LookPath(bin); err != nil {
			if require {
				t.Fatalf("missing %s (XPF_REQUIRE_NETNS is set)", bin)
			}
			t.Skipf("missing %s", bin)
		}
	}
	for _, p := range []string{"/lib/systemd/systemd-networkd", "/lib/systemd/systemd-udevd"} {
		if _, err := os.Stat(p); err != nil {
			if require {
				t.Fatalf("missing %s (XPF_REQUIRE_NETNS is set)", p)
			}
			t.Skipf("missing %s", p)
		}
	}

	scenarios := []struct {
		name string
		body string
	}{
		{name: "neg", body: "[Match]\nName=!eth0 !eth1\n\n[Network]\nDHCP=yes\nLinkLocalAddressing=no\n"},
		{name: "ip", body: "[Match]\nMACAddress=192.0.2.1\n\n[Network]\nDHCP=yes\nLinkLocalAddressing=no\n"},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			xpfDir := t.TempDir()
			writeExternalNetwork12135(t, xpfDir, "05-ext.network", sc.body)
			set := FindExternallyManaged(xpfDir)

			probeDir := t.TempDir()
			writeExternalNetwork12135(t, probeDir, "05-ext.network", sc.body)
			script := `#!/bin/bash
set -u
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /etc/systemd/network
mkdir -p /run/systemd/network
cp /probe-nets/05-ext.network /etc/systemd/network/
/lib/systemd/systemd-udevd > /probe-nets/udevd.log 2>&1 &
/lib/systemd/systemd-networkd > /probe-nets/networkd.log 2>&1 &
NPID=$!
for i in $(seq 1 30); do [ -S /run/systemd/netif/io.systemd.Network ] && break; sleep 0.5; done
sleep 1
for d in eth0 eth1 eth2 eth9; do ip link add $d type dummy; ip link set $d up; done
ip tunnel add gre1 mode gre local 192.0.2.1 remote 192.0.2.2; ip link set gre1 up
sleep 4
fail=0
for d in eth0 eth1 eth2 gre1 eth9; do
  f=$(networkctl --no-pager status $d 2>/dev/null | grep -m1 "Network File:" || true)
  case "$f" in *05-ext.network*) verdict=configured;; *) verdict=unmanaged;; esac
  mac=$(cat /sys/class/net/$d/address)
  echo "VERDICT $d $verdict $mac"
done
cat /probe-nets/networkd.log
kill $NPID 2>/dev/null; pkill systemd-udevd 2>/dev/null; wait 2>/dev/null
exit $fail
`
			scriptPath := filepath.Join(probeDir, "probe.sh")
			if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			inner := "mkdir -p /probe-nets; mount --bind " + probeDir + " /probe-nets; exec /probe-nets/probe.sh"
			cmd := exec.Command("unshare", "-n", "-m", "--propagation", "private", "bash", "-c", inner)
			out, err := cmd.CombinedOutput()
			t.Logf("netns parity probe (%s) output:\n%s", sc.name, out)
			if err != nil {
				t.Fatalf("parity probe failed: %v", err)
			}

			verdicts := map[string]bool{}
			macs := map[string]string{}
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 4 && fields[0] == "VERDICT" {
					verdicts[fields[1]] = fields[2] == "configured"
					macs[fields[1]] = fields[3]
				}
			}
			for _, d := range []string{"eth0", "eth1", "eth2", "gre1", "eth9"} {
				if _, ok := verdicts[d]; !ok {
					t.Fatalf("probe reported no verdict for %s", d)
				}
			}
			// Fixed expectations from systemd 262 source + the issue's
			// executed probes: these pin the probe itself, so a broken
			// environment (no file applied anywhere, or match-all)
			// fails instead of silently agreeing with a broken xpf.
			wantNet := map[string]map[string]bool{
				"neg": {"eth0": false, "eth1": true, "eth2": true, "gre1": true, "eth9": true},
				"ip":  {"eth0": false, "eth1": false, "eth2": false, "gre1": true, "eth9": false},
			}[sc.name]
			for d, want := range wantNet {
				if verdicts[d] != want {
					t.Errorf("networkd verdict for %s = %v, want %v (scenario %s)", d, verdicts[d], want, sc.name)
				}
			}
			// xpf must agree with networkd on every interface. The
			// mac string is the production caller shape: dummy MACs
			// as read live; the gre tunnel's 4-byte address string
			// form is "192.0.2.1" (not the /sys colon-hex form).
			for _, d := range []string{"eth0", "eth1", "eth2", "gre1", "eth9"} {
				mac := macs[d]
				if d == "gre1" {
					mac = "192.0.2.1"
				}
				if got := set.Matches(d, mac); got != verdicts[d] {
					t.Errorf("xpf Matches(%q, %q) = %v, networkd verdict = %v (scenario %s)", d, mac, got, verdicts[d], sc.name)
				}
				if got := set.MatchesForApply(d, mac); got != verdicts[d] {
					t.Errorf("xpf MatchesForApply(%q, %q) = %v, networkd verdict = %v (scenario %s)", d, mac, got, verdicts[d], sc.name)
				}
			}
		})
	}
}
