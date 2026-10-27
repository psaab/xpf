package networkd

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// #17857: shared host-safety scaffolding for the real-systemd netns
// probes (the #14594 survival harness and the #16797 parity cell).
// Both probes run as root on privileged legs and start the real
// systemd-udevd/systemd-networkd, so their cleanup is a host-safety
// surface: the historical shape recorded only the networkd pid and
// swept udevd away with a host-wide `pkill systemd-udevd`, which —
// without a PID namespace — also terminates the HOST's udev daemon and
// every other visible process of that name (the 2026-10-26
// host-isolation class: a test that flips from SKIP to REAL EFFECT the
// moment it runs privileged).
//
// The scaffolding makes the probes safe by construction, in depth:
//
//   - netnsProbeUnshareArgs17857 adds `-p --fork --mount-proc`, so the
//     probe runs as PID 1 of its own PID namespace with a matching
//     fresh /proc. Processes inside that namespace can neither see nor
//     signal host processes, and when PID 1 exits the kernel SIGKILLs
//     every process left in the namespace — so probe-owned daemons
//     (including udevd workers) are always reaped, even when the probe
//     dies midway. --mount-proc is REQUIRED with -p: /proc of the
//     parent namespace still lists host pids, which kill(2) would
//     reinterpret as namespace-relative ids.
//   - netnsProbeGuard17857 makes the script refuse (loudly, exit 99)
//     unless it really is PID 1 of a PID namespace, so a reverted
//     unshare line fails the test instead of reaching the host.
//   - netnsProbeDaemons17857 records BOTH daemon pids; the cleanup
//     kills and waits for exactly those two pids. No name-based kill
//     exists anywhere.
//
// TestNetnsProbeCleanupIsScoped17857 pins all of this; reverting any
// leg reds it.
//
// Host-isolation class (2026-10-26 directive): R/F — root + real
// systemd daemons. On the workstation the probes skip (non-root);
// the privileged run belongs to the standalone Incus VM leg only.

// netnsProbeUnshareArgs17857 returns the unshare(1) flags every
// real-systemd probe runs under. -n/-m give the private netns and
// mount ns as before; -p --fork --mount-proc add the PID namespace
// with a fresh /proc that makes the probe host-safe (see above).
func netnsProbeUnshareArgs17857() []string {
	return []string{"-n", "-m", "-p", "--fork", "--mount-proc", "--propagation", "private"}
}

// netnsProbeCommand17857 builds the unshare command every probe runs.
func netnsProbeCommand17857(inner string) *exec.Cmd {
	return exec.Command("unshare", append(netnsProbeUnshareArgs17857(), "bash", "-c", inner)...)
}

// netnsProbeGuard17857 is the first executable statement of every
// probe script: with the flags above, the probe is PID 1 of its own
// PID namespace; any other pid means the containment is gone, and the
// script must refuse rather than touch anything host-visible.
const netnsProbeGuard17857 = `[ "$$" -eq 1 ] || { echo "PROBE REFUSED: not PID-namespace contained (bash PID $$, want 1)" >&2; exit 99; }`

// netnsProbeDaemons17857 starts the probe's own udevd and networkd
// with BOTH pids recorded (the historical shape recorded only the
// networkd pid and swept udevd by name), then waits for networkd's
// varlink socket.
const netnsProbeDaemons17857 = `/lib/systemd/systemd-udevd > /probe-nets/udevd.log 2>&1 &
UPID=$!
/lib/systemd/systemd-networkd > /probe-nets/networkd.log 2>&1 &
NPID=$!
for i in $(seq 1 30); do [ -S /run/systemd/netif/io.systemd.Network ] && break; sleep 0.5; done`

// netnsProbeCleanup17857 terminates exactly the two daemons this
// script started, by recorded pid — never by name. udevd worker
// children that outlive their parent are reaped by the kernel when
// PID 1 (this script) exits.
const netnsProbeCleanup17857 = `kill "$NPID" "$UPID" 2>/dev/null
wait "$NPID" "$UPID" 2>/dev/null`

// netnsProbeScript17857 assembles a probe script from the host-safety
// scaffolding (refuse guard, scoped cleanup) around the probe-specific
// setup (mounts, config copy, daemon start via netnsProbeDaemons17857)
// and body.
func netnsProbeScript17857(setup, body string) string {
	return "#!/bin/bash\nset -u\n" +
		netnsProbeGuard17857 + "\n" +
		strings.Trim(setup, "\n") + "\n" +
		strings.Trim(body, "\n") + "\n" +
		netnsProbeCleanup17857 + "\n" +
		"exit $fail\n"
}

// parityProbeScript16797 returns the exact script the #16797 parity
// probe executes (both scenarios share it; only the installed
// 05-ext.network differs).
func parityProbeScript16797() string {
	return netnsProbeScript17857(`
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /etc/systemd/network
mkdir -p /run/systemd/network
cp /probe-nets/05-ext.network /etc/systemd/network/
`+netnsProbeDaemons17857+`
sleep 1
`, `
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
`)
}

// dhcpSurvivalProbeScript14594 returns the exact script the #14594
// lease-survival probe executes.
func dhcpSurvivalProbeScript14594() string {
	return netnsProbeScript17857(`
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /etc/systemd/network
mkdir -p /run/systemd/network
cp /probe-nets/*.network /etc/systemd/network/
`+netnsProbeDaemons17857+`
sleep 2
`, `
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
`)
}

// TestNetnsProbeCleanupIsScoped17857 is the fail-on-revert guard for
// the host safety of the real-systemd netns probes (#17857): it reds
// if any probe regresses to host-wide process termination — a
// name-based kill (pkill/killall), a missing PID namespace, a stale
// host /proc (no --mount-proc), an unrecorded daemon pid, or a missing
// refuse-when-uncontained guard. Pure source shape: it runs
// unprivileged everywhere; the probes themselves are the privileged
// VM leg.
func TestNetnsProbeCleanupIsScoped17857(t *testing.T) {
	args := netnsProbeUnshareArgs17857()
	has := func(f string) bool { return slices.Contains(args, f) }
	for _, f := range []string{"-n", "-m", "--fork", "--mount-proc", "--propagation", "private"} {
		if !has(f) {
			t.Errorf("unshare args missing %s: probes must run in their own PID namespace with a fresh /proc", f)
		}
	}
	if !has("-p") && !has("--pid") {
		t.Errorf("unshare args create no PID namespace: name-matched cleanup could reach host processes")
	}

	cmd := netnsProbeCommand17857("echo hi")
	if len(cmd.Args) < 4 || cmd.Args[0] != "unshare" {
		t.Fatalf("unexpected probe command %v", cmd.Args)
	}
	for _, f := range []string{"--fork", "--mount-proc"} {
		if !slices.Contains(cmd.Args[1:], f) {
			t.Errorf("executed unshare command missing %s", f)
		}
	}
	if !(slices.Contains(cmd.Args[1:], "-p") || slices.Contains(cmd.Args[1:], "--pid")) {
		t.Errorf("executed unshare command creates no PID namespace")
	}
	if tail := cmd.Args[len(cmd.Args)-3:]; !slices.Equal(tail, []string{"bash", "-c", "echo hi"}) {
		t.Errorf("probe command tail = %v, want bash -c <inner>", tail)
	}

	for name, script := range map[string]string{
		"parity16797":   parityProbeScript16797(),
		"survival14594": dhcpSurvivalProbeScript14594(),
	} {
		for _, forbidden := range []string{"pkill", "killall"} {
			if strings.Contains(script, forbidden) {
				t.Errorf("%s: script contains host-wide name kill %q", name, forbidden)
			}
		}
		guardAt := strings.Index(script, `[ "$$" -eq 1 ] ||`)
		if guardAt < 0 {
			t.Fatalf("%s: no PID-namespace refuse guard in script", name)
		}
		if !strings.Contains(script, "PROBE REFUSED") || !strings.Contains(script, "exit 99") {
			t.Errorf("%s: refuse guard must fail loudly (PROBE REFUSED + exit 99)", name)
		}
		if daemonAt := strings.Index(script, "/lib/systemd/systemd-udevd"); daemonAt >= 0 && daemonAt < guardAt {
			t.Errorf("%s: refuse guard must run before any daemon start", name)
		}
		if mountAt := strings.Index(script, "mount "); mountAt >= 0 && mountAt < guardAt {
			t.Errorf("%s: refuse guard must run before any mount", name)
		}
		if !strings.Contains(script, "UPID=$!") || !strings.Contains(script, "NPID=$!") {
			t.Errorf("%s: probe must record BOTH daemon pids (UPID for udevd, NPID for networkd)", name)
		}
		if !strings.Contains(script, `kill "$NPID" "$UPID"`) {
			t.Errorf("%s: cleanup must kill exactly the two recorded daemon pids", name)
		}
		if !strings.Contains(script, `wait "$NPID" "$UPID"`) {
			t.Errorf("%s: cleanup must wait for exactly the two recorded daemon pids", name)
		}
		if killAt := strings.Index(script, `kill "$NPID" "$UPID"`); killAt < guardAt {
			t.Errorf("%s: cleanup must come after the guard", name)
		}
	}
}
