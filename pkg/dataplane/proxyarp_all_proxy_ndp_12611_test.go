package dataplane

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// #12611: all.proxy_ndp must be written for IPv6 proxy NDP. When the FIB
// routes a forwarded unicast NUD probe back out the proxy interface, the
// kernel's forwarded-NS path consults net.ipv6.conf.all.proxy_ndp, not only
// the per-interface sysctl; with all.proxy_ndp=0 the probe egressed (hop
// limit 255->254) and no proxy NA came back, so the upstream neighbour
// entry went FAILED. With all.proxy_ndp=1 the proxy replied.

func countFor(got []sysctlWrite, iface string, family int) []sysctlWrite {
	var out []sysctlWrite
	for _, w := range got {
		if w.iface == iface && w.family == family {
			out = append(out, w)
		}
	}
	return out
}

// On the ENABLE pass, one IPv6 interface yields BOTH the per-interface
// write AND exactly one all write, both enable=true, with the all write
// AFTER the per-interface write (all is the only write whose target is
// the literal "all" interface).
func TestEnableV6WritesAllProxyNDP12611(t *testing.T) {
	got := captureProxySysctl(t, false)
	enableProxyResponders(map[string]map[int]struct{}{
		"ge-0-0-1": {unix.AF_INET6: {}},
	})
	if len(*got) != 2 {
		t.Fatalf("got %d writes, want 2 (per-interface + all): %+v", len(*got), *got)
	}
	if (*got)[0].iface != "ge-0-0-1" || (*got)[0].family != unix.AF_INET6 || !(*got)[0].enable {
		t.Fatalf("first write = %+v, want {ge-0-0-1 AF_INET6 enable}", (*got)[0])
	}
	if (*got)[1].iface != "all" || (*got)[1].family != unix.AF_INET6 || !(*got)[1].enable {
		t.Fatalf("second write = %+v, want {all AF_INET6 enable}: %+v", (*got)[1], *got)
	}
}

// IPv4-only entries must never touch the v6 all sysctl.
func TestEnableV4OnlyWritesNoAllProxyNDP12611(t *testing.T) {
	got := captureProxySysctl(t, false)
	enableProxyResponders(map[string]map[int]struct{}{
		"ge-0-0-1": {unix.AF_INET: {}},
	})
	if len(countFor(*got, "all", unix.AF_INET6)) != 0 {
		t.Fatalf("v4-only enable wrote all.proxy_ndp: %+v", *got)
	}
	if len(countFor(*got, "all", unix.AF_INET)) != 0 {
		t.Fatalf("v4-only enable wrote all.proxy_arp: %+v", *got)
	}
}

// Two IPv6 interfaces: still exactly ONE all write, after the last
// per-interface write (the all write must not interleave with or repeat
// per interface).
func TestEnableMultiIfaceV6WritesAllOnce12611(t *testing.T) {
	got := captureProxySysctl(t, false)
	enableProxyResponders(map[string]map[int]struct{}{
		"ge-0-0-2": {unix.AF_INET6: {}},
		"ge-0-0-1": {unix.AF_INET6: {}},
	})
	all := countFor(*got, "all", unix.AF_INET6)
	if len(all) != 1 || !all[0].enable {
		t.Fatalf("all.proxy_ndp writes = %+v, want exactly one enable: %+v", all, *got)
	}
	if (*got)[len(*got)-1].iface != "all" {
		t.Fatalf("the all write is not last: %+v", *got)
	}
	if len(*got) != 3 {
		t.Fatalf("got %d writes, want 3 (2 per-interface + 1 all): %+v", len(*got), *got)
	}
}

// The disable pass for an IPv6 interface clears the per-interface write
// but must NOT clear all.proxy_ndp: the diff it serves is per-interface
// removal while other interfaces may still run proxy NDP, and xpf only
// clears state it exclusively owns. A disable that wrote all=0 would
// silently break every other proxy-NDP user on the node (and any
// operator-set expectation).
func TestDisableV6DoesNotTouchAllProxyNDP12611(t *testing.T) {
	got := captureProxySysctl(t, false)
	disableProxyResponders(map[string]map[int]struct{}{
		"ge-0-0-1": {unix.AF_INET6: {}},
	})
	if len(countFor(*got, "all", unix.AF_INET6)) != 0 || len(countFor(*got, "all", unix.AF_INET)) != 0 {
		t.Fatalf("disable pass wrote an all write: %+v", *got)
	}
	if len(*got) != 1 || (*got)[0].enable {
		t.Fatalf("disable pass writes = %+v, want one per-interface disable", *got)
	}
}

// A write failure on the all write must not drop the per-interface count
// and must not allocate the failure as a success: the returned count
// counts only successful writes, so it is 1 when the all write fails.
func TestEnableV6AllWriteFailureCountsOnlySuccess12611(t *testing.T) {
	prev := proxyARPSysctlSeam
	defer func() { proxyARPSysctlSeam = prev }()
	var calls []sysctlWrite
	proxyARPSysctlSeam = func(iface string, family int, enable bool) error {
		calls = append(calls, sysctlWrite{iface, family, enable})
		if iface == "all" {
			return errors.New("all.proxy_ndp failed")
		}
		return nil
	}
	n := enableProxyResponders(map[string]map[int]struct{}{
		"ge-0-0-1": {unix.AF_INET6: {}},
	})
	if n != 1 {
		t.Fatalf("enabled count = %d, want 1 (only the per-interface write succeeded): calls=%+v", n, calls)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %+v, want per-interface + all attempted", calls)
	}
}

// Dual-stack: the all write fires iff an IPv6 family is present anywhere:
// once, after all per-interface writes, and IPv4 writes remain untouched.
func TestEnableDualStackWritesAllOnce12611(t *testing.T) {
	got := captureProxySysctl(t, false)
	enableProxyResponders(map[string]map[int]struct{}{
		"ge-0-0-1": {unix.AF_INET: {}, unix.AF_INET6: {}},
		"ge-0-0-2": {unix.AF_INET: {}},
	})
	all := countFor(*got, "all", unix.AF_INET6)
	if len(all) != 1 || !all[0].enable {
		t.Fatalf("all.proxy_ndp writes = %+v, want exactly one enable: %+v", all, *got)
	}
	if (*got)[len(*got)-1].iface != "all" {
		t.Fatalf("the all write is not the last write: %+v", *got)
	}
	// ge-0-0-1 v4(0) v6(1) + ge-0-0-2 v4(0) + all(1) = 4 writes.
	if len(*got) != 4 {
		t.Fatalf("got %d writes, want 4: %+v", len(*got), *got)
	}
}
