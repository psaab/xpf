package dataplane

import (
	"sort"
	"testing"

	"golang.org/x/sys/unix"
)

// #8637: the per-interface `proxy_arp` sysctl is no longer enabled for IPv4,
// and `proxy_ndp` still is for IPv6. See proxyResponderSysctlEnabledFor for the
// derivation and the measurement; this pins the resulting behaviour.

func writesFor(got []sysctlWrite, family int) []sysctlWrite {
	var out []sysctlWrite
	for _, w := range got {
		if w.family == family {
			out = append(out, w)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].iface < out[j].iface })
	return out
}

// The narrowing itself, and its exact shape: on the ENABLE pass, v4 is written
// FALSE and v6 TRUE.
//
// v4 is written false rather than skipped on purpose. Skipping would leave a
// stale `proxy_arp=1` on every interface an older build had already set it on —
// so the over-answer would survive this change on precisely the deployments
// that have it today.
//
// RED ON REVERT: make proxyResponderSysctlEnabledFor return true for AF_INET
// and the v4 half fails; drop the v6 arm and the v6 half fails.
func TestTheEnablePassTurnsV4OffAndV6On8637(t *testing.T) {
	got := captureProxySysctl(t, false)
	enableProxyResponders(map[string]map[int]struct{}{
		"ge-0-0-2.80": {unix.AF_INET: {}, unix.AF_INET6: {}},
	})

	v4 := writesFor(*got, unix.AF_INET)
	if len(v4) != 1 {
		t.Fatalf("v4 writes = %d, want exactly 1 (the interface must still be "+
			"written, to 0 — skipping it leaves a stale proxy_arp=1 across an "+
			"upgrade): %+v", len(v4), *got)
	}
	if v4[0].enable {
		t.Errorf("proxy_arp was ENABLED for v4. That sysctl's only distinct " +
			"contribution is answering ARP for addresses nobody configured — it " +
			"cannot answer for a same-subnet proxied address (arp_fwd_proxy " +
			"returns 0 on rt->dst.dev == dev before reading it), and the pneigh " +
			"arm answers different-device targets without it. Measured both ways " +
			"on hardware; see proxyResponderSysctlEnabledFor")
	}

	v6 := writesFor(*got, unix.AF_INET6)
	if len(v6) != 2 {
		t.Fatalf("proxy_ndp writes = %+v, want per-interface and all-interface writes", v6)
	}
	if v6[0].iface != "all" || !v6[0].enable || v6[1].iface != "ge-0-0-2.80" || !v6[1].enable {
		t.Fatalf("proxy_ndp writes = %+v, want all and per-interface enables", v6)
	}
}

// The teardown path is unchanged: #2475's disable must still write 0 for BOTH
// families when an interface drops out of the config.
//
// Without this, a change that made v4 "always false" by short-circuiting the
// whole write would satisfy the cell above while silently removing the v6
// teardown, leaving proxy_ndp latched on across a config removal — the exact
// leak #2475 was filed for.
func TestTheDisablePassStillClearsBothFamilies8637(t *testing.T) {
	got := captureProxySysctl(t, false)
	disableProxyResponders(map[string]map[int]struct{}{
		"ge-0-0-2.80": {unix.AF_INET: {}, unix.AF_INET6: {}},
	})
	if len(*got) != 2 {
		t.Fatalf("teardown wrote %d sysctls, want 2 (v4 and v6): %+v", len(*got), *got)
	}
	for _, w := range *got {
		if w.enable {
			t.Errorf("teardown ENABLED family %d on %s; #2475 requires both driven "+
				"to 0 when the entry leaves the config", w.family, w.iface)
		}
	}
}

// The predicate alone, so a mutation of it is attributable without going
// through the iteration.
func TestOnlyIPv6KeepsItsResponderSysctl8637(t *testing.T) {
	if proxyResponderSysctlEnabledFor(unix.AF_INET) {
		t.Error("AF_INET: want false — the v4 sysctl contributes only the over-answer")
	}
	if !proxyResponderSysctlEnabledFor(unix.AF_INET6) {
		t.Error("AF_INET6: want true — proxy_ndp is a required conjunct for v6")
	}
}
