package userspace

import (
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// #16241 residual (via #16695): the native-GRE inner classifiers'
// post-session DNAT / interface-NAT / local lookups cannot change any
// disposition. Both consumers of classify_native_gre_inner act only on
// PASS_TO_KERNEL (healthy: `inner_action == PASS_TO_KERNEL` plus a local
// outer; degraded: InnerSessionAction, which likewise only distinguishes
// PASS_TO_KERNEL), so a REDIRECT-or-0 result from those lookups is
// indistinguishable from a plain miss — both keep the outer frame on the
// XSK path. The lookups are removed; this file pins that removal and
// proves by BPF_PROG_TEST_RUN that the dispositions they could never
// change are unchanged.
//
// The classifier bodies live in the no_std shim and cannot be executed
// by a host test, so the dead-lookup removal itself is pinned
// structurally (the same source-pin shape as the shim's other
// verifier-cost invariants): the classifier function bodies must not
// reference the DNAT helpers or the NAT/local maps.

func shimClassifierBody16241(t *testing.T, src, sig string) string {
	t.Helper()
	start := strings.Index(src, sig)
	if start < 0 {
		t.Fatalf("shim source missing %q", sig)
	}
	rest := src[start:]
	// The body ends at the function's closing brace at column 0; taking
	// the next "\nfn " instead would sweep in the inter-function comment
	// block (which legitimately names the retained DNAT maps).
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func TestXDPGREInnerClassifiersHaveNoDeadPostSessionLookups16241(t *testing.T) {
	raw, err := os.ReadFile("../../../userspace-xdp/src/lib.rs")
	if err != nil {
		t.Fatalf("read shim source: %v", err)
	}
	src := string(raw)
	for _, sig := range []string{
		"fn classify_native_gre_inner_ipv4(",
		"fn classify_native_gre_inner_ipv6(",
	} {
		body := shimClassifierBody16241(t, src, sig)
		for _, dead := range []string{
			"dnat_lookup_v4", "dnat_lookup_v6",
			"USERSPACE_INTERFACE_NAT_V4", "USERSPACE_INTERFACE_NAT_V6",
			"USERSPACE_LOCAL_V4", "USERSPACE_LOCAL_V6",
			"DNAT_TABLE",
		} {
			if strings.Contains(body, dead) {
				t.Errorf("%s still references %s: the post-session lookup cannot change any disposition (both consumers act only on PASS_TO_KERNEL) and must not be reintroduced", sig, dead)
			}
		}
		if !strings.Contains(body, "session_action_for_key(&key)") {
			t.Errorf("%s no longer returns the inner session action; the PASS_TO_KERNEL steer is the classifier's only live disposition", sig)
		}
	}
	// The helpers themselves are gone (they had no other caller).
	for _, deadFn := range []string{"fn dnat_lookup_v4(", "fn dnat_lookup_v6("} {
		if strings.Contains(src, deadFn) {
			t.Errorf("shim still defines %s with no caller after the dead-lookup removal", deadFn)
		}
	}
}

// Disposition invariance, executed: a native-GRE packet whose inner
// destination matches ONLY the (now-removed) post-session lookups —
// an interface-NAT row or a local row for the inner
// destination, with NO inner session — took the XSK redirect before the
// removal (classifier REDIRECT == miss to both consumers) and must take
// exactly the same redirect after it. With the harness's empty XSK map
// that is XDP_DROP + redirect_err and never pass_to_kernel. The inner
// PASS_TO_KERNEL control proves the one live steer still works.
func TestXDPGREInnerDeadLookupDispositionsUnchanged16241(t *testing.T) {
	localOuter := [4]byte{192, 0, 2, 1}
	remoteOuter := [4]byte{203, 0, 113, 1}
	innerSrc := [4]byte{10, 0, 0, 1}
	innerDst := [4]byte{198, 51, 100, 9}

	cases := []struct {
		name string
		seed func(*testing.T, *ebpf.Collection)
	}{
		{"inner interface-NAT row only, no session", func(t *testing.T, coll *ebpf.Collection) {
			updateUserspaceXDPTestInterfaceNATV4(t, coll, innerDst)
		}},
		{"inner local row only, no session", func(t *testing.T, coll *ebpf.Collection) {
			updateUserspaceXDPTestLocalV4(t, coll, innerDst)
		}},
		{"no inner state at all (control)", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			seedHealthy16241(t, coll, xdpDispatchNativeGREFlag10864)
			updateUserspaceXDPTestLocalV4(t, coll, localOuter)
			if tc.seed != nil {
				tc.seed(t, coll)
			}
			pkt := xdpDispatchGREIPv4Packet10864(remoteOuter, localOuter, innerSrc, innerDst, 12345, 443)
			if got := runUserspaceXDPTestPacket(t, coll, pkt); got != xdpActionDrop {
				t.Fatalf("XDP action = %d, want %d (XSK redirect attempt on empty XSK map): the removed lookups never kernel-passed, and the packet must stay on the helper path", got, xdpActionDrop)
			}
			assertXDPBranchStat(t, coll, "redirect_err")
			assertXDPBranchStatAbsent(t, coll, "gre_inner_pass_kernel")
		})
	}

	t.Run("inner PASS_TO_KERNEL session still steers to kernel", func(t *testing.T) {
		coll := loadUserspaceXDPTestCollection(t)
		seedHealthy16241(t, coll, xdpDispatchNativeGREFlag10864)
		updateUserspaceXDPTestLocalV4(t, coll, localOuter)
		seedXDPDispatchInnerSession10864(t, coll, innerSrc, innerDst, 12345, 443, xdpDispatchSessionPass10864)
		pkt := xdpDispatchGREIPv4Packet10864(remoteOuter, localOuter, innerSrc, innerDst, 12345, 443)
		if got := runUserspaceXDPTestPacket(t, coll, pkt); got != xdpActionPass {
			t.Fatalf("XDP action = %d, want %d: the live PASS_TO_KERNEL steer must survive the dead-lookup removal", got, xdpActionPass)
		}
		assertXDPBranchStat(t, coll, "gre_inner_pass_kernel")
	})
}
