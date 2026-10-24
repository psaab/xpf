package userspace

import (
	"encoding/binary"
	"testing"
)

// Behavioural coverage for #16038: an IPv6 extension-header chain longer than
// the shim's walk can resolve must fail closed in the shim, even when its
// destination is firewall-local (or multicast/link-local).
//
// Before the fix, walk exhaustion returned the last declared extension-header
// type as `protocol`, parse_l4's catch-all yielded ports 0/0, and the
// destination-qualified kernel-PASS arms (session-miss local-destination,
// degraded local/control, early-filter) could hand the packet to the kernel
// unscreened — no session, zone policy, or screen ever evaluated it. The
// only thing standing in the way was the cross-crate invariant that no
// session writer mints (traversable, 0, 0) keys, which those PASS arms do
// not consult.
//
// These cells run the REAL retained object via BPF_PROG_TEST_RUN (shared
// harness in xdp_shim_decouple_test.go); they skip unprivileged and execute
// under `make test-shim-run` / `make test-root`. RED on the pre-fix object:
// the local/multicast/link-local exhausted rows return XDP_PASS instead of
// XDP_DROP. The at-limit and terminal controls pass on both objects.
//
// Chain shape: DestOpt (60) is the GENERIC arm. Each header is
// [next, 0, 0,0,0,0,0,0] (HdrExtLen 0 -> advance 8). MAX_EXT_HDRS is 7, so
// 8 headers exhaust the walk (the 8th declares TCP but the loop never
// consumes another header to reach it... precisely: after 7 iterations the
// shim holds the 7th header's next value, still DestOpt), while 7 headers
// resolve to the trailing TCP header with real ports.

var (
	ext16038Src       = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
	ext16038Local     = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ext16038Transit   = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99}
	ext16038Mcast     = [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	ext16038LinkLocal = [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
)

// extChainFrame16038 builds eth + IPv6 + n DestOpt headers + TCP.
// payload_len covers exactly the headers + TCP.
func extChainFrame16038(dst [16]byte, n int) []byte {
	payloadLen := n*8 + 20
	pkt := make([]byte, 14+40+payloadLen)
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(pkt[12:14], 0x86dd)
	ip := pkt[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(payloadLen))
	if n == 0 {
		ip[6] = 6
	} else {
		ip[6] = 60
	}
	ip[7] = 64
	copy(ip[8:24], ext16038Src[:])
	copy(ip[24:40], dst[:])
	for i := range n {
		at := 54 + i*8
		if i+1 == n {
			pkt[at] = 6
		} else {
			pkt[at] = 60
		}
		pkt[at+1] = 0
	}
	tcp := pkt[54+n*8:]
	binary.BigEndian.PutUint16(tcp[0:2], 0x1234)
	binary.BigEndian.PutUint16(tcp[2:4], 0x5678)
	tcp[12] = 0x50
	tcp[13] = 0x02 // SYN
	return pkt
}

func TestUserspaceXDPExtChainExhaustionLocalDrops16038(t *testing.T) {
	tests := []struct {
		name         string
		dst          [16]byte
		n            int
		seedLocal    bool
		enabled      uint32
		wantAction   uint32
		wantParse    bool // parse_fail + transit_drop expected
		wantRedirect bool
	}{
		{name: "exhausted to local drops enabled", dst: ext16038Local, n: 8, seedLocal: true, enabled: 1, wantAction: xdpActionDrop, wantParse: true},
		{name: "exhausted to local drops ctrl disabled", dst: ext16038Local, n: 8, seedLocal: true, enabled: 0, wantAction: xdpActionDrop, wantParse: false},
		{name: "exhausted to multicast drops", dst: ext16038Mcast, n: 8, enabled: 1, wantAction: xdpActionDrop, wantParse: true},
		{name: "exhausted to link-local drops", dst: ext16038LinkLocal, n: 8, enabled: 1, wantAction: xdpActionDrop, wantParse: true},
		{name: "exhausted to transit drops", dst: ext16038Transit, n: 8, enabled: 1, wantAction: xdpActionDrop, wantParse: true},
		// Controls: resolvable chains and terminals are unaffected.
		{name: "at-limit to local passes", dst: ext16038Local, n: 7, seedLocal: true, enabled: 1, wantAction: xdpActionPass},
		{name: "plain tcp to local passes", dst: ext16038Local, n: 0, seedLocal: true, enabled: 1, wantAction: xdpActionPass},
		// At-limit transit reaches the XSK redirect; with no XSK bound in this
		// harness that surfaces as redirect_err + DROP, which proves it was
		// adjudicated (not parse-dropped, not kernel-passed).
		{name: "at-limit to transit reaches redirect", dst: ext16038Transit, n: 7, enabled: 1, wantAction: xdpActionDrop, wantRedirect: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
				Enabled:            tc.enabled,
				MetadataVersion:    userspaceMetadataVersion,
				Workers:            1,
				QueueCount:         1,
				HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
			})
			updateUserspaceXDPTestIngress(t, coll, userspaceXDPTestRunIfindex(t))
			updateUserspaceXDPTestBinding(t, coll, userspaceXDPTestRunBindingIndex(t, 0), userspaceBindingValue{
				Slot: 0, Flags: userspaceBindingReady,
			})
			updateUserspaceXDPTestHeartbeat(t, coll, 0)
			if tc.seedLocal {
				updateUserspaceXDPTestLocalV6(t, coll, tc.dst)
			}
			ret := runUserspaceXDPTestPacket(t, coll, extChainFrame16038(tc.dst, tc.n))
			if ret != tc.wantAction {
				t.Fatalf("#16038 %s: action = %d, want %d (reasons: %s)", tc.name, ret, tc.wantAction, userspaceXDPDegradedPathStatsSummary(t, coll))
			}
			if tc.wantParse {
				assertUserspaceXDPDegradedPathStat(t, coll, "parse_fail")
				assertUserspaceXDPDegradedPathStat(t, coll, "transit_drop")
				assertUserspaceXDPDegradedPathStatAbsent(t, coll, "pass_to_kernel")
			}
			if tc.wantRedirect {
				assertUserspaceXDPDegradedPathStat(t, coll, "redirect_err")
				assertUserspaceXDPDegradedPathStatAbsent(t, coll, "parse_fail")
				assertUserspaceXDPDegradedPathStatAbsent(t, coll, "pass_to_kernel")
			}
			if tc.enabled == 0 && tc.n == 8 {
				// Degraded entry: parse failure takes the ctrl_disabled transit drop.
				assertUserspaceXDPDegradedPathStat(t, coll, "ctrl_disabled")
				assertUserspaceXDPDegradedPathStat(t, coll, "transit_drop")
				assertUserspaceXDPDegradedPathStatAbsent(t, coll, "pass_to_kernel")
			}
		})
	}
}
