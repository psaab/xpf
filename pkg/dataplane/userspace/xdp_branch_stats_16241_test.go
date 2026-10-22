package userspace

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// #16241: per-arm XDP branch hit counters + fail-closed analysis.
//
// The issue asks, in order: (1) fallback-reason/branch hit counts for
// plain TCP hit-forwards, (2) a per-arm fail-closed analysis, and only
// then (3) removal of arms proven disposition-identical. This file is
// the test half of (1) and the executable half of (2): every arm gets
// a BPF_PROG_TEST_RUN cell proving its disposition (action + branch
// counter + degraded counter) per packet class, and the analysis table
// in docs/log/16241.md records why no arm is disposition-identical to
// another. No arm is removed by this change.
//
// The counters live in a NEW per-CPU map (userspace_branch_stats), not
// in the degraded map: the degraded indices are a pinned operator ABI
// (degradedPathReasonNames, the Rust debug reader, #8258), and a
// hit-forward is not a degraded disposition. Counting is gated on the
// TRACE ctrl flag inside the one outlined incr_branch_stat callee, so
// with tracing off the hot path pays only a flag test.

var shimBranchArmRe = regexp.MustCompile(
	`(?m)^const USERSPACE_BRANCH_ARM_([A-Z0-9_]+): u32 = (\d+);`)

// shimBranchArms returns branch arm name (lowercased, no prefix) by
// index, plus the value of the _MAX bound. Same extraction shape as
// the #8258 degraded-reason scan: a constant list is a syntactic fact.
func shimBranchArms(t *testing.T) (map[int]string, int) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "userspace-xdp", "src", "lib.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the shim source at %s: %v", path, err)
	}
	byIndex := map[int]string{}
	max := -1
	for _, m := range shimBranchArmRe.FindAllStringSubmatch(string(src), -1) {
		name, valueText := m[1], m[2]
		value, err := strconv.Atoi(valueText)
		if err != nil {
			t.Fatalf("branch arm %s has a non-numeric value %q", name, valueText)
		}
		if name == "MAX" {
			max = value
			continue
		}
		if prior, dup := byIndex[value]; dup {
			t.Fatalf("the shim assigns branch index %d to BOTH %s and %s — "+
				"two arms counting into one slot", value, prior, strings.ToLower(name))
		}
		byIndex[value] = strings.ToLower(name)
	}
	return byIndex, max
}

// The agreement: Go's xdpBranchArmNames must match the shim's
// USERSPACE_BRANCH_ARM_* constants index-for-index. Self-maintaining
// in the direction that matters: adding an arm in Rust enrols it here.
func TestXDPBranchArmNamesAgreeWithTheShim16241(t *testing.T) {
	byIndex, max := shimBranchArms(t)

	// Positive control: a regex that stopped matching finds nothing and
	// compares nothing to nothing forever.
	if len(byIndex) < 10 {
		t.Fatalf("the shim scan found only %d branch arm constants (%v). "+
			"The pattern has rotted or the file moved", len(byIndex), byIndex)
	}
	if max <= 0 {
		t.Fatalf("USERSPACE_BRANCH_ARM_MAX was not found in the shim source")
	}
	if got := len(xdpBranchArmNames); got != max {
		t.Fatalf("xdpBranchArmNames has %d slots but the shim's "+
			"USERSPACE_BRANCH_ARM_MAX is %d. The Go reader sizes its scan "+
			"from len(xdpBranchArmNames), so extra shim arms would be "+
			"counted in the kernel and never read", got, max)
	}
	for index, want := range byIndex {
		if index >= len(xdpBranchArmNames) {
			t.Errorf("the shim defines branch arm %q at index %d, beyond "+
				"the Go table's %d slots", want, index, len(xdpBranchArmNames))
			continue
		}
		if got := xdpBranchArmNames[index]; got != want {
			t.Errorf("index %d: the shim calls this %q, Go renders it as %q. "+
				"The two sides are joined by INDEX, so a renumbering on one "+
				"side re-labels every slot above it", index, want, got)
		}
	}
	for index, name := range xdpBranchArmNames {
		if _, ok := byIndex[index]; !ok {
			t.Errorf("Go renders branch index %d as %q but the shim defines "+
				"no arm there", index, name)
		}
	}
}

// Every branch arm the shim defines must be COUNTED somewhere in the
// shim, or the table carries a row for an arm that cannot fire. (The
// degraded sibling excuses two dead reasons with commit citations;
// branch arms have no such residue — a dead arm here means the
// analysis table in docs/log/16241.md describes a phantom.)
func TestXDPBranchArmsAreAllCounted16241(t *testing.T) {
	byIndex, _ := shimBranchArms(t)
	path := filepath.Join("..", "..", "..", "userspace-xdp", "src", "lib.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the shim source: %v", err)
	}
	text := string(src)
	for index, name := range byIndex {
		constName := "USERSPACE_BRANCH_ARM_" + strings.ToUpper(name)
		// Definition plus at least one incr_branch_stat call site.
		if got := strings.Count(text, constName); got < 2 {
			t.Errorf("branch arm %q (index %d, %s) appears %d time(s) in "+
				"the shim; want its definition plus at least one "+
				"incr_branch_stat call site", name, index, constName, got)
		}
	}
}

func xdpBranchStat(t *testing.T, coll *ebpf.Collection, name string) uint64 {
	t.Helper()
	stats := coll.Maps["userspace_branch_stats"]
	if stats == nil {
		t.Fatal("userspace_branch_stats map not loaded")
	}
	var idx uint32
	found := false
	for i, candidate := range xdpBranchArmNames {
		if candidate == name {
			idx = uint32(i)
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("branch arm %q not found in xdpBranchArmNames", name)
	}
	var perCPU []uint64
	if err := stats.Lookup(idx, &perCPU); err != nil {
		t.Fatalf("lookup userspace_branch_stats[%d] (%s): %v", idx, name, err)
	}
	var got uint64
	for _, v := range perCPU {
		got += v
	}
	return got
}

func assertXDPBranchStat(t *testing.T, coll *ebpf.Collection, name string) {
	t.Helper()
	if got := xdpBranchStat(t, coll, name); got == 0 {
		var fired []string
		for _, arm := range xdpBranchArmNames {
			if arm == "" {
				continue
			}
			if v := xdpBranchStat(t, coll, arm); v != 0 {
				fired = append(fired, arm+"="+strconv.FormatUint(v, 10))
			}
		}
		sort.Strings(fired)
		t.Fatalf("branch stat %q = 0, want incremented. Arms that DID fire: %s",
			name, strings.Join(fired, " "))
	}
}

func assertXDPBranchStatAbsent(t *testing.T, coll *ebpf.Collection, name string) {
	t.Helper()
	if got := xdpBranchStat(t, coll, name); got != 0 {
		t.Fatalf("branch stat %q = %d, want 0", name, got)
	}
}

// seedHealthy16241 arms a healthy shim: ctrl enabled with TRACE (branch
// counting is TRACE-gated), adjudicated ingress, ready binding, fresh
// heartbeat. Extra flags (native GRE, WG) are ORed in by the caller.
func seedHealthy16241(t *testing.T, coll *ebpf.Collection, extraFlags uint32) {
	t.Helper()
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            1,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		Flags:              userspaceCtrlFlagTrace | extraFlags,
		HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
	})
	ifindex := userspaceXDPTestRunIfindex(t)
	updateUserspaceXDPTestIngress(t, coll, ifindex)
	updateUserspaceXDPTestBinding(t, coll, userspaceXDPTestRunBindingIndex(t, 0), userspaceBindingValue{
		Slot:  0,
		Flags: userspaceBindingReady,
	})
	updateUserspaceXDPTestHeartbeat(t, coll, 0)
}

// The disposition matrix. Each cell runs the retained XDP program
// itself (BPF_PROG_TEST_RUN) and asserts the action AND the branch
// counter that proves which arm produced it. An empty XSK map makes a
// redirect surface as DROP + redirect_err (the established harness
// convention), which is what distinguishes "reached the redirect"
// from "passed to the kernel".
//
// Packet classes named by the issue — local / WG / GRE / NAT-miss /
// early-filter — each appear, plus the plain-TCP hit-forward the
// counters exist to attribute.
func TestXDPBranchDispositionMatrix16241(t *testing.T) {
	src := [4]byte{198, 51, 100, 10}
	localDst := [4]byte{192, 0, 2, 1}
	transitDst := [4]byte{203, 0, 113, 20}
	natDst := [4]byte{192, 0, 2, 254}
	multicast := [4]byte{224, 0, 0, 1}

	cases := []struct {
		name       string
		packet     []byte
		seed       func(*testing.T, *ebpf.Collection)
		extraFlags uint32
		wantAction uint32
		wantArm    string
		absentArms []string
	}{
		{
			// The packet class the counters exist for: an established
			// plain-TCP flow. It must take exactly one redirect-origin
			// slot and no kernel-pass / drop arm.
			name:   "plain TCP session hit forwards via redirect origin",
			packet: xdpDispatchIPv4TCPPacket10864(src, transitDst, 12345, 443),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				seedXDPDispatchInnerSession10864(t, coll, src, transitDst,
					12345, 443, xdpDispatchSessionRedirect10864)
			},
			wantAction: xdpActionDrop, // empty XSK map: redirect_err drop
			wantArm:    "session_hit_redirect",
			absentArms: []string{"session_hit_pass_kernel", "session_miss_redirect",
				"early_filter", "wg_steer", "gre_inner_pass_kernel"},
		},
		{
			name:   "plain TCP session hit to kernel (PASS_TO_KERNEL session)",
			packet: xdpDispatchIPv4TCPPacket10864(src, transitDst, 12345, 443),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				seedXDPDispatchInnerSession10864(t, coll, src, transitDst,
					12345, 443, xdpDispatchSessionPass10864)
			},
			wantAction: xdpActionPass,
			wantArm:    "session_hit_pass_kernel",
			absentArms: []string{"session_hit_redirect", "redirect"},
		},
		{
			name:       "plain TCP session miss redirects for adjudication",
			packet:     xdpDispatchIPv4TCPPacket10864(src, transitDst, 12345, 443),
			wantAction: xdpActionDrop,
			wantArm:    "session_miss_redirect",
			absentArms: []string{"session_hit_redirect", "session_miss_local"},
		},
		{
			name:   "local destination session miss passes to kernel",
			packet: xdpDispatchIPv4TCPPacket10864(src, localDst, 12345, 443),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				updateUserspaceXDPTestLocalV4(t, coll, localDst)
			},
			wantAction: xdpActionPass,
			wantArm:    "session_miss_local",
			absentArms: []string{"session_miss_redirect", "redirect"},
		},
		{
			name:   "NAT-miss (interface-NAT destination, no session) redirects",
			packet: xdpDispatchIPv4TCPPacket10864(src, natDst, 12345, 443),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				updateUserspaceXDPTestInterfaceNATV4(t, coll, natDst)
			},
			wantAction: xdpActionDrop,
			wantArm:    "session_miss_ifnat_redirect",
			absentArms: []string{"session_miss_redirect", "session_miss_local"},
		},
		{
			name:       "early-filter multicast passes before any session lookup",
			packet:     ipv4TestPacket(src, multicast, 17, 8),
			wantAction: xdpActionPass,
			wantArm:    "early_filter",
			absentArms: []string{"session_miss_redirect", "session_hit_redirect"},
		},
		{
			name: "GRE inner PASS with local outer passes to kernel",
			packet: xdpDispatchGREIPv4Packet10864(
				[4]byte{203, 0, 113, 1}, localDst, src, transitDst, 12345, 443),
			seed: func(t *testing.T, coll *ebpf.Collection) {
				updateUserspaceXDPTestLocalV4(t, coll, localDst)
				seedXDPDispatchInnerSession10864(t, coll, src, transitDst,
					12345, 443, xdpDispatchSessionPass10864)
			},
			extraFlags: xdpDispatchNativeGREFlag10864,
			wantAction: xdpActionPass,
			wantArm:    "gre_inner_pass_kernel",
			absentArms: []string{"session_hit_pass_kernel", "redirect"},
		},
		{
			name:       "ARP takes the non-IP direct pass",
			packet:     arpTestPacket(),
			wantAction: xdpActionPass,
			wantArm:    "non_ip_pass",
			absentArms: []string{"early_filter", "session_miss_redirect"},
		},
		{
			// Ethertype claims a VLAN tag but the tag header is absent:
			// parse_l2 fails on a full Ethernet header, so the runner
			// accepts the frame and the shim takes its parse-fail arm.
			name:       "VLAN header truncated takes the L2 parse-fail pass",
			packet:     []byte{0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x81, 0x00},
			wantAction: xdpActionPass, // cpumap empty in harness: XDP_PASS
			wantArm:    "l2_parse_fail",
			absentArms: []string{"non_ip_pass", "l3_parse_fail"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coll := loadUserspaceXDPTestCollection(t)
			seedHealthy16241(t, coll, tc.extraFlags)
			if tc.seed != nil {
				tc.seed(t, coll)
			}
			got := runUserspaceXDPTestPacket(t, coll, tc.packet)
			if got != tc.wantAction {
				t.Fatalf("XDP action = %d, want %d", got, tc.wantAction)
			}
			assertXDPBranchStat(t, coll, tc.wantArm)
			for _, absent := range tc.absentArms {
				assertXDPBranchStatAbsent(t, coll, absent)
			}
		})
	}
}

// WG packet class: a WireGuard handshake-shaped UDP datagram to a
// steered listen port on a local destination is steered to the kernel
// control socket (wg_steer), NOT redirected and NOT passed as ordinary
// local delivery. WG_RX flag + steered port set are required; without
// the flag the same packet is an ordinary session miss.
func TestXDPBranchWGSteer16241(t *testing.T) {
	localDst := [4]byte{192, 0, 2, 1}
	src := [4]byte{198, 51, 100, 10}

	run := func(t *testing.T, wgEnabled bool) (*ebpf.Collection, uint32) {
		coll := loadUserspaceXDPTestCollection(t)
		flags := uint32(userspaceCtrlFlagTrace)
		var wgCount uint32
		// WgPorts is sized by config.MaxSteeredWireGuardPorts in the ctrl struct.
		if wgEnabled {
			flags |= userspaceCtrlFlagWgRx
			wgCount = 1
		}
		ctrl := userspaceCtrlValue{
			Enabled:            1,
			MetadataVersion:    userspaceMetadataVersion,
			Workers:            1,
			QueueCount:         1,
			Flags:              flags,
			WgPortCount:        wgCount,
			HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
		}
		if wgEnabled {
			ctrl.WgPorts[0] = 51820
		}
		updateUserspaceXDPTestCtrl(t, coll, ctrl)
		ifindex := userspaceXDPTestRunIfindex(t)
		updateUserspaceXDPTestIngress(t, coll, ifindex)
		updateUserspaceXDPTestBinding(t, coll, userspaceXDPTestRunBindingIndex(t, 0), userspaceBindingValue{
			Slot:  0,
			Flags: userspaceBindingReady,
		})
		updateUserspaceXDPTestHeartbeat(t, coll, 0)
		updateUserspaceXDPTestLocalV4(t, coll, localDst)
		// UDP to the WG port; payload first byte 1 = handshake initiation
		// (not transport data), so the steer applies.
		pkt := udpIPv4TestPacket(src, localDst)
		// ipv4TestPacket writes UDP dst port 443; rewrite to the WG port
		// and set a handshake-shaped payload.
		pkt[36] = 0xca
		pkt[37] = 0x6c // 51820
		if len(pkt) > 42 {
			pkt[42] = 1
		}
		return coll, runUserspaceXDPTestPacket(t, coll, pkt)
	}

	t.Run("WG handshake to steered port steers to kernel", func(t *testing.T) {
		coll, got := run(t, true)
		if got != xdpActionPass {
			t.Fatalf("WG steer action = %d, want XDP_PASS (cpumap empty)", got)
		}
		assertXDPBranchStat(t, coll, "wg_steer")
		assertXDPBranchStatAbsent(t, coll, "session_miss_local")
		assertXDPBranchStatAbsent(t, coll, "session_miss_redirect")
	})

	t.Run("same packet without WG_RX is an ordinary local miss", func(t *testing.T) {
		coll, got := run(t, false)
		if got != xdpActionPass {
			t.Fatalf("no-WG action = %d, want XDP_PASS (local delivery)", got)
		}
		assertXDPBranchStatAbsent(t, coll, "wg_steer")
		assertXDPBranchStat(t, coll, "session_miss_local")
	})
}

// TRACE-off control: with the TRACE flag clear, NO branch arm counts
// (the gate is what keeps the instrumentation off the hot path), while
// the disposition itself is unchanged. This is the fail-on-revert cell
// for the gate: removing it makes the first subtest's counters fire.
func TestXDPBranchCountingIsTraceGated16241(t *testing.T) {
	src := [4]byte{198, 51, 100, 10}
	dst := [4]byte{203, 0, 113, 20}

	coll := loadUserspaceXDPTestCollection(t)
	// Healthy but NO trace flag.
	updateUserspaceXDPTestCtrl(t, coll, userspaceCtrlValue{
		Enabled:            1,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
	})
	ifindex := userspaceXDPTestRunIfindex(t)
	updateUserspaceXDPTestIngress(t, coll, ifindex)
	updateUserspaceXDPTestBinding(t, coll, userspaceXDPTestRunBindingIndex(t, 0), userspaceBindingValue{
		Slot:  0,
		Flags: userspaceBindingReady,
	})
	updateUserspaceXDPTestHeartbeat(t, coll, 0)
	seedXDPDispatchInnerSession10864(t, coll, src, dst, 12345, 443, xdpDispatchSessionRedirect10864)

	got := runUserspaceXDPTestPacket(t, coll, xdpDispatchIPv4TCPPacket10864(src, dst, 12345, 443))
	if got != xdpActionDrop {
		t.Fatalf("trace-off hit-forward action = %d, want DROP (redirect_err on empty XSK)", got)
	}
	for _, arm := range xdpBranchArmNames {
		assertXDPBranchStatAbsent(t, coll, arm)
	}
	// The degraded counters are NOT gated: redirect_err still records.
	assertUserspaceXDPDegradedPathStat(t, coll, "redirect_err")
}
