package config

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// #15115: the #9727 budget omitted the kernel's fixed XDP_PACKET_HEADROOM.
// The kernel's usable RX frame size is
//
//	UMEM_FRAME_SIZE - (XDP_PACKET_HEADROOM + UMEM_HEADROOM)
//
// (xsk_pool_get_headroom sums the kernel's 256 with the configured pool
// headroom), so with 4096/256 constants the largest single-frame MTU is
// 4096 - (256+256) - 14 - 4 = 3566, not 3822. These tests derive that
// expectation from the kernel term as an independent literal and from the
// Rust UMEM constants, never from userspaceRxMTUBudget itself, so reverting
// the budget to 3822 fails here rather than silently moving the boundary.

func TestRxMTUBudgetIncludesKernelXDPHeadroom15115(t *testing.T) {
	src, err := os.ReadFile("../../userspace-dp/src/afxdp/mod.rs")
	if err != nil {
		t.Fatalf("read helper source: %v", err)
	}
	parse := func(name string) int {
		m := regexp.MustCompile(`(?m)^const ` + name + `: u32 = (\d+);`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("no %s declaration found in userspace-dp/src/afxdp/mod.rs", name)
		}
		v, _ := strconv.Atoi(string(m[1]))
		return v
	}
	frameSize := parse("UMEM_FRAME_SIZE")
	umemHeadroom := parse("UMEM_HEADROOM")
	// XDP_PACKET_HEADROOM is a kernel constant (include/uapi/linux/if_xdp.h /
	// net/xdp/xsk.c), not a value this tree configures: 256.
	const kernelXDPacketHeadroom = 256
	want := frameSize - (kernelXDPacketHeadroom + umemHeadroom) - 14 - 4
	if want != 3566 {
		t.Fatalf("derived budget = %d, want 3566 (frame %d)", want, frameSize)
	}
	if userspaceRxMTUBudget != want {
		t.Fatalf("userspaceRxMTUBudget = %d, want %d derived from XDP_PACKET_HEADROOM + UMEM_HEADROOM", userspaceRxMTUBudget, want)
	}
}

func TestRxMTUAdvisoryWarnsInsideFormerSilentWindow15115(t *testing.T) {
	for _, tc := range []struct {
		name string
		mtu  int
		warn bool
	}{
		{"3566 exactly fits one frame", 3566, false},
		{"3567 is one byte over", 3567, true},
		{"3700 inside the old silent window", 3700, true},
		{"3822 top of the old silent window", 3822, true},
		{"3823 already warned before the fix", 3823, true},
		{"1500 control does not warn", 1500, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := rxMTUCfg9727(map[string][]string{"trust": {"ge-0/0/1.0"}},
				map[string]*InterfaceConfig{"ge-0/0/1": iface9727("ge-0/0/1", tc.mtu, map[int]int{0: 0})})
			appendUserspaceRxMTUAdvisoryLocked(cfg, compileOpts{})
			w := rxMTUWarnings9727(cfg)
			if got := len(w) == 1; got != tc.warn {
				t.Fatalf("MTU %d: warned=%v, want %v: %v", tc.mtu, got, tc.warn, cfg.Warnings)
			}
			if tc.warn {
				for _, want := range []string{"3566", "XDP_PACKET_HEADROOM", "UMEM headroom"} {
					if !strings.Contains(w[0], want) {
						t.Errorf("advisory must name %q: %s", want, w[0])
					}
				}
			}
		})
	}
}
