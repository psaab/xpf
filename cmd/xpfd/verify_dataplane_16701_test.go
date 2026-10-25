package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #16701: verify-dataplane must print and ENFORCE the target-kernel
// headroom floor. Before the fix it called
// VerifyEmbeddedUserspaceShim() (error only) and printed a bare
// PASS for any load the guest kernel accepted — including the
// 2.28%-headroom guest measurement of #15645 and objects the guest
// would REJECT after one more edit (#15854). These tests inject
// stats at the guest-observed spread: the same object that passes
// on the build host must refuse here when this kernel charges more.
func gateWith(stats dataplane.ShimVerifierStats, kernel string, err error) func() (dataplane.ShimVerifierStats, string, error) {
	return func() (dataplane.ShimVerifierStats, string, error) { return stats, kernel, err }
}

func TestVerifyDataplaneEnforcesTargetKernelHeadroom16701(t *testing.T) {
	// Host PASS shape: 920733/1000000 = 7.93% is already below the
	// floor; the guest at +6.1% (977241) is the #15645 record. Both
	// must refuse with exit 4, never a bare PASS.
	for _, tc := range []struct {
		name       string
		stats      dataplane.ShimVerifierStats
		kernel     string
		err        error
		wantCode   int
		wantOut    string
		wantKernel bool
	}{
		{
			name:   "measured above floor passes and names kernel",
			stats:  dataplane.ShimVerifierStats{ProcessedInsns: 696219, InsnLimit: 1000000},
			kernel: "7.0.0-30-generic", wantCode: 0, wantOut: "PASS", wantKernel: true,
		},
		{
			name:   "guest charge above host count refuses below floor",
			stats:  dataplane.ShimVerifierStats{ProcessedInsns: 977241, InsnLimit: 1000000},
			kernel: "7.0.0-30-generic", wantCode: verifyDataplaneExitLowHeadroom, wantOut: "LOW-HEADROOM", wantKernel: true,
		},
		{
			name:   "exactly at floor passes",
			stats:  dataplane.ShimVerifierStats{ProcessedInsns: 850000, InsnLimit: 1000000},
			kernel: "7.0.0", wantCode: 0, wantOut: "PASS", wantKernel: true,
		},
		{
			name:   "unmeasured refuses, never passes",
			stats:  dataplane.ShimVerifierStats{},
			kernel: "7.0.0", wantCode: verifyDataplaneExitUnmeasured, wantOut: "UNMEASURED-HEADROOM", wantKernel: true,
		},
		{
			name:   "verifier reject keeps exit 3",
			err:    fmt.Errorf("load: %w", dataplane.ErrUserspaceShimVerifierReject),
			kernel: "7.0.0", wantCode: verifyDataplaneExitReject, wantOut: "REJECT",
		},
		{
			name:   "other error keeps exit 1",
			err:    fmt.Errorf("operation not permitted"),
			kernel: "7.0.0", wantCode: verifyDataplaneExitOther, wantOut: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := runVerifyDataplaneGate(&stdout, &stderr, gateWith(tc.stats, tc.kernel, tc.err))
			if got != tc.wantCode {
				t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q", got, tc.wantCode, stdout.String(), stderr.String())
			}
			if tc.wantOut != "" && !strings.Contains(stdout.String(), tc.wantOut) {
				t.Fatalf("stdout %q does not contain %q", stdout.String(), tc.wantOut)
			}
			if tc.wantCode == 0 && !strings.Contains(stdout.String(), "PASS embedded userspace shim") {
				t.Fatalf("PASS arm lost its historic prefix: %q", stdout.String())
			}
			if tc.wantKernel {
				for _, want := range []string{tc.kernel, fmt.Sprintf("%d", tc.stats.ProcessedInsns), "floor"} {
					if !strings.Contains(stdout.String(), want) {
						t.Fatalf("stdout %q does not report %q (kernel/processed/floor must be printed)", stdout.String(), want)
					}
				}
			}
			// Fail-closed invariant: only the measured above-floor arm exits 0.
			if tc.wantCode != 0 && got == 0 {
				t.Fatalf("non-pass arm exited 0")
			}
		})
	}
}
