package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #16701: exit codes for `xpfd verify-dataplane` beyond the historic
// 0 PASS / 3 verifier REJECT / 1 other / 2 usage. Exit 4 = loads on
// THIS kernel but below the UserspaceShimMinVerifierHeadroomPct
// floor; exit 5 = loads but headroom could not be measured. These
// mirror cmd/shimverify's refusals 4/5 deliberately. Before #16701
// this pre-flight was a binary PASS/REJECT on the target kernel: an
// object at 2% guest headroom passed silently and the next edit
// discovered the 1M wall as a deploy-blocking REJECT (#15645,
// #15854). Now the floor fires on the kernel that will actually
// load the object. No override is honoured here: the pre-flight
// runs unattended from ExecStartPre and deploy tooling, so a
// low-headroom deploy must be a deliberate build-time decision
// (XPF_SHIM_ALLOW_LOW_HEADROOM at shimverify), never an ambient
// guest-side env var. Fail-closed by construction: every non-PASS
// arm exits nonzero, and deploy callers already treat any nonzero
// as "refuse the deploy".
const (
	verifyDataplaneExitOK          = 0
	verifyDataplaneExitOther       = 1
	verifyDataplaneExitReject      = 3
	verifyDataplaneExitLowHeadroom = 4
	verifyDataplaneExitUnmeasured  = 5
)

// verifyDataplaneGate is runVerifyDataplane with the verifier and
// both streams injected, for tests.
var verifyDataplaneGate = func() (dataplane.ShimVerifierStats, string, error) {
	return dataplane.VerifyEmbeddedUserspaceShimStats()
}

// runVerifyDataplane prints and enforces the target-kernel headroom
// (#16701): PASS requires a measured headroom at or above the floor
// on the running kernel, not merely verifier acceptance. The kernel
// release, processed count, headroom and floor are printed on every
// arm so a refusal (or a thinning PASS) is self-describing in deploy
// logs without re-running anything.
func runVerifyDataplane(stdout, stderr io.Writer) int {
	return runVerifyDataplaneGate(stdout, stderr, verifyDataplaneGate)
}

func runVerifyDataplaneGate(stdout, stderr io.Writer, gate func() (dataplane.ShimVerifierStats, string, error)) int {
	stats, kernel, err := gate()
	if err != nil {
		if errors.Is(err, dataplane.ErrUserspaceShimVerifierReject) {
			fmt.Fprintf(stdout, "REJECT embedded userspace shim\n%v\n", err)
			return verifyDataplaneExitReject
		}
		fmt.Fprintf(stderr, "verify-dataplane: %v\n", err)
		return verifyDataplaneExitOther
	}
	label := kernel
	if label == "" {
		label = "unknown"
	}
	if !stats.Measured() {
		fmt.Fprintf(stdout, "UNMEASURED-HEADROOM embedded userspace shim on kernel %s (verifier accepted but processed-insn stats unavailable; the %.1f%% headroom floor could not be applied; no production state touched)\n", label, dataplane.UserspaceShimMinVerifierHeadroomPct)
		return verifyDataplaneExitUnmeasured
	}
	summary := fmt.Sprintf("processed %d insns (limit %d) on kernel %s, headroom %.2f%%, floor %.1f%%",
		stats.ProcessedInsns, stats.InsnLimit, label, stats.HeadroomPct(),
		dataplane.UserspaceShimMinVerifierHeadroomPct)
	if stats.HeadroomPct() < dataplane.UserspaceShimMinVerifierHeadroomPct {
		fmt.Fprintf(stdout, "LOW-HEADROOM embedded userspace shim (%s; below the %.1f%% floor on this kernel; no production state touched)\n",
			summary, dataplane.UserspaceShimMinVerifierHeadroomPct)
		return verifyDataplaneExitLowHeadroom
	}
	fmt.Fprintf(stdout, "PASS embedded userspace shim (%s; verifier accepted; no production state touched)\n", summary)
	return verifyDataplaneExitOK
}

// runVerifyDataplaneCmd adapts runVerifyDataplane's exit code for
// main(): codes 0/3 keep their historic os.Exit values; 4/5 exit
// with their own codes so deploy tooling can distinguish a
// below-floor refusal from a verifier REJECT; all nonzero refusals
// already block the deploy in every caller.
func runVerifyDataplaneCmd() {
	os.Exit(runVerifyDataplane(os.Stdout, os.Stderr))
}
