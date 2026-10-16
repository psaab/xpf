// Package dataplane: verify-only loader for the retained Rust AF_XDP
// shim object (#1864).
//
// On 2026-06-10 a `make generate` run with a drifted Rust nightly
// produced a shim object that exceeded the kernel verifier's 1M
// processed-insn cap and took both HA cluster dataplanes down
// (config-only mode). The functions here run the real kernel verifier
// against a candidate object WITHOUT touching any production state,
// so the failure surfaces as a failed build or a refused deploy
// instead of a dead dataplane.
//
// HARD INVARIANT: nothing in this file may call LoadUserspaceShim /
// loadUserspaceShimObjectsOnce, set ebpf.PinByName / MapOptions.PinPath,
// or use MapReplacements. The verify path creates only anonymous maps
// and programs, never attaches anything, and frees everything when the
// collection is closed (or the process exits). A good program loaded
// by a running daemon keeps forwarding throughout.
//
// The one interaction with production state is READ-ONLY: the shared
// validateUserspaceShimSpec gate now inspects the running daemon's live
// pinned maps to catch an ABI incompatibility at the pre-flight rather
// than after the old daemon is stopped (#5307). That inspection opens a
// handle, reads the map shape, and closes it — it never unpins,
// attaches, or mutates the pin, so the running daemon keeps forwarding.
package dataplane

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// UserspaceShimMinVerifierHeadroomPct is the committed floor for how much
// of the kernel verifier's 1M processed-insn budget a shim candidate must
// leave unused (#4555).
//
// The 2026-06-10 incident (#1864) was a shim object that blew the cap and
// took both HA dataplanes down. The gates added after it are all BINARY —
// the object either loads or it does not — so an object creeping toward
// the wall is indistinguishable from a comfortable one until the day it
// crosses. That is exactly what happened: master sat at 990,796/1,000,000
// (0.92% headroom) with every gate green, and the next person to touch the
// IPv6 extension-header walk discovered it as a REJECT after the work was
// already done.
//
// 3% is deliberately loose. It is not a performance target; it is a
// tripwire that says "the next change here will not fit" while there is
// still room to plan.
//
// #6884: there is deliberately NO "the current object sits at X%" sentence
// here any more. The one that used to be ("~5.3%") was written when the floor
// was chosen and was FALSE within weeks — #6676 freed ~193k insns and the
// object moved to 21.58% headroom. That matters more than a wrong number in a
// comment, because the floor was CALIBRATED against 5.3%: at 21.58% the same
// 3% admits ~186k additional insns, which is one to two IPv6 extension-header
// iterations (87k-106k each) landing SILENTLY — so the tripwire no longer
// fires "before the next change will not fit", which is the entire claim above
// it. A hand-maintained number is exactly the wrong instrument for judging
// whether a threshold is still calibrated, because it drifts in the same
// silence the threshold is supposed to break.
//
// The live figures are reported by EVERY build instead: cmd/shimverify's PASS
// banner prints the processed count, the headroom, and — the one to judge this
// floor's sensitivity on — how many insns of slack the floor still admits.
// Those are computed, so they cannot rot.
// #6884 raised this from 3.0 to 15.0. 3% was chosen against a 5.3% object; by
// the time the object reached 21.58% the same constant admitted ~186k insns —
// one to two whole extension-header iterations landing silently — so the
// tripwire fired only after the thing it exists to prevent had happened twice.
//
// 15% is NOT the mathematical minimum. That is 12.88% (the floor at which the
// admitted delta equals UserspaceShimStructuralChangeInsns exactly), and a
// threshold placed on its own boundary satisfies the property for an 87,000
// insn change and fails it for an 88,000 one. The extra 2.1 points are margin,
// and they are a JUDGEMENT, not a measurement — recorded as such so whoever
// revisits this knows which inputs were which:
//
//   - MEASURED at 268346838: the object at 784,175/1,000,000, 21.58% headroom.
//     DATED DELIBERATELY (#8241). The object has since moved -- 801,448 as of
//     eaf589bac, 19.86% -- and this derivation is NOT re-run against it. The
//     figure records which inputs the 15% judgement was made from, so a reader
//     who checks the live object and gets a different number can tell that this
//     is an old derivation rather than a stale claim about today. Renumbering
//     it would silently re-derive the JUDGEMENT below, which is the one thing
//     this block exists to keep separable from the measurement.
//   - JUDGED:   the 87,000-insn structural-change cost the property is defined
//     against. That is the number to revisit.
//
// Erring high is cheap and erring low is not: the gate carries a loud
// XPF_SHIM_ALLOW_LOW_HEADROOM=1 override that names the object and the reason,
// so a floor set too high is an announced detour, while one set too low is the
// silent hole described above.
const UserspaceShimMinVerifierHeadroomPct = 15.0

// UserspaceShimStructuralChangeInsns is the measured cost of the shim's
// cheapest known STRUCTURAL change — one additional IPv6 extension-header
// iteration, which #4555 measured at 87,000-106,000 insns. The conservative
// end is used deliberately: the floor's stated property is that it fires
// BEFORE one of these lands, and the cheapest change is the one that tests it.
//
// This is the constant the floor is calibrated AGAINST, which is why it is
// named rather than inlined: cmd/shimverify checks the relationship between
// them on every build, so a future floor that stops satisfying the property
// says so out loud instead of drifting quietly the way 3% did.
const UserspaceShimStructuralChangeInsns = 87000

// verifyShrinkHashMaxEntries is the verify-only ceiling applied to
// hash-map MaxEntries before the anonymous load. Hash maps allocate bucket
// storage based on MaxEntries even when BPF_F_NO_PREALLOC is set; shrinking
// this copy avoids production-capacity memory cost during verifier-only loads.
// Hash-map MaxEntries does not feed the verifier's program safety analysis,
// and this load never uses the runtime capacity. Array-type maps are untouched.
const verifyShrinkHashMaxEntries = 1

// verifierLogTailLines bounds how much of the verifier log a REJECT
// report carries. The interesting part (the failure and final stats)
// is always at the tail.
const verifierLogTailLines = 16

// ErrUserspaceShimVerifierReject marks a kernel-verifier rejection of
// a shim candidate (as opposed to I/O, spec-validation, or privilege
// errors). Callers branch on it with errors.Is.
var ErrUserspaceShimVerifierReject = errors.New("userspace shim verifier reject")

// VerifyEmbeddedUserspaceShim runs the verify-only load against the
// shim object embedded in this binary (the exact bytes the daemon
// would load at startup). Used by `xpfd verify-dataplane` as the
// deploy-time pre-flight.
func VerifyEmbeddedUserspaceShim() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}
	spec, err := loadRustUserspaceXDP()
	if err != nil {
		return err
	}
	return verifyUserspaceShimSpecOnly(spec)
}

// VerifyUserspaceShimObject runs the verify-only load against an
// on-disk candidate object. Used by cmd/shimverify as the build-time
// gate in build-userspace-xdp.sh (verify-then-install).
func VerifyUserspaceShimObject(path string) error {
	_, err := VerifyUserspaceShimObjectStats(path)
	return err
}

// VerifyUserspaceShimObjectStats is VerifyUserspaceShimObject plus the
// kernel verifier's processed-insn accounting for a candidate that
// LOADED, so the build-time gate can enforce
// UserspaceShimMinVerifierHeadroomPct rather than only the hard 1M wall.
// The returned stats are meaningful only when err is nil and
// stats.Measured() is true.
func VerifyUserspaceShimObjectStats(path string) (ShimVerifierStats, error) {
	var stats ShimVerifierStats
	if err := rlimit.RemoveMemlock(); err != nil {
		return stats, fmt.Errorf("remove memlock rlimit: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return stats, fmt.Errorf("load candidate spec from %s: %w", path, err)
	}
	return verifyUserspaceShimSpecWithShrinkStats(spec, true)
}

// verifyUserspaceShimSpecOnly validates the spec exactly as the
// production loader would, then runs the kernel verifier via an
// anonymous (unpinned, unattached) collection load.
//
// ORDER MATTERS: validateUserspaceShimSpec checks the UNMODIFIED spec
// (it asserts dnat_table.MaxEntries == userspaceShimMaxSessions among
// others); the hash-map shrink is applied to a copy afterwards, just
// before the load.
func verifyUserspaceShimSpecOnly(spec *ebpf.CollectionSpec) error {
	return verifyUserspaceShimSpecWithShrink(spec, true)
}

// verifyUserspaceShimSpecWithShrink exists so the root-gated
// shrink-equivalence test can prove that the MaxEntries shrink does
// not change the verifier verdict (PASS object passes both ways, the
// preserved #1864 REJECT object rejects both ways). Production
// callers always shrink.
func verifyUserspaceShimSpecWithShrink(spec *ebpf.CollectionSpec, shrink bool) error {
	_, err := verifyUserspaceShimSpecWithShrinkStats(spec, shrink)
	return err
}

// verifyUserspaceShimSpecWithShrinkStats is the implementation. It loads
// with LogLevelStats so the verifier's processed-insn count is available
// on SUCCESS as well as on reject — the binary PASS/REJECT verdict alone
// cannot tell you the object is one edit away from the 1M wall, which is
// how master came to sit at 0.92% headroom unnoticed (#4555).
//
// Requesting stats does not change the verdict: it only asks the kernel
// to emit its summary line into the log buffer. A load that passes
// without the flag passes with it.
func verifyUserspaceShimSpecWithShrinkStats(spec *ebpf.CollectionSpec, shrink bool) (ShimVerifierStats, error) {
	var stats ShimVerifierStats
	if err := validateUserspaceShimSpec(spec); err != nil {
		return stats, fmt.Errorf("spec validation (production-load viability): %w", err)
	}

	vspec := spec.Copy()
	if shrink {
		for _, ms := range vspec.Maps {
			switch ms.Type {
			case ebpf.Hash, ebpf.PerCPUHash, ebpf.LRUHash, ebpf.LRUCPUHash:
				if ms.MaxEntries > verifyShrinkHashMaxEntries {
					ms.MaxEntries = verifyShrinkHashMaxEntries
				}
			}
		}
	}

	coll, err := ebpf.NewCollectionWithOptions(vspec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return stats, fmt.Errorf("%w: kernel verifier rejected %s:\n%s",
				ErrUserspaceShimVerifierReject, userspaceShimEntryProg, verifierLogTail(ve))
		}
		return stats, fmt.Errorf("verify-only collection load: %w", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs[userspaceShimEntryProg]
	if !ok {
		return stats, fmt.Errorf("candidate object loaded but %s program is missing", userspaceShimEntryProg)
	}
	stats = parseShimVerifierStats(prog.VerifierLog)
	return stats, nil
}

// ShimVerifierStats carries the kernel verifier's own accounting for a
// shim candidate that LOADED. Measured is false when the running
// kernel's log did not carry a recognisable stats line — callers must
// treat that as "cannot measure", never as "headroom is fine".
type ShimVerifierStats struct {
	ProcessedInsns int
	InsnLimit      int
}

// Measured reports whether a usable processed-insn count was recovered.
func (s ShimVerifierStats) Measured() bool {
	return s.ProcessedInsns > 0 && s.InsnLimit > 0
}

// HeadroomPct is the percentage of the verifier's processed-insn budget
// the candidate leaves unused. Zero when unmeasured.
func (s ShimVerifierStats) HeadroomPct() float64 {
	if !s.Measured() {
		return 0
	}
	return 100 * float64(s.InsnLimit-s.ProcessedInsns) / float64(s.InsnLimit)
}

// SlackToFloorInsns is how many additional processed instructions a change may
// cost before this object would trip the given headroom floor (#6884).
//
// HeadroomPct answers "how close is this object to the 1M wall". This answers
// the question the FLOOR's sensitivity actually depends on: "how much can still
// land without the tripwire firing". They diverge as the object improves, and
// that divergence is silent — the floor was chosen against a 5.3% object and
// went on reading 3% while the object moved to 21.58%, at which point the same
// constant admitted 1-2 whole extension-header iterations without a word.
// Reporting this on every build is what makes that drift visible at the moment
// it happens rather than by archaeology.
//
// Negative means the object is already past the floor, and the magnitude is how
// far — useful in the refusal path, where "by how much" is the first thing
// asked. Returns 0 when unmeasured, which callers must not read as "no slack":
// stats.Measured() is the guard, and an unmeasured object is a refusal on its
// own (see decide()).
func (s ShimVerifierStats) SlackToFloorInsns(floorPct float64) int {
	if !s.Measured() {
		return 0
	}
	admitted := int(float64(s.InsnLimit) * (1 - floorPct/100))
	return admitted - s.ProcessedInsns
}

// shimVerifierStatsRe matches the kernel's end-of-verification summary,
// e.g. "processed 947188 insns (limit 1000000) max_states_per_insn 34 ...".
var shimVerifierStatsRe = regexp.MustCompile(`processed (\d+) insns \(limit (\d+)\)`)

func parseShimVerifierStats(log string) ShimVerifierStats {
	var stats ShimVerifierStats
	m := shimVerifierStatsRe.FindStringSubmatch(log)
	if len(m) != 3 {
		return stats
	}
	processed, err := strconv.Atoi(m[1])
	if err != nil {
		return stats
	}
	limit, err := strconv.Atoi(m[2])
	if err != nil {
		return stats
	}
	return ShimVerifierStats{ProcessedInsns: processed, InsnLimit: limit}
}

func verifierLogTail(ve *ebpf.VerifierError) string {
	log := ve.Log
	if len(log) > verifierLogTailLines {
		log = log[len(log)-verifierLogTailLines:]
	}
	var b strings.Builder
	for _, line := range log {
		b.WriteString("  ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
