// shimverify runs the kernel BPF verifier against a userspace-xdp shim
// candidate object without touching any production state (#1864).
//
// It is the build-time gate invoked by
// pkg/dataplane/build-userspace-xdp.sh: the freshly-built candidate is
// verified BEFORE it may replace the git-tracked
// pkg/dataplane/userspace_xdp_bpfel.o. A REJECT here is a failed
// `make generate`, not a dead dataplane.
//
// Requires CAP_BPF (typically root): the check is a real
// BPF_PROG_LOAD against the running kernel — static analysis cannot
// substitute (the 2026-06-10 incident objects differed by only 7
// static instructions; the explosion was in the verifier's state
// walk).
//
// #4555 headroom floor: a binary PASS/REJECT cannot distinguish an
// object with room to grow from one a single edit away from the 1M
// processed-insn wall. Master sat at 0.92% headroom with every gate
// green until a routine change to the IPv6 extension-header walk hit
// that wall. So a candidate that LOADS but leaves less than
// dataplane.UserspaceShimMinVerifierHeadroomPct of the budget unused is
// also refused, with XPF_SHIM_ALLOW_LOW_HEADROOM=1 as the deliberate
// override (mirroring XPF_SHIM_ALLOW_UNPINNED_INSTALL in the recipe).
//
// UNMEASURABLE IS ALSO A FAILURE (exit 5). An earlier revision warned
// and passed when the kernel's log carried no recognisable stats line,
// reasoning that "cannot measure" is not "at the wall". That was wrong:
// this tripwire exists because nothing was watching while the shim crept
// to 0.92%, and a gate that switches itself off when the log format
// changes reproduces exactly that failure mode — silently, at the one
// moment headroom is unknown. A warning is invisible in an automated
// build, which is the only place this matters. It takes the SAME
// override, so a genuine kernel/log-format difference is one documented
// env var away from unblocking, but installing an unmeasured object now
// requires someone to say so.
//
// An OVERRIDDEN run gets its OWN exit code (6), never 0. Returning 0
// collapsed "measured and comfortably above the floor" into "we could not
// check, and someone had the variable exported", which a non-interactive
// caller cannot tell apart — and the recipe's `0) ;;` arm installed both
// without comment. 6 still INSTALLS (the override means the operator
// accepted the risk) but it is visible to the recipe and to CI as an exit
// code and as the `OVERRIDDEN` status word on stdout, without anyone
// parsing stderr. At install time the build recipe asks shimverify to write
// a sidecar with the decision, override bit, verifier stats, reason and hash
// of the candidate object.
//
// Exit codes: 0 PASS (measured, above the floor), 2 usage, 3 verifier
// REJECT, 4 loads but headroom below the floor, 5 loads but headroom could
// not be measured, 6 loads and INSTALLS with the gate overridden, 1 other
// error (including insufficient privileges).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// main is DELIBERATELY a single expression. Everything it used to do lives in
// `run`, which returns the exit status instead of calling os.Exit, so the
// binary's own behaviour is reachable from a test.
//
// This is not tidiness. `decide` was unit-tested while `main` independently
// REPEATED both of the gate's predicates — `!stats.Measured()` and
// `headroom < UserspaceShimMinVerifierHeadroomPct` — to choose its branch AND
// its os.Exit call. The tested function was therefore not the binary's
// decision. Measured, at e2a85e311: rewriting main's low-headroom predicate to
// `if false` left `go build`, `go vet` and the whole cmd/shimverify suite green
// while a 990796/1000000 object printed "LOW-HEADROOM ... headroom 0.92%" and
// exited 0 — the recipe's `0) ;;` arm installs that, which is precisely the
// pre-#4555 fail-open the gate exists to close, restored underneath passing
// tests. A safety gate whose guard cannot fire on the gate itself is the worst
// case here, so the predicates now exist in exactly one place (`decide`) and
// `run` only PRESENTS what it returns.
func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr, os.Getenv, dataplane.VerifyUserspaceShimObjectStats))
}

// run is the whole of shimverify, with the process boundary (argv, the two
// output streams, the environment and the kernel verifier) taken as parameters
// so TestShimverifyRun can exercise the REAL control flow — including the exit
// status the build recipe branches on — without a kernel, root, or an object.
//
// It re-derives NOTHING. `decide` maps (stats, override) to a verdict; the
// switch below picks the matching diagnostic off `decision.refusal` and every
// path returns `decision.exit`. The optional `--gate-verdict` path records the
// same decision before it is presented.
func run(
	args []string,
	stdout, stderr io.Writer,
	getenv func(string) string,
	verify func(string) (dataplane.ShimVerifierStats, error),
) int {
	withVerdict := len(args) == 4 && args[2] == "--gate-verdict" && args[3] != ""
	if len(args) != 2 && !withVerdict {
		fmt.Fprintln(stderr, "usage: shimverify <userspace_xdp_bpfel.o> [--gate-verdict path]")
		return 2
	}
	path := args[1]
	stats, err := verify(path)
	if err != nil {
		if errors.Is(err, dataplane.ErrUserspaceShimVerifierReject) {
			fmt.Fprintf(stdout, "REJECT %s\n%v\n", path, err)
			return 3
		}
		fmt.Fprintf(stderr, "shimverify: %s: %v\n", path, err)
		return 1
	}

	decision := decide(stats, getenv(allowLowHeadroomEnv) == "1")
	if withVerdict && (decision.exit == 0 || decision.exit == 6) {
		if err := writeGateVerdict(args[3], path, stats, decision); err != nil {
			fmt.Fprintf(stderr, "shimverify: write gate verdict %s: %v\n", args[3], err)
			return 1
		}
	}
	// #6884: the banner carries the floor's remaining SLACK, not just the
	// headroom. Headroom answers "how close to the 1M wall"; slack answers the
	// question this gate's sensitivity actually rests on — "how much can still
	// land before the tripwire fires". The two diverge as the object improves,
	// silently: the floor was chosen against a 5.3% object and went on reading
	// 3% while the object reached 21.58%, at which point it admitted 1-2 whole
	// extension-header iterations without a word. Printing slack on every build
	// is what surfaces that drift when it happens instead of by archaeology.
	summary := fmt.Sprintf("processed %d insns (limit %d), headroom %.2f%%, "+
		"%d insns of slack before the %.1f%% floor",
		stats.ProcessedInsns, stats.InsnLimit, stats.HeadroomPct(),
		stats.SlackToFloorInsns(dataplane.UserspaceShimMinVerifierHeadroomPct),
		dataplane.UserspaceShimMinVerifierHeadroomPct)

	switch decision.refusal {
	case refusalUnmeasured:
		if decision.overrideConsumed {
			fmt.Fprintf(stdout, "%s %s (headroom UNMEASURED)\n", decision.label, path)
			announceOverrideConsumed(stderr, path,
				"this kernel's verifier log carried no \"processed N insns (limit M)\" line, "+
					"so the floor could not be applied at all")
			break
		}
		fmt.Fprintf(stdout, "%s %s\n", decision.label, path)
		fmt.Fprintf(stderr,
			"shimverify: the candidate LOADS, but this kernel's verifier log carried no "+
				"\"processed N insns (limit M)\" line, so the #4555 headroom floor (%.1f%%) "+
				"could NOT be applied. How close this object is to the 1M processed-insn wall "+
				"is UNKNOWN.\n"+
				"  Unmeasurable is treated as a failure on purpose. This tripwire exists "+
				"because nothing was watching while the shim crept to 0.92%% headroom; a gate "+
				"that switches itself off when the log format changes reproduces that exact "+
				"failure mode at the one moment headroom is unknown.\n"+
				"  If your kernel genuinely reports differently, set %s=1 to install anyway — "+
				"that is an explicit acknowledgement that this object shipped unmeasured.\n",
			dataplane.UserspaceShimMinVerifierHeadroomPct, allowLowHeadroomEnv)

	case refusalLowHeadroom:
		fmt.Fprintf(stdout, "%s %s (%s)\n", decision.label, path, summary)
		if decision.overrideConsumed {
			announceOverrideConsumed(stderr, path, fmt.Sprintf(
				"headroom %.2f%% is below the floor of %.1f%%; the next change to the shim's "+
					"hot parsing paths may not fit",
				stats.HeadroomPct(), dataplane.UserspaceShimMinVerifierHeadroomPct))
			break
		}
		fmt.Fprintf(stderr,
			"shimverify: the candidate LOADS, but leaves only %.2f%% of the verifier's "+
				"processed-insn budget unused — below the #4555 floor of %.1f%%.\n"+
				"  This is not a kernel rejection; it is the tripwire that exists because "+
				"a binary PASS/REJECT gate let the shim reach 0.92%% headroom unnoticed, "+
				"and the next edit to its parsing paths then hit the 1M wall (#1864 is "+
				"what that costs: both HA dataplanes down).\n"+
				"  Reduce verifier cost — the fully-unrolled IPv6 extension-header walk in "+
				"parse_ipv6 is the largest consumer, see pkg/dataplane/README.md — or set "+
				"%s=1 to install anyway with the risk understood.\n",
			stats.HeadroomPct(), dataplane.UserspaceShimMinVerifierHeadroomPct, allowLowHeadroomEnv)

	case refusalNone:
		// The override is read from the ambient environment, so a value
		// exported once to get past a low-headroom object would silently
		// disarm every later run. Surface it on the HEALTHY path too: the
		// only place staleness is visible is a build that did not need it.
		if decision.staleOverrideNote {
			fmt.Fprintf(stderr,
				"shimverify: NOTE: %s=1 is set in the environment but was NOT needed — this object "+
					"is measured at %.2f%% headroom, above the %.1f%% floor. If that value is left "+
					"exported it will silently disarm the gate on a future run. Unset it.\n",
				allowLowHeadroomEnv, stats.HeadroomPct(), dataplane.UserspaceShimMinVerifierHeadroomPct)
		}
		fmt.Fprintf(stdout, "%s %s (%s)\n", decision.label, path, summary)
		noteFloorNoLongerTripwires(stderr,
			stats.SlackToFloorInsns(dataplane.UserspaceShimMinVerifierHeadroomPct))
	}

	return decision.exit
}

// allowLowHeadroomEnv is the documented, deliberate override for BOTH
// #4555 refusals: measured-but-below-floor and could-not-measure.
const allowLowHeadroomEnv = "XPF_SHIM_ALLOW_LOW_HEADROOM"

// shimverifyDecision is what the #4555 gate CONCLUDES about one candidate,
// separated from how it says so. main() prints the long-form diagnostics;
// this carries the part a caller acts on.
//
// It exists so the decision can be TESTED. Before it, the only assertion
// about "an unmeasurable stats line must reach the refusal path" re-tested
// parseShimVerifierStats and HeadroomPct() — both already covered
// elsewhere — and would have stayed green with this binary passing every
// input. A gate's decision has to be checkable without a kernel verifier.
type shimverifyDecision struct {
	// refusal names WHICH #4555 condition was found, so `run` can pick the
	// matching diagnostic without re-deriving the condition from the stats.
	// This field is the fix for the divergence documented on `main`: with
	// `run` branching on the verdict instead of on its own copy of the
	// predicates, `decide` is the only place either predicate exists, and
	// TestShimverifyDecision therefore binds what the binary does.
	refusal shimverifyRefusal
	// exit is the process exit status; build-userspace-xdp.sh carries one
	// arm per value.
	exit int
	// label is the status word on stdout: PASS, LOW-HEADROOM,
	// UNMEASURED-HEADROOM or OVERRIDDEN.
	label string
	// overrideConsumed is true when XPF_SHIM_ALLOW_LOW_HEADROOM=1 turned a
	// refusal into an install. That run must announce itself loudly.
	overrideConsumed bool
	// staleOverrideNote is true when the override was exported but the
	// object did not need it — the only run where a stale exported value is
	// visible, so it is where we warn.
	staleOverrideNote bool
}

// shimverifyRefusal names the #4555 condition `decide` found. It is what lets
// `run` present a refusal without re-testing the stats for which refusal it is
// — the repetition that made the tested `decide` and the shipped binary two
// different gates.
//
// Adding a kind means adding a `run` case AND a TestShimverifyRun row. Go
// cannot enforce that: an unhandled kind still returns `decision.exit`, so the
// gate stays correct, but it would print no diagnostic at all. Deliberately not
// papered over with an unreachable `default:` arm — untested code in the
// presentation of a safety gate is what this file is being repaired for.
type shimverifyRefusal int

const (
	// refusalNone: measured, at or above the floor.
	refusalNone shimverifyRefusal = iota
	// refusalUnmeasured: the object loads, but no "processed N insns
	// (limit M)" line was found, so the floor could not be applied at all.
	refusalUnmeasured
	// refusalLowHeadroom: measured, below the floor.
	refusalLowHeadroom
)

// decide maps (stats, override) to the gate's verdict.
//
// UNMEASURED is a refusal, not a pass: this tripwire exists because nothing
// was watching while the shim crept to 0.92% headroom, and a gate that
// switches itself off when the kernel's log format changes reproduces that
// failure at the one moment headroom is unknown. Both refusals take the
// same override, and an overridden run is 6 — never 0 — so "installed with
// the gate satisfied" and "installed because someone said so" stay distinct
// to a non-interactive caller.
func decide(stats dataplane.ShimVerifierStats, overridden bool) shimverifyDecision {
	if !stats.Measured() {
		if overridden {
			return shimverifyDecision{
				refusal: refusalUnmeasured, exit: 6, label: "OVERRIDDEN", overrideConsumed: true,
			}
		}
		return shimverifyDecision{refusal: refusalUnmeasured, exit: 5, label: "UNMEASURED-HEADROOM"}
	}
	if stats.HeadroomPct() < dataplane.UserspaceShimMinVerifierHeadroomPct {
		if overridden {
			return shimverifyDecision{
				refusal: refusalLowHeadroom, exit: 6, label: "OVERRIDDEN", overrideConsumed: true,
			}
		}
		return shimverifyDecision{refusal: refusalLowHeadroom, exit: 4, label: "LOW-HEADROOM"}
	}
	return shimverifyDecision{refusal: refusalNone, exit: 0, label: "PASS", staleOverrideNote: overridden}
}

// noteFloorNoLongerTripwires reports, on a PASSING build, that the floor has
// stopped satisfying its own stated property (#6884).
//
// The floor promises to fire BEFORE the next structural change lands. Whether
// it still does is a fact about the RELATIONSHIP between the floor and the
// current object, and that relationship moves whenever the object does —
// silently, and in the direction that looks like good news. 3% was chosen
// against a 5.3% object and went on reading 3% while the object reached
// 21.58%, at which point it admitted one to two whole extension-header
// iterations with every gate green.
//
// A test cannot own this. The property depends on the current object size, and
// pinning that in a test reintroduces exactly the hand-maintained live number
// #6884 removed from the floor's doc comment. The BUILD can, because it already
// computes slack from live inputs — so the check needs no maintained current
// value, only the structural-change cost the property is defined against.
//
// This is the general form of the lesson: a threshold whose sensitivity is
// defined relative to a moving value needs a check on the RELATIONSHIP, not on
// the value.
//
// Silent when the property holds. It is a NOTE, not a refusal: the object
// verified and the floor was satisfied, so the build is good — what has decayed
// is the tripwire's usefulness, which is a thing to fix deliberately rather
// than a reason to fail someone's build.
func noteFloorNoLongerTripwires(w io.Writer, slack int) {
	if slack < dataplane.UserspaceShimStructuralChangeInsns {
		return
	}
	fmt.Fprintf(w,
		"shimverify: NOTE (#6884): the %.1f%% floor now admits %d more insns before it "+
			"fires, which is at least one STRUCTURAL change (%d insns — one IPv6 "+
			"extension-header iteration).\n"+
			"  The floor's stated property is that it fires BEFORE the next structural "+
			"change lands. It no longer does: a change that large would be admitted "+
			"silently, which is the exact condition that let the shim reach 0.92%% "+
			"headroom with every gate green.\n"+
			"  This is not a failure — the object verified and the floor was satisfied. "+
			"It means the floor has drifted out of calibration because the object "+
			"IMPROVED, and raising it is now a deliberate decision someone should make.\n",
		dataplane.UserspaceShimMinVerifierHeadroomPct, slack,
		dataplane.UserspaceShimStructuralChangeInsns)
}

// announceOverrideConsumed logs, loudly and unambiguously, that a build
// installed an object the #4555 gate would otherwise have refused, and
// which run consumed the override. The override lives in the ambient
// environment (the recipe threads it through sudo deliberately), so
// without this a stale exported value would suppress the gate with no
// trace in the build log.
func announceOverrideConsumed(w io.Writer, path, reason string) {
	fmt.Fprintf(w,
		"shimverify: ============================================================\n"+
			"shimverify: #4555 HEADROOM GATE OVERRIDDEN via %s=1\n"+
			"shimverify:   object: %s\n"+
			"shimverify:   reason: %s\n"+
			"shimverify:   This object is being installed WITHOUT a satisfied headroom check.\n"+
			"shimverify:   If you did not intend this, the variable is stale in your\n"+
			"shimverify:   environment — unset it and re-run.\n"+
			"shimverify: ============================================================\n",
		allowLowHeadroomEnv, path, reason)
}

type gateVerdictStats struct {
	Measured          bool    `json:"measured"`
	ProcessedInsns    int     `json:"processed_insns"`
	InsnLimit         int     `json:"insn_limit"`
	HeadroomPct       float64 `json:"headroom_pct"`
	FloorPct          float64 `json:"floor_pct"`
	SlackToFloorInsns int     `json:"slack_to_floor_insns"`
}

type gateVerdict struct {
	SchemaVersion    int              `json:"schema_version"`
	VerifiedAt       string           `json:"verified_at"`
	ObjectSHA256     string           `json:"object_sha256"`
	Verdict          string           `json:"verdict"`
	OverrideConsumed bool             `json:"override_consumed"`
	Reason           string           `json:"reason"`
	Stats            gateVerdictStats `json:"stats"`
}

func writeGateVerdict(outPath, objectPath string, stats dataplane.ShimVerifierStats, decision shimverifyDecision) error {
	objectHash, err := shimCandidateSHA256(objectPath)
	if err != nil {
		return err
	}
	reason := fmt.Sprintf("measured headroom %.2f%% meets the %.1f%% floor",
		stats.HeadroomPct(), dataplane.UserspaceShimMinVerifierHeadroomPct)
	switch decision.refusal {
	case refusalUnmeasured:
		reason = "verifier statistics could not be measured; installed with " + allowLowHeadroomEnv + "=1"
	case refusalLowHeadroom:
		reason = fmt.Sprintf("measured headroom %.2f%% is below the %.1f%% floor; installed with %s=1",
			stats.HeadroomPct(), dataplane.UserspaceShimMinVerifierHeadroomPct, allowLowHeadroomEnv)
	}
	verdict := gateVerdict{
		SchemaVersion:    1,
		VerifiedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		ObjectSHA256:     objectHash,
		Verdict:          decision.label,
		OverrideConsumed: decision.overrideConsumed,
		Reason:           reason,
		Stats: gateVerdictStats{
			Measured:          stats.Measured(),
			ProcessedInsns:    stats.ProcessedInsns,
			InsnLimit:         stats.InsnLimit,
			HeadroomPct:       stats.HeadroomPct(),
			FloorPct:          dataplane.UserspaceShimMinVerifierHeadroomPct,
			SlackToFloorInsns: stats.SlackToFloorInsns(dataplane.UserspaceShimMinVerifierHeadroomPct),
		},
	}
	b, err := json.MarshalIndent(verdict, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, append(b, '\n'), 0o644)
}

func shimCandidateSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
