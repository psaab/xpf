package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #4555: the gate's DECISION, pinned where it is made.
//
// pkg/dataplane can pin the stats parsing and the headroom arithmetic, but
// not what this binary concludes from them — and an earlier test that
// claimed to pin "an unmeasurable stats line must reach the refusal path"
// only re-asserted `Measured() == false` and `HeadroomPct() == 0`, both
// already covered by TestParseShimVerifierStats_Unmeasurable. It would have
// stayed green with `decide` returning 0 for every input, which is exactly
// the failure it names.
//
// `decide` consumes only `Measured()` and `HeadroomPct()`, so the fixtures
// below are built as ShimVerifierStats values rather than parsed from logs;
// which logs produce an unmeasured value is pinned in pkg/dataplane's
// TestParseShimVerifierStats_Unmeasurable.
//
// Every reachable (stats, override) combination is enumerated, including the
// exit-6 override-success arm the build recipe carries an arm for, and
// including the object sitting EXACTLY ON the floor. The comparison is `<`,
// so exactly-on-the-floor PASSES; every other fixture here is strictly on one
// side or the other and leaves `<` and `<=` indistinguishable, which is a
// whole missing case rather than a stylistic one — changing the comparison to
// `<=` flips a 3.00%% object from install to refusal with every other fixture
// unmoved.
func TestShimverifyDecision(t *testing.T) {
	// Above the floor: 800000/1000000 leaves 20.00%. SYNTHETIC and round,
	// chosen purely for its relation to the floor.
	//
	// #6884: this was 947,188 labelled "the current object" — a hand-maintained
	// live number, the same defect this issue removed from the floor's doc
	// comment, and the one that misled a reviewer into a cross-kernel inference
	// the data did not support. When the floor moved 3% -> 15% it also turned a
	// correct raise into a phantom "rejects the current object" failure. A
	// fixture's job is to sit above or below the threshold; claiming to be the
	// live object is a different job that goes stale by construction.
	above := dataplane.ShimVerifierStats{ProcessedInsns: 800000, InsnLimit: 1000000}
	// Below it: 990796/1000000 leaves 0.92%, master before #4555.
	below := dataplane.ShimVerifierStats{ProcessedInsns: 990796, InsnLimit: 1000000}
	// EXACTLY on it: 850000/1000000 leaves 15.00%, which in IEEE-754 is the
	// floor's value bit for bit (100*(10^6-97*10^4)/10^6 == 3.0 exactly, both
	// operands being exactly representable), so this fixture straddles nothing.
	atFloor := dataplane.ShimVerifierStats{ProcessedInsns: 850000, InsnLimit: 1000000}
	// No recognisable stats line: Measured() is false.
	unmeasured := dataplane.ShimVerifierStats{}

	if unmeasured.Measured() {
		t.Fatalf("the unmeasured fixture is measured (%+v); the cases below would not exercise the refusal path", unmeasured)
	}
	if above.HeadroomPct() < dataplane.UserspaceShimMinVerifierHeadroomPct {
		t.Fatalf("the above-floor fixture (%.2f%%) is below the floor %.1f%%",
			above.HeadroomPct(), dataplane.UserspaceShimMinVerifierHeadroomPct)
	}
	if below.HeadroomPct() >= dataplane.UserspaceShimMinVerifierHeadroomPct {
		t.Fatalf("the below-floor fixture (%.2f%%) is above the floor %.1f%%",
			below.HeadroomPct(), dataplane.UserspaceShimMinVerifierHeadroomPct)
	}
	if atFloor.HeadroomPct() != dataplane.UserspaceShimMinVerifierHeadroomPct {
		t.Fatalf("the exact-floor fixture measures %v, not the floor %v; it would not distinguish `<` from `<=`",
			atFloor.HeadroomPct(), dataplane.UserspaceShimMinVerifierHeadroomPct)
	}

	for _, tc := range []struct {
		name       string
		stats      dataplane.ShimVerifierStats
		overridden bool
		want       shimverifyDecision
	}{
		{
			name:  "measured above the floor",
			stats: above,
			want:  shimverifyDecision{refusal: refusalNone, exit: 0, label: "PASS"},
		},
		{
			name:       "measured above the floor, override exported but not needed",
			stats:      above,
			overridden: true,
			want:       shimverifyDecision{refusal: refusalNone, exit: 0, label: "PASS", staleOverrideNote: true},
		},
		{
			// The floor is a MINIMUM, so an object leaving exactly it is
			// acceptable. This is the only fixture that binds the comparison's
			// strictness.
			name:  "measured exactly at the floor",
			stats: atFloor,
			want:  shimverifyDecision{refusal: refusalNone, exit: 0, label: "PASS"},
		},
		{
			name:       "measured exactly at the floor, override exported but not needed",
			stats:      atFloor,
			overridden: true,
			want:       shimverifyDecision{refusal: refusalNone, exit: 0, label: "PASS", staleOverrideNote: true},
		},
		{
			name:  "measured below the floor",
			stats: below,
			want:  shimverifyDecision{refusal: refusalLowHeadroom, exit: 4, label: "LOW-HEADROOM"},
		},
		{
			name:       "measured below the floor, overridden",
			stats:      below,
			overridden: true,
			want: shimverifyDecision{
				refusal: refusalLowHeadroom, exit: 6, label: "OVERRIDDEN", overrideConsumed: true,
			},
		},
		{
			name:  "unmeasurable",
			stats: unmeasured,
			want:  shimverifyDecision{refusal: refusalUnmeasured, exit: 5, label: "UNMEASURED-HEADROOM"},
		},
		{
			name:       "unmeasurable, overridden",
			stats:      unmeasured,
			overridden: true,
			want: shimverifyDecision{
				refusal: refusalUnmeasured, exit: 6, label: "OVERRIDDEN", overrideConsumed: true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decide(tc.stats, tc.overridden); got != tc.want {
				t.Errorf("decide(%+v, %v) = %+v, want %+v", tc.stats, tc.overridden, got, tc.want)
			}
		})
	}
}

// #4555: the BINARY's exit status, which is the only thing
// build-userspace-xdp.sh reads.
//
// TestShimverifyDecision above pins `decide`. That was NOT enough: `main` used
// to call `decide` and then INDEPENDENTLY repeat both of its predicates to pick
// its branch and its os.Exit call, so the tested function was not the shipped
// gate. Measured at e2a85e311 — rewriting main's low-headroom predicate to
// `if false` left `go build`, `go vet` and this whole package's suite green
// while a 990796/1000000 object printed "LOW-HEADROOM ... headroom 0.92%" and
// exited 0, which the recipe's `0) ;;` arm INSTALLS.
//
// So this runs `run` itself, with argv, the environment, both streams and the
// kernel verifier injected, and asserts the exit status AND the status word on
// stdout for every arm the recipe branches on. A predicate reintroduced into
// `run`, or an arm returning the wrong code, reds here.
func TestShimverifyRun(t *testing.T) {
	const obj = "/tmp/candidate.o"
	ok := func(s dataplane.ShimVerifierStats) func(string) (dataplane.ShimVerifierStats, error) {
		return func(p string) (dataplane.ShimVerifierStats, error) {
			if p != obj {
				t.Errorf("verify called with %q, want %q", p, obj)
			}
			return s, nil
		}
	}
	failWith := func(err error) func(string) (dataplane.ShimVerifierStats, error) {
		return func(string) (dataplane.ShimVerifierStats, error) {
			return dataplane.ShimVerifierStats{}, err
		}
	}
	env := func(v string) func(string) string {
		return func(k string) string {
			if k != allowLowHeadroomEnv {
				t.Errorf("run read env %q, want only %q", k, allowLowHeadroomEnv)
			}
			return v
		}
	}

	above := dataplane.ShimVerifierStats{ProcessedInsns: 800000, InsnLimit: 1000000}
	atFloor := dataplane.ShimVerifierStats{ProcessedInsns: 850000, InsnLimit: 1000000}
	below := dataplane.ShimVerifierStats{ProcessedInsns: 990796, InsnLimit: 1000000}

	for _, tc := range []struct {
		name     string
		args     []string
		env      string
		verify   func(string) (dataplane.ShimVerifierStats, error)
		wantExit int
		// wantOut is the status word `build-userspace-xdp.sh` and CI read off
		// stdout; empty means stdout must be empty.
		wantOut string
	}{
		{
			name: "no argument", args: []string{"shimverify"}, env: "",
			verify: ok(above), wantExit: 2, wantOut: "",
		},
		{
			name: "too many arguments", args: []string{"shimverify", obj, obj}, env: "",
			verify: ok(above), wantExit: 2, wantOut: "",
		},
		{
			name: "kernel verifier REJECT", args: []string{"shimverify", obj}, env: "",
			verify: failWith(fmt.Errorf("load: %w", dataplane.ErrUserspaceShimVerifierReject)),
			// The recipe's `3)` arm refuses to install and names #1864.
			wantExit: 3, wantOut: "REJECT",
		},
		{
			name: "other error (no CAP_BPF)", args: []string{"shimverify", obj}, env: "",
			verify: failWith(fmt.Errorf("operation not permitted")), wantExit: 1, wantOut: "",
		},
		{
			name: "measured above the floor", args: []string{"shimverify", obj}, env: "",
			verify: ok(above), wantExit: 0, wantOut: "PASS",
		},
		{
			name: "measured exactly at the floor", args: []string{"shimverify", obj}, env: "",
			verify: ok(atFloor), wantExit: 0, wantOut: "PASS",
		},
		{
			// The case the `if false` mutation turned into an exit 0.
			name: "measured below the floor", args: []string{"shimverify", obj}, env: "",
			verify: ok(below), wantExit: 4, wantOut: "LOW-HEADROOM",
		},
		{
			name: "measured below the floor, overridden", args: []string{"shimverify", obj}, env: "1",
			verify: ok(below), wantExit: 6, wantOut: "OVERRIDDEN",
		},
		{
			name: "unmeasurable", args: []string{"shimverify", obj}, env: "",
			verify: ok(dataplane.ShimVerifierStats{}), wantExit: 5, wantOut: "UNMEASURED-HEADROOM",
		},
		{
			name: "unmeasurable, overridden", args: []string{"shimverify", obj}, env: "1",
			verify: ok(dataplane.ShimVerifierStats{}), wantExit: 6, wantOut: "OVERRIDDEN",
		},
		{
			// Any value other than exactly "1" is not the override.
			name: "below the floor, override set to 0", args: []string{"shimverify", obj}, env: "0",
			verify: ok(below), wantExit: 4, wantOut: "LOW-HEADROOM",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			got := run(tc.args, &out, &errOut, env(tc.env), tc.verify)
			if got != tc.wantExit {
				t.Errorf("run(%q, env=%q) = exit %d, want %d\nstdout: %s\nstderr: %s",
					tc.args, tc.env, got, tc.wantExit, out.String(), errOut.String())
			}
			switch {
			case tc.wantOut == "" && out.Len() != 0:
				t.Errorf("run(%q) wrote %q to stdout, want nothing", tc.args, out.String())
			case tc.wantOut != "" && !strings.HasPrefix(out.String(), tc.wantOut+" "):
				t.Errorf("run(%q) stdout = %q, want it to start with the status word %q",
					tc.args, out.String(), tc.wantOut)
			}
		})
	}
}

// The property that makes the exit status usable as a gate, stated over `run`
// rather than over `decide`: the ONLY input that exits 0 is a measured object
// at or above the floor. Everything else — below the floor, unmeasurable, a
// verifier reject, an error, a usage mistake — must be nonzero, with or
// without the override, because the recipe installs on 0.
func TestShimverifyRunNeverExitsZeroWithoutMeasuredHeadroom(t *testing.T) {
	const obj = "/tmp/candidate.o"
	stats := []dataplane.ShimVerifierStats{
		{},                                      // no stats line at all
		{ProcessedInsns: 0, InsnLimit: 1000000}, // limit but no count
		{ProcessedInsns: 947188, InsnLimit: 0},  // count but no limit
		{ProcessedInsns: 990796, InsnLimit: 1000000},  // 0.92%, pre-#4555 master
		{ProcessedInsns: 999999, InsnLimit: 1000000},  // 0.0001%
		{ProcessedInsns: 1000000, InsnLimit: 1000000}, // at the wall
	}
	for _, s := range stats {
		for _, envVal := range []string{"", "1"} {
			var out, errOut bytes.Buffer
			got := run([]string{"shimverify", obj}, &out, &errOut,
				func(string) string { return envVal },
				func(string) (dataplane.ShimVerifierStats, error) { return s, nil })
			if got == 0 {
				t.Errorf("run(%+v, override=%q) exited 0 — build-userspace-xdp.sh installs on 0, "+
					"so this object would ship with the #4555 gate unsatisfied. stdout: %s",
					s, envVal, out.String())
			}
			if strings.HasPrefix(out.String(), "PASS ") {
				t.Errorf("run(%+v, override=%q) printed PASS", s, envVal)
			}
		}
	}
	for _, verify := range []func(string) (dataplane.ShimVerifierStats, error){
		failWithErr(fmt.Errorf("wrapped: %w", dataplane.ErrUserspaceShimVerifierReject)),
		failWithErr(fmt.Errorf("operation not permitted")),
	} {
		var out, errOut bytes.Buffer
		if got := run([]string{"shimverify", obj}, &out, &errOut,
			func(string) string { return "1" }, verify); got == 0 {
			t.Errorf("run exited 0 on a verifier failure even with the override set; stdout: %s", out.String())
		}
	}
}

func failWithErr(err error) func(string) (dataplane.ShimVerifierStats, error) {
	return func(string) (dataplane.ShimVerifierStats, error) {
		return dataplane.ShimVerifierStats{}, err
	}
}

// The property the exit codes exist for, stated on its own rather than left
// to be read off the table above: the ONLY way to exit 0 is a MEASURED
// object above the floor. An unmeasurable one must never pass, overridden or
// not — a gate that switches itself off when the kernel's log format changes
// reproduces the blind spot it exists to close. An overridden install is 6,
// which still installs but stays distinguishable to the recipe and to CI.
func TestShimverifyNeverPassesAnUnmeasuredObject(t *testing.T) {
	for _, stats := range []dataplane.ShimVerifierStats{
		{},
		{ProcessedInsns: 0, InsnLimit: 1000000},
		{ProcessedInsns: 947188, InsnLimit: 0},
	} {
		if stats.Measured() {
			t.Fatalf("fixture %+v is measured", stats)
		}
		for _, overridden := range []bool{false, true} {
			got := decide(stats, overridden)
			if got.exit == 0 {
				t.Errorf("decide(unmeasured %+v, overridden=%v) = exit 0 — an object whose headroom could not be measured passed the gate", stats, overridden)
			}
			if got.label == "PASS" {
				t.Errorf("decide(unmeasured %+v, overridden=%v) reports PASS", stats, overridden)
			}
			if overridden && !got.overrideConsumed {
				t.Errorf("decide(unmeasured %+v, overridden=true) did not record the override as consumed, so the run would install without announcing itself", stats)
			}
		}
	}
}

// The durable gate record is the only evidence left after the build log
// expires. Exercise shimverify's actual output path for both a normal pass
// and both override reasons, including the hash that binds the verdict to
// the installed object.
func TestShimverifyWritesGateVerdict(t *testing.T) {
	for _, tc := range []struct {
		name       string
		stats      dataplane.ShimVerifierStats
		override   string
		wantExit   int
		wantLabel  string
		wantReason string
	}{
		{
			name:       "measured pass",
			stats:      dataplane.ShimVerifierStats{ProcessedInsns: 800000, InsnLimit: 1000000},
			wantExit:   0,
			wantLabel:  "PASS",
			wantReason: "meets",
		},
		{
			name:       "measured low-headroom override",
			stats:      dataplane.ShimVerifierStats{ProcessedInsns: 990796, InsnLimit: 1000000},
			override:   "1",
			wantExit:   6,
			wantLabel:  "OVERRIDDEN",
			wantReason: "below",
		},
		{
			name:       "unmeasured override",
			override:   "1",
			wantExit:   6,
			wantLabel:  "OVERRIDDEN",
			wantReason: "could not be measured",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			objectPath := filepath.Join(dir, "candidate.o")
			object := []byte("candidate object for verdict binding")
			if err := os.WriteFile(objectPath, object, 0o600); err != nil {
				t.Fatal(err)
			}
			verdictPath := filepath.Join(dir, "gate-verdict.json")
			var stdout, stderr bytes.Buffer
			gotExit := run(
				[]string{"shimverify", objectPath, "--gate-verdict", verdictPath},
				&stdout, &stderr,
				func(string) string { return tc.override },
				func(path string) (dataplane.ShimVerifierStats, error) {
					if path != objectPath {
						t.Fatalf("verifier path = %q, want %q", path, objectPath)
					}
					return tc.stats, nil
				},
			)
			if gotExit != tc.wantExit {
				t.Fatalf("run exit = %d, want %d; stdout=%q stderr=%q", gotExit, tc.wantExit, stdout.String(), stderr.String())
			}

			raw, err := os.ReadFile(verdictPath)
			if err != nil {
				t.Fatalf("read verdict: %v", err)
			}
			var got gateVerdict
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("decode verdict: %v", err)
			}
			sum := sha256.Sum256(object)
			if got.SchemaVersion != 1 || got.ObjectSHA256 != hex.EncodeToString(sum[:]) {
				t.Errorf("schema/object binding = (%d, %q), want schema 1 and candidate SHA-256", got.SchemaVersion, got.ObjectSHA256)
			}
			if _, err := time.Parse(time.RFC3339Nano, got.VerifiedAt); err != nil {
				t.Errorf("verified_at %q is not a timestamp: %v", got.VerifiedAt, err)
			}
			if got.Verdict != tc.wantLabel || got.OverrideConsumed != (tc.override == "1") {
				t.Errorf("verdict/override = (%q, %v), want (%q, %v)", got.Verdict, got.OverrideConsumed, tc.wantLabel, tc.override == "1")
			}
			if !strings.Contains(got.Reason, tc.wantReason) {
				t.Errorf("reason %q does not explain %q", got.Reason, tc.wantReason)
			}
			if got.Stats.Measured != tc.stats.Measured() ||
				got.Stats.ProcessedInsns != tc.stats.ProcessedInsns ||
				got.Stats.InsnLimit != tc.stats.InsnLimit ||
				got.Stats.HeadroomPct != tc.stats.HeadroomPct() ||
				got.Stats.SlackToFloorInsns != tc.stats.SlackToFloorInsns(dataplane.UserspaceShimMinVerifierHeadroomPct) ||
				got.Stats.FloorPct != dataplane.UserspaceShimMinVerifierHeadroomPct {
				t.Errorf("recorded stats = %+v, want source stats %+v and floor %.1f",
					got.Stats, tc.stats, dataplane.UserspaceShimMinVerifierHeadroomPct)
			}
		})
	}
}

func TestShimverifyDoesNotPassWhenVerdictCannotBeRecorded(t *testing.T) {
	dir := t.TempDir()
	objectPath := filepath.Join(dir, "candidate.o")
	if err := os.WriteFile(objectPath, []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	got := run(
		[]string{"shimverify", objectPath, "--gate-verdict", filepath.Join(dir, "missing", "verdict.json")},
		&stdout, &stderr, func(string) string { return "" },
		func(string) (dataplane.ShimVerifierStats, error) {
			return dataplane.ShimVerifierStats{ProcessedInsns: 800000, InsnLimit: 1000000}, nil
		},
	)
	if got != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "write gate verdict") {
		t.Fatalf("run = %d stdout=%q stderr=%q; want fail-closed verdict write error", got, stdout.String(), stderr.String())
	}
}
