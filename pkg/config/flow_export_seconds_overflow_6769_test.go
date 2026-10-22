package config

import (
	"strconv"
	"strings"
	"testing"
)

// #6769 — `services flow-monitoring` template `seconds` knobs were unbounded.
//
// The compiler stores `template-refresh-rate seconds`, `flow-active-timeout`
// and `flow-inactive-timeout` with a bare `strconv.Atoi` and no range check.
// pkg/flowexport then computed `time.Duration(n) * time.Second`, which
// overflows int64 past MaxDurationSeconds (math.MaxInt64/1e9 = 9223372036) and
// WRAPS. The wrapped product can be small and positive — the dangerous half,
// because the consumer's only guard was `<= 0`. gcd(1e9, 2^64) = 512, so the
// smallest positive residue is exactly 512ns: the fixture below produces a
// 512ns template ticker, re-exporting templates thousands of times a second at
// every collector.
//
// Three layers, one constant (MaxDurationSeconds):
//   - setSchema types the leaves (#1979 Layer B) -> strict operator commit
//     rejects before the compiler runs. Guarded by the SchemaValidate cells.
//   - validateFlowExportSecondsStrict is the compiler-side defense-in-depth for
//     the paths SchemaValidate does not cover (tolerant load / peer-sync,
//     direct CompileConfig callers), mirroring #5244. Guarded by the
//     CompileConfig / CompileConfigLenient cells, which do NOT run
//     SchemaValidate and so isolate the gate.
//   - flowexport.secondsToDuration falls back at the consumer (guarded in
//     pkg/flowexport/template_seconds_overflow_6769_test.go).
const overflowRefreshSeconds = "20211507185753197"

func v9RefreshCmds(seconds string) []string {
	return []string{
		"set services flow-monitoring version9 template t template-refresh-rate seconds " + seconds,
		"set forwarding-options sampling instance s input rate 1000",
		"set forwarding-options sampling instance s family inet output flow-server 10.0.0.1 port 2055 version9 template t",
	}
}

func ipfixRefreshCmds(seconds string) []string {
	return []string{
		"set services flow-monitoring version-ipfix template t template-refresh-rate seconds " + seconds,
		"set forwarding-options sampling instance s input rate 1000",
		"set forwarding-options sampling instance s family inet output flow-server 10.0.0.1 port 2055 version-ipfix template t",
	}
}

// TestFlowExportRefreshOverflowRejectedAtCommit_6769: the compiler-side gate
// hard-rejects an out-of-range v9 refresh rate. Reverting
// validateFlowExportSecondsStrict (or unregistering it) makes this accept.
func TestFlowExportRefreshOverflowRejectedAtCommit_6769(t *testing.T) {
	tree := buildTreeFromSet(t, v9RefreshCmds(overflowRefreshSeconds))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an overflowing template-refresh-rate; expected rejection")
	}
	for _, want := range []string{"flow-monitoring", "version9", "t", "template-refresh-rate", overflowRefreshSeconds} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// TestFlowExportIPFIXRefreshOverflowRejectedAtCommit_6769 is the IPFIX arm.
// The compiler parses the two template families in separate code paths, so a
// gate that walked only Version9 would pass the v9 cell and leave this open.
func TestFlowExportIPFIXRefreshOverflowRejectedAtCommit_6769(t *testing.T) {
	tree := buildTreeFromSet(t, ipfixRefreshCmds(overflowRefreshSeconds))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an overflowing IPFIX template-refresh-rate; expected rejection")
	}
	if !strings.Contains(err.Error(), "version-ipfix") {
		t.Errorf("error %q does not name the version-ipfix family", err.Error())
	}
}

// TestFlowExportTimeoutOverflowRejectedAtCommit_6769: the two timeout leaves go
// through the same gate. They are typed in setSchema at maxWireU32 (#1979),
// which is BELOW MaxDurationSeconds and therefore already blocks the overflow
// at strict operator commit — but SchemaValidate does not run on the tolerant
// load / peer-sync path or for direct CompileConfig callers, which is what this
// cell covers.
func TestFlowExportTimeoutOverflowRejectedAtCommit_6769(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set services flow-monitoring version9 template t flow-active-timeout " + overflowRefreshSeconds,
		"set forwarding-options sampling instance s input rate 1000",
		"set forwarding-options sampling instance s family inet output flow-server 10.0.0.1 port 2055 version9 template t",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an overflowing flow-active-timeout; expected rejection")
	}
	if !strings.Contains(err.Error(), "flow-active-timeout") {
		t.Errorf("error %q does not name the offending leaf", err.Error())
	}
}

// TestFlowExportRefreshOverflowLenientWarns_6769: on the tolerant load /
// peer-sync path the same value is downgraded to a warning so an
// already-persisted or peer-synced config authored by a pre-guard version still
// BOOTS (#1960). The running exporter is safe regardless because
// flowexport.secondsToDuration falls back independently.
func TestFlowExportRefreshOverflowLenientWarns_6769(t *testing.T) {
	tree := buildTreeFromSet(t, v9RefreshCmds(overflowRefreshSeconds))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must NOT hard-reject an overflowing refresh rate: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "flow-export template seconds") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("lenient compile must emit a downgraded warning; warnings=%v", cfg.Warnings)
	}
}

// TestFlowExportSaneSecondsAccepted_6769 is the negative control. An ordinary
// configuration must compile cleanly AND store the values unchanged — a gate
// that rejected too much, or a "fix" that clamped every value, fails here. The
// ceiling itself is in range (it is the last value that does not overflow).
func TestFlowExportSaneSecondsAccepted_6769(t *testing.T) {
	for _, seconds := range []string{"0", "60", "300", "9223372036"} {
		tree := buildTreeFromSet(t, v9RefreshCmds(seconds))
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig rejected an in-range template-refresh-rate %s: %v", seconds, err)
		}
		fm := cfg.Services.FlowMonitoring
		if fm == nil || fm.Version9 == nil || fm.Version9.Templates["t"] == nil {
			t.Fatalf("template t missing after compiling refresh rate %s", seconds)
		}
		got := fm.Version9.Templates["t"].TemplateRefreshRate
		if want := atoiOrFatal(t, seconds); got != want {
			t.Errorf("TemplateRefreshRate = %d, want %d (an in-range value must be stored unchanged)", got, want)
		}
	}
}

// TestFlowExportCeilingBoundaryIsExact_6769 pins the bound itself, in BOTH
// directions. The mutation matrix for this change loosened the comparison to
// `> MaxDurationSeconds+1` and every other cell stayed green: the ceiling was
// accepted and a huge value rejected, but the first value PAST the ceiling was
// exercised by nothing, so the bound could drift upward undetected. It is not a
// cosmetic drift — MaxDurationSeconds+1 is precisely the smallest value whose
// `time.Duration(n) * time.Second` overflows int64.
func TestFlowExportCeilingBoundaryIsExact_6769(t *testing.T) {
	const ceiling = MaxDurationSeconds // 9223372036
	accept := strconv.FormatInt(ceiling, 10)
	reject := strconv.FormatInt(ceiling+1, 10)

	if _, err := CompileConfig(buildTreeFromSet(t, v9RefreshCmds(accept))); err != nil {
		t.Errorf("CompileConfig rejected the ceiling %s, which does NOT overflow: %v", accept, err)
	}
	_, err := CompileConfig(buildTreeFromSet(t, v9RefreshCmds(reject)))
	if err == nil {
		t.Fatalf("CompileConfig accepted %s — one past the ceiling, and the smallest value "+
			"whose nanosecond conversion overflows int64", reject)
	}
	if !strings.Contains(err.Error(), reject) {
		t.Errorf("error %q does not name the offending value", err.Error())
	}
	if err := SchemaValidate(buildTreeFromSet(t, []string{
		"set services flow-monitoring version9 template t template-refresh-rate seconds " + reject,
	})); err == nil {
		t.Errorf("SchemaValidate accepted %s — the typed leaf's ceiling must be exact too", reject)
	}
}

// TestFlowExportRefreshSecondsIsTypedInSchema_6769 binds the SCHEMA layer.
// `template-refresh-rate seconds` was the one untyped member of the trio (its
// two siblings already carried ValidateInteger), so SchemaValidate — the gate
// that runs at strict operator commit BEFORE the compiler — passed it through.
// Dropping the validator from setSchema reds here while every CompileConfig
// cell above still passes, which is why this cell exists separately.
func TestFlowExportRefreshSecondsIsTypedInSchema_6769(t *testing.T) {
	for _, family := range []string{"version9", "version-ipfix"} {
		bad := buildTreeFromSet(t, []string{
			"set services flow-monitoring " + family + " template t template-refresh-rate seconds " + overflowRefreshSeconds,
		})
		if err := SchemaValidate(bad); err == nil {
			t.Errorf("%s: SchemaValidate accepted an overflowing template-refresh-rate seconds; "+
				"the leaf must be typed so strict operator commit rejects before the compiler runs", family)
		}
		good := buildTreeFromSet(t, []string{
			"set services flow-monitoring " + family + " template t template-refresh-rate seconds 60",
		})
		if err := SchemaValidate(good); err != nil {
			t.Errorf("%s: SchemaValidate rejected an ordinary 60s refresh rate: %v", family, err)
		}
	}
}

func atoiOrFatal(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("non-numeric fixture %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}
