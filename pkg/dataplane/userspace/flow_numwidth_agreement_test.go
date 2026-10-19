package userspace

// #1979 Layer B / Layer A agreement (the directional invariant, plan §8 item
// 5). Layer A (#1977, flow.go coerceWire*) coerces every flow/flow-export
// wire field into its Rust range at the snapshot boundary; Layer B (#1979,
// config.setSchema typed leaves + validateTCPMSSRanges) rejects out-of-range
// values at commit. The two MUST agree:
//
//	Layer B never REJECTS a value Layer A ACCEPTS (leaves unchanged), and
//	every value Layer B rejects is one Layer A would have coerced.
//
// Asymmetry (Q3 = [0, u32max]): Layer B ACCEPTS sampling rate 0 but Layer A
// NORMALIZES 0 -> 1 (a sentinel, not a clamp). So the invariant is "does not
// reject what Layer A accepts", NOT "leaves accepted values unchanged" —
// sampling 0 is the documented exception.
//
// Scope: ONLY the wire-reaching fields (the 11 fields / Layer-A coercions).
// version-ipfix timeouts do NOT reach Layer A (buildFlowExportSnapshot reads
// fm.Version9 only), so they are EXCLUDED — their typing is UX parity only.

import (
	"math"
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// layerBField pairs a Layer-B validator with the Layer-A coercion it must
// agree with, plus a name for diagnostics.
type layerBField struct {
	name string
	// validate runs the Layer-B commit-time validator (nil error = accept).
	validate func(int64) error
	// coerce runs the Layer-A build-time coercion and returns the resulting
	// wire value (already in range).
	coerce func(int) int
	// accept0AsSentinel: Layer A accepts the input but normalizes it to a
	// different value (the sampling 0 -> 1 sentinel). When true, an
	// "accepted-but-changed" 0 is the documented exception, not a violation.
	zeroIsSentinel bool
}

func intValidator(min, max int64) func(int64) error {
	v := config.ValidateInteger(min, max)
	return func(n int64) error { return v(strconv.FormatInt(n, 10), nil) }
}

func numwidthFields() []layerBField {
	return []layerBField{
		{
			// #15171: Layer B is now stricter than the wire bound — it
			// rejects 0..63 (Junos floor 64) that Layer A leaves unchanged.
			// Those values are Layer-A-safe (0=unset, 1..63 written as-is)
			// but operator-invalid, so they are a documented exception to
			// invariant #2 below, modelled here by coercing them to the
			// -2 sentinel (not Layer-A-unchanged) exactly like the
			// collector-port field. Layer A itself is unchanged.
			name:     "tcp_mss_u16",
			validate: intValidator(config.MinTCPMSS, math.MaxUint16),
			coerce: func(v int) int {
				if v >= int(config.MinTCPMSS) && v <= math.MaxUint16 {
					return v
				}
				if v > math.MaxUint16 || v < 0 {
					return coerceWireU16("t", v)
				}
				return -2
			},
		},
		{
			name:     "active_inactive_timeout_u32",
			validate: intValidator(0, math.MaxUint32),
			coerce:   func(v int) int { return coerceWireU32Timeout("t", v) },
		},
		{
			name:     "session_timeout_u64",
			validate: intValidator(0, config.MaxDurationSeconds),
			coerce:   func(v int) int { return coerceWireSessionTimeout("t", v) },
		},
		{
			name:     "collector_port_u16",
			validate: intValidator(1, math.MaxUint16),
			// Layer A FORWARDS a server only when its port is in [1, 65535];
			// port 0 is the absent sentinel (skipped) and <1 / >u16 are
			// skipped too (flow.go: server.Port==0 -> continue; <0||>u16 ->
			// continue). So the "accepts unchanged" set is exactly [1, 65535].
			// Model coerce to return the value for an in-range port and a
			// distinct sentinel (-2) for a skipped one, so layerAUnchanged is
			// false (and invariant #2 correctly does not apply) outside range.
			coerce: func(v int) int {
				if v >= 1 && v <= math.MaxUint16 {
					return v
				}
				return -2
			},
		},
		{
			name:           "sampling_rate_u32",
			validate:       intValidator(0, math.MaxUint32), // Q3 = [0, u32max]
			coerce:         coerceSamplingRate,
			zeroIsSentinel: true,
		},
	}
}

// coerceSamplingRate mirrors buildFlowExportSnapshot's rate handling
// (rate<=0 -> 1, >u32max -> u32max).
func coerceSamplingRate(v int) int {
	if v <= 0 {
		return 1
	}
	if int64(v) > math.MaxUint32 {
		return math.MaxUint32
	}
	return v
}

func TestNumWidth_LayerAB_Agreement(t *testing.T) {
	// Boundary values spanning every wire width.
	values := []int64{
		-1, 0, 1,
		65535, 65536, // u16 boundary
		math.MaxUint32, math.MaxUint32 + 1, // u32 boundary
		config.MaxDurationSeconds, config.MaxDurationSeconds + 1, // u64 session cap
	}

	for _, f := range numwidthFields() {
		for _, v := range values {
			// All test values fit in a 64-bit int (the Layer-A coercion
			// signature). int is 64-bit on the supported platforms.
			bAccepts := f.validate(v) == nil
			got := int64(f.coerce(int(v)))
			layerAUnchanged := got == v

			// Directional invariant #1: if Layer B accepts v, Layer A must
			// leave it unchanged — UNLESS it is the sampling-0 sentinel, the
			// one documented exception (Layer A normalizes 0 -> 1).
			if bAccepts && !layerAUnchanged {
				if f.zeroIsSentinel && v == 0 {
					if got != 1 {
						t.Fatalf("%s: sampling 0 should normalize to 1, got %d", f.name, got)
					}
				} else {
					t.Fatalf("%s: Layer B accepted %d but Layer A changed it to %d (Layer B must not accept a value Layer A coerces)", f.name, v, got)
				}
			}

			// Directional invariant #2 (the headline, plan §8 item 5): Layer B
			// must NEVER reject a value Layer A leaves unchanged. (Where Layer
			// A changes the value — out-of-range, or the sampling-0 sentinel —
			// there is nothing to assert in this direction.)
			if layerAUnchanged && !bAccepts {
				t.Fatalf("%s: Layer A left %d unchanged but Layer B REJECTED it (Layer B must not reject what Layer A accepts)", f.name, v)
			}
		}
	}
}
