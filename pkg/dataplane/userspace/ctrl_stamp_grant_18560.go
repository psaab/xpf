package userspace

import (
	"time"

	"golang.org/x/sys/unix"
)

// #18560: the grant that lets the helper advance the userspace_ctrl
// generation stamp itself.
//
// The XDP shim copies ctrl.config_generation / ctrl.fib_generation into every
// redirected packet, and a helper worker drops a packet whose stamp differs
// from its published validation. Go wrote the stamp only from the status
// reply, after the helper had already published the new view and finished
// the rest of the apply, so every redirected packet in between was dropped as
// a generation mismatch (on loss 3.5k-13k per RG-move run, about 1 ms of line
// rate per generation change). The helper now advances the stamp right after
// its RuntimeView store, but the ctrl row is one value whose other fields Go
// owns, so it may only write while Go cannot.
//
// That is what the grant encodes. Go holds m.mu across every apply_snapshot
// and bump_fib_generation round trip and writes ctrl only under m.mu, so Go
// cannot write ctrl until the round trip returns. The round trip cannot
// return before the grant expires unless the helper has already replied: the
// grant is stamped BEFORE the request is marshalled and the deadline armed,
// it is shorter than the smallest deadline the round trip can be given
// (controlBaseDeadline, and controlShutdownCutover for a round trip that a
// shutdown cuts short), and the helper refuses to write within
// CTRL_STAMP_DEADLINE_MARGIN_NS of it. A helper that cannot write inside the
// grant declines and Go writes the stamp from the reply as before.
//
// Both clocks are CLOCK_MONOTONIC: Go's runtime timers (which fire the
// connection deadline) and the helper's monotonic_nanos.
const ctrlStampGrant = 250 * time.Millisecond

// Compile-time bounds: a negative constant does not convert to uint64, so
// either inequality failing breaks the build.
const (
	_ = uint64(controlShutdownCutover - ctrlStampGrant)
	_ = uint64(controlBaseDeadline - ctrlStampGrant)
)

// ctrlStampGrantFor reports whether a request carries the grant: exactly the
// requests that carry a snapshot, which today are the two that change the
// validation the shim stamps (apply_snapshot, the full apply, and
// bump_fib_generation, the route-only FIB bump). Keyed on the payload rather
// than the verb string so the #9520 single-send-site census keeps the
// "apply_snapshot" literal in one place. The helper honours the grant only in
// its apply_snapshot and bump_fib_generation handlers, so a future verb that
// carries a snapshot gains nothing unless its handler opts in.
func ctrlStampGrantFor(req *ControlRequest) bool {
	return req.Snapshot != nil
}

// ctrlStampGrantDeadline is the absolute CLOCK_MONOTONIC deadline of a grant
// that starts now; 0 if the clock cannot be read (no grant).
func ctrlStampGrantDeadline() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil || ts.Sec < 0 {
		return 0
	}
	return uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec) + uint64(ctrlStampGrant)
}
