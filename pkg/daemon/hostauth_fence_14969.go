package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"sync"
)

// hostauth_fence_14969.go — #14969: generation fence for abandoned
// host-auth closeout owners.
//
// runHostAuthCloseoutOwners abandons an owner goroutine when the shared
// budget expires. Since #14356 that abandonment also happens on LIVE
// post-promotion aborts: the closeout returns, applySem is released, and
// the stale owner keeps writing host-auth state from its captured
// config — the two nft loads and every credential phase the #12169
// live-config fences do not cover — potentially after (and over) a
// later commit.
//
// The fence is a generation token checked AT THE SYSCALL BOUNDARY, not
// a gate: gating a later commit behind the stale owner would deadlock
// against the #12169 settlement (which needs applySem) and would break
// the #12169 contract that a new commit returns while an old revocation
// is still blocked. Instead:
//
//   - Every host-auth authority (each closeout invocation, each normal
//     apply tail) advances hostAuthGeneration14969 at entry.
//   - The closeout runner runs each owner under its launch generation
//     (runWithHostAuthGeneration14969), published for the calling
//     goroutine in the cell below.
//   - Every host-mutation seam the owners reach — the nft installer
//     (nftInstallerGuard14969), the credential/sshd exec seam
//     (runCommandTimeout / runCommandStdinTimeout), and the sshd
//     drop-in write/remove seams — re-checks the calling goroutine's
//     captured generation. Once a newer authority has advanced the
//     token, the stale seam returns errHostAuthStaleOwner14969 WITHOUT
//     performing the syscall, and the owner abstains (its closeout
//     outcome is already the fail-visible timed-out error).
//   - A stale seam that passed its check before the newer authority
//     began is ordered before that authority; the newer authority's own
//     seam overwrites it. The newest authority therefore always wins,
//     and no interleaving lets a stale syscall land after the newer
//     authority's final seam for the same target.
//
// Goroutine affinity: Go has no goroutine-local storage, so the cell is
// keyed by the runtime goroutine id parsed from runtime.Stack. That is
// the standard (if regrettable) mechanism for exactly this shape — a
// value that must follow one goroutine's call tree without threading a
// context through dozens of reconciler signatures. The map is tiny (at
// most one abandoned owner plus transient owners) and every entry is
// removed when its owner goroutine returns. A parse failure yields id
// 0, whose generation is never armed, so the fence fails OPEN toward
// the pre-#14969 behavior rather than breaking the owner — acceptable
// because the parse is stable across the supported Go toolchain and
// the failure mode is the historical one, never a new corruption.

var errHostAuthStaleOwner14969 = errors.New("host-auth mutation refused: this closeout owner was superseded by a newer host-authorization apply (#14969)")

var hostAuthGoroutineGen14969 sync.Map // map[uint64]uint64 — goroutine id -> captured generation

// currentGoroutineID14969 returns the runtime goroutine id, or 0 when
// it cannot be parsed (the fence then disarms for this goroutine).
func currentGoroutineID14969() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	fields := bytes.Fields(buf[:n]) // "goroutine", "<id>", "[...]:"
	if len(fields) < 2 {
		return 0
	}
	id, err := strconv.ParseUint(string(fields[1]), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// runWithHostAuthGeneration14969 runs fn with gen published as the
// calling goroutine's captured host-auth generation, restoring any
// previous value on return. The closeout runner wraps every owner in
// this; nested live-config restores (#12169) re-enter reconcilers on
// the SAME goroutine, so they inherit the owner's generation — correct,
// because a restore is part of the stale owner's convergence and its
// seams must fence identically.
func runWithHostAuthGeneration14969(gen uint64, fn func() error) error {
	id := currentGoroutineID14969()
	if id == 0 || gen == 0 {
		return fn()
	}
	prev, hadPrev := hostAuthGoroutineGen14969.Load(id)
	hostAuthGoroutineGen14969.Store(id, gen)
	defer func() {
		if hadPrev {
			hostAuthGoroutineGen14969.Store(id, prev)
		} else {
			hostAuthGoroutineGen14969.Delete(id)
		}
	}()
	return fn()
}

// hostAuthSeamStale14969 reports whether the CALLING goroutine is a
// closeout owner whose generation a newer host-auth authority has
// superseded. Goroutines with no captured generation (the normal apply
// tail, direct reconciler tests, every non-owner caller of the shared
// seams) are never stale.
func hostAuthSeamStale14969() bool {
	id := currentGoroutineID14969()
	if id == 0 {
		return false
	}
	v, ok := hostAuthGoroutineGen14969.Load(id)
	if !ok {
		return false
	}
	gen, _ := v.(uint64)
	return gen != 0 && hostAuthGeneration14969.Load() != gen
}

// checkHostAuthSeam14969 is the seam guard: nil while the caller may
// mutate host state, errHostAuthStaleOwner14969 once it is a superseded
// closeout owner.
func checkHostAuthSeam14969() error {
	if hostAuthSeamStale14969() {
		return fmt.Errorf("%w", errHostAuthStaleOwner14969)
	}
	return nil
}
