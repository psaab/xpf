package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// hostauth_fence_14969.go — #14969: generation fence for abandoned
// host-auth closeout owners; #15539 extends it to every direct
// write/install seam (the #15219 residual).
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
//   - Every host-mutation seam the owners reach re-checks the calling
//     goroutine's captured generation IMMEDIATELY before the mutation
//     (not only at owner entry — #15539): the nft installer guard
//     (guardedNftInstaller14969 wraps nftInstaller in daemon_nft.go),
//     the exec seam (runCommandTimeout / runCommandStdinTimeout, via
//     runWithHostAuthExec15539 which re-validates BOTH sides of the
//     child spawn and kills a stale owner's in-flight command when a
//     newer authority advances), and the direct filesystem seams in
//     daemon_hostauth_apply.go / login_password.go (guardedWriteFile-
//     Durable14969, guardedWriteFileAtomic14969, guardedRemove14969,
//     the fenced provenance claim/forget helpers and the sshd drop-in
//     write/remove seams). Once a newer authority has advanced the
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

// --- #15539: direct write/install seam guards ---------------------------
//
// The owner-entry checks alone left every direct write below them
// unfenced: a stale owner already inside applySystemLogin /
// reconcileSudoers / applySSHConfig / applyRootAuth (or inside an nft
// owner, or reconcileAbsentLoginUsers, which had NO entry check) could
// pass its entry, be superseded mid-owner, and still be the last writer
// of authorized_keys, a sudoers grant, the sshd drop-in, root's keys, a
// provenance marker, or an nft table. Each helper below re-checks the
// calling goroutine's generation IMMEDIATELY before its syscall, so a
// superseded owner abstains at the write itself. Uncaptured goroutines
// (the normal tail, direct reconciler tests) are never refused — the
// helpers are byte-identical to the raw calls for them.

// guardedWriteFileDurable14969 is fsatomic.WriteFileDurable fenced at
// the write: a superseded owner never creates/replaces the file.
func guardedWriteFileDurable14969(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
	if err := checkHostAuthSeam14969(); err != nil {
		return err
	}
	return fsatomic.WriteFileDurable(path, data, perm, opts...)
}

// guardedWriteFileAtomic14969 is fsatomic.WriteFileAtomic fenced at the
// write (the sshd drop-in install/revert seam default).
func guardedWriteFileAtomic14969(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
	if err := checkHostAuthSeam14969(); err != nil {
		return err
	}
	return fsatomic.WriteFileAtomic(path, data, perm, opts...)
}

// guardedRemove14969 is os.Remove fenced at the unlink: a superseded
// owner never removes a file (keys, sudoers grant, sshd drop-in,
// provenance marker) a newer authority may have just (re)written.
func guardedRemove14969(path string) error {
	if err := checkHostAuthSeam14969(); err != nil {
		return err
	}
	return os.Remove(path)
}

// guardedMkdirAllDurable14969 is fsatomic.MkdirAllDurable fenced at the
// call (authorized_keys / root .ssh directory creation).
func guardedMkdirAllDurable14969(path string, perm os.FileMode) error {
	if err := checkHostAuthSeam14969(); err != nil {
		return err
	}
	return fsatomic.MkdirAllDurable(path, perm)
}

// claimOwnershipFenced14969 is claimOwnership with the generation
// re-checked immediately before the marker write: a superseded owner
// must not (re)claim provenance for a credential it is about to be
// refused from writing, and must not resurrect a marker a newer
// authority's revocation already dropped.
func claimOwnershipFenced14969(dir, name string, uid int) (ownershipClaim, error) {
	if err := checkHostAuthSeam14969(); err != nil {
		return ownershipClaim{}, err
	}
	return claimOwnership(dir, name, uid)
}

// forgetProvenanceFenced14969 is forgetProvenance fenced at the marker
// removals: a superseded owner's forget must not drop the provenance a
// newer authority relies on to revoke the account it just re-created.
func forgetProvenanceFenced14969(name string) error {
	if err := checkHostAuthSeam14969(); err != nil {
		return err
	}
	return forgetProvenance(name)
}

// removeProvenanceMarkerFenced14969 is removeProvenanceMarker fenced at
// the unlink, for the direct revocation call sites.
func removeProvenanceMarkerFenced14969(dir, name string) error {
	if err := checkHostAuthSeam14969(); err != nil {
		return err
	}
	return removeProvenanceMarker(dir, name)
}
