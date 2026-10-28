package factoryreset

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// SweepOpts parameterises the shared helper-state sweep/verify primitive
// (#17087). ErrPrefix prefixes every error message (e.g. "zeroize: " on
// the offline wipe, "reset handoff: " on the daemon handoff); callers
// whose historic messages carry no uniform prefix leave it empty and
// their per-message literals below supply the wording. ReservedRecovery
// is the caller-specific operator recovery sentence appended to the
// reserved-alias errors: the daemon handoff and the ungated offline
// wipe converge differently, so each caller supplies its own. SyncDir
// is the directory-fsync barrier; nil means fsatomic.SyncDir (the
// factoryreset wipe passes its wipeSyncDir test seam).
type SweepOpts struct {
	ErrPrefix        string
	ReservedRecovery string
	SyncDir          func(string) error
}

func (o SweepOpts) syncDir() func(string) error {
	if o.SyncDir != nil {
		return o.SyncDir
	}
	return fsatomic.SyncDir
}

// SweepHelperState removes the helper state file at path plus dead-writer
// temp siblings (including exact pre-#2957 legacy orphans: callers run
// post-stop/pre-start or offline with no live writer, so they are verified
// orphans), syncs the parent, and verifies absence. Live writers' temps,
// removal/durability failures, or anything still present afterwards is an
// error. A canonical aliasing reserved reset-gate/identity state is never
// unlinked (unlinking it would delete a gate or identity file, the
// original bypass), but the sweep FAILS CLOSED: exact-shape temps beside
// it are still swept, then an error naming the reserved alias fails the
// caller. Recovery is operator-side and caller-specific (see
// SweepOpts.ReservedRecovery). Symlinked or hardlinked canonicals fail
// closed before unlinking (FactoryResetHardlinkError with the inode
// scan), retry-persistent. Callers pass a non-empty path only.
func SweepHelperState(path string, opts SweepOpts) error {
	p := opts.ErrPrefix
	// Reserved alias FIRST: a smuggled config named a gate or identity
	// file. The missing-parent fast path below must not report clean
	// over it — callers flip their clean claim on a nil sweep alone, so
	// the reserved failure surfaces here even when there is no
	// directory to sweep beside it. Never unlink the reserved file;
	// the exact-shape temps beside it are still swept below when the
	// parent exists.
	skipCanonical := config.HelperStatePathTouchesReserved(path)
	if skipCanonical {
		slog.Warn(p+"helper path aliases reserved state; skipping canonical removal, sweeping temps only", "path", path)
	}
	var errs []error
	if skipCanonical {
		errs = append(errs, fmt.Errorf("%shelper state path %s aliases reserved reset-gate/identity state and was NOT erased (the reserved file was left untouched); recovery: %s", p, path, opts.ReservedRecovery))
	}
	// A missing state directory means no helper state was ever written
	// here: nothing to remove, verify, or sync. A reserved alias still
	// fails via the error above (joined, not nil).
	if _, err := os.Lstat(filepath.Dir(path)); errors.Is(err, os.ErrNotExist) {
		return errors.Join(errs...)
	}
	var canonicalErr error
	if !skipCanonical {
		if err := configstore.EraseFileForReset(path); err != nil {
			var symErr *configstore.FactoryResetSymlinkError
			var linkErr *configstore.FactoryResetHardlinkError
			switch {
			case errors.As(err, &symErr):
				canonicalErr = fmt.Errorf("%srefusing to sweep symlinked helper state %s: link target is out of erase scope", p, path)
			case errors.As(err, &linkErr):
				canonicalErr = fmt.Errorf("%srefusing to erase hard-linked helper state %s: %w", p, path, linkErr)
			case errors.Is(err, configstore.ErrEraseInspect):
				canonicalErr = fmt.Errorf("%sinspect helper state %s: %w", p, path, err)
			case errors.Is(err, configstore.ErrEraseInspectLinks):
				canonicalErr = fmt.Errorf("%sinspect hard links for helper state %s: %w", p, path, err)
			case errors.Is(err, configstore.ErrEraseRemove):
				canonicalErr = fmt.Errorf("%sremove helper state file %s: %w", p, path, err)
			default:
				// Non-regular refusal: no historic helper spelling
				// (the old code lumped the class into its remove
				// error); keep the primitive's wording under the
				// caller's prefix.
				canonicalErr = fmt.Errorf("%s%w", p, err)
			}
		}
		if canonicalErr != nil {
			errs = append(errs, canonicalErr)
		}
	}
	live, serr := dpuserspace.SweepStaleStateTempsIncludingLegacy(path)
	if serr != nil {
		errs = append(errs, serr)
	}
	if len(live) != 0 {
		errs = append(errs, fmt.Errorf("%slive helper writer temps present for %s: %v", p, path, live))
	}
	if err := opts.syncDir()(filepath.Dir(path)); err != nil {
		errs = append(errs, fmt.Errorf("%ssync helper state directory %s: %w", p, filepath.Dir(path), err))
	}
	if !skipCanonical && canonicalErr == nil {
		if _, err := os.Lstat(path); err == nil {
			errs = append(errs, fmt.Errorf("%shelper state %s still present after sweep", p, path))
		} else if !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("%sinspect helper state %s: %w", p, path, err))
		}
	}
	if dead, live, verr := dpuserspace.ListStaleStateTempsIncludingLegacy(path); verr != nil {
		errs = append(errs, verr)
	} else if len(dead) != 0 || len(live) != 0 {
		errs = append(errs, fmt.Errorf("%shelper state temps remain for %s: dead=%v live=%v", p, path, dead, live))
	}
	return errors.Join(errs...)
}

// VerifyHelperStateErased checks the helper residue class without
// removing anything: the state file plus dead/live temp siblings (legacy
// included). A reserved canonical FAILS verification: the sweep never
// unlinks gates or identity, so erasure of that class is unprovable and
// the caller must stay dirty/failed until the operator completes
// SweepOpts.ReservedRecovery. Temp siblings are still checked and joined
// below.
func VerifyHelperStateErased(path string, opts SweepOpts) error {
	p := opts.ErrPrefix
	var errs []error
	if config.HelperStatePathTouchesReserved(path) {
		errs = append(errs, fmt.Errorf("%shelper state path %s aliases reserved reset-gate/identity state: helper-state erasure cannot be verified (the reserved file is never unlinked); recovery: %s", p, path, opts.ReservedRecovery))
	} else if _, err := os.Lstat(path); err == nil {
		errs = append(errs, fmt.Errorf("%shelper state %s present", p, path))
	} else if !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("%sinspect helper state %s: %w", p, path, err))
	}
	if dead, live, verr := dpuserspace.ListStaleStateTempsIncludingLegacy(path); verr != nil {
		errs = append(errs, verr)
	} else if len(dead) != 0 || len(live) != 0 {
		errs = append(errs, fmt.Errorf("%shelper state temps present for %s: dead=%v live=%v", p, path, dead, live))
	}
	return errors.Join(errs...)
}

// ResetStatePaths returns the helper-state paths a reset must erase for
// helperPath: the helper path itself (when non-empty) plus the
// persistent-NAT generation state path, deduplicated. The generation
// path is read through the wipePersistentNatGenerationStatePath seam so
// tests keep redirecting it; an empty generation path contributes
// nothing (production always resolves the constant
// /var/lib/xpf/persistent-nat-lease-generation.json).
func ResetStatePaths(helperPath string) []string {
	var paths []string
	if helperPath != "" {
		paths = append(paths, helperPath)
	}
	if generationPath := wipePersistentNatGenerationStatePath(); generationPath != "" && generationPath != helperPath {
		paths = append(paths, generationPath)
	}
	return paths
}
