package feeds

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// ListShrinkHistoryCrashTemps returns the crash-leaked fsatomic write temps
// staged for the shrink-guard high-water history at path but never renamed
// over it by a crashed save, without removing anything. Backs both the
// zeroize erase sweep and post-sweep verification so the match rule has one
// definition. Every durable save stages the full history JSON in a
// ".<base>.tmp-*" file first, so a temp orphaned by a crash holds prior-tenant
// feed epochs a canonical-only erase would hand to the next tenant.
func ListShrinkHistoryCrashTemps(path string) ([]string, error) {
	dir := filepath.Dir(path)
	prefix := "." + filepath.Base(path) + ".tmp-"
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("feeds: inspect shrink-history directory for %s: %w", path, err)
	}
	var out []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			out = append(out, filepath.Join(dir, entry.Name()))
		}
	}
	return out, nil
}

// EraseShrinkHistoryCrashTemps removes crash-leaked shrink-history snapshots,
// syncs their parent, and verifies the sweep. Symlinked and hardlinked temps
// fail closed so a clean zeroize receipt cannot leave prior-tenant bytes under
// another name.
func EraseShrinkHistoryCrashTemps(path string) error {
	listErr, err := configstore.SweepCrashTempsWithListError(func() ([]string, error) { return ListShrinkHistoryCrashTemps(path) })
	if listErr != nil {
		// ListShrinkHistoryCrashTemps already embeds "feeds: ";
		// returning it under the sweep wrap read "feeds: feeds: …"
		// (#17171 fold F2).
		return listErr
	}
	if err != nil {
		// Per-temp failures keep their historic feeds spellings
		// (#17171 fold), mapped per surviving temp.
		temps, lerr := ListShrinkHistoryCrashTemps(path)
		if lerr != nil {
			return lerr
		}
		var errs []error
		for _, temp := range temps {
			errs = append(errs, feedsTempEraseError(temp))
		}
		if len(errs) == 0 {
			return fmt.Errorf("feeds: %w", err)
		}
		return errors.Join(errs...)
	}
	if err := fsatomic.SyncDir(filepath.Dir(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("feeds: sync shrink-history directory for %s: %w", path, err)
	}
	if temps, err := ListShrinkHistoryCrashTemps(path); err != nil {
		return err
	} else if len(temps) != 0 {
		return fmt.Errorf("feeds: shrink-history crash temps reappeared for %s after sweep: %v", path, temps)
	}
	return nil
}

// feedsTempEraseError re-derives the historic per-temp feeds wording
// for a temp that survived the shared sweep (#17171 fold).
func feedsTempEraseError(temp string) error {
	err := configstore.EraseFileForReset(temp)
	if err == nil {
		return fmt.Errorf("feeds: shrink-history crash temp %s reappeared after sweep", temp)
	}
	var symErr *configstore.FactoryResetSymlinkError
	var linkErr *configstore.FactoryResetHardlinkError
	switch {
	case errors.As(err, &symErr):
		// Historic wording AND the typed refusal: wrap the type
		// inside the sentence so errors.As still finds it.
		return fmt.Errorf("feeds: shrink-history crash temp %s is a symlink; NOT erasing it: %w", temp, symErr)
	case errors.As(err, &linkErr):
		return fmt.Errorf("feeds: refusing to erase hard-linked shrink-history crash temp %s: %w", temp, linkErr)
	case errors.Is(err, configstore.ErrEraseInspectLinks):
		return fmt.Errorf("feeds: inspect hard links for shrink-history crash temp %s: %w", temp, err)
	case errors.Is(err, configstore.ErrEraseInspect):
		return fmt.Errorf("feeds: inspect shrink-history crash temp %s: %w", temp, err)
	case errors.Is(err, configstore.ErrEraseRemove):
		return fmt.Errorf("feeds: remove shrink-history crash temp %s: %w", temp, err)
	default:
		return fmt.Errorf("feeds: %w", err)
	}
}
