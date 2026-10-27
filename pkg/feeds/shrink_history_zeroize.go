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
	if err := configstore.SweepCrashTemps(func() ([]string, error) { return ListShrinkHistoryCrashTemps(path) }); err != nil {
		return fmt.Errorf("feeds: %w", err)
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
