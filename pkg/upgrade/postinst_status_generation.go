package upgrade

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/fsatomic"
)

const statusGenerationFile = ".upgrade-status-generation"

func (r *Runner) statusGenerationPath() string {
	return filepath.Join(r.cfg.VersionsDir, statusGenerationFile)
}

// readStatusGeneration treats an absent or malformed counter as the legacy
// generation zero. Other I/O errors are not safe to ignore at a clear gate.
func readStatusGeneration(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("read upgrade status generation %s: %w", path, err)
	}
	generation, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, nil
	}
	return generation, nil
}

// beginStatusGeneration advances the durable fence for every locked Run or
// rollback invocation. A failed write must not prevent recovery; it marks this
// invocation's evidence unusable for supersession clearing.
func (r *Runner) beginStatusGeneration() {
	path := r.statusGenerationPath()
	previous, err := readStatusGeneration(path)
	if err == nil && previous != math.MaxUint64 {
		err = os.MkdirAll(filepath.Dir(path), 0o755)
	}
	if err == nil && previous != math.MaxUint64 {
		next := previous + 1
		err = fsatomic.WriteFileDurable(path, []byte(strconv.FormatUint(next, 10)+"\n"), 0o600)
		if err == nil {
			r.statusGeneration = next
			r.statusGenerationValid = true
			return
		}
	}
	if err == nil {
		err = fmt.Errorf("upgrade status generation overflow")
	}
	r.statusGeneration = math.MaxUint64
	r.statusGenerationValid = false
	r.logf("WARNING could not advance durable upgrade status generation; supersession evidence from this invocation will not clear status: %v", err)
}
