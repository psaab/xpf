package factoryreset

import (
	"errors"
	"fmt"
	"os"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

var wipePersistentNatGenerationStatePath = dpuserspace.PersistentNatLeaseGenerationStatePath

func wipeEraseResetState(helperPath string) error {
	var errs []error
	if helperPath != "" {
		errs = append(errs, wipeEraseHelperState(helperPath))
	}
	generationPath := wipePersistentNatGenerationStatePath()
	if generationPath != "" && generationPath != helperPath {
		errs = append(errs, wipeEraseHelperState(generationPath))
	}
	return errors.Join(errs...)
}

func wipeVerifyPersistentNatGenerationState() error {
	path := wipePersistentNatGenerationStatePath()
	if path == "" {
		return errors.New("zeroize: persistent-NAT generation state path unavailable")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("zeroize: persistent-NAT generation state %s present at final verification", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("zeroize: inspect persistent-NAT generation state %s: %w", path, err)
	}
	if dead, live, err := dpuserspace.ListStaleStateTempsIncludingLegacy(path); err != nil {
		return err
	} else if len(dead) != 0 || len(live) != 0 {
		return fmt.Errorf("zeroize: persistent-NAT generation state temps present for %s: dead=%v live=%v", path, dead, live)
	}
	return nil
}
