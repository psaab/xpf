package grpcapi

import (
	"context"
	"github.com/psaab/xpf/pkg/factoryreset"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func TestZeroizeCustomArchiveStillErasesDefault15729(t *testing.T) {
	origWipe := factoryreset.PerformWipeWithLogInventoryForTest
	origStop := scheduleStopDaemon
	origArchive := configstore.DefaultArchiveDir
	t.Cleanup(func() {
		factoryreset.PerformWipeWithLogInventoryForTest = origWipe
		scheduleStopDaemon = origStop
		configstore.DefaultArchiveDir = origArchive
	})
	factoryreset.PerformWipeWithLogInventoryForTest = func(_, _, archiveDir string, _ factoryreset.LogInventory, _ factoryreset.Completion) error {
		return configstore.FactoryResetArchiveDir(archiveDir)
	}
	scheduleStopDaemon = func() {}

	dir := t.TempDir()
	defaultDir := filepath.Join(dir, "default-archive")
	configstore.DefaultArchiveDir = defaultDir
	defaultSnap := filepath.Join(defaultDir, "config-20260101.1.conf")
	mustWriteFile(t, defaultSnap, []byte("system { authentication-key SECRET; }\n"))

	customDir := filepath.Join(dir, "compliance-archive")
	customSnap := filepath.Join(customDir, "config-20260101.1.conf")
	mustWriteFile(t, customSnap, []byte("system { authentication-key SECRET; }\n"))

	store := newConfigStore(t, filepath.Join(dir, "site.conf"))
	store.SetArchiveConfig(customDir, 10)
	s := &Server{store: store}
	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"})
	if err == nil {
		t.Fatal("SystemAction(zeroize) with custom archive-dir must report incomplete reset (ArchiveDirSkippedError wrapped as Internal)")
	}
	if _, statErr := os.Stat(defaultSnap); !os.IsNotExist(statErr) {
		t.Errorf("default archive snapshot survived custom-dir zeroize (stat err=%v)", statErr)
	}
	if _, statErr := os.Stat(customSnap); statErr != nil {
		t.Errorf("custom archive must survive untouched: %v", statErr)
	}
}
