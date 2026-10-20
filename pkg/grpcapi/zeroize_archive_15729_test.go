package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15729 gRPC legs: through the real archive eraser, a custom configured
// archive-dir must still erase the xpf-owned default; and the gRPC
// config-dir wipe must erase day0 staged temps.

func TestZeroizeCustomArchiveStillErasesDefault15729(t *testing.T) {
	origWipe := performZeroizeWipeWithLogInventory
	origStop := scheduleStopDaemon
	origArchive := configstore.DefaultArchiveDir
	t.Cleanup(func() {
		performZeroizeWipeWithLogInventory = origWipe
		scheduleStopDaemon = origStop
		configstore.DefaultArchiveDir = origArchive
	})
	performZeroizeWipeWithLogInventory = func(_, _, archiveDir string, _ ZeroizeLogInventory, _ zeroizeCompletion) error {
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

func TestZeroizeConfigDirErasesDay0StagedTemps15729(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, ".xpf.conf.Ab12Cd")
	mustWriteFile(t, staged, []byte("system { authentication-key DAY0-SECRET; }\n"))
	keep := filepath.Join(dir, ".keepme")
	mustWriteFile(t, keep, []byte("keep"))

	if err := zeroizeConfigDir(dir, "xpf.conf"); err != nil {
		t.Fatalf("zeroizeConfigDir: %v", err)
	}
	assertAbsent(t, staged)
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("zeroize removed unrelated dotfile %s: %v", keep, err)
	}
}
