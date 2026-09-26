package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestFactoryResetFencesRescueSaves_10769 proves factoryReset fences the
// applySem-bypassing rescue save during the wipe and leaves the fence latched
// through the post-wipe stop grace. A failed wipe must instead resume saves.
func TestFactoryResetFencesRescueSaves_10769(t *testing.T) {
	t.Run("successful wipe remains fenced", func(t *testing.T) {
		dir := t.TempDir()
		store, err := configstore.New(filepath.Join(dir, "xpf.conf"))
		if err != nil {
			t.Fatalf("configstore.New: %v", err)
		}
		if err := store.SaveRescueConfig(); err != nil {
			t.Fatalf("initial rescue save: %v", err)
		}
		d := &Daemon{applySem: semaphore.NewWeighted(1), store: store}
		wipeStarted := make(chan struct{})
		finishWipe := make(chan struct{})
		var wipeReleaseOnce sync.Once
		releaseWipe := func() { wipeReleaseOnce.Do(func() { close(finishWipe) }) }
		defer releaseWipe()
		resetDone := make(chan error, 1)
		go func() {
			resetDone <- d.factoryReset(context.Background(), func() error {
				close(wipeStarted)
				<-finishWipe
				return os.Remove(filepath.Join(dir, configstore.RescueConfigBase))
			})
		}()
		select {
		case <-wipeStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("factoryReset did not begin the wipe")
		}
		// factoryReset is holding applySem and blocked in its wipe closure
		// while this independent caller races the explicit store save.
		if err := store.SaveRescueConfig(); !errors.Is(err, configstore.ErrRescueSaveFenced) {
			releaseWipe()
			t.Fatalf("concurrent rescue save during wipe = %v, want ErrRescueSaveFenced", err)
		}
		releaseWipe()
		select {
		case err := <-resetDone:
			if err != nil {
				t.Fatalf("factoryReset: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("factoryReset did not finish")
		}
		if err := store.SaveRescueConfig(); !errors.Is(err, configstore.ErrRescueSaveFenced) {
			t.Fatalf("rescue save during stop grace = %v, want ErrRescueSaveFenced", err)
		}
		if _, err := os.Stat(filepath.Join(dir, configstore.RescueConfigBase)); !os.IsNotExist(err) {
			t.Fatalf("rescue.conf was recreated after successful wipe: stat err=%v", err)
		}
	})

	t.Run("failed wipe resumes saves", func(t *testing.T) {
		store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
		if err != nil {
			t.Fatalf("configstore.New: %v", err)
		}
		d := &Daemon{applySem: semaphore.NewWeighted(1), store: store}
		wipeErr := errors.New("wipe failed")
		if err := d.factoryReset(context.Background(), func() error {
			if err := store.SaveRescueConfig(); !errors.Is(err, configstore.ErrRescueSaveFenced) {
				t.Errorf("rescue save during failed wipe = %v, want ErrRescueSaveFenced", err)
			}
			return wipeErr
		}); !errors.Is(err, wipeErr) {
			t.Fatalf("factoryReset error = %v, want %v", err, wipeErr)
		}
		if err := store.SaveRescueConfig(); err != nil {
			t.Fatalf("rescue save after failed wipe should resume: %v", err)
		}
	})
}
