package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestQuiesceRescueWritesJoinsAndRejectsSaves_10769 pins both halves of the
// factory-reset rescue fence: an already-registered save is joined before the
// wipe, and a save during/after the wipe is rejected instead of recreating the
// prior tenant's secret-bearing rescue.conf.
func TestQuiesceRescueWritesJoinsAndRejectsSaves_10769(t *testing.T) {
	s := newTestStore(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseWriter := func() { releaseOnce.Do(func() { close(release) }) }
	oldBarrier := rescueWriteBarrier
	rescueWriteBarrier = func() {
		close(started)
		<-release
	}
	defer func() {
		rescueWriteBarrier = oldBarrier
		releaseWriter()
	}()

	saveDone := make(chan error, 1)
	go func() { saveDone <- s.SaveRescueConfig() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("rescue save did not reach the registered-write barrier")
	}

	quiesced := make(chan struct{})
	go func() {
		s.QuiesceRescueWrites()
		close(quiesced)
	}()
	deadline := time.After(2 * time.Second)
	for !s.rescueFenced.Load() {
		select {
		case <-deadline:
			t.Fatal("QuiesceRescueWrites did not set the rescue fence")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	if err := s.SaveRescueConfig(); !errors.Is(err, ErrRescueSaveFenced) {
		t.Fatalf("save during reset = %v, want ErrRescueSaveFenced", err)
	}
	select {
	case <-quiesced:
		t.Fatal("QuiesceRescueWrites returned before joining the in-flight save")
	default:
	}

	releaseWriter()
	select {
	case err := <-saveDone:
		if err != nil {
			t.Fatalf("registered rescue save failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("registered rescue save did not finish")
	}
	select {
	case <-quiesced:
	case <-time.After(2 * time.Second):
		t.Fatal("QuiesceRescueWrites did not finish after the registered save")
	}

	// Model the wipe after the JOIN. A save during the 1s stop grace must not
	// recreate the just-erased file.
	rescuePath := filepath.Join(filepath.Dir(s.ConfigPath()), RescueConfigBase)
	if err := os.Remove(rescuePath); err != nil {
		t.Fatalf("remove rescue.conf as the wipe does: %v", err)
	}
	if err := s.SaveRescueConfig(); !errors.Is(err, ErrRescueSaveFenced) {
		t.Fatalf("save during stop grace = %v, want ErrRescueSaveFenced", err)
	}
	if _, err := os.Stat(rescuePath); !os.IsNotExist(err) {
		t.Fatalf("fenced rescue save recreated rescue.conf: stat err=%v", err)
	}
}
