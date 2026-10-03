package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const archivalPassword11774 = "ARCHIVE-PW-SENTINEL"

type archivalLogCapture11774 struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	done chan struct{}
	once sync.Once
}

func (w *archivalLogCapture11774) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buf.Write(p)
	if bytes.Contains(p, []byte("config archival failed")) || bytes.Contains(p, []byte("config archived successfully")) {
		w.once.Do(func() { close(w.done) })
	}
	return n, err
}

func (w *archivalLogCapture11774) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func TestArchiveToSitesRedactsDestinationAndTransferError11774(t *testing.T) {
	const dest = "scp://alice:" + archivalPassword11774 + "@archive.example/configs"
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name archived"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	capture := &archivalLogCapture11774{done: make(chan struct{})}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(capture, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	d := &Daemon{
		store: store,
		opts:  Options{ConfigFile: filepath.Join(dir, "xpf.conf")},
		archiveTransfer: func(_ context.Context, _ string, gotDest string) error {
			if gotDest != dest {
				t.Errorf("transfer destination = %q, want %q", gotDest, dest)
			}
			return fmt.Errorf("scp failed for destination %s: %w", gotDest, errors.New("exit status 1"))
		},
	}
	d.archiveToSites([]string{dest})

	select {
	case <-capture.done:
	case <-time.After(5 * time.Second):
		t.Fatal("archive transfer log was not emitted")
	}
	logs := capture.String()
	if strings.Contains(logs, archivalPassword11774) || strings.Contains(logs, "alice:") {
		t.Fatalf("archival logs expose the destination password:\n%s", logs)
	}
	if !strings.Contains(logs, "archive.example") || !strings.Contains(logs, "<redacted>") {
		t.Fatalf("archival logs lost useful redacted destination detail:\n%s", logs)
	}
}

func TestScpArchiveTransferRejectsInlineURLPassword11774(t *testing.T) {
	knownHosts, argsPath := stageFakeSCP10298(t)
	if err := os.WriteFile(knownHosts, []byte("archive.example ssh-ed25519 trusted-key\n"), 0600); err != nil {
		t.Fatalf("write known hosts: %v", err)
	}
	srcPath := filepath.Join(t.TempDir(), "xpf.conf")
	if err := os.WriteFile(srcPath, []byte("system { host-name archived; }\n"), 0600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	err := scpArchiveTransfer(context.Background(), srcPath,
		"scp://alice:"+archivalPassword11774+"@archive.example/configs")
	if err == nil || !strings.Contains(err.Error(), "inline URL password") {
		t.Fatalf("scpArchiveTransfer error = %v, want inline URL password rejection", err)
	}
	if strings.Contains(err.Error(), archivalPassword11774) {
		t.Fatalf("transport rejection exposed password: %v", err)
	}
	if _, statErr := os.Stat(argsPath); !os.IsNotExist(statErr) {
		t.Fatalf("scp was invoked with inline URL password (stat err=%v)", statErr)
	}
}
