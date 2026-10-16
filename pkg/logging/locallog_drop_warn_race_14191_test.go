package logging

import (
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
)

// #14191: SendFromEventReader called warnRateLimited on lastDropWarn without
// holding lw.mu, while the async writer goroutine (via Send/SendBinary) did
// so under lw.mu. Under log pressure both run concurrently by design
// (#9025), racing on the time.Time clock.
//
// RED (pre-fix, go test -race): concurrent SendFromEventReader drop path
// (retired writer, no lw.mu taken) vs concurrent Send on the same closed
// writer (lw.mu held) reports WARNING: DATA RACE on LocalLogWriter's
// lastDropWarn inside warnRateLimited. GREEN after warnRateLimited guards
// its clock with the dedicated warnMu instead of relying on lw.mu.
//
// Both sides must actually reach warnRateLimited: a retired async writer
// makes SendFromEventReader's enqueue fail, and Closed makes Send fail
// with file-unavailable. slog is discarded so the WARN cannot re-enter
// any writer (and so the loop is not slowed by real log output).
func TestLocalLogReaderVsWriterDropWarnRace14191(t *testing.T) {
	withSlogDefault(t, slog.NewTextHandler(io.Discard, nil))

	dir := t.TempDir()
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: filepath.Join(dir, "security.log")})
	if err != nil {
		t.Fatal(err)
	}
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}

	const workers = 4
	const iterations = 2000
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range workers {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			for range iterations {
				_ = lw.SendFromEventReader(SyslogInfo, "reader drop")
			}
		}()
		go func() {
			defer wg.Done()
			for range iterations {
				_ = lw.Send(SyslogInfo, "writer drop")
				_ = lw.SendBinary([]byte("writer drop"))
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := lw.DroppedWrites(); got == 0 {
		t.Fatal("DroppedWrites = 0; neither concurrent path counted a drop, so the race was never exercised")
	}
}
