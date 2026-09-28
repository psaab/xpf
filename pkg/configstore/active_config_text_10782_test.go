package configstore

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestActiveConfigAndTextStayOnOnePromotion10782(t *testing.T) {
	s := newTestStore(t)
	configs := []string{
		"system {\n    host-name snapshot-a;\n}\n",
		"system {\n    host-name snapshot-b;\n}\n",
	}
	if _, err := s.SyncApply(configs[0], nil); err != nil {
		t.Fatalf("SyncApply initial config: %v", err)
	}

	writerReady := make(chan struct{})
	startWriter := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		close(writerReady)
		<-startWriter
		for i := range 300 {
			if _, err := s.SyncApply(configs[i%len(configs)], nil); err != nil {
				writerDone <- fmt.Errorf("SyncApply iteration %d: %w", i, err)
				return
			}
			runtime.Gosched()
		}
		writerDone <- nil
	}()
	<-writerReady
	close(startWriter)

	for {
		cfg, text, gen := s.ActiveConfigAndText()
		if cfg == nil || gen == 0 {
			t.Fatalf("active snapshot = (%v, %q, %d), want a compiled promoted config", cfg, text, gen)
		}
		if !strings.Contains(text, "host-name "+cfg.System.HostName+";") {
			t.Fatalf("active config/text came from different promotions: compiled host=%q text=%q", cfg.System.HostName, text)
		}
		select {
		case err := <-writerDone:
			if err != nil {
				t.Fatal(err)
			}
			cfg, text, gen = s.ActiveConfigAndText()
			if cfg == nil || gen == 0 || !strings.Contains(text, "host-name "+cfg.System.HostName+";") {
				t.Fatalf("final active snapshot is inconsistent: cfg=%v text=%q gen=%d", cfg, text, gen)
			}
			return
		default:
			runtime.Gosched()
		}
	}
}
