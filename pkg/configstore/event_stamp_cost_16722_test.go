package configstore

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// #16722: an interactive candidate mutation on a large config with no
// event-options commands payload must not pay two full lenient compiles
// (≈0.1-0.6s at 1k-8k lines) under the store write lock. This drives the
// acceptance shape from the issue: `set system host-name` on a 16k-line
// config. The bound is deliberately generous (5s for the whole mutation
// including the O(config) Clone the mutation itself needs) — two compiles
// of this tree cost multiple seconds, so the cell still fails if the
// compiles come back, while staying robust on a loaded host. The
// decisive fail-on-revert signal is the gate unit tests in pkg/config
// (TestTreeMayHaveEventCommands16722); this cell pins the end-to-end
// store path (SetFromInputAs → stamper under s.mu).
func TestSetHostNameLargeConfigNoEventCompile16722(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// Build a large candidate without event-options: one hostname plus
	// thousands of distinct firewall terms, loaded in one batch (which
	// stamps once). Distinct terms keep the tree large — repeated
	// identical statements would collapse into one node.
	var b strings.Builder
	b.WriteString("set system host-name before\n")
	for i := range 4000 {
		fmt.Fprintf(&b, "set firewall family inet filter f term t%d from source-address 10.%d.%d.0/24\n", i, i/256, i%256)
		fmt.Fprintf(&b, "set firewall family inet filter f term t%d then accept\n", i)
		fmt.Fprintf(&b, "set firewall family inet filter f term t%d from protocol tcp\n", i)
		fmt.Fprintf(&b, "set firewall family inet filter f term t%d from destination-port %d\n", i, 1024+i%50000)
	}
	if _, err := s.LoadSet(b.String()); err != nil {
		t.Fatalf("LoadSet large fixture: %v", err)
	}

	start := time.Now()
	if err := s.SetFromInput("system host-name after"); err != nil {
		t.Fatalf("SetFromInput host-name: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("set system host-name on large commandless config took %v; "+
			"two full lenient compiles under the lock would cost seconds (#16722)", elapsed)
	}
	cfg, err := s.CompileCandidate()
	if err != nil {
		t.Fatalf("CompileCandidate: %v", err)
	}
	if cfg.System.HostName != "after" {
		t.Fatalf("HostName=%q, want after (mutation lost)", cfg.System.HostName)
	}
}
