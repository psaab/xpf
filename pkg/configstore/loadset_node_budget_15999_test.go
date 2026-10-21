package configstore

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15999: LoadSet capped only bytes, so >200k-node flat input replayed
// unbounded under the store lock.

func TestLoadSetNodeBudgetRefused15999(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	// Each distinct line creates at least one new node; total well over
	// MaxParseNodes while staying under the 16 MiB byte cap. The line-count
	// pre-check must refuse before the super-linear replay starts.
	for i := range config.MaxParseNodes + 50_000 {
		fmt.Fprintf(&b, "set security address-book global address a%d 10.0.0.1/32\n", i)
	}
	if len(b.String()) > MaxConfigSize {
		t.Fatalf("fixture exceeds byte cap (%d), test would not isolate node budget", len(b.String()))
	}
	_, err := s.LoadSet(b.String())
	if err == nil || !strings.Contains(err.Error(), "#15999") {
		t.Fatalf("LoadSet over node budget: err=%v, want #15999 refusal", err)
	}
}

func TestLoadSetBelowBudgetAccepted15999(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	n, err := s.LoadSet("set system host-name fw1\nset system services ssh\n")
	if err != nil || n != 2 {
		t.Fatalf("small LoadSet: n=%d err=%v", n, err)
	}
}
