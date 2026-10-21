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

func TestFlatReplayNodeBudgetAllVerbs15999(t *testing.T) {
	var ob strings.Builder
	for i := range config.MaxParseNodes + 1000 {
		fmt.Fprintf(&ob, "set security address-book global address a%d 10.0.0.1/32\n", i)
	}
	over := ob.String()
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadMerge(over); err == nil || !strings.Contains(err.Error(), "#15999") {
		t.Fatalf("LoadMerge over budget: err=%v", err)
	}
	s2 := newTestStore(t)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s2.LoadOverride(over); err == nil || !strings.Contains(err.Error(), "#15999") {
		t.Fatalf("LoadOverride over budget: err=%v", err)
	}
	// Key-dense single line: >budget tokens in ONE set line (parser units).
	var kb strings.Builder
	kb.WriteString("set unknown")
	for range config.MaxParseNodes + 1000 {
		kb.WriteString(" k")
	}
	kb.WriteString("\n")
	s3 := newTestStore(t)
	if err := s3.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s3.LoadSet(kb.String()); err == nil || !strings.Contains(err.Error(), "#15999") {
		t.Fatalf("key-dense LoadSet: err=%v", err)
	}
	// Sub-budget sibling-heavy control: many distinct interfaces, still
	// under budget, must succeed (incremental abort must not fire early).
	s4 := newTestStore(t)
	if err := s4.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s4.LoadSet("set system host-name fw1\nset interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24\n"); err != nil {
		t.Fatalf("below-budget control: %v", err)
	}
}
