package daemon

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"golang.org/x/sync/semaphore"
)

// #8484: the daemon commit seam must return the compiled config the store
// produced, advisories intact.
//
// This is the hop #8484's own trail pointed at ("compiled comes from
// d.commitAndApplyOperator -> commitAndApply -> commitWithGenBinding") and it
// was the ONE link in produce -> seam -> transport -> render with nothing
// binding it. pkg/grpcapi's #6515 file states the seam is "separately covered
// in pkg/daemon"; at the time #8484 was filed it was not — this is that cover.
//
// It matters because the seam is where a config could plausibly be REPLACED
// rather than passed through: commitWithGenBinding RETRIES on a generation
// conflict, re-running CompileCandidateGen and re-committing, and it is the
// sole origin of the `compiled` value every layer above renders.
//
// SCOPE, stated so this is not read as more than it is: these cells bind
// commitWithGenBinding — store commit -> the config the seam hands back. They
// deliberately do NOT drive applyAndSyncCommitted, whose reconcile pipeline
// needs a started daemon (VRRP manager, netlink, sysctls) that a unit test
// cannot stand up. applyAndSyncCommitted returns `compiled` unmodified; what
// is NOT covered here is a future change that starts rewriting it there.

func commitSeamStore8484(t *testing.T) *configstore.Store {
	t.Helper()
	s := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// The #7509 shape: unit 1 unzoned, sharing a kernel device with a zoned
	// unit 0.
	for _, line := range []string{
		"interfaces gr-0/0/0 tunnel source 10.1.1.1",
		"interfaces gr-0/0/0 tunnel destination 10.1.1.2",
		"interfaces gr-0/0/0 unit 0 family inet address 10.255.192.42/30",
		"interfaces gr-0/0/0 unit 1 family inet address 10.255.193.42/30",
		"security zones security-zone sfmix interfaces gr-0/0/0.0",
	} {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	return s
}

func TestCommitSeamReturnsAdvisories_8484(t *testing.T) {
	s := commitSeamStore8484(t)
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    s,
		opts:     Options{NoDataplane: true},
	}

	_, compiled, err := d.commitWithGenBinding(
		0,
		func(*config.Config) error { return nil },
		func(gen uint64) (*config.Config, error) {
			return d.store.CommitWithDescriptionGenAs(configstore.InternalCommitter(), "", gen)
		},
	)
	if err != nil {
		t.Fatalf("commitWithGenBinding: %v", err)
	}
	if compiled == nil {
		t.Fatal("commit seam returned a nil config; nothing downstream can carry an advisory")
	}

	var got []string
	for _, w := range compiled.Warnings {
		if strings.Contains(w, "gr-0/0/0.1") {
			got = append(got, w)
		}
	}
	if len(got) != 1 {
		t.Fatalf("the commit seam must return the compiled config's advisories; got %d "+
			"mentioning gr-0/0/0.1 out of %d warning(s): %v\n"+
			"An advisory dropped HERE is invisible to every surface above — the gRPC\n"+
			"response, the remote CLI, and the local CLI all faithfully render nothing.",
			len(got), len(compiled.Warnings), compiled.Warnings)
	}
}

// ACCEPT-SIDE CONTROL: a candidate raising no advisory must come back clean,
// so the cell above cannot be satisfied by a seam that attaches warnings
// unconditionally.
func TestCommitSeamStaysSilentWithoutAdvisories_8484(t *testing.T) {
	s := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"interfaces ge-0/0/8 unit 0 family inet address 10.8.8.1/24",
		"security zones security-zone trust interfaces ge-0/0/8.0",
	} {
		if err := s.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    s,
		opts:     Options{NoDataplane: true},
	}

	_, compiled, err := d.commitWithGenBinding(
		0,
		func(*config.Config) error { return nil },
		func(gen uint64) (*config.Config, error) {
			return d.store.CommitWithDescriptionGenAs(configstore.InternalCommitter(), "", gen)
		},
	)
	if err != nil {
		t.Fatalf("commitWithGenBinding: %v", err)
	}
	if len(compiled.Warnings) != 0 {
		t.Fatalf("a clean candidate must come back with no advisories; got %d: %v",
			len(compiled.Warnings), compiled.Warnings)
	}
}
