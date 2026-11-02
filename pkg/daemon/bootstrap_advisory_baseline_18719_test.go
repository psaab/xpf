package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)
const fabricStampBootstrapConfig18719 = `set chassis cluster cluster-id 1
set chassis cluster node 0
set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
set chassis cluster fabric-interface fab0
`

func TestBootstrapDoesNotHideFabricReminder18719(t *testing.T) {
	d, _ := bootstrapDaemon(t, fabricStampBootstrapConfig18719, 0)
	if err := d.bootstrapFromFile(); err != nil {
		t.Fatalf("bootstrapFromFile: %v", err)
	}
	if active := d.store.ActiveConfig(); active == nil || !hasWarningText18719(active.Warnings) {
		t.Fatalf("premise: bootstrap compiled the fabric reminder; active=%v", active)
	}
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := d.store.LoadSet("set system host-name after-bootstrap"); err != nil {
		t.Fatalf("stage unrelated operator change: %v", err)
	}
	compiled, err := d.store.Commit()
	if err != nil {
		t.Fatalf("first operator commit after bootstrap: %v", err)
	}
	if !hasWarningText18719(compiled.Warnings) {
		t.Fatalf("first operator commit hid the bootstrap reminder: %v", compiled.Warnings)
	}
}

func TestEventEnginePromotionDoesNotHideFabricReminder18719(t *testing.T) {
	s, err := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, command := range []string{
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"chassis cluster fabric-interface fab0",
	} {
		if err := s.SetFromInput(command); err != nil {
			t.Fatalf("stage %q: %v", command, err)
		}
	}
	seed, err := s.Commit()
	if err != nil {
		t.Fatalf("commit fabric baseline: %v", err)
	}
	if !hasWarningText18719(seed.Warnings) {
		t.Fatalf("premise: initial commit must contain #10105 reminder; warnings=%v", seed.Warnings)
	}
	if err := s.SetFromInput("system host-name event-engine"); err != nil {
		t.Fatalf("stage event-engine change: %v", err)
	}

	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    s,
		cluster:  cluster.NewManager(0, 1),
	}
	d.applyBodyForTest = func(*config.Config) {}
	if compiled, err := d.commitAndApply(
		context.Background(),
		configstore.InternalCommitterAs("system:event-engine"),
		"automated advisory baseline test",
		peerSyncNever,
	); err != nil || compiled == nil {
		t.Fatalf("event-engine commit = (%v, %v), want promoted config", compiled, err)
	}

	if err := s.SetFromInput("system domain-name after-event-engine"); err != nil {
		t.Fatalf("stage operator change: %v", err)
	}
	operatorCommit, err := s.Commit()
	if err != nil {
		t.Fatalf("operator commit after event-engine promotion: %v", err)
	}
	if !hasWarningText18719(operatorCommit.Warnings) {
		t.Fatalf("event-engine promotion hid the next operator reminder: %v", operatorCommit.Warnings)
	}
}

func TestApplyErrorInvalidatesBeforeConcurrentCommit18719(t *testing.T) {
	s, err := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, command := range []string{
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"chassis cluster fabric-interface fab0",
		"interfaces fab0 fabric-options member-interfaces ge-0/0/0",
	} {
		if err := s.SetFromInput(command); err != nil {
			t.Fatalf("stage %q: %v", command, err)
		}
	}
	seed, err := s.Commit()
	if err != nil || !hasWarningText18719(seed.Warnings) {
		t.Fatalf("baseline commit = (%v, %v), want #10105 reminder", seed, err)
	}
	if err := s.SetFromInput("interfaces fab0 fabric-options member-interfaces ge-0/0/1"); err != nil {
		t.Fatalf("stage first commit's fabric change: %v", err)
	}

	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    s,
		cluster:  cluster.NewManager(0, 1),
	}
	applyStarted := make(chan struct{})
	releaseApply := make(chan struct{})
	applyErr := errors.New("simulated post-promotion apply error")
	applyCalls := 0
	d.applyBodyForTest = func(*config.Config) {
		applyCalls++
		if applyCalls == 1 {
			d.applyErrForTest = applyErr
			close(applyStarted)
			<-releaseApply
			return
		}
		d.applyErrForTest = nil
	}
	type result struct {
		compiled *config.Config
		err      error
	}
	firstDone := make(chan result, 1)
	go func() {
		compiled, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "first", peerSyncNever)
		firstDone <- result{compiled: compiled, err: err}
	}()
	<-applyStarted
	if err := s.SetFromInput("system domain-name concurrent-operator"); err != nil {
		t.Fatalf("stage concurrent operator change: %v", err)
	}
	secondStarted := make(chan struct{})
	secondDone := make(chan result, 1)
	go func() {
		close(secondStarted)
		compiled, err := d.commitAndApply(context.Background(), configstore.InternalCommitter(), "second", peerSyncNever)
		secondDone <- result{compiled: compiled, err: err}
	}()
	<-secondStarted
	time.Sleep(10 * time.Millisecond)
	close(releaseApply)

	first := <-firstDone
	if first.compiled == nil || !errors.Is(first.err, applyErr) || !hasWarningText18719(first.compiled.Warnings) {
		t.Fatalf("first post-promotion apply result = (%v, %v), want warning plus apply error", first.compiled, first.err)
	}
	second := <-secondDone
	if second.err != nil || second.compiled == nil {
		t.Fatalf("concurrent operator commit = (%v, %v), want success", second.compiled, second.err)
	}
	if !hasWarningText18719(second.compiled.Warnings) {
		t.Fatalf("concurrent commit scoped against the failed apply's unseen baseline: %v", second.compiled.Warnings)
	}
}

func hasWarningText18719(warnings []string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, "fabric zone stamp (#10105)") {
			return true
		}
	}
	return false
}
