package configstore

import (
	"strings"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15995 fold (GLM F3 / Codex C4): ShowConfigTrees & friends used to
// hand back the store's LIVE trees after dropping the store lock, and
// the descendant-pricing gate walked them lock-free while candidate
// edits mutated the same tree in place — a Go data race and a
// price/render generation mismatch. The accessors now deep-copy under
// one lock acquisition. Run with -race: the walk/render below races the
// in-place candidate writer if a live tree ever leaks again.
func TestSnapshotTreesAreImmutableCopies15995(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride("system { host-name snap-15995; } security { zones { security-zone trust { description BEFORE-15995; } } }"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	s.ExitConfigure()
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	defer s.ExitConfigure()
	if err := s.SetFromInput("security zones security-zone trust description BEFORE-15995"); err != nil {
		t.Fatal(err)
	}

	snaps := s.ShowConfigTrees("candidate")
	if len(snaps) != 1 || snaps[0] == nil {
		t.Fatalf("candidate snapshot missing: %v", snaps)
	}
	snap := snaps[0]

	// Mutate the live candidate in place after snapshotting.
	if err := s.SetFromInput("security zones security-zone trust description AFTER-15995"); err != nil {
		t.Fatal(err)
	}
	if out := RenderShowRedacted(snap, []string{"security"}, "text"); !strings.Contains(out, "BEFORE-15995") || strings.Contains(out, "AFTER-15995") {
		t.Errorf("snapshot render does not reflect the priced generation:\n%s", out)
	}

	// Concurrent writer vs snapshot walk/render: must be race-free
	// (meaningful under -race; also exercises torn-walk safety).
	classTree, perrs := config.NewParser("system { login { class limited { permissions [ view configure ]; deny-configuration \"^security ipsec\"; } } }").Parse()
	if len(perrs) > 0 {
		t.Fatal(perrs)
	}
	compiled, cerr := config.CompileConfig(classTree)
	if cerr != nil {
		t.Fatal(cerr)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 25 {
				_ = s.SetFromInput("security zones security-zone trust description RACE-15995")
			}
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 25 {
				fresh := s.ShowConfigTrees("candidate")
				_ = config.AuthorizeConfigShowPathRendered(compiled, "limited", []string{"security"}, "", fresh)
				if len(fresh) == 1 {
					_ = RenderShowRedacted(fresh[0], []string{"security"}, "text")
				}
			}
		}()
	}
	wg.Wait()
}
