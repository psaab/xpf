package configstore

import (
	"path/filepath"
	"strings"
	"testing"
)

// #9641: the IPsec apply names charon's generation marker with ActiveDigestFor, and HA
// attribution turns a marker back into a config with RetainedGeneration.

func commitHostName9641(t *testing.T, s *Store, name string) string {
	t.Helper()
	if err := s.SetFromInput("system host-name " + name); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return s.ActiveDigest()
}

func configuredStore9641(t *testing.T, path string) *Store {
	t.Helper()
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	return s
}

// The digest names a config only while that exact config IS the active one. A replaced
// config, nil, and an identical-content config that is not the store's own pointer all
// get "", which the IPsec apply writes as an unknown marker.
func TestActiveDigestForNamesOnlyTheActiveConfig9641(t *testing.T) {
	s := configuredStore9641(t, filepath.Join(t.TempDir(), "config"))
	d0 := commitHostName9641(t, s, "gen0")
	c0 := s.ActiveConfig()
	if got := s.ActiveDigestFor(c0); got == "" || got != d0 {
		t.Errorf("ActiveDigestFor(active) = %q, want the active digest %q", got, d0)
	}
	d1 := commitHostName9641(t, s, "gen1")
	if d1 == d0 {
		t.Fatal("FIXTURE: two generations must have different digests")
	}
	if got := s.ActiveDigestFor(c0); got != "" {
		t.Errorf("C0 is no longer active, yet ActiveDigestFor named it %q; the IPsec apply would stamp "+
			"charon's marker with a generation C0 is not", got)
	}
	if got := s.ActiveDigestFor(s.ActiveConfig()); got != d1 {
		t.Errorf("ActiveDigestFor(new active) = %q, want %q", got, d1)
	}
	if got := s.ActiveDigestFor(nil); got != "" {
		t.Errorf("ActiveDigestFor(nil) = %q, want empty", got)
	}
	other := configuredStore9641(t, filepath.Join(t.TempDir(), "config"))
	commitHostName9641(t, other, "gen1")
	if got := s.ActiveDigestFor(other.ActiveConfig()); got != "" {
		t.Errorf("a config that is not this store's active pointer was named %q", got)
	}
}

// The active generation resolves to the active config itself, and every earlier
// generation to a recompile of its history tree. Anything else does not resolve.
func TestRetainedGenerationResolvesActiveAndHistory9641(t *testing.T) {
	s := configuredStore9641(t, filepath.Join(t.TempDir(), "config"))
	d0 := commitHostName9641(t, s, "gen0")
	d1 := commitHostName9641(t, s, "gen1")
	d2 := commitHostName9641(t, s, "gen2")

	if cfg, ok := s.RetainedGeneration(d2); !ok || cfg != s.ActiveConfig() {
		t.Errorf("the active generation must resolve to the active config itself (ok=%v)", ok)
	}
	for _, tc := range []struct{ digest, host string }{{d0, "gen0"}, {d1, "gen1"}} {
		cfg, ok := s.RetainedGeneration(tc.digest)
		if !ok || cfg == nil {
			t.Errorf("generation %s must resolve from history", tc.host)
			continue
		}
		if cfg.System.HostName != tc.host {
			t.Errorf("digest of %s resolved to host-name %q", tc.host, cfg.System.HostName)
		}
	}
	for _, digest := range []string{"", "unknown", strings.Repeat("0", 64)} {
		if cfg, ok := s.RetainedGeneration(digest); ok || cfg != nil {
			t.Errorf("RetainedGeneration(%q) resolved; nothing retained has that digest", digest)
		}
	}
}

// THE #9641 STATE: after an xpfd restart, charon still runs a generation named by the
// previous process. The rollback history is reloaded from disk, and a digest named
// before the restart must still resolve, and the active digest must not change across
// the restart, or every marker written before it would read as unknown after it.
func TestRetainedGenerationSurvivesARestart9641(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := configuredStore9641(t, path)
	d0 := commitHostName9641(t, s, "gen0")
	d1 := commitHostName9641(t, s, "gen1")

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := restarted.ActiveDigest(); got != d1 {
		t.Fatalf("the active digest changed across a restart (%s before, %s after)", d1, got)
	}
	if cfg, ok := restarted.RetainedGeneration(d1); !ok || cfg != restarted.ActiveConfig() {
		t.Errorf("after a restart the active generation must resolve to the active config (ok=%v)", ok)
	}
	cfg, ok := restarted.RetainedGeneration(d0)
	if !ok || cfg == nil || cfg.System.HostName != "gen0" {
		t.Errorf("after a restart the previous generation must resolve from the reloaded history (ok=%v)", ok)
	}
}
