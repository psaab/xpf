package cluster

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #16027 cluster-side anchor tests: the persisted first-keyed time is what
// pkg/grpcapi anchors its 5-minute rollout grace to, so its semantics are
// pinned here at the Manager level as well as through the fabric
// interceptor (pkg/grpcapi/fabric_auth_16027_test.go).

func pinGraceClock16027(t *testing.T, now *time.Time) {
	t.Helper()
	orig := fabricAuthGraceNow
	fabricAuthGraceNow = func() time.Time { return *now }
	t.Cleanup(func() { fabricAuthGraceNow = orig })
}

func graceManager16027(t *testing.T, path string) *Manager {
	t.Helper()
	restore := SetFabricAuthGraceStatePathForTesting(path)
	t.Cleanup(restore)
	return NewManager(0, 1)
}

func TestFabricGraceAnchorSurvivesRestart16027(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fabric-auth-grace")
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	pinGraceClock16027(t, &now)

	first := graceManager16027(t, path)
	first.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.NewSecret("key-a")})
	firstAt := first.ControlLinkAuthKeyConfiguredAt()
	if !firstAt.Equal(now) {
		t.Fatalf("first keying anchored at %v, want %v", firstAt, now)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("first keying did not persist the anchor: %v", err)
	}

	// Restart 10 minutes later under the same key: the anchor must be the
	// persisted first-keyed time, not the restart time.
	now = now.Add(10 * time.Minute)
	restart := graceManager16027(t, path)
	restart.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.NewSecret("key-a")})
	if got := restart.ControlLinkAuthKeyConfiguredAt(); !got.Equal(firstAt) {
		t.Fatalf("restart re-anchored the grace: got %v, want persisted %v", got, firstAt)
	}

	// A backwards-stepped restart clock sees the persisted stamp as
	// future-dated. It is CLAMPED to the stepped-back clock (anchor ==
	// now) rather than rejected: the grace expires at now+5m instead of
	// first-keyed+5m — shortened, never extended — and the future stamp
	// stays on disk, so when the clock recovers the original first-keyed
	// time is restored instead of having been overwritten by `now`.
	// FAIL-ON-REVERT: restoring the pre-fold rejection (return zero for a
	// future stamp) reds the on-disk assertion below — the apply would
	// persist `now` over the stamp.
	now = firstAt.Add(-time.Hour)
	stepped := graceManager16027(t, path)
	stepped.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.NewSecret("key-a")})
	if got := stepped.ControlLinkAuthKeyConfiguredAt(); !got.Equal(now) {
		t.Fatalf("future-dated stamp was not clamped under a stepped-back clock: got %v, want clamp to %v", got, now)
	}
	if onDisk := loadFabricAuthGraceAnchorRaw(path, controlAuthKeySetDigest([]byte("key-a"), nil)); !onDisk.Equal(firstAt) {
		t.Fatalf("stepped-back apply overwrote the persisted stamp: on disk %v, want the original %v preserved for clock recovery", onDisk, firstAt)
	}

	// Clock recovered (past the original first keying + grace): the
	// preserved stamp is restored, so no fresh grace opens.
	now = firstAt.Add(10 * time.Minute)
	recovered := graceManager16027(t, path)
	recovered.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.NewSecret("key-a")})
	if got := recovered.ControlLinkAuthKeyConfiguredAt(); !got.Equal(firstAt) {
		t.Fatalf("clock recovery did not restore the original stamp: got %v, want %v", got, firstAt)
	}
}

func TestFabricGraceAnchorNewSetReanchors16027(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fabric-auth-grace")
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	pinGraceClock16027(t, &now)

	m := graceManager16027(t, path)
	m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.NewSecret("key-a")})
	firstAt := m.ControlLinkAuthKeyConfiguredAt()

	now = now.Add(time.Hour)
	// Adding the rotation (additional) key changes the accepted set.
	m.UpdateConfig(&config.ClusterConfig{
		ControlLinkAuthKey:    config.NewSecret("key-a"),
		ControlLinkAuthKeyAlt: config.NewSecret("key-b"),
	})
	if got := m.ControlLinkAuthKeyConfiguredAt(); !got.Equal(now) {
		t.Fatalf("adding the additional key did not re-anchor: got %v, want %v (first %v)", got, now, firstAt)
	}
	// Unchanged re-apply keeps it.
	m.UpdateConfig(&config.ClusterConfig{
		ControlLinkAuthKey:    config.NewSecret("key-a"),
		ControlLinkAuthKeyAlt: config.NewSecret("key-b"),
	})
	if got := m.ControlLinkAuthKeyConfiguredAt(); !got.Equal(now) {
		t.Fatalf("unchanged re-apply re-anchored: got %v, want %v", got, now)
	}
	// Finalizing (retiring the additional key) is again a new set.
	now = now.Add(time.Hour)
	m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.NewSecret("key-a")})
	if got := m.ControlLinkAuthKeyConfiguredAt(); !got.Equal(now) {
		t.Fatalf("retiring the additional key did not re-anchor: got %v, want %v", got, now)
	}
}

func TestFabricGraceAnchorCorruptStateFallsBack16027(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	pinGraceClock16027(t, &now)

	for _, body := range []string{
		"not-a-record\n",
		"12345\n",
		"-5 " + controlAuthKeySetDigest([]byte("key-a"), nil) + "\n",
		// A stamp for a DIFFERENT set must not anchor this key.
		strconv.FormatInt(now.Add(-time.Hour).UnixNano(), 10) + " " +
			controlAuthKeySetDigest([]byte("other-key"), nil) + "\n",
	} {
		path := filepath.Join(dir, "fabric-auth-grace")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		m := graceManager16027(t, path)
		m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.NewSecret("key-a")})
		if got := m.ControlLinkAuthKeyConfiguredAt(); !got.Equal(now) {
			t.Fatalf("corrupt/mismatched state %q anchored at %v, want fresh anchor %v", strings.TrimSpace(body), got, now)
		}
	}
}

func TestFabricGraceSetDigestDiscriminates16027(t *testing.T) {
	a := controlAuthKeySetDigest([]byte("key-a"), nil)
	b := controlAuthKeySetDigest([]byte("key-b"), nil)
	ab := controlAuthKeySetDigest([]byte("key-a"), []byte("key-b"))
	ba := controlAuthKeySetDigest([]byte("key-b"), []byte("key-a"))
	if a == "" || b == "" || ab == "" {
		t.Fatal("keyed sets must have a non-empty digest")
	}
	if a == b || a == ab || ab == ba {
		t.Fatal("the accepted-set digest must discriminate signing/additional slots and key changes")
	}
	if got := controlAuthKeySetDigest(nil, nil); got != "" {
		t.Fatalf("empty set digest = %q, want empty", got)
	}
	if strings.Contains(ab, "key-a") || strings.Contains(ab, "key-b") {
		t.Fatal("the persisted digest must never contain key bytes")
	}
}

func TestFabricGraceAnchorClearDeletesPersistedState16027(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fabric-auth-grace")
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	pinGraceClock16027(t, &now)

	m := graceManager16027(t, path)
	m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.NewSecret("key-a")})
	firstAt := m.ControlLinkAuthKeyConfiguredAt()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("first keying did not persist the anchor: %v", err)
	}

	// Clearing the key set must delete the persisted record.
	// FAIL-ON-REVERT: dropping deleteFabricAuthGraceAnchor from the
	// clear branch reds both assertions below — the file survives and
	// the reinstall resumes firstAt.
	now = now.Add(time.Hour)
	m.UpdateConfig(&config.ClusterConfig{})
	if got := m.ControlLinkAuthKeyConfiguredAt(); !got.IsZero() {
		t.Fatalf("cleared key left a configuration time: %v", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("clear did not delete the persisted anchor (stat err = %v); reinstalling the same key would resume the stale anchor", err)
	}

	// Reinstalling the SAME key is a genuine new first keying: it must
	// anchor at the reinstall time (fresh grace), not resume firstAt.
	m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.NewSecret("key-a")})
	if got := m.ControlLinkAuthKeyConfiguredAt(); !got.Equal(now) {
		t.Fatalf("reinstall after clear resumed the stale anchor: got %v, want fresh anchor %v (first keying was %v)", got, now, firstAt)
	}
	if onDisk := loadFabricAuthGraceAnchorRaw(path, controlAuthKeySetDigest([]byte("key-a"), nil)); !onDisk.Equal(now) {
		t.Fatalf("reinstall after clear did not persist the fresh anchor: on disk %v, want %v", onDisk, now)
	}
}
