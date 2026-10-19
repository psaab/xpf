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

// #15262 cluster-side anchor tests: the persisted first-keyed time is what
// pkg/grpcapi anchors its 5-minute rollout grace to, so its semantics are
// pinned here at the Manager level as well as through the fabric
// interceptor (pkg/grpcapi/fabric_auth_15262_test.go).

func pinGraceClock15262(t *testing.T, now *time.Time) {
	t.Helper()
	orig := fabricAuthGraceNow
	fabricAuthGraceNow = func() time.Time { return *now }
	t.Cleanup(func() { fabricAuthGraceNow = orig })
}

func graceManager15262(t *testing.T, path string) *Manager {
	t.Helper()
	restore := SetFabricAuthGraceStatePathForTesting(path)
	t.Cleanup(restore)
	return NewManager(0, 1)
}

func TestFabricGraceAnchorSurvivesRestart15262(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fabric-auth-grace")
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	pinGraceClock15262(t, &now)

	first := graceManager15262(t, path)
	first.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret("key-a")})
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
	restart := graceManager15262(t, path)
	restart.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret("key-a")})
	if got := restart.ControlLinkAuthKeyConfiguredAt(); !got.Equal(firstAt) {
		t.Fatalf("restart re-anchored the grace: got %v, want persisted %v", got, firstAt)
	}

	// A backwards-stepped restart clock sees the persisted stamp as
	// future-dated, so it is not credible and the apply re-anchors to the
	// local clock. That can only SHORTEN the grace versus true first
	// keying (expiry moves earlier), never extend it — fail-closed.
	now = firstAt.Add(-time.Hour)
	stepped := graceManager15262(t, path)
	stepped.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret("key-a")})
	if got := stepped.ControlLinkAuthKeyConfiguredAt(); !got.Equal(now) {
		t.Fatalf("future-dated stamp was honoured under a stepped-back clock: got %v, want re-anchor to %v", got, now)
	}
}

func TestFabricGraceAnchorNewSetReanchors15262(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fabric-auth-grace")
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	pinGraceClock15262(t, &now)

	m := graceManager15262(t, path)
	m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret("key-a")})
	firstAt := m.ControlLinkAuthKeyConfiguredAt()

	now = now.Add(time.Hour)
	// Adding the rotation (additional) key changes the accepted set.
	m.UpdateConfig(&config.ClusterConfig{
		ControlLinkAuthKey:    config.Secret("key-a"),
		ControlLinkAuthKeyAlt: config.Secret("key-b"),
	})
	if got := m.ControlLinkAuthKeyConfiguredAt(); !got.Equal(now) {
		t.Fatalf("adding the additional key did not re-anchor: got %v, want %v (first %v)", got, now, firstAt)
	}
	// Unchanged re-apply keeps it.
	m.UpdateConfig(&config.ClusterConfig{
		ControlLinkAuthKey:    config.Secret("key-a"),
		ControlLinkAuthKeyAlt: config.Secret("key-b"),
	})
	if got := m.ControlLinkAuthKeyConfiguredAt(); !got.Equal(now) {
		t.Fatalf("unchanged re-apply re-anchored: got %v, want %v", got, now)
	}
	// Finalizing (retiring the additional key) is again a new set.
	now = now.Add(time.Hour)
	m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret("key-a")})
	if got := m.ControlLinkAuthKeyConfiguredAt(); !got.Equal(now) {
		t.Fatalf("retiring the additional key did not re-anchor: got %v, want %v", got, now)
	}
}

func TestFabricGraceAnchorCorruptStateFallsBack15262(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	pinGraceClock15262(t, &now)

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
		m := graceManager15262(t, path)
		m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret("key-a")})
		if got := m.ControlLinkAuthKeyConfiguredAt(); !got.Equal(now) {
			t.Fatalf("corrupt/mismatched state %q anchored at %v, want fresh anchor %v", strings.TrimSpace(body), got, now)
		}
	}
}

func TestFabricGraceSetDigestDiscriminates15262(t *testing.T) {
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
