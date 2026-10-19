package grpcapi

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #15262: the #11676 rollout-grace anchor is process-local, so every xpfd
// restart of a long-keyed node re-opens up to 5 minutes of tokenless
// read-only fabric RPCs until the peer authenticates. Persist the
// first-keyed time (keyed by the accepted-key set digest) in node state and
// anchor the grace to it: a restart under an unchanged key more than 5 min
// after first keying denies tokenless GetSessions immediately, while a new
// key still gets the grace.

func fabricAuth15262ManagerAt(t *testing.T, path string) *cluster.Manager {
	t.Helper()
	restore := cluster.SetFabricAuthGraceStatePathForTesting(path)
	t.Cleanup(restore)
	return cluster.NewManager(0, 1)
}

func TestFabricAuth15262_RestartUnderUnchangedKeyDeniesAfterGrace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fabric-auth-grace")

	// First incarnation: key first installed now.
	first := fabricAuth15262ManagerAt(t, path)
	first.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret(fabricTestKey)})
	firstAt := first.ControlLinkAuthKeyConfiguredAt()
	if firstAt.IsZero() {
		t.Fatal("first keyed apply did not publish a configuration time")
	}

	// Simulated restart: a fresh Manager (empty in-memory state) applying
	// the same key, well after the grace measured from first keying.
	restart := fabricAuth15262ManagerAt(t, path)
	restart.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret(fabricTestKey)})
	got := restart.ControlLinkAuthKeyConfiguredAt()
	if got.IsZero() {
		t.Fatal("restart under unchanged key published no configuration time; the persisted first-keyed anchor was not loaded")
	}
	if !got.Equal(firstAt) {
		t.Fatalf("restart under unchanged key re-anchored the grace: configuredAt=%v, want the persisted first-keyed time %v", got, firstAt)
	}

	// Through the real fabric interceptor: tokenless GetSessions is denied
	// immediately after that restart, not granted a fresh 5-minute grace.
	now := firstAt.Add(fabricAuth11676RolloutGrace + time.Second)
	s := &Server{
		cluster:         restart,
		fabricAuthNowFn: func() time.Time { return now },
	}
	probe, err := fabricAuth11676ReadOnlyCall(s)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("tokenless GetSessions after restart past first-keyed grace: err=%v (%s), want Unauthenticated", err, status.Code(err))
	}
	if probe.called {
		t.Fatal("tokenless GetSessions after restart past first-keyed grace reached the handler")
	}
}

func TestFabricAuth15262_RestartWithinGraceKeepsRemainingGrace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fabric-auth-grace")

	first := fabricAuth15262ManagerAt(t, path)
	first.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret(fabricTestKey)})
	firstAt := first.ControlLinkAuthKeyConfiguredAt()
	if firstAt.IsZero() {
		t.Fatal("first keyed apply did not publish a configuration time")
	}

	restart := fabricAuth15262ManagerAt(t, path)
	restart.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret(fabricTestKey)})

	// One minute after first keying (still inside grace): allowed.
	now := firstAt.Add(time.Minute)
	s := &Server{
		cluster:         restart,
		fabricAuthNowFn: func() time.Time { return now },
	}
	probe, err := fabricAuth11676ReadOnlyCall(s)
	if err != nil || !probe.called {
		t.Fatalf("tokenless read inside remaining grace after restart: called=%t err=%v", probe.called, err)
	}

	// At expiry measured from FIRST keying (not from restart): denied.
	now = firstAt.Add(fabricAuth11676RolloutGrace)
	probe, err = fabricAuth11676ReadOnlyCall(s)
	if status.Code(err) != codes.Unauthenticated || probe.called {
		t.Fatalf("tokenless read at first-keyed grace expiry after restart: called=%t err=%v, want Unauthenticated with no handler call", probe.called, err)
	}
}

func TestFabricAuth15262_NewKeyAfterRestartGetsGrace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fabric-auth-grace")

	first := fabricAuth15262ManagerAt(t, path)
	first.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret(fabricTestKey)})
	firstAt := first.ControlLinkAuthKeyConfiguredAt()
	if firstAt.IsZero() {
		t.Fatal("first keyed apply did not publish a configuration time")
	}

	// Restart with a DIFFERENT key (rotation / first keying of a new key):
	// the persisted anchor belongs to the old key digest, so the new key
	// gets a fresh grace.
	restart := fabricAuth15262ManagerAt(t, path)
	restart.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret("rotated-control-key")})
	newAt := restart.ControlLinkAuthKeyConfiguredAt()
	if newAt.IsZero() {
		t.Fatal("new key after restart published no configuration time")
	}
	if !newAt.After(firstAt) {
		t.Fatalf("new key after restart inherited the old key's anchor: configuredAt=%v, first key at %v; a new key must get a fresh grace", newAt, firstAt)
	}

	now := newAt.Add(time.Minute)
	s := &Server{
		cluster:         restart,
		fabricAuthNowFn: func() time.Time { return now },
	}
	// The server reads its accepted keys from the restarted manager, which
	// now holds the rotated key; a tokenless read inside the new grace is
	// admitted.
	probe, err := fabricAuth11676ReadOnlyCall(s)
	if err != nil || !probe.called {
		t.Fatalf("tokenless read inside new-key grace after restart: called=%t err=%v", probe.called, err)
	}
}

func TestFabricAuth15262_KeyFingerprintChangeInPlaceGetsGrace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fabric-auth-grace")

	m := fabricAuth15262ManagerAt(t, path)
	m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret(fabricTestKey)})
	firstAt := m.ControlLinkAuthKeyConfiguredAt()
	if firstAt.IsZero() {
		t.Fatal("first keyed apply did not publish a configuration time")
	}

	// Same process, key rotated to a different secret: this is a new
	// first-keying for that digest and must re-anchor (operator rollout),
	// unlike an unchanged-key re-apply which must not.
	m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret("rotated-control-key")})
	rotatedAt := m.ControlLinkAuthKeyConfiguredAt()
	if rotatedAt.IsZero() || !rotatedAt.After(firstAt) {
		t.Fatalf("in-place key rotation did not re-anchor: rotated=%v first=%v", rotatedAt, firstAt)
	}

	// Unchanged re-apply of the rotated key keeps its anchor.
	m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret("rotated-control-key")})
	if got := m.ControlLinkAuthKeyConfiguredAt(); !got.Equal(rotatedAt) {
		t.Fatalf("unchanged re-apply re-anchored: got %v want %v", got, rotatedAt)
	}

	// Clearing the key clears the anchor; re-keying the ORIGINAL key after
	// a clear is a fresh first-keying (the accepted set was empty between),
	// so it also re-anchors rather than resurrecting the stale anchor.
	m.UpdateConfig(&config.ClusterConfig{})
	if got := m.ControlLinkAuthKeyConfiguredAt(); !got.IsZero() {
		t.Fatalf("cleared key left a configuration time: %v", got)
	}
	m.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret(fabricTestKey)})
	if got := m.ControlLinkAuthKeyConfiguredAt(); got.IsZero() || !got.After(rotatedAt) {
		t.Fatalf("re-key after clear did not re-anchor: got %v (rotated anchor %v)", got, rotatedAt)
	}
}

func TestFabricAuth15262_UnkeyedWritesNoGraceState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fabric-auth-grace")
	m := fabricAuth15262ManagerAt(t, path)
	m.UpdateConfig(&config.ClusterConfig{})
	if got := m.ControlLinkAuthKeyConfiguredAt(); !got.IsZero() {
		t.Fatalf("unkeyed apply published a configuration time: %v", got)
	}
}
