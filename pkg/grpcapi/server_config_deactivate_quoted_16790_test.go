package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16790: Server.Set re-joined the lexed deactivate/activate path with
// strings.Join, so a whitespace-bearing element (policy "allow web")
// split into two tokens when the store re-lexed it and the path was not
// found. The server must re-join with config.JoinConfigPathTokens so the
// quoted element round-trips as one token and the store deactivates it.

func TestSetRPCDeactivateQuotedPolicy16790(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, line := range []string{
		`set security policies from-zone trust to-zone untrust policy "allow web" match source-address any`,
		`set security policies from-zone trust to-zone untrust policy "allow web" match destination-address any`,
		`set security policies from-zone trust to-zone untrust policy "allow web" match application junos-http`,
		`set security policies from-zone trust to-zone untrust policy "allow web" then permit`,
		"set system host-name keep",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q) error = %v", line, err)
		}
	}
	s := &Server{store: store}
	ctx := ctxWithAuthorizedRoot(ctxWithPeerUID(0))

	if _, err := s.Set(ctx, &pb.SetRequest{
		Input: `deactivate security policies from-zone trust to-zone untrust policy "allow web"`,
	}); err != nil {
		t.Fatalf("Set(deactivate quoted policy) error = %v (#16790)", err)
	}
	out := store.ShowCandidateSet()
	if !strings.Contains(out, `deactivate security policies from-zone trust to-zone untrust policy "allow web"`) {
		t.Fatalf("quoted policy not actually deactivated:\n%s (#16790)", out)
	}
	if !strings.Contains(out, "set system host-name keep") {
		t.Fatalf("active sibling lost:\n%s", out)
	}

	// Activate round-trips the same quoted path back to active.
	if _, err := s.Set(ctx, &pb.SetRequest{
		Input: `activate security policies from-zone trust to-zone untrust policy "allow web"`,
	}); err != nil {
		t.Fatalf("Set(activate quoted policy) error = %v (#16790)", err)
	}
	out = store.ShowCandidateSet()
	if strings.Contains(out, "deactivate ") {
		t.Fatalf("activate via Set RPC did not clear the quoted-policy marker:\n%s (#16790)", out)
	}

	// Control: plain path still deactivates.
	if _, err := s.Set(ctx, &pb.SetRequest{Input: "deactivate system host-name keep"}); err != nil {
		t.Fatalf("Set(deactivate plain) error = %v", err)
	}
	if out := store.ShowCandidateSet(); !strings.Contains(out, "deactivate system host-name keep") {
		t.Fatalf("plain deactivate control lost:\n%s", out)
	}
}
