package cli

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/frr"
)

// #15265 B08-04 CLI surface: a VRF-only fixture must list its tenant
// peer with the instance name, not "No BGP peers".
type bgpVRFAllExecutor15265 struct{ cmd string }

func (e *bgpVRFAllExecutor15265) Vtysh(_ context.Context, cmd string) (string, error) {
	e.cmd = cmd
	if cmd == "show bgp vrf all summary json" {
		return `{"vrf-tenant":{"ipv4Unicast":{"routerId":"10.1.0.1","as":65011,"vrfName":"vrf-tenant","peers":{"203.0.113.2":{"remoteAs":65012,"msgRcvd":5,"msgSent":6,"peerUptime":"00:10:00","state":"Established","pfxRcd":7}}}}}`, nil
	}
	return "", nil
}
func (e *bgpVRFAllExecutor15265) FrrReloadPy(context.Context, string) error { return nil }
func (e *bgpVRFAllExecutor15265) FrrReloadPyTest(context.Context, string) error {
	return errors.New("diff")
}
func (e *bgpVRFAllExecutor15265) VtyshLoad(context.Context, string) ([]byte, error) {
	return nil, nil
}
func (e *bgpVRFAllExecutor15265) VtyshStream(context.Context, string) (io.ReadCloser, func() error, error) {
	return io.NopCloser(strings.NewReader("")), func() error { return nil }, nil
}
func (e *bgpVRFAllExecutor15265) VtyshDaemon(context.Context, string, string) ([]byte, error) {
	return nil, nil
}
func (e *bgpVRFAllExecutor15265) VtyshLoadDaemon(context.Context, string, string) ([]byte, error) {
	return nil, nil
}

func TestShowBGPListsVRFOnlyPeerWithInstance15265(t *testing.T) {
	exec := &bgpVRFAllExecutor15265{}
	m := frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), exec)
	c := &CLI{frr: m}
	var runErr error
	out := captureStdout(t, func() { runErr = c.showBGP([]string{"summary"}) })
	if runErr != nil {
		t.Fatalf("showBGP summary: %v", runErr)
	}
	if exec.cmd != "show bgp vrf all summary json" {
		t.Fatalf("vtysh cmd = %q", exec.cmd)
	}
	if strings.Contains(out, "No BGP peers") {
		t.Fatalf("VRF-only box printed No BGP peers:\n%s", out)
	}
	for _, want := range []string{"203.0.113.2", "tenant", "Established", "Instance"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}
