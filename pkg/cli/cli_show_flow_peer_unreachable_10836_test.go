package cli

import (
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	"google.golang.org/grpc"
)

func TestFlowSessionPeerRPCFailureIsVisible10836(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })

	_, portString, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	c := &CLI{
		store:            newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:               &summaryMaxCLIDP{Manager: dataplane.New(), maxSessions: 786432},
		cluster:          cluster.NewManager(0, 1),
		fabricPeerAddrFn: func() []string { return []string{"127.0.0.1"} },
		fabricPeerPort:   port,
	}

	summary := captureStdout(t, func() {
		if err := c.showFlowSession([]string{"summary"}); err != nil {
			t.Fatalf("showFlowSession summary: %v", err)
		}
	})
	for _, want := range []string{
		"node0 (LOCAL-ONLY):",
		"node1: unreachable (fetch peer session summary:",
		"Maximum-sessions: 786432",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing %q:\n%s", want, summary)
		}
	}

	detail := captureStdout(t, func() {
		if err := c.showFlowSession(nil); err != nil {
			t.Fatalf("showFlowSession detail: %v", err)
		}
	})
	for _, want := range []string{
		"Total sessions (LOCAL-ONLY): 0",
		"node1: unreachable (fetch peer sessions:",
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail missing %q:\n%s", want, detail)
		}
	}
}
