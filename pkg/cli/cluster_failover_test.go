package cli

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	defer func() {
		os.Stdout = oldStdout
		_ = w.Close()
		_ = r.Close()
	}()
	os.Stdout = w

	type readResult struct {
		out []byte
		err error
	}
	readDone := make(chan readResult, 1)
	go func() {
		out, err := io.ReadAll(r)
		readDone <- readResult{out: out, err: err}
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("stdout close error = %v", err)
	}
	result := <-readDone
	if result.err != nil {
		t.Fatalf("io.ReadAll() error = %v", result.err)
	}
	return string(result.out)
}

func TestHandleRequestChassisClusterFailoverProxiesPeerTarget(t *testing.T) {
	c := &CLI{cluster: cluster.NewManager(0, 1)}

	var gotAction string
	c.peerSystemActionFn = func(ctx context.Context, action string) (string, error) {
		gotAction = action
		return "proxied manual failover", nil
	}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1", "node", "1"})
	})
	if callErr != nil {
		t.Fatalf("handleRequestChassisClusterFailover() error = %v", callErr)
	}
	if gotAction != "cluster-failover:1:node1" {
		t.Fatalf("peer action = %q, want %q", gotAction, "cluster-failover:1:node1")
	}
	if strings.TrimSpace(out) != "proxied manual failover" {
		t.Fatalf("stdout = %q, want proxied response", out)
	}
}

func TestHandleRequestChassisClusterFailoverDataProxiesPeerTarget(t *testing.T) {
	c := &CLI{cluster: cluster.NewManager(0, 1)}

	var gotAction string
	c.peerSystemActionFn = func(ctx context.Context, action string) (string, error) {
		gotAction = action
		return "proxied data failover", nil
	}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleRequestChassisClusterFailover([]string{"data", "node", "1"})
	})
	if callErr != nil {
		t.Fatalf("handleRequestChassisClusterFailover() error = %v", callErr)
	}
	if gotAction != "cluster-failover-data:node1" {
		t.Fatalf("peer action = %q, want %q", gotAction, "cluster-failover-data:node1")
	}
	if strings.TrimSpace(out) != "proxied data failover" {
		t.Fatalf("stdout = %q, want proxied response", out)
	}
}

func TestHandleRequestChassisClusterFailoverDataRejectsUnsupportedTargetNode(t *testing.T) {
	c := &CLI{cluster: cluster.NewManager(0, 1)}
	c.peerSystemActionFn = func(ctx context.Context, action string) (string, error) {
		t.Fatalf("unexpected peer proxy for action %q", action)
		return "", nil
	}

	err := c.handleRequestChassisClusterFailover([]string{"data", "node", "2"})
	if err == nil {
		t.Fatal("expected error for unsupported target node")
	}
	if got, want := err.Error(), "unsupported cluster failover target node 2"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}
