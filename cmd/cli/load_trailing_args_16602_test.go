package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// #16602 (remote surface): cmd/cli's handleLoad took mode=args[0],
// source=args[1] and never read args[2:], so `load merge terminal relative`
// — and any trailing garbage — silently dropped the modifier and sent
// LoadRequest{Mode, Content} with no path field, applying the snippet at
// the root. The fix refuses any token after the source before reading
// content or issuing the RPC.
//
// FAIL-ON-REVERT: delete the `len(args) > 2` guard in cmd/cli handleLoad and
// the cells below fail — a file cell reaches the counting stub and reports
// success; terminal cells panic on the nil readline because the guard no
// longer stops them before the paste prompt.

type countingLoadClient struct {
	pb.BpfrxServiceClient
	loads int
}

func (m *countingLoadClient) Load(_ context.Context, _ *pb.LoadRequest, _ ...grpc.CallOption) (*pb.LoadResponse, error) {
	m.loads++
	return &pb.LoadResponse{}, nil
}

func TestCtlLoadTrailingArgRefused16602(t *testing.T) {
	writeSnippet := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "snippet.conf")
		if err := os.WriteFile(path, []byte("system {\n    host-name fw-trailing;\n}\n"), 0o600); err != nil {
			t.Fatalf("write snippet: %v", err)
		}
		return path
	}

	for _, mode := range []string{"merge", "set", "override"} {
		for _, extra := range []string{"relative", "bogus"} {
			t.Run(mode+"_file_"+extra, func(t *testing.T) {
				client := &countingLoadClient{}
				c := &ctl{client: client}
				err := c.handleLoad([]string{mode, writeSnippet(t), extra})
				if err == nil || !strings.Contains(err.Error(), `unexpected argument "`+extra+`"`) {
					t.Fatalf("load %s <file> %s error = %v, want unexpected-argument refusal (#16602)", mode, extra, err)
				}
				if client.loads != 0 {
					t.Fatalf("Load RPC issued %d times for a refused load; nothing may be sent", client.loads)
				}
			})
			t.Run(mode+"_terminal_"+extra, func(t *testing.T) {
				client := &countingLoadClient{}
				// rl is nil: if the guard regresses, handleLoad proceeds
				// to the terminal read and panics/fails instead of
				// returning the unexpected-argument error.
				c := &ctl{client: client}
				err := c.handleLoad([]string{mode, "terminal", extra})
				if err == nil || !strings.Contains(err.Error(), `unexpected argument "`+extra+`"`) {
					t.Fatalf("load %s terminal %s error = %v, want unexpected-argument refusal (#16602)", mode, extra, err)
				}
				if client.loads != 0 {
					t.Fatalf("Load RPC issued %d times for a refused load", client.loads)
				}
			})
		}
	}

	t.Run("multiple_trailing_tokens_name_first", func(t *testing.T) {
		client := &countingLoadClient{}
		c := &ctl{client: client}
		err := c.handleLoad([]string{"merge", writeSnippet(t), "bogus", "trailing"})
		if err == nil || !strings.Contains(err.Error(), `unexpected argument "bogus"`) {
			t.Fatalf("error = %v, want refusal naming the first extra token", err)
		}
		if client.loads != 0 {
			t.Fatalf("Load RPC issued for a refused load")
		}
	})

	// Narrowness: the exact two-argument file form still loads.
	t.Run("plain_merge_file_still_loads", func(t *testing.T) {
		client := &countingLoadClient{}
		c := &ctl{client: client}
		if err := c.handleLoad([]string{"merge", writeSnippet(t)}); err != nil {
			t.Fatalf("plain load merge <file> refused: %v", err)
		}
		if client.loads != 1 {
			t.Fatalf("plain load issued %d Load RPCs, want 1", client.loads)
		}
	})
}
