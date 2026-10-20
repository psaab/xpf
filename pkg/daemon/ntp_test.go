package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenderChronySources(t *testing.T) {
	got := renderChronySources([]string{"10.0.0.1", "pool.example.net"}, nil)
	want := "server 10.0.0.1 iburst\npool pool.example.net iburst\n"
	if got != want {
		t.Fatalf("renderChronySources() = %q, want %q", got, want)
	}
}

func TestRenderChronyPeers15709(t *testing.T) {
	got := renderChronyPeers([]string{"192.0.2.1", "pool.example.net"}, nil)
	want := "peer 192.0.2.1 iburst\npeer pool.example.net iburst\n"
	if got != want {
		t.Fatalf("renderChronyPeers() = %q, want %q", got, want)
	}
}

func TestRenderChronyThresholdAccept(t *testing.T) {
	got := renderChronyThreshold(400, "accept")
	want := "logchange 400\n"
	if got != want {
		t.Fatalf("renderChronyThreshold(accept) = %q, want %q", got, want)
	}
}

func TestRenderChronyThresholdReject(t *testing.T) {
	got := renderChronyThreshold(400, "reject")
	want := "logchange 400\nmaxchange 400 1 -1\n"
	if got != want {
		t.Fatalf("renderChronyThreshold(reject) = %q, want %q", got, want)
	}
}

func TestReconcileManagedFileWriteAndRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	changed, err := reconcileManagedFile(path, "hello\n")
	if err != nil {
		t.Fatalf("reconcile write: %v", err)
	}
	if !changed {
		t.Fatal("expected initial write to report change")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if string(data) != "hello\n" {
		t.Fatalf("file contents = %q, want %q", string(data), "hello\n")
	}

	changed, err = reconcileManagedFile(path, "hello\n")
	if err != nil {
		t.Fatalf("reconcile unchanged: %v", err)
	}
	if changed {
		t.Fatal("expected unchanged content to report no change")
	}

	changed, err = reconcileManagedFile(path, "")
	if err != nil {
		t.Fatalf("reconcile remove: %v", err)
	}
	if !changed {
		t.Fatal("expected removal to report change")
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected file to be removed, stat err = %v", err)
	}
}
