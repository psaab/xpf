// Command sunpath-canary is the executed AF_UNIX length canary for
// #16494, run by scripts/scratch-pinning-selftest.sh under the pinned
// GOTMPDIR/TMPDIR.
//
// It reproduces Go's testing.TempDir path shape exactly: a 64-byte
// test-name prefix (the cap in testing.(*common).makeTempDir) plus a
// 10-digit random suffix (os.MkdirTemp's nextRandom is a uint32 in
// decimal, at most 10 digits), then the /001 sequence directory
// testing.TempDir appends, then control.sock. Binding that socket
// fails with EINVAL when the pinned root is too long — the failure
// the pre-#16494 modelled-path check (71 bytes, a shape Go never
// produces) could not detect.
//
// scratch-pinning-selftest.sh also runs it under a deliberately
// over-long root and requires failure there, so a canary that stops
// binding (or a root check that stops measuring the real shape)
// reds in both directions.
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

func main() {
	root := os.Getenv("GOTMPDIR")
	if root == "" {
		root = os.Getenv("TMPDIR")
	}
	if root == "" {
		fmt.Fprintln(os.Stderr, "sunpath-canary: GOTMPDIR and TMPDIR both unset")
		os.Exit(2)
	}
	// 64-byte name prefix + fixed 10-digit stand-in for the random
	// suffix MkdirTemp appends: the longest directory testing.TempDir
	// can create for one test.
	name := "TestSunpathCanaryBindsControlSockUnderPinnedGoTmp16494XXXXXXXXXX" + "3191902123"
	dir := filepath.Join(root, name, "001")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "sunpath-canary: mkdir %q: %v\n", dir, err)
		os.Exit(2)
	}
	defer os.RemoveAll(filepath.Join(root, name))
	sock := filepath.Join(dir, "control.sock")
	if len(sock) > 107 {
		fmt.Fprintf(os.Stderr, "sunpath-canary: socket path is %d octets, over the 107-octet AF_UNIX sun_path limit: %q\n", len(sock), sock)
		os.Exit(1)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sunpath-canary: bind %q (%d octets): %v\n", sock, len(sock), err)
		os.Exit(1)
	}
	defer ln.Close()
	fmt.Printf("sunpath-canary: bound %q (%d octets)\n", sock, len(sock))
}
