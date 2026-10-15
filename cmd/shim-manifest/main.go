// shim-manifest recomputes the userspace-xdp source→object freshness
// manifest (#4977) and writes it to
// pkg/dataplane/userspace_xdp_manifest.json.
//
// It is invoked by pkg/dataplane/build-userspace-xdp.sh immediately
// after the verifier-gated install of userspace_xdp_bpfel.o, so the
// manifest stays in lockstep with the object it describes. Running it by
// hand does NOT rebuild the shim object — use `make generate` for that;
// this tool only re-hashes whatever object and source currently sit in
// the tree.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/psaab/xpf/pkg/dataplane"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("shim-manifest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repoRoot := fs.String("repo-root", ".", "repository root the manifest paths are relative to")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "shim-manifest: unexpected argument(s) %v\n", fs.Args())
		return 2
	}
	if err := dataplane.WriteUserspaceXDPManifest(*repoRoot); err != nil {
		fmt.Fprintf(stderr, "shim-manifest: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "shim-manifest: wrote %s\n", dataplane.UserspaceXDPManifestRelPath)
	return 0
}
