// Throwaway research harness for #1864: load a userspace-xdp shim
// object through cilium/ebpf (same path as production
// loadRustUserspaceXDP) and report the verifier outcome.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: shimverify <obj.o>")
		os.Exit(2)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintln(os.Stderr, "memlock:", err)
		os.Exit(1)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	spec, err := ebpf.LoadCollectionSpecFromReader(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spec:", err)
		os.Exit(1)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			n := len(ve.Log)
			tail := ve.Log
			if n > 12 {
				tail = ve.Log[n-12:]
			}
			fmt.Printf("VERIFIER-REJECT %s\n", os.Args[1])
			for _, l := range tail {
				fmt.Println("  ", l)
			}
			os.Exit(3)
		}
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
	defer coll.Close()
	prog := coll.Programs["xdp_userspace_prog"]
	if prog == nil {
		fmt.Println("LOADED but xdp_userspace_prog missing")
		os.Exit(1)
	}
	info, _ := prog.Info()
	fmt.Printf("VERIFIER-PASS %s prog=%s\n", os.Args[1], info.Name)
	if insns, err := info.Instructions(); err == nil {
		fmt.Printf("  xlated insns: %d\n", len(insns))
	}
	os.Exit(0)
}
