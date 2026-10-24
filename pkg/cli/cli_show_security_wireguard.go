package cli

import (
	"fmt"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/mgmtview"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
)

// showSecurityWireguard renders `show security wireguard [detail]`
// from the userspace helper's per-tunnel telemetry rows (#1865). The
// rendering is shared with the remote CLI via
// dpformat.FormatWireguardStatus (the FormatSystemBuffers pattern),
// so local and gRPC output are identical.
func (c *CLI) showSecurityWireguard(detail bool) error {
	// #2114/#6743 r2-B4: the publication check must ask the CELL, not the
	// field. `c.dp == nil` is permanently false under the daemon's live
	// indirection, so an emptied cell fell into the arm below and told the
	// operator the firewall is running a non-userspace dataplane — the
	// r6-F3 defect at a site the dpProbe() conversion left behind. ONE
	// resolution feeds both decisions, as in showSystemBuffers (r7).
	backend := mgmtview.Probe(c.dp)
	if backend == nil {
		fmt.Println("Dataplane not loaded")
		return nil
	}
	provider, ok := backend.(cliUserspaceStatusProvider)
	if !ok {
		fmt.Println("WireGuard telemetry requires the userspace dataplane")
		return nil
	}
	status, err := provider.Status()
	if err != nil {
		fmt.Printf("WireGuard telemetry unavailable: %v\n", err)
		return nil
	}
	fmt.Print(dpformat.FormatWireguardStatus(status, detail, time.Now()))
	return nil
}

// showSecurityWireguardPublicKey renders `show security wireguard
// public-key` (#1434 Increment 1): the LOCAL public key per configured
// WG tunnel, in WireGuard-canonical base64 — the key an operator hands
// to the peer. Like the status view it reads helper telemetry only and
// works without an active config.
func (c *CLI) showSecurityWireguardPublicKey() error {
	// #2114/#6743 r2-B4: same single-resolution publication check as
	// showSecurityWireguard.
	backend := mgmtview.Probe(c.dp)
	if backend == nil {
		fmt.Println("Dataplane not loaded")
		return nil
	}
	provider, ok := backend.(cliUserspaceStatusProvider)
	if !ok {
		fmt.Println("WireGuard telemetry requires the userspace dataplane")
		return nil
	}
	status, err := provider.Status()
	if err != nil {
		fmt.Printf("WireGuard telemetry unavailable: %v\n", err)
		return nil
	}
	fmt.Print(dpformat.FormatWireguardPublicKeys(status))
	return nil
}
