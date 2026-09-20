package daemon

import (
	"fmt"
	"sync"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// ipsecQuarantineIdentityPath9506 is the durable operation allocator state.
// /var/lib/xpf is the daemon's persistent runtime-state root; tests redirect
// this package variable to a temporary file. The file is created only when
// the production netlink installer is about to stage an active IPsec divert.
var ipsecQuarantineIdentityPath9506 = "/var/lib/xpf/ipsec-quarantine-identity"

var (
	ipsecCaptureIdentityMu                 sync.Mutex
	ipsecCaptureIdentityAllocatorState9506 *xnft.IpsecDivertIdentityAllocator
	ipsecCaptureIdentityPath9506           string
)

type ipsecDurableIdentityInstaller9506 interface {
	UsesDurableIpsecIdentity9506() bool
}

type ipsecIdentityRemover9506 interface {
	RemoveIpsecDivertWithIdentity9506(xnft.IpsecDivertRemovalIdentity9506) error
}

// ipsecCaptureDurableIdentityEnabled9506 keeps test installers from creating
// /var/lib/xpf state. The real netlink installer is the only implementation
// that can read/write the kernel metadata witness and therefore the only path
// that needs the durable allocator.
func ipsecCaptureDurableIdentityEnabled9506() bool {
	if nftInstaller == nil {
		return false
	}
	installer, ok := nftInstaller.(ipsecDurableIdentityInstaller9506)
	return ok && installer.UsesDurableIpsecIdentity9506()
}

func ipsecCaptureIdentityAllocator9506() (*xnft.IpsecDivertIdentityAllocator, error) {
	if !ipsecCaptureDurableIdentityEnabled9506() {
		return nil, nil
	}
	ipsecCaptureIdentityMu.Lock()
	defer ipsecCaptureIdentityMu.Unlock()
	if ipsecCaptureIdentityAllocatorState9506 != nil && ipsecCaptureIdentityPath9506 == ipsecQuarantineIdentityPath9506 {
		return ipsecCaptureIdentityAllocatorState9506, nil
	}
	allocator, err := xnft.NewIpsecDivertIdentityAllocator(ipsecQuarantineIdentityPath9506)
	if err != nil {
		return nil, err
	}
	ipsecCaptureIdentityAllocatorState9506 = allocator
	ipsecCaptureIdentityPath9506 = ipsecQuarantineIdentityPath9506
	return allocator, nil
}

// ipsecCaptureRunID9506 returns the one durable run ID used by both the
// capture actor's Status().RunID and every IpsecDivertSpec metadata witness.
func ipsecCaptureRunID9506() (string, error) {
	allocator, err := ipsecCaptureIdentityAllocator9506()
	if err != nil {
		return "", fmt.Errorf("ipsec capture identity allocator: %w", err)
	}
	if allocator == nil {
		// Unit-only fake installers do not touch the kernel. Preserve the
		// existing process identity there without creating durable state.
		return ipsecCaptureProcessRunID, nil
	}
	return allocator.CurrentRunID(), nil
}

// ipsecCaptureInstallSpec9506 consumes a fresh durable operation sequence.
// QuarantineGeneration remains the logical config/queue generation; the
// operation sequence advances for every actual install mutation, including
// actor-start rollback and quarantine fallback installs.
func ipsecCaptureInstallSpec9506(spec xnft.IpsecDivertSpec) (xnft.IpsecDivertSpec, error) {
	allocator, err := ipsecCaptureIdentityAllocator9506()
	if err != nil {
		return spec, fmt.Errorf("ipsec capture identity allocator: %w", err)
	}
	if allocator == nil {
		return spec, nil
	}
	identity, err := allocator.Allocate()
	if err != nil {
		return spec, err
	}
	spec.RunID = identity.RunID
	spec.InstallSequence = identity.InstallSequence
	spec.LabelSchema = identity.LabelSchema
	spec.IdentityLockPath = allocator.StatePath()
	return spec, nil
}

// removeIpsecDivert9506 consumes a fresh operation sequence before removing
// the active table. The active runtime's identity remains the ownership
// authorization; the fresh sequence is only the removal event and must not
// authorize deleting another runtime's table.
func removeIpsecDivert9506(owner *xnft.IpsecDivertSpec) error {
	if !ipsecCaptureDurableIdentityEnabled9506() {
		return nftInstaller.RemoveIpsecDivert()
	}
	allocator, err := ipsecCaptureIdentityAllocator9506()
	if err != nil {
		return err
	}
	operation, err := allocator.Allocate()
	if err != nil {
		return err
	}
	request := xnft.IpsecDivertRemovalIdentity9506{Operation: operation, LockPath: allocator.StatePath()}
	if owner != nil {
		request.Owner = xnft.IpsecDivertIdentity{
			RunID:           owner.RunID,
			InstallSequence: owner.InstallSequence,
			LabelSchema:     owner.LabelSchema,
		}
	}
	if remover, ok := nftInstaller.(ipsecIdentityRemover9506); ok {
		return remover.RemoveIpsecDivertWithIdentity9506(request)
	}
	return nftInstaller.RemoveIpsecDivert()
}

// installIpsecQuarantine9506 obtains a fresh operation identity before the
// deny-first fallback used after an actor-start failure. It never reuses the
// staged install's earlier sequence.
func installIpsecQuarantine9506(spec xnft.IpsecDivertSpec) error {
	spec.QuarantineAll = true
	stamped, err := ipsecCaptureInstallSpec9506(spec)
	if err != nil {
		return err
	}
	if guardInstaller, ok := nftInstaller.(ipsecCaptureQuarantineInstaller); ok {
		return guardInstaller.InstallIpsecQuarantineGuard(stamped)
	}
	return nftInstaller.InstallIpsecDivert(stamped)
}
