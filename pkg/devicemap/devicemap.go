// Package devicemap implements the #1956 bare-metal device-map identity
// resolver: it binds host NICs (by stable identity — PCI bus address with
// permanent-MAC fallback) to xpf logical names. The resolver core is pure
// (caller supplies the NIC inventory) so it is unit-testable without
// sysfs/netlink; EnumeratePresentNICs reads the live host inventory. Both
// the daemon (rename + pre-flight) and the CLI (`show chassis device-map`)
// import this package so there is ONE resolution discipline.
package devicemap

import (
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// PresentNIC is one live host NIC as seen at resolve time. Captured as plain
// data so the resolver core is unit-testable without sysfs/netlink.
type PresentNIC struct {
	Name       string // current kernel name (post-udev, pre-xpf-rename)
	PCIAddr    string // PCI bus address ("" if none)
	PermMAC    string // permanent/factory MAC ("" when IdentityUnread is false: hardware has none)
	RunningMAC string // current running MAC (diagnostic only)
	LinkUp     bool   // operational/admin state (diagnostic; for `candidates`)

	// IdentityUnread reports that the per-NIC identity read FAILED, so
	// PermMAC / RunningMAC / LinkUp are UNKNOWN rather than known-absent
	// (#6786).
	//
	// Before this the two states were the same value. EnumeratePresentNICs
	// listed the NIC from sysfs and then read its attributes over netlink
	// under `if link, err := netlink.LinkByName(name); err == nil` — with the
	// error DISCARDED — so a failed read left PermMAC == "", which is exactly
	// what hardware with no permanent-MAC attribute produces. Resolve's
	// topology-change guard is conditioned on `PermMAC != ""`, so a failed
	// read did not merely lose information: it silently DISABLED the card-swap
	// refusal and downgraded the entry to BindBoundPCIOnly ("bound, PCI-only,
	// unverified"), renaming a NIC whose permanent MAC was never checked
	// against the one the operator pinned. That inverts the #1956 contract
	// that a PCI hit with a mismatched permanent MAC must REFUSE and never
	// silently hijack.
	//
	// INVARIANT: only EnumeratePresentNICs may set this true. A PresentNIC
	// built by hand asserts a KNOWN identity, which is why the zero value is
	// false — a synthesized record describes a NIC the caller already knows,
	// and the unknown state is only observable by the code that did the read.
	IdentityUnread bool
}

// PermMACDisplay renders this NIC's permanent MAC for the operator-facing
// `show chassis device-map candidates` table (#6786).
//
// It distinguishes the two states an empty PermMAC used to collapse: "(none)"
// asserts the positive fact that the hardware reported no permanent-MAC
// attribute, while "(unknown)" says the identity read FAILED and nothing is
// known. Printing "(none)" for a failed read tells an operator authoring a map
// that this NIC cannot be MAC-pinned, which may be false — and it hides the
// reason a MAC-pinned entry for it now refuses to bind.
//
// Single-sourced deliberately: the local CLI and the gRPC/remote CLI render
// this same table from two call sites, and a divergence between them is always
// a bug — they describe one machine's hardware to one operator.
func (n PresentNIC) PermMACDisplay() string {
	if n.IdentityUnread {
		return "(unknown)"
	}
	if n.PermMAC == "" {
		return "(none)"
	}
	return n.PermMAC
}

// LinkDisplay renders this NIC's link state for the candidates table. Like
// PermMACDisplay it separates a read that succeeded from one that did not:
// LinkUp is false both for a NIC that is genuinely down and for one whose
// state was never read, and reporting an unread NIC as "down" invites an
// operator to go hunting for a cabling fault that does not exist.
func (n PresentNIC) LinkDisplay() string {
	if n.IdentityUnread {
		return "unknown"
	}
	if n.LinkUp {
		return "up"
	}
	return "down"
}

// BindStatus classifies how a device-map entry resolved.
type BindStatus int

const (
	BindBound        BindStatus = iota // resolved cleanly to a present NIC
	BindBoundPCIOnly                   // PCI matched, no perm-MAC to cross-check
	BindBoundViaMAC                    // PCI missed, perm-MAC matched (PCI moved)
	BindUnbound                        // no present NIC matches the identity
	BindRefusedAmbig                   // PCI matched but perm-MAC mismatched, or ambiguous MAC
	// BindRefusedDupName: two or more entries resolved to the SAME logical
	// name (#6546). It is its own status rather than BindRefusedAmbig because
	// the operator-facing remedy is the opposite one: nothing is wrong with
	// the hardware and re-pinning an identity fixes nothing — the MAP has two
	// entries claiming one interface name and one of them must go.
	BindRefusedDupName
	// BindRefusedIdentityUnknown: the NIC at this entry's pinned identity
	// could not be READ, so its permanent MAC is unknown and the entry's
	// pinned MAC cannot be verified against it (#6786). Distinct from
	// BindRefusedAmbig because nothing is known to be wrong with the hardware
	// — the remedy is to retry/repair the identity read, not to re-pin the
	// entry — and distinct from BindBoundPCIOnly, which asserts the positive
	// fact that the hardware HAS no permanent MAC to check.
	BindRefusedIdentityUnknown
	// BindRefusedPinnedMACAbsent: the NIC at this entry's pinned PCI identity
	// was READ successfully and reports NO permanent MAC (known-absent, e.g. a
	// replacement card without a factory-MAC attribute), while the entry pins
	// one (#10905). Binding PCI-only would rename an unverified NIC into the
	// pinned logical name (and its zone) and persist it via .link — the same
	// durable wrong-device binding #6786 fixed for the unreadable case. Distinct
	// from BindRefusedIdentityUnknown (unknown vs known-absent: retry/repair vs
	// verify-replacement-then-drop-the-pin), from BindRefusedAmbig (no MAC was
	// read to mismatch), and from BindBoundPCIOnly (which remains correct for
	// PCI-only entries that never asked for MAC verification, #4884).
	BindRefusedPinnedMACAbsent
)

func (s BindStatus) String() string {
	switch s {
	case BindBound:
		return "bound"
	case BindBoundPCIOnly:
		return "bound (PCI-only, unverified — no permanent MAC)"
	case BindBoundViaMAC:
		return "bound (via MAC fallback — PCI moved, re-pin)"
	case BindUnbound:
		return "UNBOUND (no NIC at identity)"
	case BindRefusedAmbig:
		return "REFUSED (topology changed — card swapped at this identity)"
	case BindRefusedDupName:
		return "REFUSED (logical name claimed by more than one device-map entry)"
	case BindRefusedIdentityUnknown:
		return "REFUSED (identity unreadable — cannot verify pinned MAC)"
	case BindRefusedPinnedMACAbsent:
		return "REFUSED (pinned MAC unavailable — NIC reports no permanent MAC)"
	default:
		return "unknown"
	}
}

// Decisive reports whether the status is a final outcome (bound or refused),
// Refusal statuses are decisive: a refusal means the pinned identity WAS
// matched, it just must not be acted on.
func (s BindStatus) Decisive() bool {
	return s != BindUnbound
}

// Refused reports whether the status is one of the refusal variants. Callers
// that hard-stop on a refusal must use this rather than comparing against a
// single sentinel, so a new refusal reason cannot slip past a `== BindRefusedAmbig`
// check and be silently treated as a clean result (#6546).
func (s BindStatus) Refused() bool {
	return s == BindRefusedAmbig || s == BindRefusedDupName ||
		s == BindRefusedIdentityUnknown || s == BindRefusedPinnedMACAbsent
}

// Bound reports whether the status is one of the three bound variants.
func (s BindStatus) Bound() bool {
	return s == BindBound || s == BindBoundPCIOnly || s == BindBoundViaMAC
}

// Binding is the outcome of resolving one device-map entry.
type Binding struct {
	Entry      config.DeviceMapEntry
	Logical    string // Linux logical name (ge-0-0-3), "" if unbound/refused
	CurrentNIC string // the NIC's CURRENT kernel name, "" if unbound/refused
	Status     BindStatus
}

// Resolve resolves every entry against the present NICs using each entry's
// key order, applying topology-change detection (PCI hit but perm-MAC
// mismatch => REFUSE, never silent hijack — R-1/AGY HIGH-3). RETH members
// are restricted to PCI matching (their MAC alternates physical<->virtual,
// R-6); the strict commit validator already rejects key mac on a RETH
// member, so here the MAC leg is skipped for them as defense in depth.
func Resolve(entries []config.DeviceMapEntry, nics []PresentNIC, rethMembers map[string]bool) []Binding {
	byPCI := make(map[string][]*PresentNIC)
	byPermMAC := make(map[string][]*PresentNIC)
	for i := range nics {
		n := &nics[i]
		if n.PCIAddr != "" {
			lp := strings.ToLower(n.PCIAddr)
			byPCI[lp] = append(byPCI[lp], n)
		}
		if n.PermMAC != "" {
			lm := strings.ToLower(n.PermMAC)
			byPermMAC[lm] = append(byPermMAC[lm], n)
		}
	}

	out := make([]Binding, 0, len(entries))
	for _, e := range entries {
		logical := config.LinuxIfName(e.LogicalName)
		isRETH := rethMembers[e.LogicalName]
		rb := Binding{Entry: e, Status: BindUnbound}

		allowMAC := e.MAC != "" && !isRETH
		allowPCI := e.PCIAddr != ""

		// Order-INDEPENDENT refusals (run BEFORE the key loop so NO key order
		// can bypass them — Codex HIGH-1 / r2 HIGH-B):
		if allowPCI {
			pm := byPCI[strings.ToLower(e.PCIAddr)]
			// (a) Same-PCI ambiguity: two present NICs share this entry's PCI
			// address. Refuse regardless of key order (a `key mac` /
			// `mac-then-pci` entry would otherwise bind via MAC and never
			// reach the PCI arm's len>1 guard).
			if len(pm) > 1 {
				rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedAmbig, "", ""
				out = append(out, rb)
				continue
			}
			// (b) Topology change: a single present NIC at the pinned PCI
			// whose permanent MAC mismatches the entry's MAC means a card was
			// swapped into the slot. Refuse regardless of key order. Skip for
			// RETH members (MAC is not a usable key for them) and when either
			// side lacks a perm-MAC to compare.
			if e.MAC != "" && !isRETH && len(pm) == 1 &&
				pm[0].PermMAC != "" && !strings.EqualFold(pm[0].PermMAC, e.MAC) {
				rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedAmbig, "", ""
				out = append(out, rb)
				continue
			}
			// (c) #6786: the NIC at the pinned PCI is present but its identity
			// could not be READ, so its permanent MAC is UNKNOWN and the check
			// in (b) could not run. The entry pins a MAC precisely to detect a
			// card swap at this slot; binding anyway would assert "verified by
			// PCI, hardware has no MAC to check" — a claim the failed read does
			// not support. Refuse instead, order-independently like (a)/(b).
			//
			// This is deliberately NARROW. It fires only when the operator
			// pinned a MAC for this entry, so an entry keyed on PCI alone is
			// unaffected: its identity is the PCI address, which came from
			// sysfs and was read successfully, and the failed netlink read cost
			// it nothing it asked for. Widening it to every unreadable NIC
			// would let one transient netlink failure refuse interfaces whose
			// operator never requested MAC verification.
			if e.MAC != "" && !isRETH && len(pm) == 1 && pm[0].IdentityUnread {
				rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedIdentityUnknown, "", ""
				out = append(out, rb)
				continue
			}
			// (d) #10905: the identity read SUCCEEDED, but the hardware
			// positively reports no permanent MAC. A MAC-pinned entry must not
			// silently degrade to a PCI-only bind here: that would adopt a
			// replacement whose hardware identity cannot be verified. This is
			// narrower than refusing all MAC-less PCI bindings (#4884): a
			// PCI-only entry never asked for this MAC cross-check, and unread
			// identities have the distinct refusal above.
			if e.MAC != "" && !isRETH && len(pm) == 1 &&
				!pm[0].IdentityUnread && pm[0].PermMAC == "" {
				rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedPinnedMACAbsent, "", ""
				out = append(out, rb)
				continue
			}
		}

		pciTried := false
		for _, key := range keySequence(e, allowPCI, allowMAC) {
			switch key {
			case config.DeviceMapKeyPCI:
				pciTried = true
				pm := byPCI[strings.ToLower(e.PCIAddr)]
				if len(pm) > 1 {
					// Two present NICs share one PCI address — ambiguous,
					// refuse rather than bind a non-deterministic one.
					rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedAmbig, "", ""
				} else if len(pm) == 1 {
					nic := pm[0]
					if e.MAC != "" && nic.PermMAC != "" {
						if strings.EqualFold(nic.PermMAC, e.MAC) {
							rb.Status, rb.CurrentNIC, rb.Logical = BindBound, nic.Name, logical
						} else {
							rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedAmbig, "", ""
						}
					} else {
						rb.Status, rb.CurrentNIC, rb.Logical = BindBoundPCIOnly, nic.Name, logical
					}
				}
			case config.DeviceMapKeyMAC:
				matches := byPermMAC[strings.ToLower(e.MAC)]
				if len(matches) == 1 {
					// "via MAC fallback (PCI moved, re-pin)" is only true when
					// MAC was reached as a FALLBACK after a PCI miss — i.e. PCI
					// was tried first and did not bind (Copilot). For a MAC-
					// primary key order (key mac / mac-then-pci) the MAC bind
					// is the intended primary, so report a clean BindBound.
					st := BindBound
					if pciTried {
						st = BindBoundViaMAC
					}
					rb.Status, rb.CurrentNIC, rb.Logical = st, matches[0].Name, logical
				} else if len(matches) > 1 {
					rb.Status, rb.CurrentNIC, rb.Logical = BindRefusedAmbig, "", ""
				}
			}
			if rb.Status.Decisive() {
				break
			}
		}
		out = append(out, rb)
	}

	// Post-pass (Codex r2 HIGH-C): two DIFFERENT entries can resolve to the
	// SAME present NIC via cross-key identities (entry A keyed by PCI, entry B
	// keyed by that same NIC's permanent MAC) — the strict compile-time
	// duplicate checks compare PCI-to-PCI and MAC-to-MAC and miss this. Left
	// alone, the daemon's desiredByCurrent would last-wins one logical name
	// onto the NIC. Detect the collision here and REFUSE every entry that
	// landed on a multiply-claimed NIC, rather than silently dropping one.
	claims := make(map[string]int)
	// #6546: the SYMMETRIC collision. The NIC-claim pass above catches two
	// entries landing on one NIC; nothing caught two entries landing on one
	// LOGICAL NAME, so a map with a duplicate name bound BOTH entries and the
	// daemon's rename loop (device_map.go, keyed by CurrentNIC) then renamed
	// two different NICs to the same final name — whichever the map iteration
	// reached last won, durably, via the `.link` files it writes. On bare
	// metal that can strand management or put a NIC in the wrong zone, and the
	// SAME config can bind differently across boots.
	//
	// The count keys on the RESOLVED Linux name, not Entry.LogicalName: the
	// Junos slash form and the kernel dash form (`ge-0/0/3` / `ge-0-0-3`) are
	// two spellings of one interface, and before the companion fix in
	// validateDeviceMapStrict the raw-string compare let that pair through the
	// strict commit gate as well as the tolerant one.
	nameClaims := make(map[string]int)
	for i := range out {
		if out[i].Status.Bound() {
			claims[out[i].CurrentNIC]++
			nameClaims[out[i].Logical]++
		}
	}
	for i := range out {
		if !out[i].Status.Bound() {
			continue
		}
		// Duplicate-name is checked FIRST so the more precise refusal wins
		// when an entry is caught by both passes: "re-pin the identity" is
		// the wrong instruction for a map that names one interface twice.
		if nameClaims[out[i].Logical] > 1 {
			out[i].Status, out[i].CurrentNIC, out[i].Logical = BindRefusedDupName, "", ""
			continue
		}
		if claims[out[i].CurrentNIC] > 1 {
			out[i].Status, out[i].CurrentNIC, out[i].Logical = BindRefusedAmbig, "", ""
		}
	}
	return out
}

// keySequence returns the ordered identity keys to try for an entry, filtered
// by which keys are usable (allowPCI/allowMAC).
func keySequence(e config.DeviceMapEntry, allowPCI, allowMAC bool) []string {
	var raw []string
	switch e.EffectiveKeyOrder() {
	case config.DeviceMapKeyPCI:
		raw = []string{config.DeviceMapKeyPCI}
	case config.DeviceMapKeyMAC:
		raw = []string{config.DeviceMapKeyMAC}
	case config.DeviceMapKeyMACThenPCI:
		raw = []string{config.DeviceMapKeyMAC, config.DeviceMapKeyPCI}
	default: // pci-then-mac
		raw = []string{config.DeviceMapKeyPCI, config.DeviceMapKeyMAC}
	}
	out := make([]string, 0, len(raw))
	for _, k := range raw {
		if k == config.DeviceMapKeyPCI && !allowPCI {
			continue
		}
		if k == config.DeviceMapKeyMAC && !allowMAC {
			continue
		}
		out = append(out, k)
	}
	return out
}

// RethMembersFromConfig returns the set of logical names that are RETH
// members in the config (RedundantParent set).
func RethMembersFromConfig(cfg *config.Config) map[string]bool {
	m := make(map[string]bool)
	if cfg == nil {
		return m
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc != nil && ifc.RedundantParent != "" {
			m[ifc.Name] = true
		}
	}
	return m
}

// ExtractPCIAddr extracts the last canonical PCI address (DDDD:BB:DD.F) from
// a sysfs path. Mirrors the daemon's extractPCIAddr so a committed key
// resolves against the live enumeration without normalization drift.
func ExtractPCIAddr(path string) string {
	parts := strings.Split(path, "/")
	var last string
	for _, p := range parts {
		if len(p) >= 11 && p[4] == ':' && p[7] == ':' && p[10] == '.' {
			last = p
		}
	}
	return last
}

// classifyNetdev decides whether a /sys/class/net entry is a mappable physical
// NIC and extracts its PCI address (empty for a non-PCI bus). devErr is the
// error from resolving the entry's `device` symlink and devReal its resolved
// target when devErr == nil.
//
// A physical NIC — PCI, USB, platform, or SoC — exposes a `device` symlink and
// is KEPT even when it has no PCI address, so a `key mac` device-map entry can
// still bind it (#4884). Before this, ANY NIC without a PCI address was dropped
// from the inventory BEFORE its permanent MAC was read, so on a bare-metal /
// SoC / USB-NIC appliance a valid MAC-only mapping never saw its target and the
// interface was stranded (marked unbound). A purely virtual netdev — loopback,
// bridge, veth, bond, vlan, vrf, tun/tap, and the xpf-created VRF/tunnel
// devices — has no `device` symlink and is dropped: it is not a mappable
// hardware NIC and would only flood the inventory / `candidates` list.
func classifyNetdev(name, devReal string, devErr error) (pci string, keep bool) {
	if name == "lo" {
		return "", false
	}
	if devErr != nil {
		return "", false // virtual netdev — no backing hardware device
	}
	return ExtractPCIAddr(devReal), true
}

// EnumeratePresentNICs builds the present-NIC inventory from sysfs + netlink:
// current kernel name, PCI address (empty for non-PCI buses), permanent
// (factory) MAC, running MAC, and link state. Sorted by PCI address, then
// kernel name, for stable output (non-PCI NICs share an empty PCI address, so
// the name tiebreak keeps their order deterministic).
// sysClassNetDir and linkByName are seams so the enumerator's own wiring is
// testable (#6786). Without them the ONLY way to observe that a failed
// per-NIC read sets IdentityUnread is on live hardware, so every test would
// have to construct PresentNIC by hand — which binds Resolve's handling of the
// flag while leaving the code that SETS it covered by nothing. Production
// values are the real sysfs path and netlink.
var (
	sysClassNetDir = "/sys/class/net"
	linkByName     = netlink.LinkByName
)

func EnumeratePresentNICs() ([]PresentNIC, error) {
	entries, err := os.ReadDir(sysClassNetDir)
	if err != nil {
		return nil, err
	}
	var nics []PresentNIC
	for _, e := range entries {
		name := e.Name()
		devReal, derr := filepath.EvalSymlinks(filepath.Join(sysClassNetDir, name, "device"))
		pci, keep := classifyNetdev(name, devReal, derr)
		if !keep {
			continue
		}
		nic := PresentNIC{Name: name, PCIAddr: pci}
		// #6786: the error from this read is RECORDED, not discarded. A failed
		// read leaves PermMAC == "", which is the same value hardware with no
		// permanent-MAC attribute produces — and Resolve's card-swap refusal is
		// conditioned on PermMAC != "", so swallowing the error silently turned
		// "REFUSE, a different card is at this identity" into "bind, unverified".
		// The NIC is still listed (it is present in sysfs, and dropping it would
		// make a real NIC vanish from `show chassis device-map candidates`); what
		// changes is that its identity is marked UNKNOWN so a MAC-pinned entry
		// refuses instead of binding blind.
		if link, err := linkByName(name); err == nil {
			a := link.Attrs()
			nic.RunningMAC = a.HardwareAddr.String()
			if len(a.PermHWAddr) != 0 {
				nic.PermMAC = a.PermHWAddr.String()
			}
			nic.LinkUp = a.OperState == netlink.OperUp || a.Flags&1 != 0 // IFF_UP
		} else {
			nic.IdentityUnread = true
			slog.Warn("device-map: NIC identity read failed; permanent MAC is UNKNOWN. "+
				"A device-map entry that pins a MAC at this NIC's identity will REFUSE to bind "+
				"rather than bind it unverified (#6786)",
				"nic", name, "pci", pci, "err", err)
		}
		nics = append(nics, nic)
	}
	sort.Slice(nics, func(i, j int) bool {
		if nics[i].PCIAddr != nics[j].PCIAddr {
			return nics[i].PCIAddr < nics[j].PCIAddr
		}
		return nics[i].Name < nics[j].Name
	})
	return nics, nil
}
