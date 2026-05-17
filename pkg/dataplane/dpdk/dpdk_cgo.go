//go:build dpdk

package dpdk

/*
#cgo CFLAGS: -I${SRCDIR}/../../../dpdk_worker
#cgo pkg-config: libdpdk
#include "shared_mem.h"
#include "tables.h"
#include "counters.h"
#include <rte_hash.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_ring.h>
#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_cycles.h>
#include <rte_ip6.h>
#include <stdlib.h>
#include <string.h>

// memzone_addr extracts addr from anonymous union (CGo can't access anonymous union fields).
static inline void *memzone_addr(const struct rte_memzone *mz) {
	return mz->addr;
}
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

type platformState struct {
	shm            *C.struct_shared_memory
	ealInitialized bool
	workerCmd      *exec.Cmd
}

// --- Lifecycle ---

// workerPath returns the path to the dpdk_worker binary.
// It checks next to the daemon binary first, then falls back to PATH.
func workerPath() string {
	self, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(self), "dpdk_worker")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if p, err := exec.LookPath("dpdk_worker"); err == nil {
		return p
	}
	return "dpdk_worker"
}

func (m *Manager) Load() error {
	// Start the DPDK primary worker process if not already running.
	if err := m.startWorker(); err != nil {
		return fmt.Errorf("start dpdk_worker: %w", err)
	}

	// Initialize as DPDK secondary process.
	args := []string{"xpfd", "--proc-type=secondary", "--no-pci"}
	cArgs := make([]*C.char, len(args))
	for i, a := range args {
		cArgs[i] = C.CString(a)
	}
	defer func() {
		for _, ca := range cArgs {
			C.free(unsafe.Pointer(ca))
		}
	}()

	rc := C.rte_eal_init(C.int(len(args)), (**C.char)(unsafe.Pointer(&cArgs[0])))
	if rc < 0 {
		return fmt.Errorf("rte_eal_init failed: %d", rc)
	}
	m.platform.ealInitialized = true

	// Look up shared memory via memzone.
	cName := C.CString("xpf_shm")
	defer C.free(unsafe.Pointer(cName))
	mz := C.rte_memzone_lookup(cName)
	if mz == nil {
		return fmt.Errorf("rte_memzone_lookup(xpf_shm) failed: primary not running?")
	}
	m.platform.shm = (*C.struct_shared_memory)(C.memzone_addr(mz))

	if m.platform.shm.magic != C.SHM_MAGIC {
		return fmt.Errorf("shared memory magic mismatch: got 0x%x, want 0x%x",
			m.platform.shm.magic, C.SHM_MAGIC)
	}
	if m.platform.shm.version != C.SHM_VERSION {
		return fmt.Errorf("shared memory version mismatch: got %d, want %d",
			m.platform.shm.version, C.SHM_VERSION)
	}

	slog.Info("DPDK secondary process attached", "magic", fmt.Sprintf("0x%x", m.platform.shm.magic))
	m.loaded = true
	return nil
}

// startWorker launches the DPDK primary process and waits for it to be ready.
func (m *Manager) startWorker() error {
	path := workerPath()
	slog.Info("starting DPDK worker", "path", path)

	cmd := exec.Command(path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("exec %s: %w", path, err)
	}
	m.platform.workerCmd = cmd

	// Wait for the worker to create its shared memory (poll memzone).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		// Check if worker exited prematurely.
		select {
		default:
		}
		if cmd.ProcessState != nil {
			return fmt.Errorf("dpdk_worker exited prematurely: %v", cmd.ProcessState)
		}

		time.Sleep(100 * time.Millisecond)
		// We can't probe memzone until rte_eal_init succeeds, so just wait a fixed amount.
	}

	slog.Info("DPDK worker started", "pid", cmd.Process.Pid)
	return nil
}

func (m *Manager) Close() error {
	m.loaded = false
	if m.platform.ealInitialized {
		C.rte_eal_cleanup()
		m.platform.ealInitialized = false
	}
	m.platform.shm = nil
	return nil
}

func (m *Manager) Teardown() error {
	m.Close()
	// Stop the worker process on full teardown.
	if m.platform.workerCmd != nil && m.platform.workerCmd.Process != nil {
		slog.Info("stopping DPDK worker", "pid", m.platform.workerCmd.Process.Pid)
		m.platform.workerCmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- m.platform.workerCmd.Wait() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			m.platform.workerCmd.Process.Kill()
			<-done
		}
		m.platform.workerCmd = nil
	}
	return nil
}

// --- Program attachment (no-op for DPDK: ports are managed by the worker) ---

func (m *Manager) AttachXDP(ifindex int, forceGeneric bool) error {
	slog.Debug("DPDK: AttachXDP (no-op)", "ifindex", ifindex)
	return nil
}

func (m *Manager) DetachXDP(ifindex int) error {
	slog.Debug("DPDK: DetachXDP (no-op)", "ifindex", ifindex)
	return nil
}

func (m *Manager) AttachTC(ifindex int) error {
	slog.Debug("DPDK: AttachTC (no-op)", "ifindex", ifindex)
	return nil
}

func (m *Manager) DetachTC(ifindex int) error {
	slog.Debug("DPDK: DetachTC (no-op)", "ifindex", ifindex)
	return nil
}

func (m *Manager) AddTxPort(ifindex int) error {
	slog.Debug("DPDK: AddTxPort (no-op)", "ifindex", ifindex)
	return nil
}

// --- Compilation ---

func (m *Manager) Compile(cfg *config.Config) (*dataplane.CompileResult, error) {
	result, err := dataplane.CompileConfig(m, cfg, m.lastCompile != nil)
	if err != nil {
		return nil, err
	}
	m.lastCompile = result
	return result, nil
}

// --- Zone / interface mapping ---

func (m *Manager) SetZone(ifindex int, vlanID uint16, zoneID uint16, routingTable uint32, flags uint8, rgID uint8, screenFlags uint32) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	key := C.struct_iface_zone_key{
		ifindex: C.uint32_t(ifindex),
		vlan_id: C.uint16_t(vlanID),
	}
	pos := C.rte_hash_add_key(shm.iface_zone_map, unsafe.Pointer(&key))
	if pos < 0 {
		return fmt.Errorf("rte_hash_add_key(iface_zone): %d", pos)
	}
	valPtr := (*C.struct_iface_zone_value)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.iface_zone_values)) +
			uintptr(pos)*unsafe.Sizeof(C.struct_iface_zone_value{})))
	valPtr.zone_id = C.uint16_t(zoneID)
	valPtr.flags = C.uint8_t(flags)
	valPtr.rg_id = C.uint8_t(rgID)
	valPtr.routing_table = C.uint32_t(routingTable)
	valPtr.screen_flags = C.uint32_t(screenFlags)
	return nil
}

func (m *Manager) SetVlanIfaceInfo(subIfindex int, parentIfindex int, vlanID uint16) error {
	// VLAN interface info is stored in iface_zone_map via SetZone.
	// For DPDK this is a no-op since VLAN parsing happens in the worker.
	return nil
}

func (m *Manager) ClearIfaceZoneMap() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.rte_hash_reset(shm.iface_zone_map)
	return nil
}

func (m *Manager) ClearVlanIfaceMap() error {
	// No separate VLAN map in DPDK; handled via iface_zone_map.
	return nil
}

func (m *Manager) SetZoneConfig(zoneID uint16, cfg dataplane.ZoneConfig) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	ptr := (*C.struct_zone_config)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.zone_configs)) +
			uintptr(zoneID)*unsafe.Sizeof(C.struct_zone_config{})))
	ptr.zone_id = C.uint16_t(cfg.ZoneID)
	ptr.screen_profile_id = C.uint16_t(cfg.ScreenProfileID)
	ptr.host_inbound_flags = C.uint32_t(cfg.HostInbound)
	ptr.tcp_rst = C.uint8_t(cfg.TCPRst)
	return nil
}

// --- Policy ---

func (m *Manager) SetZonePairPolicy(fromZone, toZone uint16, ps dataplane.PolicySet) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	key := C.struct_zone_pair_key{
		from_zone: C.uint16_t(fromZone),
		to_zone:   C.uint16_t(toZone),
	}
	pos := C.rte_hash_add_key(shm.zone_pair_policies, unsafe.Pointer(&key))
	if pos < 0 {
		return fmt.Errorf("rte_hash_add_key(zone_pair): %d", pos)
	}
	valPtr := (*C.struct_policy_set)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.zone_pair_values)) +
			uintptr(pos)*unsafe.Sizeof(C.struct_policy_set{})))
	valPtr.policy_set_id = C.uint32_t(ps.PolicySetID)
	valPtr.num_rules = C.uint16_t(ps.NumRules)
	valPtr.default_action = C.uint16_t(ps.DefaultAction)
	return nil
}

func (m *Manager) SetPolicyRule(policySetID uint32, ruleIndex uint32, rule dataplane.PolicyRule) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	idx := policySetID*C.MAX_RULES_PER_POLICY + ruleIndex
	ptr := (*C.struct_policy_rule)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.policy_rules)) +
			uintptr(idx)*unsafe.Sizeof(C.struct_policy_rule{})))
	ptr.rule_id = C.uint32_t(rule.RuleID)
	ptr.policy_set_id = C.uint32_t(rule.PolicySetID)
	ptr.sequence = C.uint16_t(rule.Sequence)
	ptr.action = C.uint8_t(rule.Action)
	ptr.log = C.uint8_t(rule.Log)
	ptr.src_addr_id = C.uint32_t(rule.SrcAddrID)
	ptr.dst_addr_id = C.uint32_t(rule.DstAddrID)
	ptr.dst_port_low = C.uint16_t(rule.DstPortLow)
	ptr.dst_port_high = C.uint16_t(rule.DstPortHigh)
	ptr.protocol = C.uint8_t(rule.Protocol)
	ptr.active = C.uint8_t(rule.Active)
	ptr.app_id = C.uint32_t(rule.AppID)
	ptr.nat_rule_id = C.uint32_t(rule.NATRuleID)
	ptr.counter_id = C.uint32_t(rule.CounterID)
	return nil
}

func (m *Manager) ClearZonePairPolicies() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.rte_hash_reset(shm.zone_pair_policies)
	return nil
}

func (m *Manager) SetDefaultPolicy(action uint8) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	*shm.default_policy = C.uint8_t(action)
	return nil
}

func (m *Manager) UpdatePolicyScheduleState(cfg *config.Config, activeState map[string]bool) {
	shm := m.platform.shm
	if shm == nil || cfg == nil {
		return
	}

	slots, err := dataplane.BuildScheduledPolicyRuleSlots(cfg)
	if err != nil {
		slog.Warn("dpdk policy scheduler: failed to build scheduled rule slots", "err", err)
		return
	}
	for _, slot := range slots {
		active, exists := activeState[slot.SchedulerName]
		if !exists {
			active = true // default active if scheduler not found
		}

		idx := slot.AbsoluteRuleIdx
		ptr := (*C.struct_policy_rule)(unsafe.Pointer(
			uintptr(unsafe.Pointer(shm.policy_rules)) +
				uintptr(idx)*unsafe.Sizeof(C.struct_policy_rule{})))

		var newActive C.uint8_t
		if active {
			newActive = 1
		}
		if ptr.active != newActive {
			ptr.active = newActive
			slog.Info("DPDK policy schedule state updated",
				"policy", slot.PolicyName,
				"scheduler", slot.SchedulerName,
				"active", active)
		}
	}
}

// --- Address book ---

func (m *Manager) SetAddressBookEntry(cidr string, addressID uint32) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	ones, _ := ipNet.Mask.Size()

	if ip4 := ip.To4(); ip4 != nil {
		ipU32 := binary.BigEndian.Uint32(ip4)
		rc := C.rte_lpm_add(shm.address_book_v4, C.uint32_t(ipU32),
			C.uint8_t(ones), C.uint32_t(addressID))
		if rc < 0 {
			return fmt.Errorf("rte_lpm_add(%s): %d", cidr, rc)
		}
	} else {
		ip6 := ip.To16()
		var addr C.struct_rte_ipv6_addr
		for i := 0; i < 16; i++ {
			addr.a[i] = C.uint8_t(ip6[i])
		}
		rc := C.rte_lpm6_add(shm.address_book_v6, &addr,
			C.uint8_t(ones), C.uint32_t(addressID))
		if rc < 0 {
			return fmt.Errorf("rte_lpm6_add(%s): %d", cidr, rc)
		}
	}
	return nil
}

func (m *Manager) SetAddressMembership(resolvedID, setID uint32) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	key := C.struct_addr_membership_key{
		ip:         C.uint32_t(resolvedID),
		address_id: C.uint32_t(setID),
	}
	pos := C.rte_hash_add_key(shm.address_membership, unsafe.Pointer(&key))
	if pos < 0 {
		return fmt.Errorf("rte_hash_add_key(addr_membership): %d", pos)
	}
	return nil
}

func (m *Manager) ClearAddressBookV4() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.rte_lpm_delete_all(shm.address_book_v4)
	return nil
}

func (m *Manager) ClearAddressBookV6() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.rte_lpm6_delete_all(shm.address_book_v6)
	return nil
}

func (m *Manager) ClearAddressMembership() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.rte_hash_reset(shm.address_membership)
	return nil
}

// --- Application ---

func (m *Manager) SetApplication(protocol uint8, dstPort uint16, appID uint32, timeout uint32, algType uint8, srcPortLow, srcPortHigh uint16) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	key := C.struct_app_key{
		protocol: C.uint8_t(protocol),
		dst_port: C.uint16_t(dstPort),
	}
	pos := C.rte_hash_add_key(shm.applications, unsafe.Pointer(&key))
	if pos < 0 {
		return fmt.Errorf("rte_hash_add_key(app): %d", pos)
	}
	valPtr := (*C.struct_app_value)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.app_values)) +
			uintptr(pos)*unsafe.Sizeof(C.struct_app_value{})))
	valPtr.app_id = C.uint32_t(appID)
	valPtr.alg_type = C.uint8_t(algType)
	valPtr.timeout = C.uint32_t(timeout)
	valPtr.src_port_low = C.uint16_t(srcPortLow)
	valPtr.src_port_high = C.uint16_t(srcPortHigh)
	return nil
}

func (m *Manager) ClearApplications() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.rte_hash_reset(shm.applications)
	return nil
}

func (m *Manager) SetAppRange(index uint32, entry dataplane.AppRangeEntry) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	if index >= dataplane.MaxAppRanges {
		return fmt.Errorf("app range index %d out of range", index)
	}
	ptr := (*C.struct_app_range_entry)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.app_ranges)) +
			uintptr(index)*unsafe.Sizeof(C.struct_app_range_entry{})))
	ptr.protocol = C.uint8_t(entry.Protocol)
	ptr.alg_type = C.uint8_t(entry.ALGType)
	ptr.port_low = C.uint16_t(entry.PortLow)
	ptr.port_high = C.uint16_t(entry.PortHigh)
	ptr.src_port_low = C.uint16_t(entry.SrcPortLow)
	ptr.src_port_high = C.uint16_t(entry.SrcPortHigh)
	ptr.app_id = C.uint32_t(entry.AppID)
	ptr.timeout = C.uint32_t(entry.Timeout)
	return nil
}

func (m *Manager) ClearAppRanges() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.memset(unsafe.Pointer(shm.app_ranges), 0,
		C.size_t(dataplane.MaxAppRanges)*C.size_t(unsafe.Sizeof(C.struct_app_range_entry{})))
	return nil
}

// --- Sessions ---

func (m *Manager) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	var ckey unsafe.Pointer
	var cdata unsafe.Pointer
	var iter C.uint32_t
	for {
		pos := C.rte_hash_iterate(shm.sessions_v4, &ckey, &cdata, &iter)
		if pos < 0 {
			break
		}
		ck := (*C.struct_session_key)(ckey)
		sv := (*C.struct_session_value)(unsafe.Pointer(
			uintptr(unsafe.Pointer(shm.session_values_v4)) +
				uintptr(pos)*unsafe.Sizeof(C.struct_session_value{})))

		var goKey dataplane.SessionKey
		goKey.SrcIP = uint32ToBytes(uint32(ck.src_ip))
		goKey.DstIP = uint32ToBytes(uint32(ck.dst_ip))
		goKey.SrcPort = uint16(ck.src_port)
		goKey.DstPort = uint16(ck.dst_port)
		goKey.Protocol = uint8(ck.protocol)

		goVal := convertSessionValue(sv)
		if !fn(goKey, goVal) {
			break
		}
	}
	return nil
}

func (m *Manager) DeleteSession(key dataplane.SessionKey) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	ck := C.struct_session_key{
		src_ip:   C.uint32_t(bytesToUint32(key.SrcIP)),
		dst_ip:   C.uint32_t(bytesToUint32(key.DstIP)),
		src_port: C.uint16_t(key.SrcPort),
		dst_port: C.uint16_t(key.DstPort),
		protocol: C.uint8_t(key.Protocol),
	}
	C.rte_hash_del_key(shm.sessions_v4, unsafe.Pointer(&ck))
	return nil
}

func (m *Manager) SetSessionV4(_ dataplane.SessionKey, _ dataplane.SessionValue) error {
	// TODO: DPDK session write via rte_hash_add_key_data
	return nil
}

func (m *Manager) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	var ckey unsafe.Pointer
	var cdata unsafe.Pointer
	var iter C.uint32_t
	for {
		pos := C.rte_hash_iterate(shm.sessions_v6, &ckey, &cdata, &iter)
		if pos < 0 {
			break
		}
		ck := (*C.struct_session_key_v6)(ckey)
		sv := (*C.struct_session_value_v6)(unsafe.Pointer(
			uintptr(unsafe.Pointer(shm.session_values_v6)) +
				uintptr(pos)*unsafe.Sizeof(C.struct_session_value_v6{})))

		var goKey dataplane.SessionKeyV6
		copyBytes(goKey.SrcIP[:], ck.src_ip[:])
		copyBytes(goKey.DstIP[:], ck.dst_ip[:])
		goKey.SrcPort = uint16(ck.src_port)
		goKey.DstPort = uint16(ck.dst_port)
		goKey.Protocol = uint8(ck.protocol)

		goVal := convertSessionValueV6(sv)
		if !fn(goKey, goVal) {
			break
		}
	}
	return nil
}

func (m *Manager) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	var ck C.struct_session_key_v6
	copyCBytes(ck.src_ip[:], key.SrcIP[:])
	copyCBytes(ck.dst_ip[:], key.DstIP[:])
	ck.src_port = C.uint16_t(key.SrcPort)
	ck.dst_port = C.uint16_t(key.DstPort)
	ck.protocol = C.uint8_t(key.Protocol)
	C.rte_hash_del_key(shm.sessions_v6, unsafe.Pointer(&ck))
	return nil
}

func (m *Manager) SetSessionV6(_ dataplane.SessionKeyV6, _ dataplane.SessionValueV6) error {
	// TODO: DPDK session write via rte_hash_add_key_data
	return nil
}

func (m *Manager) GetSessionV4(_ dataplane.SessionKey) (dataplane.SessionValue, error) {
	return dataplane.SessionValue{}, nil
}
func (m *Manager) GetSessionV6(_ dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	return dataplane.SessionValueV6{}, nil
}

func (m *Manager) SessionCount() (int, int) {
	shm := m.platform.shm
	if shm == nil {
		return 0, 0
	}
	v4 := int(C.rte_hash_count(shm.sessions_v4))
	v6 := int(C.rte_hash_count(shm.sessions_v6))
	return v4, v6
}

func (m *Manager) ClearAllSessions() (int, int, error) {
	shm := m.platform.shm
	if shm == nil {
		return 0, 0, fmt.Errorf("DPDK not initialized")
	}

	// Collect SNAT return-path DNAT keys before clearing sessions.
	// Dynamic SNAT sessions create return-path DNAT entries that must
	// be cleaned up to avoid dnat_table filling with stale entries.
	var snatDNATKeys []dataplane.DNATKey
	m.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse == 0 &&
			val.Flags&dataplane.SessFlagSNAT != 0 &&
			val.Flags&dataplane.SessFlagStaticNAT == 0 {
			snatDNATKeys = append(snatDNATKeys, dataplane.DNATKey{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
				FromZone: 0,
			})
		}
		return true
	})

	var snatDNATKeysV6 []dataplane.DNATKeyV6
	m.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse == 0 &&
			val.Flags&dataplane.SessFlagSNAT != 0 &&
			val.Flags&dataplane.SessFlagStaticNAT == 0 {
			snatDNATKeysV6 = append(snatDNATKeysV6, dataplane.DNATKeyV6{
				Protocol: key.Protocol,
				DstIP:    val.NATSrcIP,
				DstPort:  val.NATSrcPort,
				FromZone: 0,
			})
		}
		return true
	})

	v4 := int(C.rte_hash_count(shm.sessions_v4))
	v6 := int(C.rte_hash_count(shm.sessions_v6))
	C.rte_hash_reset(shm.sessions_v4)
	C.rte_hash_reset(shm.sessions_v6)

	// Clean up return-path DNAT entries.
	for _, dk := range snatDNATKeys {
		m.DeleteDNATEntry(dk)
	}
	for _, dk := range snatDNATKeysV6 {
		m.DeleteDNATEntryV6(dk)
	}

	return v4, v6, nil
}

// --- DNAT ---

func (m *Manager) SetDNATEntry(key dataplane.DNATKey, val dataplane.DNATValue) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	ck := C.struct_dnat_key{
		protocol:  C.uint8_t(key.Protocol),
		dst_ip:    C.uint32_t(key.DstIP),
		dst_port:  C.uint16_t(key.DstPort),
		from_zone: C.uint16_t(key.FromZone),
	}
	pos := C.rte_hash_add_key(shm.dnat_table, unsafe.Pointer(&ck))
	if pos < 0 {
		return fmt.Errorf("rte_hash_add_key(dnat): %d", pos)
	}
	valPtr := (*C.struct_dnat_value)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.dnat_values)) +
			uintptr(pos)*unsafe.Sizeof(C.struct_dnat_value{})))
	valPtr.new_dst_ip = C.uint32_t(val.NewDstIP)
	valPtr.new_dst_port = C.uint16_t(val.NewDstPort)
	valPtr.flags = C.uint8_t(val.Flags)
	return nil
}

func (m *Manager) DeleteDNATEntry(key dataplane.DNATKey) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	ck := C.struct_dnat_key{
		protocol:  C.uint8_t(key.Protocol),
		dst_ip:    C.uint32_t(key.DstIP),
		dst_port:  C.uint16_t(key.DstPort),
		from_zone: C.uint16_t(key.FromZone),
	}
	C.rte_hash_del_key(shm.dnat_table, unsafe.Pointer(&ck))
	return nil
}

func (m *Manager) ClearDNATStatic() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.rte_hash_reset(shm.dnat_table)
	return nil
}

func (m *Manager) SetDNATEntryV6(key dataplane.DNATKeyV6, val dataplane.DNATValueV6) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	var ck C.struct_dnat_key_v6
	ck.protocol = C.uint8_t(key.Protocol)
	copyCBytes(ck.dst_ip[:], key.DstIP[:])
	ck.dst_port = C.uint16_t(key.DstPort)
	ck.from_zone = C.uint16_t(key.FromZone)
	pos := C.rte_hash_add_key(shm.dnat_table_v6, unsafe.Pointer(&ck))
	if pos < 0 {
		return fmt.Errorf("rte_hash_add_key(dnat_v6): %d", pos)
	}
	valPtr := (*C.struct_dnat_value_v6)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.dnat_values_v6)) +
			uintptr(pos)*unsafe.Sizeof(C.struct_dnat_value_v6{})))
	copyCBytes(valPtr.new_dst_ip[:], val.NewDstIP[:])
	valPtr.new_dst_port = C.uint16_t(val.NewDstPort)
	valPtr.flags = C.uint8_t(val.Flags)
	return nil
}

func (m *Manager) DeleteDNATEntryV6(key dataplane.DNATKeyV6) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	var ck C.struct_dnat_key_v6
	ck.protocol = C.uint8_t(key.Protocol)
	copyCBytes(ck.dst_ip[:], key.DstIP[:])
	ck.dst_port = C.uint16_t(key.DstPort)
	ck.from_zone = C.uint16_t(key.FromZone)
	C.rte_hash_del_key(shm.dnat_table_v6, unsafe.Pointer(&ck))
	return nil
}

func (m *Manager) ClearDNATStaticV6() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.rte_hash_reset(shm.dnat_table_v6)
	return nil
}

// --- SNAT ---

func (m *Manager) SetSNATRule(fromZone, toZone, ruleIdx uint16, val dataplane.SNATValue) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	key := C.struct_snat_key{
		from_zone: C.uint16_t(fromZone),
		to_zone:   C.uint16_t(toZone),
		rule_idx:  C.uint16_t(ruleIdx),
	}
	pos := C.rte_hash_add_key(shm.snat_rules, unsafe.Pointer(&key))
	if pos < 0 {
		return fmt.Errorf("rte_hash_add_key(snat): %d", pos)
	}
	valPtr := (*C.struct_snat_value)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.snat_values_v4)) +
			uintptr(pos)*unsafe.Sizeof(C.struct_snat_value{})))
	valPtr.snat_ip = C.uint32_t(val.SNATIP)
	valPtr.src_addr_id = C.uint32_t(val.SrcAddrID)
	valPtr.dst_addr_id = C.uint32_t(val.DstAddrID)
	valPtr.mode = C.uint8_t(val.Mode)
	valPtr.counter_id = C.uint16_t(val.CounterID)
	return nil
}

func (m *Manager) ClearSNATRules() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.rte_hash_reset(shm.snat_rules)
	return nil
}

func (m *Manager) SetSNATRuleV6(fromZone, toZone, ruleIdx uint16, val dataplane.SNATValueV6) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	key := C.struct_snat_key{
		from_zone: C.uint16_t(fromZone),
		to_zone:   C.uint16_t(toZone),
		rule_idx:  C.uint16_t(ruleIdx),
	}
	pos := C.rte_hash_add_key(shm.snat_rules_v6, unsafe.Pointer(&key))
	if pos < 0 {
		return fmt.Errorf("rte_hash_add_key(snat_v6): %d", pos)
	}
	valPtr := (*C.struct_snat_value_v6)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.snat_values_v6)) +
			uintptr(pos)*unsafe.Sizeof(C.struct_snat_value_v6{})))
	copyCBytes(valPtr.snat_ip[:], val.SNATIP[:])
	valPtr.src_addr_id = C.uint32_t(val.SrcAddrID)
	valPtr.dst_addr_id = C.uint32_t(val.DstAddrID)
	valPtr.mode = C.uint8_t(val.Mode)
	valPtr.counter_id = C.uint16_t(val.CounterID)
	return nil
}

func (m *Manager) ClearSNATRulesV6() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.rte_hash_reset(shm.snat_rules_v6)
	return nil
}

// --- NAT pools ---

func (m *Manager) SetNATPoolConfig(poolID uint32, cfg dataplane.NATPoolConfig) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	ptr := (*C.struct_nat_pool_config)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.nat_pool_configs)) +
			uintptr(poolID)*unsafe.Sizeof(C.struct_nat_pool_config{})))
	ptr.num_ips = C.uint16_t(cfg.NumIPs)
	ptr.num_ips_v6 = C.uint16_t(cfg.NumIPsV6)
	ptr.port_low = C.uint16_t(cfg.PortLow)
	ptr.port_high = C.uint16_t(cfg.PortHigh)
	ptr.addr_persistent = C.uint8_t(cfg.AddrPersistent)
	ptr.deterministic = C.uint8_t(cfg.Deterministic)
	ptr.block_size = C.uint16_t(cfg.BlockSize)
	ptr.host_base = C.uint32_t(cfg.HostBase)
	ptr.host_count = C.uint32_t(cfg.HostCount)
	ptr.blocks_per_ip = C.uint16_t(cfg.BlocksPerIP)
	ptr.host_prefix_len = C.uint8_t(cfg.HostPrefixLen)
	for i := 0; i < 4; i++ {
		ptr.host_base_v6[i] = C.uint32_t(cfg.HostBaseV6[i])
	}
	return nil
}

func (m *Manager) SetNATPoolIPV4(poolID, index uint32, ip uint32) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	idx := poolID*C.MAX_NAT_POOL_IPS_PER_POOL + index
	ptr := (*C.uint32_t)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.nat_pool_ips_v4)) +
			uintptr(idx)*unsafe.Sizeof(C.uint32_t(0))))
	*ptr = C.uint32_t(ip)
	return nil
}

func (m *Manager) SetNATPoolIPV6(poolID, index uint32, ip [16]byte) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	idx := poolID*C.MAX_NAT_POOL_IPS_PER_POOL + index
	ptr := (*C.struct_nat_pool_ip_v6)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.nat_pool_ips_v6)) +
			uintptr(idx)*unsafe.Sizeof(C.struct_nat_pool_ip_v6{})))
	copyCBytes(ptr.ip[:], ip[:])
	return nil
}

func (m *Manager) ClearNATPoolConfigs() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.memset(unsafe.Pointer(shm.nat_pool_configs), 0,
		C.size_t(C.MAX_NAT_POOLS)*C.size_t(unsafe.Sizeof(C.struct_nat_pool_config{})))
	return nil
}

func (m *Manager) ClearNATPoolIPs() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.memset(unsafe.Pointer(shm.nat_pool_ips_v4), 0,
		C.size_t(C.MAX_NAT_POOL_IPS)*C.size_t(unsafe.Sizeof(C.uint32_t(0))))
	C.memset(unsafe.Pointer(shm.nat_pool_ips_v6), 0,
		C.size_t(C.MAX_NAT_POOL_IPS)*C.size_t(unsafe.Sizeof(C.struct_nat_pool_ip_v6{})))
	return nil
}

// --- SNAT egress IPs (interface-mode SNAT) ---
// DPDK does not use BPF maps; interface-mode SNAT is eBPF-only for now.

func (m *Manager) SetSNATEgressIP(key dataplane.SNATEgressKey, val dataplane.SNATEgressValue) error {
	return nil
}

func (m *Manager) ClearSNATEgressIPs() error { return nil }

// --- Static NAT ---

func (m *Manager) SetStaticNATEntryV4(ip uint32, direction uint8, translated uint32) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	key := C.struct_static_nat_key_v4{
		ip:        C.uint32_t(ip),
		direction: C.uint8_t(direction),
	}
	pos := C.rte_hash_add_key(shm.static_nat_v4, unsafe.Pointer(&key))
	if pos < 0 {
		return fmt.Errorf("rte_hash_add_key(static_nat_v4): %d", pos)
	}
	// Static NAT v4 value is just a uint32 (translated IP).
	// Store directly at value array position.
	// The value array is session_values but for static NAT it stores uint32.
	// Actually, looking at shared_mem.h, static_nat_v4 hash value is implicitly
	// the position — we need to store the translated IP somewhere.
	// Since rte_hash doesn't store data, we use a separate value array approach.
	// For now, we use rte_hash_add_key_data to associate data.
	// But shared_mem.h doesn't have a dedicated value array for static_nat_v4.
	// The BPF version uses the hash value itself. For DPDK, let's use add_key_data.
	C.rte_hash_del_key(shm.static_nat_v4, unsafe.Pointer(&key))
	cTranslated := C.uint32_t(translated)
	pos = C.rte_hash_add_key_data(shm.static_nat_v4, unsafe.Pointer(&key),
		unsafe.Pointer(uintptr(cTranslated)))
	if pos < 0 {
		return fmt.Errorf("rte_hash_add_key_data(static_nat_v4): %d", pos)
	}
	return nil
}

func (m *Manager) SetStaticNATEntryV6(ip [16]byte, direction uint8, translated [16]byte) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	var key C.struct_static_nat_key_v6
	copyCBytes(key.ip[:], ip[:])
	key.direction = C.uint8_t(direction)
	var val C.struct_static_nat_value_v6
	copyCBytes(val.ip[:], translated[:])
	C.rte_hash_del_key(shm.static_nat_v6, unsafe.Pointer(&key))
	pos := C.rte_hash_add_key_data(shm.static_nat_v6, unsafe.Pointer(&key),
		unsafe.Pointer(&val))
	if pos < 0 {
		return fmt.Errorf("rte_hash_add_key_data(static_nat_v6): %d", pos)
	}
	return nil
}

func (m *Manager) ClearStaticNATEntries() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.rte_hash_reset(shm.static_nat_v4)
	C.rte_hash_reset(shm.static_nat_v6)
	return nil
}

// --- NAT64 ---

func (m *Manager) SetNAT64Config(index uint32, cfg dataplane.NAT64Config) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	ptr := (*C.struct_nat64_config)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.nat64_configs)) +
			uintptr(index)*unsafe.Sizeof(C.struct_nat64_config{})))
	ptr.prefix[0] = C.uint32_t(cfg.Prefix[0])
	ptr.prefix[1] = C.uint32_t(cfg.Prefix[1])
	ptr.prefix[2] = C.uint32_t(cfg.Prefix[2])
	ptr.snat_pool_id = C.uint8_t(cfg.SNATPoolID)

	// Also add to prefix hash map for lookups.
	var pk C.struct_nat64_prefix_key
	pk.prefix[0] = C.uint32_t(cfg.Prefix[0])
	pk.prefix[1] = C.uint32_t(cfg.Prefix[1])
	pk.prefix[2] = C.uint32_t(cfg.Prefix[2])
	C.rte_hash_add_key(shm.nat64_prefix_map, unsafe.Pointer(&pk))
	return nil
}

func (m *Manager) SetNAT64Count(count uint32) error {
	// NAT64 count is implicit from the config array; no separate storage needed.
	return nil
}

func (m *Manager) ClearNAT64Configs() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.memset(unsafe.Pointer(shm.nat64_configs), 0,
		C.size_t(C.MAX_NAT64_PREFIXES)*C.size_t(unsafe.Sizeof(C.struct_nat64_config{})))
	C.rte_hash_reset(shm.nat64_prefix_map)
	return nil
}

// --- Screen ---

func (m *Manager) SetScreenConfig(profileID uint32, cfg dataplane.ScreenConfig) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	ptr := (*C.struct_screen_config)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.screen_configs)) +
			uintptr(profileID)*unsafe.Sizeof(C.struct_screen_config{})))
	ptr.flags = C.uint32_t(cfg.Flags)
	ptr.syn_flood_thresh = C.uint32_t(cfg.SynFloodThresh)
	ptr.icmp_flood_thresh = C.uint32_t(cfg.ICMPFloodThresh)
	ptr.udp_flood_thresh = C.uint32_t(cfg.UDPFloodThresh)
	ptr.syn_flood_src_thresh = C.uint32_t(cfg.SynFloodSrcThresh)
	ptr.syn_flood_dst_thresh = C.uint32_t(cfg.SynFloodDstThresh)
	ptr.syn_flood_timeout = C.uint32_t(cfg.SynFloodTimeout)
	ptr.port_scan_thresh = C.uint32_t(cfg.PortScanThresh)
	ptr.ip_sweep_thresh = C.uint32_t(cfg.IPSweepThresh)
	ptr.session_limit_src = C.uint32_t(cfg.SessionLimitSrc)
	ptr.session_limit_dst = C.uint32_t(cfg.SessionLimitDst)
	return nil
}

func (m *Manager) ClearScreenConfigs() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.memset(unsafe.Pointer(shm.screen_configs), 0,
		C.size_t(C.MAX_SCREEN_PROFILES)*C.size_t(unsafe.Sizeof(C.struct_screen_config{})))
	return nil
}

// --- Session count maps ---

func (m *Manager) UpdateSessionCountSrc(key dataplane.SessionCountKey, count uint32) error {
	shm := m.platform.shm
	if shm == nil || shm.session_count_src == nil {
		return nil
	}
	cKey := C.struct_session_count_key{
		ip:      C.uint32_t(key.IP),
		zone_id: C.uint16_t(key.ZoneID),
	}
	pos := C.rte_hash_lookup(shm.session_count_src, unsafe.Pointer(&cKey))
	if pos < 0 {
		pos = C.rte_hash_add_key(shm.session_count_src, unsafe.Pointer(&cKey))
		if pos < 0 {
			return nil // hash full, best-effort
		}
	}
	shm.session_count_src_values[pos].count = C.uint32_t(count)
	return nil
}

func (m *Manager) UpdateSessionCountDst(key dataplane.SessionCountKey, count uint32) error {
	shm := m.platform.shm
	if shm == nil || shm.session_count_dst == nil {
		return nil
	}
	cKey := C.struct_session_count_key{
		ip:      C.uint32_t(key.IP),
		zone_id: C.uint16_t(key.ZoneID),
	}
	pos := C.rte_hash_lookup(shm.session_count_dst, unsafe.Pointer(&cKey))
	if pos < 0 {
		pos = C.rte_hash_add_key(shm.session_count_dst, unsafe.Pointer(&cKey))
		if pos < 0 {
			return nil // hash full, best-effort
		}
	}
	shm.session_count_dst_values[pos].count = C.uint32_t(count)
	return nil
}

func (m *Manager) ClearSessionCounts() error {
	shm := m.platform.shm
	if shm == nil {
		return nil
	}
	if shm.session_count_src != nil {
		C.rte_hash_reset(shm.session_count_src)
	}
	if shm.session_count_dst != nil {
		C.rte_hash_reset(shm.session_count_dst)
	}
	return nil
}

// --- Port mirroring ---

func (m *Manager) SetMirrorConfig(ifindex int, mirrorIfindex int, rate uint32) error { return nil }
func (m *Manager) ClearMirrorConfigs() error                                         { return nil }

// --- Flow ---

func (m *Manager) SetFlowTimeout(idx, seconds uint32) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	ptr := (*C.uint32_t)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.flow_timeouts)) +
			uintptr(idx)*unsafe.Sizeof(C.uint32_t(0))))
	*ptr = C.uint32_t(seconds)
	return nil
}

func (m *Manager) SetFlowConfig(cfg dataplane.FlowConfigValue) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	shm.flow_config.tcp_mss_ipsec = C.uint16_t(cfg.TCPMSSIPsec)
	shm.flow_config.tcp_mss_gre_in = C.uint16_t(cfg.TCPMSSGreIn)
	shm.flow_config.tcp_mss_gre_out = C.uint16_t(cfg.TCPMSSGreOut)
	shm.flow_config.allow_dns_reply = C.uint8_t(cfg.AllowDNSReply)
	shm.flow_config.allow_embedded_icmp = C.uint8_t(cfg.AllowEmbeddedICMP)
	shm.flow_config.gre_accel = C.uint8_t(cfg.GREAccel)
	shm.flow_config.alg_flags = C.uint8_t(cfg.ALGFlags)
	shm.flow_config.lo0_filter_v4 = C.uint16_t(cfg.Lo0FilterV4)
	shm.flow_config.lo0_filter_v6 = C.uint16_t(cfg.Lo0FilterV6)
	shm.flow_config.tcp_flags = C.uint8_t(cfg.TCPFlags)
	shm.flow_config.app_flags = C.uint8_t(cfg.AppFlags)
	return nil
}

// --- Fabric cross-chassis forwarding ---

func (m *Manager) UpdateFabricFwd(info dataplane.FabricFwdInfo) error {
	shm := m.platform.shm
	if shm == nil {
		return nil
	}
	// NOTE (#126): DPDK fabric redirect is only partially supported.
	// The fabric port ID is programmed for inbound zone-encoded MAC
	// detection (zone.c), but there is no DPDK equivalent of the BPF
	// try_fabric_redirect() / try_fabric_redirect_with_zone() helpers.
	// Cross-chassis redirect for synced sessions and new connections
	// is not implemented in the DPDK pipeline.
	slog.Warn("DPDK: fabric port_id programmed for fab0 but cross-chassis redirect is not implemented in DPDK mode",
		"ifindex", info.Ifindex)

	// Translate kernel ifindex to DPDK port_id using the mapping
	// populated by the DPDK worker at port init time.
	ifidx := info.Ifindex
	if ifidx == 0 || ifidx >= C.MAX_PORT_MAP {
		shm.fabric_port_id = 0xFFFF // sentinel: not mapped
		return nil
	}
	portID := shm.ifindex_to_port[ifidx]
	if portID == 0xFF {
		shm.fabric_port_id = 0xFFFF // sentinel: not mapped
		return nil
	}
	shm.fabric_port_id = C.uint16_t(portID)
	return nil
}

func (m *Manager) UpdateFabricFwd1(info dataplane.FabricFwdInfo) error {
	shm := m.platform.shm
	if shm == nil {
		return nil
	}
	// NOTE (#126): Same limitation as UpdateFabricFwd — see above.
	slog.Warn("DPDK: fabric port_id programmed for fab1 but cross-chassis redirect is not implemented in DPDK mode",
		"ifindex", info.Ifindex)

	ifidx := info.Ifindex
	if ifidx == 0 || ifidx >= C.MAX_PORT_MAP {
		shm.fabric1_port_id = 0xFFFF
		return nil
	}
	portID := shm.ifindex_to_port[ifidx]
	if portID == 0xFF {
		shm.fabric1_port_id = 0xFFFF
		return nil
	}
	shm.fabric1_port_id = C.uint16_t(portID)
	return nil
}

func (m *Manager) UpdateHAWatchdog(rgID int, timestamp uint64) error { return nil }

func (m *Manager) UpdateRGActive(rgID int, active bool) error {
	shm := m.platform.shm
	if shm == nil || shm.rg_active == nil {
		return nil
	}
	if rgID < 0 || rgID >= 16 {
		return nil
	}
	var val C.uint8_t
	if active {
		val = 1
	}
	ptr := (*C.uint8_t)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.rg_active)) + uintptr(rgID)))
	*ptr = val
	return nil
}

// --- Firewall filters ---

func (m *Manager) SetIfaceFilter(key dataplane.IfaceFilterKey, filterID uint32) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	ck := C.struct_iface_filter_key{
		ifindex:   C.uint32_t(key.Ifindex),
		vlan_id:   C.uint16_t(key.VlanID),
		family:    C.uint8_t(key.Family),
		direction: C.uint8_t(key.Direction),
	}
	C.rte_hash_del_key(shm.iface_filter_map, unsafe.Pointer(&ck))
	cFilterID := C.uint32_t(filterID)
	pos := C.rte_hash_add_key_data(shm.iface_filter_map, unsafe.Pointer(&ck),
		unsafe.Pointer(uintptr(cFilterID)))
	if pos < 0 {
		return fmt.Errorf("rte_hash_add_key_data(iface_filter): %d", pos)
	}
	return nil
}

func (m *Manager) ClearIfaceFilterMap() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.rte_hash_reset(shm.iface_filter_map)
	return nil
}

func (m *Manager) SetFilterConfig(filterID uint32, cfg dataplane.FilterConfig) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	ptr := (*C.struct_filter_config)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.filter_configs)) +
			uintptr(filterID)*unsafe.Sizeof(C.struct_filter_config{})))
	ptr.num_rules = C.uint32_t(cfg.NumRules)
	ptr.rule_start = C.uint32_t(cfg.RuleStart)
	return nil
}

func (m *Manager) ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error) {
	shm := m.platform.shm
	if shm == nil {
		return dataplane.FilterConfig{}, fmt.Errorf("DPDK not initialized")
	}
	ptr := (*C.struct_filter_config)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.filter_configs)) +
			uintptr(filterID)*unsafe.Sizeof(C.struct_filter_config{})))
	return dataplane.FilterConfig{
		NumRules:  uint32(ptr.num_rules),
		RuleStart: uint32(ptr.rule_start),
	}, nil
}

func (m *Manager) SetFilterRule(index uint32, rule dataplane.FilterRule) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	ptr := (*C.struct_filter_rule)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.filter_rules)) +
			uintptr(index)*unsafe.Sizeof(C.struct_filter_rule{})))
	ptr.match_flags = C.uint16_t(rule.MatchFlags)
	ptr.dscp = C.uint8_t(rule.DSCP)
	ptr.protocol = C.uint8_t(rule.Protocol)
	ptr.action = C.uint8_t(rule.Action)
	ptr.icmp_type = C.uint8_t(rule.ICMPType)
	ptr.icmp_code = C.uint8_t(rule.ICMPCode)
	ptr.family = C.uint8_t(rule.Family)
	ptr.dst_port = C.uint16_t(rule.DstPort)
	ptr.src_port = C.uint16_t(rule.SrcPort)
	ptr.dst_port_hi = C.uint16_t(rule.DstPortHi)
	ptr.src_port_hi = C.uint16_t(rule.SrcPortHi)
	ptr.dscp_rewrite = C.uint8_t(rule.DSCPRewrite)
	ptr.log_flag = C.uint8_t(rule.LogFlag)
	ptr.tcp_flags = C.uint8_t(rule.TCPFlags)
	ptr.is_fragment = C.uint8_t(rule.IsFragment)
	copyCBytes(ptr.src_addr[:], rule.SrcAddr[:])
	copyCBytes(ptr.src_mask[:], rule.SrcMask[:])
	copyCBytes(ptr.dst_addr[:], rule.DstAddr[:])
	copyCBytes(ptr.dst_mask[:], rule.DstMask[:])
	ptr.routing_table = C.uint32_t(rule.RoutingTable)
	ptr.policer_id = C.uint8_t(rule.PolicerID)
	ptr.flex_offset = C.uint8_t(rule.FlexOffset)
	ptr.flex_length = C.uint8_t(rule.FlexLength)
	ptr.flex_value = C.uint32_t(rule.FlexValue)
	ptr.flex_mask = C.uint32_t(rule.FlexMask)
	return nil
}

func (m *Manager) ClearFilterConfigs() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.memset(unsafe.Pointer(shm.filter_configs), 0,
		C.size_t(C.MAX_FILTER_CONFIGS)*C.size_t(unsafe.Sizeof(C.struct_filter_config{})))
	C.memset(unsafe.Pointer(shm.filter_rules), 0,
		C.size_t(C.MAX_FILTER_RULES)*C.size_t(unsafe.Sizeof(C.struct_filter_rule{})))
	return nil
}

// --- Policers ---

func (m *Manager) SetPolicerConfig(id uint32, cfg dataplane.PolicerConfig) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	ptr := (*C.struct_policer_config)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.policer_configs)) +
			uintptr(id)*unsafe.Sizeof(C.struct_policer_config{})))
	ptr.rate_bytes_sec = C.uint64_t(cfg.RateBytesSec)
	ptr.burst_bytes = C.uint64_t(cfg.BurstBytes)
	ptr.action = C.uint8_t(cfg.Action)
	ptr.color_mode = C.uint8_t(cfg.ColorMode)
	ptr.peak_rate = C.uint64_t(cfg.PeakRate)
	ptr.peak_burst = C.uint64_t(cfg.PeakBurst)
	return nil
}

func (m *Manager) ClearPolicerConfigs() error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.memset(unsafe.Pointer(shm.policer_configs), 0,
		C.size_t(C.MAX_POLICERS)*C.size_t(unsafe.Sizeof(C.struct_policer_config{})))
	C.memset(unsafe.Pointer(shm.policer_states), 0,
		C.size_t(C.MAX_POLICERS)*C.size_t(unsafe.Sizeof(C.struct_policer_state{})))
	return nil
}

// --- Counters ---

func (m *Manager) ReadGlobalCounter(index uint32) (uint64, error) {
	if m.platform.shm == nil {
		return 0, fmt.Errorf("DPDK not initialized")
	}
	return uint64(C.counters_aggregate_global(C.uint32_t(index))), nil
}

func (m *Manager) ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error) {
	if m.platform.shm == nil {
		return dataplane.FloodState{}, fmt.Errorf("DPDK not initialized")
	}
	var syn, icmp, udp C.uint64_t
	C.counters_aggregate_flood(C.uint32_t(zoneID), &syn, &icmp, &udp)
	return dataplane.FloodState{
		SynCount:  uint64(syn),
		ICMPCount: uint64(icmp),
		UDPCount:  uint64(udp),
	}, nil
}

func (m *Manager) ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error) {
	shm := m.platform.shm
	if shm == nil {
		return dataplane.InterfaceCounterValue{}, fmt.Errorf("DPDK not initialized")
	}
	var rxPkts, rxBytes, txPkts, txBytes C.uint64_t
	C.counters_aggregate_iface(C.uint32_t(ifindex), &rxPkts, &rxBytes, &txPkts, &txBytes)
	return dataplane.InterfaceCounterValue{
		RxPackets: uint64(rxPkts),
		RxBytes:   uint64(rxBytes),
		TxPackets: uint64(txPkts),
		TxBytes:   uint64(txBytes),
	}, nil
}

func (m *Manager) ReadZoneCounters(zoneID uint16, direction int) (dataplane.CounterValue, error) {
	shm := m.platform.shm
	if shm == nil {
		return dataplane.CounterValue{}, fmt.Errorf("DPDK not initialized")
	}
	var packets, bytes C.uint64_t
	C.counters_aggregate_zone(C.uint32_t(zoneID), C.uint8_t(direction), &packets, &bytes)
	return dataplane.CounterValue{
		Packets: uint64(packets),
		Bytes:   uint64(bytes),
	}, nil
}

func (m *Manager) ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error) {
	shm := m.platform.shm
	if shm == nil {
		return dataplane.CounterValue{}, fmt.Errorf("DPDK not initialized")
	}
	var packets, bytes C.uint64_t
	C.counters_aggregate_policy(C.uint32_t(policyID), &packets, &bytes)
	return dataplane.CounterValue{
		Packets: uint64(packets),
		Bytes:   uint64(bytes),
	}, nil
}

func (m *Manager) ReadFilterCounters(ruleIdx uint32) (dataplane.CounterValue, error) {
	shm := m.platform.shm
	if shm == nil {
		return dataplane.CounterValue{}, fmt.Errorf("DPDK not initialized")
	}
	var packets, bytes C.uint64_t
	C.counters_aggregate_filter(C.uint32_t(ruleIdx), &packets, &bytes)
	return dataplane.CounterValue{
		Packets: uint64(packets),
		Bytes:   uint64(bytes),
	}, nil
}

func (m *Manager) ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error) {
	shm := m.platform.shm
	if shm == nil {
		return dataplane.CounterValue{}, fmt.Errorf("DPDK not initialized")
	}
	var packets, bytes C.uint64_t
	C.counters_aggregate_nat_rule(C.uint32_t(counterID), &packets, &bytes)
	return dataplane.CounterValue{
		Packets: uint64(packets),
		Bytes:   uint64(bytes),
	}, nil
}

func (m *Manager) ReadNATPortCounter(poolID uint32) (uint64, error) {
	if m.platform.shm == nil {
		return 0, fmt.Errorf("DPDK not initialized")
	}
	var allocs C.uint64_t
	C.counters_aggregate_nat_port(C.uint32_t(poolID), &allocs)
	return uint64(allocs), nil
}

func (m *Manager) SeedNATPortCounters() {
	// DPDK port counter seeded via shared memory init
}

func (m *Manager) SeedSessionIDCounter(nodeID int) {
	if m.platform.shm == nil || m.platform.shm.session_id_gen == nil {
		return
	}
	base := C.uint64_t(uint64(nodeID) << 32)
	*m.platform.shm.session_id_gen = base
}

func (m *Manager) IncrementGlobalCounter(_ uint32, _ uint64) error {
	// DPDK dataplane manages its own counters; no-op for BPF map increment.
	return nil
}

func (m *Manager) ClearGlobalCounters() error {
	if m.platform.shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.counters_clear_global()
	return nil
}

func (m *Manager) ClearInterfaceCounters() error {
	if m.platform.shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.counters_clear_interface()
	return nil
}

func (m *Manager) ClearZoneCounters() error {
	if m.platform.shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.counters_clear_zone()
	return nil
}

func (m *Manager) ClearPolicyCounters() error {
	if m.platform.shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.counters_clear_policy()
	return nil
}

func (m *Manager) ClearFilterCounters() error {
	if m.platform.shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.counters_clear_filter()
	return nil
}

func (m *Manager) ClearAllCounters() error {
	if m.platform.shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.counters_clear_all()
	return nil
}

func (m *Manager) ClearNATRuleCounters() error {
	if m.platform.shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	C.counters_clear_nat_rule()
	return nil
}

// --- Events ---

// dpdkEventSource reads events from an rte_ring shared with the primary process.
type dpdkEventSource struct {
	ring   *C.struct_rte_ring
	closed uint32 // atomic flag
}

func (m *Manager) NewEventSource() (dataplane.EventSource, error) {
	shm := m.platform.shm
	if shm == nil {
		return nil, fmt.Errorf("DPDK shared memory not loaded")
	}
	if shm.event_ring == nil {
		return nil, fmt.Errorf("DPDK event_ring not allocated")
	}
	return &dpdkEventSource{ring: shm.event_ring}, nil
}

func (s *dpdkEventSource) ReadEvent() ([]byte, error) {
	for {
		if atomic.LoadUint32(&s.closed) != 0 {
			return nil, fmt.Errorf("event source closed")
		}

		var obj unsafe.Pointer
		n := C.rte_ring_dequeue(s.ring, &obj)
		if n != 0 {
			// Ring empty — brief sleep to avoid busy-wait
			C.rte_delay_us_sleep(C.uint(1000)) // 1ms
			continue
		}

		// obj points to a struct event allocated by the DPDK worker
		evt := (*C.struct_event)(obj)

		// Serialize to bytes matching the eBPF event layout
		data := make([]byte, unsafe.Sizeof(dataplane.Event{}))
		binary.LittleEndian.PutUint64(data[0:8], uint64(evt.timestamp))
		copy(data[8:24], C.GoBytes(unsafe.Pointer(&evt.src_ip[0]), 16))
		copy(data[24:40], C.GoBytes(unsafe.Pointer(&evt.dst_ip[0]), 16))
		binary.BigEndian.PutUint16(data[40:42], uint16(evt.src_port))
		binary.BigEndian.PutUint16(data[42:44], uint16(evt.dst_port))
		binary.LittleEndian.PutUint32(data[44:48], uint32(evt.policy_id))
		binary.LittleEndian.PutUint16(data[48:50], uint16(evt.ingress_zone))
		binary.LittleEndian.PutUint16(data[50:52], uint16(evt.egress_zone))
		data[52] = uint8(evt.event_type)
		data[53] = uint8(evt.protocol)
		data[54] = uint8(evt.action)
		data[55] = uint8(evt.addr_family)
		binary.LittleEndian.PutUint64(data[56:64], uint64(evt.session_packets))
		binary.LittleEndian.PutUint64(data[64:72], uint64(evt.session_bytes))
		copy(data[72:88], C.GoBytes(unsafe.Pointer(&evt.nat_src_ip[0]), 16))
		copy(data[88:104], C.GoBytes(unsafe.Pointer(&evt.nat_dst_ip[0]), 16))
		binary.BigEndian.PutUint16(data[104:106], uint16(evt.nat_src_port))
		binary.BigEndian.PutUint16(data[106:108], uint16(evt.nat_dst_port))
		binary.LittleEndian.PutUint32(data[108:112], uint32(evt.created))
		binary.LittleEndian.PutUint64(data[112:120], uint64(evt.rev_packets))
		binary.LittleEndian.PutUint64(data[120:128], uint64(evt.rev_bytes))
		binary.LittleEndian.PutUint32(data[128:132], uint32(evt.ingress_ifindex))
		binary.LittleEndian.PutUint16(data[132:134], uint16(evt.app_id))
		data[134] = uint8(evt.close_reason)
		data[135] = uint8(evt.pad_event)

		// Free the event allocated by the worker
		C.rte_free(unsafe.Pointer(evt))

		return data, nil
	}
}

func (s *dpdkEventSource) Close() error {
	atomic.StoreUint32(&s.closed, 1)
	return nil
}

// --- FIB ---

// SetFIBRoute adds a route to the DPDK FIB table.
// nexthopID must index into the nexthops array (set via SetFIBNexthop).
func (m *Manager) SetFIBRoute(family uint8, dst net.IP, prefixLen int, nexthopID uint32) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	if family == 2 { // AF_INET
		if shm.fib_v4 == nil {
			return fmt.Errorf("fib_v4 not allocated")
		}
		ip := binary.BigEndian.Uint32(dst.To4())
		rc := C.rte_lpm_add(shm.fib_v4, C.uint32_t(ip), C.uint8_t(prefixLen),
			C.uint32_t(nexthopID))
		if rc < 0 {
			return fmt.Errorf("rte_lpm_add: %d", rc)
		}
	} else { // AF_INET6
		if shm.fib_v6 == nil {
			return fmt.Errorf("fib_v6 not allocated")
		}
		var ip6 C.struct_rte_ipv6_addr
		ip6bytes := dst.To16()
		for i := 0; i < 16; i++ {
			ip6.a[i] = C.uint8_t(ip6bytes[i])
		}
		rc := C.rte_lpm6_add(shm.fib_v6, &ip6, C.uint8_t(prefixLen),
			C.uint32_t(nexthopID))
		if rc < 0 {
			return fmt.Errorf("rte_lpm6_add: %d", rc)
		}
	}
	return nil
}

// SetFIBNexthop configures a next-hop entry in the shared nexthops table.
func (m *Manager) SetFIBNexthop(id uint32, portID uint32, ifindex uint32,
	vlanID uint16, dmac, smac [6]byte) error {
	shm := m.platform.shm
	if shm == nil {
		return fmt.Errorf("DPDK not initialized")
	}
	if id >= C.MAX_NEXTHOPS {
		return fmt.Errorf("nexthop ID %d exceeds max %d", id, C.MAX_NEXTHOPS)
	}
	if shm.nexthops == nil {
		return fmt.Errorf("nexthops array not allocated")
	}
	nh := (*C.struct_fib_nexthop)(unsafe.Pointer(
		uintptr(unsafe.Pointer(shm.nexthops)) +
			uintptr(id)*unsafe.Sizeof(C.struct_fib_nexthop{})))
	nh.port_id = C.uint32_t(portID)
	nh.ifindex = C.uint32_t(ifindex)
	nh.vlan_id = C.uint16_t(vlanID)
	copy((*[6]byte)(unsafe.Pointer(&nh.dmac[0]))[:], dmac[:])
	copy((*[6]byte)(unsafe.Pointer(&nh.smac[0]))[:], smac[:])
	return nil
}

// ClearFIBRoutes removes all routes from the DPDK FIB tables.
func (m *Manager) ClearFIBRoutes() {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	if shm.fib_v4 != nil {
		C.rte_lpm_delete_all(shm.fib_v4)
	}
	if shm.fib_v6 != nil {
		C.rte_lpm6_delete_all(shm.fib_v6)
	}
}

func (m *Manager) NotifyLinkCycle() {} // no-op for DPDK
func (m *Manager) SyncFabricState() {} // no-op for DPDK

func (m *Manager) BumpFIBGeneration() uint32 {
	shm := m.platform.shm
	if shm == nil {
		return 0
	}
	return atomic.AddUint32((*uint32)(unsafe.Pointer(shm.fib_gen)), 1)
}

// --- Map statistics ---

func (m *Manager) GetMapStats() []dataplane.MapStats {
	shm := m.platform.shm
	if shm == nil {
		return nil
	}
	type hashInfo struct {
		name       string
		hash       *C.struct_rte_hash
		maxEntries uint32
	}
	snatMax := uint32(C.MAX_ZONES * C.MAX_ZONES * C.MAX_SNAT_RULES_PER_PAIR)
	hashes := []hashInfo{
		{"sessions_v4", shm.sessions_v4, C.MAX_SESSIONS},
		{"sessions_v6", shm.sessions_v6, C.MAX_SESSIONS},
		{"iface_zone_map", shm.iface_zone_map, C.MAX_LOGICAL_INTERFACES},
		{"zone_pair_policies", shm.zone_pair_policies, C.MAX_ZONES * C.MAX_ZONES},
		{"applications", shm.applications, C.MAX_APPLICATIONS},
		{"dnat_table", shm.dnat_table, C.MAX_STATIC_NAT_ENTRIES},
		{"dnat_table_v6", shm.dnat_table_v6, C.MAX_STATIC_NAT_ENTRIES},
		{"snat_rules", shm.snat_rules, snatMax},
		{"snat_rules_v6", shm.snat_rules_v6, snatMax},
		{"static_nat_v4", shm.static_nat_v4, C.MAX_STATIC_NAT_ENTRIES},
		{"static_nat_v6", shm.static_nat_v6, C.MAX_STATIC_NAT_ENTRIES},
		{"address_membership", shm.address_membership, C.MAX_ADDRESSES},
		{"iface_filter_map", shm.iface_filter_map, C.MAX_LOGICAL_INTERFACES * 2},
		{"nat64_prefix_map", shm.nat64_prefix_map, C.MAX_NAT64_PREFIXES},
	}

	var stats []dataplane.MapStats
	for _, h := range hashes {
		if h.hash == nil {
			continue
		}
		count := C.rte_hash_count(h.hash)
		stats = append(stats, dataplane.MapStats{
			Name:       h.name,
			Type:       "rte_hash",
			MaxEntries: h.maxEntries,
			UsedCount:  uint32(count),
		})
	}
	return stats
}

// --- Hitless restart: delete stale entries ---

func (m *Manager) DeleteStaleIfaceZone(written map[dataplane.IfaceZoneKey]bool) {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	deleteStaleHash(shm.iface_zone_map, func(key unsafe.Pointer) bool {
		ck := (*C.struct_iface_zone_key)(key)
		gk := dataplane.IfaceZoneKey{
			Ifindex: uint32(ck.ifindex),
			VlanID:  uint16(ck.vlan_id),
		}
		return written[gk]
	})
}

func (m *Manager) DeleteStaleVlanIface(written map[uint32]bool) {
	// No separate VLAN map in DPDK.
}

func (m *Manager) DeleteStaleZonePairPolicies(written map[dataplane.ZonePairKey]bool) {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	deleteStaleHash(shm.zone_pair_policies, func(key unsafe.Pointer) bool {
		ck := (*C.struct_zone_pair_key)(key)
		gk := dataplane.ZonePairKey{
			FromZone: uint16(ck.from_zone),
			ToZone:   uint16(ck.to_zone),
		}
		return written[gk]
	})
}

func (m *Manager) DeleteStaleApplications(written map[dataplane.AppKey]bool) {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	deleteStaleHash(shm.applications, func(key unsafe.Pointer) bool {
		ck := (*C.struct_app_key)(key)
		gk := dataplane.AppKey{
			Protocol: uint8(ck.protocol),
			DstPort:  uint16(ck.dst_port),
		}
		return written[gk]
	})
}

func (m *Manager) DeleteStaleSNATRules(written map[dataplane.SNATKey]bool) {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	deleteStaleHash(shm.snat_rules, func(key unsafe.Pointer) bool {
		ck := (*C.struct_snat_key)(key)
		gk := dataplane.SNATKey{
			FromZone: uint16(ck.from_zone),
			ToZone:   uint16(ck.to_zone),
			RuleIdx:  uint16(ck.rule_idx),
		}
		return written[gk]
	})
}

func (m *Manager) DeleteStaleSNATRulesV6(written map[dataplane.SNATKey]bool) {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	deleteStaleHash(shm.snat_rules_v6, func(key unsafe.Pointer) bool {
		ck := (*C.struct_snat_key)(key)
		gk := dataplane.SNATKey{
			FromZone: uint16(ck.from_zone),
			ToZone:   uint16(ck.to_zone),
			RuleIdx:  uint16(ck.rule_idx),
		}
		return written[gk]
	})
}

func (m *Manager) DeleteStaleDNATStatic(written map[dataplane.DNATKey]bool) {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	deleteStaleHash(shm.dnat_table, func(key unsafe.Pointer) bool {
		ck := (*C.struct_dnat_key)(key)
		gk := dataplane.DNATKey{
			Protocol: uint8(ck.protocol),
			DstIP:    uint32(ck.dst_ip),
			DstPort:  uint16(ck.dst_port),
			FromZone: uint16(ck.from_zone),
		}
		return written[gk]
	})
}

func (m *Manager) DeleteStaleDNATStaticV6(written map[dataplane.DNATKeyV6]bool) {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	deleteStaleHash(shm.dnat_table_v6, func(key unsafe.Pointer) bool {
		ck := (*C.struct_dnat_key_v6)(key)
		var gk dataplane.DNATKeyV6
		gk.Protocol = uint8(ck.protocol)
		copyBytes(gk.DstIP[:], ck.dst_ip[:])
		gk.DstPort = uint16(ck.dst_port)
		gk.FromZone = uint16(ck.from_zone)
		return written[gk]
	})
}

func (m *Manager) DeleteStaleStaticNAT(writtenV4 map[dataplane.StaticNATKeyV4]bool, writtenV6 map[dataplane.StaticNATKeyV6]bool) {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	deleteStaleHash(shm.static_nat_v4, func(key unsafe.Pointer) bool {
		ck := (*C.struct_static_nat_key_v4)(key)
		gk := dataplane.StaticNATKeyV4{
			IP:        uint32(ck.ip),
			Direction: uint8(ck.direction),
		}
		return writtenV4[gk]
	})
	deleteStaleHash(shm.static_nat_v6, func(key unsafe.Pointer) bool {
		ck := (*C.struct_static_nat_key_v6)(key)
		var gk dataplane.StaticNATKeyV6
		copyBytes(gk.IP[:], ck.ip[:])
		gk.Direction = uint8(ck.direction)
		return writtenV6[gk]
	})
}

func (m *Manager) SetNPTv6Rule(key dataplane.NPTv6Key, val dataplane.NPTv6Value) error {
	// TODO: implement DPDK NPTv6 support when needed
	return nil
}

func (m *Manager) DeleteStaleNPTv6(_ map[dataplane.NPTv6Key]bool) {}

func (m *Manager) DeleteStaleNAT64(count uint32, writtenPrefixes map[dataplane.NAT64PrefixKey]bool) {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	deleteStaleHash(shm.nat64_prefix_map, func(key unsafe.Pointer) bool {
		ck := (*C.struct_nat64_prefix_key)(key)
		gk := dataplane.NAT64PrefixKey{
			Prefix: [3]uint32{uint32(ck.prefix[0]), uint32(ck.prefix[1]), uint32(ck.prefix[2])},
		}
		return writtenPrefixes[gk]
	})
	// Zero configs beyond count.
	for i := count; i < C.MAX_NAT64_PREFIXES; i++ {
		ptr := (*C.struct_nat64_config)(unsafe.Pointer(
			uintptr(unsafe.Pointer(shm.nat64_configs)) +
				uintptr(i)*unsafe.Sizeof(C.struct_nat64_config{})))
		C.memset(unsafe.Pointer(ptr), 0, C.size_t(unsafe.Sizeof(C.struct_nat64_config{})))
	}
}

func (m *Manager) ZeroStaleScreenConfigs(maxID uint32) {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	for i := maxID; i < C.MAX_SCREEN_PROFILES; i++ {
		ptr := (*C.struct_screen_config)(unsafe.Pointer(
			uintptr(unsafe.Pointer(shm.screen_configs)) +
				uintptr(i)*unsafe.Sizeof(C.struct_screen_config{})))
		C.memset(unsafe.Pointer(ptr), 0, C.size_t(unsafe.Sizeof(C.struct_screen_config{})))
	}
}

func (m *Manager) ZeroStaleNATPoolConfigs(startID uint32) {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	for i := startID; i < C.MAX_NAT_POOLS; i++ {
		ptr := (*C.struct_nat_pool_config)(unsafe.Pointer(
			uintptr(unsafe.Pointer(shm.nat_pool_configs)) +
				uintptr(i)*unsafe.Sizeof(C.struct_nat_pool_config{})))
		C.memset(unsafe.Pointer(ptr), 0, C.size_t(unsafe.Sizeof(C.struct_nat_pool_config{})))
	}
}

func (m *Manager) DeleteStaleIfaceFilter(written map[dataplane.IfaceFilterKey]bool) {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	deleteStaleHash(shm.iface_filter_map, func(key unsafe.Pointer) bool {
		ck := (*C.struct_iface_filter_key)(key)
		gk := dataplane.IfaceFilterKey{
			Ifindex:   uint32(ck.ifindex),
			VlanID:    uint16(ck.vlan_id),
			Family:    uint8(ck.family),
			Direction: uint8(ck.direction),
		}
		return written[gk]
	})
}

func (m *Manager) ZeroStaleFilterConfigs(startID uint32) {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	for i := startID; i < C.MAX_FILTER_CONFIGS; i++ {
		ptr := (*C.struct_filter_config)(unsafe.Pointer(
			uintptr(unsafe.Pointer(shm.filter_configs)) +
				uintptr(i)*unsafe.Sizeof(C.struct_filter_config{})))
		C.memset(unsafe.Pointer(ptr), 0, C.size_t(unsafe.Sizeof(C.struct_filter_config{})))
	}
}

// ============================================================
// Helper functions
// ============================================================

// uint32ToBytes converts a uint32 (native endian) to [4]byte.
func uint32ToBytes(v uint32) [4]byte {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return b
}

// bytesToUint32 converts [4]byte to uint32 (native endian).
func bytesToUint32(b [4]byte) uint32 {
	return binary.NativeEndian.Uint32(b[:])
}

// copyBytes copies C uint8_t array to Go byte slice.
func copyBytes(dst []byte, src []C.uint8_t) {
	for i := range dst {
		dst[i] = byte(src[i])
	}
}

// copyCBytes copies Go byte slice to C uint8_t array.
func copyCBytes(dst []C.uint8_t, src []byte) {
	for i := range src {
		dst[i] = C.uint8_t(src[i])
	}
}

// convertSessionValue converts a C session_value to Go SessionValue.
func convertSessionValue(sv *C.struct_session_value) dataplane.SessionValue {
	var rv dataplane.SessionValue
	rv.State = uint8(sv.state)
	rv.Flags = uint8(sv.flags)
	rv.TCPState = uint8(sv.tcp_state)
	rv.IsReverse = uint8(sv.is_reverse)
	rv.SessionID = uint64(sv.session_id)
	rv.Created = uint64(sv.created)
	rv.LastSeen = uint64(sv.last_seen)
	rv.Timeout = uint32(sv.timeout)
	rv.PolicyID = uint32(sv.policy_id)
	rv.IngressZone = uint16(sv.ingress_zone)
	rv.EgressZone = uint16(sv.egress_zone)
	rv.NATSrcIP = uint32(sv.nat_src_ip)
	rv.NATDstIP = uint32(sv.nat_dst_ip)
	rv.NATSrcPort = uint16(sv.nat_src_port)
	rv.NATDstPort = uint16(sv.nat_dst_port)
	rv.FwdPackets = uint64(sv.fwd_packets)
	rv.FwdBytes = uint64(sv.fwd_bytes)
	rv.RevPackets = uint64(sv.rev_packets)
	rv.RevBytes = uint64(sv.rev_bytes)
	rv.ReverseKey.SrcIP = uint32ToBytes(uint32(sv.reverse_key.src_ip))
	rv.ReverseKey.DstIP = uint32ToBytes(uint32(sv.reverse_key.dst_ip))
	rv.ReverseKey.SrcPort = uint16(sv.reverse_key.src_port)
	rv.ReverseKey.DstPort = uint16(sv.reverse_key.dst_port)
	rv.ReverseKey.Protocol = uint8(sv.reverse_key.protocol)
	rv.ALGType = uint8(sv.alg_type)
	rv.LogFlags = uint8(sv.log_flags)
	rv.AppID = uint16(sv.app_id)
	rv.FibIfindex = uint32(sv.fib_ifindex)
	rv.FibVlanID = uint16(sv.fib_vlan_id)
	for i := 0; i < 6; i++ {
		rv.FibDmac[i] = byte(sv.fib_dmac[i])
		rv.FibSmac[i] = byte(sv.fib_smac[i])
	}
	rv.FibGen = uint16(sv.fib_gen)
	return rv
}

// convertSessionValueV6 converts a C session_value_v6 to Go SessionValueV6.
func convertSessionValueV6(sv *C.struct_session_value_v6) dataplane.SessionValueV6 {
	var rv dataplane.SessionValueV6
	rv.State = uint8(sv.state)
	rv.Flags = uint8(sv.flags)
	rv.TCPState = uint8(sv.tcp_state)
	rv.IsReverse = uint8(sv.is_reverse)
	rv.SessionID = uint64(sv.session_id)
	rv.Created = uint64(sv.created)
	rv.LastSeen = uint64(sv.last_seen)
	rv.Timeout = uint32(sv.timeout)
	rv.PolicyID = uint32(sv.policy_id)
	rv.IngressZone = uint16(sv.ingress_zone)
	rv.EgressZone = uint16(sv.egress_zone)
	copyBytes(rv.NATSrcIP[:], sv.nat_src_ip[:])
	copyBytes(rv.NATDstIP[:], sv.nat_dst_ip[:])
	rv.NATSrcPort = uint16(sv.nat_src_port)
	rv.NATDstPort = uint16(sv.nat_dst_port)
	rv.FwdPackets = uint64(sv.fwd_packets)
	rv.FwdBytes = uint64(sv.fwd_bytes)
	rv.RevPackets = uint64(sv.rev_packets)
	rv.RevBytes = uint64(sv.rev_bytes)
	copyBytes(rv.ReverseKey.SrcIP[:], sv.reverse_key.src_ip[:])
	copyBytes(rv.ReverseKey.DstIP[:], sv.reverse_key.dst_ip[:])
	rv.ReverseKey.SrcPort = uint16(sv.reverse_key.src_port)
	rv.ReverseKey.DstPort = uint16(sv.reverse_key.dst_port)
	rv.ReverseKey.Protocol = uint8(sv.reverse_key.protocol)
	rv.ALGType = uint8(sv.alg_type)
	rv.LogFlags = uint8(sv.log_flags)
	rv.AppID = uint16(sv.app_id)
	rv.FibIfindex = uint32(sv.fib_ifindex)
	rv.FibVlanID = uint16(sv.fib_vlan_id)
	for i := 0; i < 6; i++ {
		rv.FibDmac[i] = byte(sv.fib_dmac[i])
		rv.FibSmac[i] = byte(sv.fib_smac[i])
	}
	rv.FibGen = uint16(sv.fib_gen)
	return rv
}

// deleteStaleHash iterates an rte_hash and deletes keys not in the written set.
func deleteStaleHash(hash *C.struct_rte_hash, isWritten func(key unsafe.Pointer) bool) {
	if hash == nil {
		return
	}
	// Collect stale keys first to avoid modifying during iteration.
	type staleEntry struct {
		key [64]byte // large enough for any key
		sz  int
	}
	var stale []unsafe.Pointer

	var ckey unsafe.Pointer
	var cdata unsafe.Pointer
	var iter C.uint32_t
	for {
		pos := C.rte_hash_iterate(hash, &ckey, &cdata, &iter)
		if pos < 0 {
			break
		}
		if !isWritten(ckey) {
			// Save a copy of the key for deletion after iteration.
			keyCopy := C.malloc(64)
			C.memcpy(keyCopy, ckey, 64)
			stale = append(stale, keyCopy)
		}
	}

	for _, k := range stale {
		C.rte_hash_del_key(hash, k)
		C.free(k)
	}
}

// GCStats returns session garbage collection statistics from the C worker.
// Reads directly from shared memory (no CGo function call needed).
func (m *Manager) GCStats() (expired, scanned uint64) {
	shm := m.platform.shm
	if shm == nil {
		return 0, 0
	}
	return uint64(shm.gc_sessions_expired), uint64(shm.gc_sessions_scanned)
}

// SetPacketTrace enables packet tracing for packets matching the given filter.
// Zero-valued fields match any value. Call with all zeros to trace all packets.
func (m *Manager) SetPacketTrace(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8) {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	// Clear existing filter
	C.memset(unsafe.Pointer(&shm.trace_src_ip[0]), 0, 16)
	C.memset(unsafe.Pointer(&shm.trace_dst_ip[0]), 0, 16)
	shm.trace_src_port = C.uint16_t(srcPort)
	shm.trace_dst_port = C.uint16_t(dstPort)
	shm.trace_protocol = C.uint8_t(protocol)

	if len(srcIP) > 0 {
		ip := srcIP.To16()
		if ip != nil {
			for i := 0; i < 16; i++ {
				shm.trace_src_ip[i] = C.uint8_t(ip[i])
			}
		}
	}
	if len(dstIP) > 0 {
		ip := dstIP.To16()
		if ip != nil {
			for i := 0; i < 16; i++ {
				shm.trace_dst_ip[i] = C.uint8_t(ip[i])
			}
		}
	}

	// Enable after filter is set (atomic visibility)
	shm.trace_enabled = 1
}

// ClearPacketTrace disables packet tracing.
func (m *Manager) ClearPacketTrace() {
	shm := m.platform.shm
	if shm == nil {
		return
	}
	shm.trace_enabled = 0
}

// DNATKey helper: the DstIP field in DNATKey is uint32 not [4]byte.
// bytesToUint32 already handles this via the native endian field.

// ReadLatencyHistogram aggregates per-packet processing latency across
// all lcores. Returns 16 buckets: bucket 0 = sub-microsecond,
// bucket N = 2^(N-1) to 2^N microseconds, bucket 15 = 16ms+.
func (m *Manager) ReadLatencyHistogram() [16]uint64 {
	var out [16]C.uint64_t
	C.counters_aggregate_latency(&out[0])
	var result [16]uint64
	for i := range result {
		result[i] = uint64(out[i])
	}
	return result
}

// ClearLatencyHistogram clears latency histograms on all lcores.
func (m *Manager) ClearLatencyHistogram() {
	C.counters_clear_latency()
}

// PortStats holds hardware-level statistics for a single DPDK port.
type PortStats struct {
	RxPackets uint64
	RxBytes   uint64
	TxPackets uint64
	TxBytes   uint64
	RxErrors  uint64
	TxErrors  uint64
	RxMissed  uint64
}

// PortCount returns the number of DPDK ports available.
func (m *Manager) PortCount() int {
	shm := m.platform.shm
	if shm == nil {
		return 0
	}
	return int(shm.nb_ports)
}

// ReadPortLinkState returns (linkUp, speedMbps) for a given DPDK port ID.
func (m *Manager) ReadPortLinkState(portID int) (bool, uint32) {
	shm := m.platform.shm
	if shm == nil {
		return false, 0
	}
	if portID < 0 || portID >= C.MAX_PORT_MAP {
		return false, 0
	}
	up := shm.port_link_state[portID] != 0
	speed := uint32(shm.port_link_speed[portID])
	return up, speed
}

// ReadPortStats returns hardware-level statistics for a given DPDK port ID.
func (m *Manager) ReadPortStats(portID int) PortStats {
	shm := m.platform.shm
	if shm == nil {
		return PortStats{}
	}
	if portID < 0 || portID >= C.MAX_PORT_MAP {
		return PortStats{}
	}
	ps := &shm.port_stats[portID]
	return PortStats{
		RxPackets: uint64(ps.rx_packets),
		RxBytes:   uint64(ps.rx_bytes),
		TxPackets: uint64(ps.tx_packets),
		TxBytes:   uint64(ps.tx_bytes),
		RxErrors:  uint64(ps.rx_errors),
		TxErrors:  uint64(ps.tx_errors),
		RxMissed:  uint64(ps.rx_missed),
	}
}

// IsWorkerHealthy checks if DPDK worker lcores are alive by reading
// their heartbeat timestamps from shared memory. Returns true if all
// workers updated their heartbeat within the last maxAge duration.
func (m *Manager) IsWorkerHealthy(maxAge time.Duration) bool {
	shm := m.platform.shm
	if shm == nil {
		return false
	}
	now := uint64(C.rte_rdtsc())
	hz := uint64(C.rte_get_tsc_hz())
	if hz == 0 {
		return false
	}
	maxTicks := uint64(maxAge.Seconds()) * hz

	for i := 0; i < 64; i++ {
		hb := uint64(shm.worker_heartbeat[i])
		if hb == 0 {
			continue // lcore not started
		}
		if now > hb && (now-hb) > maxTicks {
			return false
		}
	}
	return true
}
