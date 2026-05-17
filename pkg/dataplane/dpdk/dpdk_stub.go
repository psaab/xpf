//go:build !dpdk

package dpdk

import (
	"context"
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

type platformState struct{}

// --- Lifecycle ---

func (m *Manager) Load() error {
	slog.Info("DPDK dataplane loaded (stub)")
	m.loaded = true
	return nil
}

func (m *Manager) Close() error {
	m.loaded = false
	return nil
}

func (m *Manager) Teardown() error {
	return m.Close()
}

// --- Program attachment ---

func (m *Manager) AttachXDP(ifindex int, forceGeneric bool) error {
	slog.Debug("DPDK: AttachXDP stub", "ifindex", ifindex)
	return nil
}

func (m *Manager) DetachXDP(ifindex int) error {
	slog.Debug("DPDK: DetachXDP stub", "ifindex", ifindex)
	return nil
}

func (m *Manager) AttachTC(ifindex int) error {
	slog.Debug("DPDK: AttachTC stub", "ifindex", ifindex)
	return nil
}

func (m *Manager) DetachTC(ifindex int) error {
	slog.Debug("DPDK: DetachTC stub", "ifindex", ifindex)
	return nil
}

func (m *Manager) AddTxPort(ifindex int) error {
	slog.Debug("DPDK: AddTxPort stub", "ifindex", ifindex)
	return nil
}

// --- Compilation ---

func (m *Manager) Compile(cfg *config.Config) (*dataplane.CompileResult, error) {
	result, err := dataplane.CompileConfig(m, cfg, m.lastCompile != nil)
	if err != nil {
		return nil, err
	}
	m.lastCompile = result
	m.recordApplyResult(dataplane.ApplyResultFromCompileResult(result))
	return result, nil
}

// --- Zone / interface mapping ---

func (m *Manager) SetZone(ifindex int, vlanID uint16, zoneID uint16, routingTable uint32, flags uint8, rgID uint8, screenFlags uint32) error {
	return nil
}

func (m *Manager) SetVlanIfaceInfo(subIfindex int, parentIfindex int, vlanID uint16) error {
	return nil
}

func (m *Manager) ClearIfaceZoneMap() error { return nil }
func (m *Manager) ClearVlanIfaceMap() error { return nil }

func (m *Manager) SetZoneConfig(zoneID uint16, cfg dataplane.ZoneConfig) error {
	return nil
}

// --- Policy ---

func (m *Manager) SetZonePairPolicy(fromZone, toZone uint16, ps dataplane.PolicySet) error {
	return nil
}

func (m *Manager) SetPolicyRule(policySetID uint32, ruleIndex uint32, rule dataplane.PolicyRule) error {
	return nil
}

func (m *Manager) ClearZonePairPolicies() error { return nil }

func (m *Manager) SetDefaultPolicy(action uint8) error { return nil }

func (m *Manager) UpdatePolicyScheduleState(_ *config.Config, _ map[string]bool) {}

// --- Address book ---

func (m *Manager) SetAddressBookEntry(cidr string, addressID uint32) error { return nil }

func (m *Manager) SetAddressMembership(resolvedID, setID uint32) error { return nil }

func (m *Manager) ClearAddressBookV4() error { return nil }

func (m *Manager) ClearAddressBookV6() error { return nil }

func (m *Manager) ClearAddressMembership() error { return nil }

// --- Application ---

func (m *Manager) SetApplication(protocol uint8, dstPort uint16, appID uint32, timeout uint32, algType uint8, srcPortLow, srcPortHigh uint16) error {
	return nil
}

func (m *Manager) SetAppRange(_ uint32, _ dataplane.AppRangeEntry) error { return nil }
func (m *Manager) ClearAppRanges() error                                 { return nil }
func (m *Manager) ClearApplications() error                              { return nil }

// --- Sessions ---

func (m *Manager) IterateSessions(_ func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return nil
}

func (m *Manager) BatchIterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return m.IterateSessions(fn)
}

func (m *Manager) DeleteSession(_ dataplane.SessionKey) error { return nil }

func (m *Manager) BatchDeleteSessions(_ []dataplane.SessionKey) (int, error) { return 0, nil }

func (m *Manager) SetSessionV4(_ dataplane.SessionKey, _ dataplane.SessionValue) error { return nil }

func (m *Manager) IterateSessionsV6(_ func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func (m *Manager) BatchIterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return m.IterateSessionsV6(fn)
}

func (m *Manager) DeleteSessionV6(_ dataplane.SessionKeyV6) error { return nil }

func (m *Manager) BatchDeleteSessionsV6(_ []dataplane.SessionKeyV6) (int, error) { return 0, nil }

func (m *Manager) SetSessionV6(_ dataplane.SessionKeyV6, _ dataplane.SessionValueV6) error {
	return nil
}

func (m *Manager) GetSessionV4(_ dataplane.SessionKey) (dataplane.SessionValue, error) {
	return dataplane.SessionValue{}, nil
}
func (m *Manager) GetSessionV6(_ dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	return dataplane.SessionValueV6{}, nil
}

func (m *Manager) SessionCount() (int, int) { return 0, 0 }

func (m *Manager) ClearAllSessions() (int, int, error) { return 0, 0, nil }

// --- DNAT ---

func (m *Manager) SetDNATEntry(_ dataplane.DNATKey, _ dataplane.DNATValue) error       { return nil }
func (m *Manager) DeleteDNATEntry(_ dataplane.DNATKey) error                           { return nil }
func (m *Manager) ClearDNATStatic() error                                              { return nil }
func (m *Manager) SetDNATEntryV6(_ dataplane.DNATKeyV6, _ dataplane.DNATValueV6) error { return nil }
func (m *Manager) DeleteDNATEntryV6(_ dataplane.DNATKeyV6) error                       { return nil }
func (m *Manager) ClearDNATStaticV6() error                                            { return nil }

// --- SNAT ---

func (m *Manager) SetSNATRule(fromZone, toZone, ruleIdx uint16, val dataplane.SNATValue) error {
	return nil
}

func (m *Manager) ClearSNATRules() error { return nil }

func (m *Manager) SetSNATRuleV6(fromZone, toZone, ruleIdx uint16, val dataplane.SNATValueV6) error {
	return nil
}

func (m *Manager) ClearSNATRulesV6() error { return nil }

// --- NAT pools ---

func (m *Manager) SetNATPoolConfig(poolID uint32, cfg dataplane.NATPoolConfig) error { return nil }
func (m *Manager) SetNATPoolIPV4(poolID, index uint32, ip uint32) error              { return nil }
func (m *Manager) SetNATPoolIPV6(poolID, index uint32, ip [16]byte) error            { return nil }
func (m *Manager) ClearNATPoolConfigs() error                                        { return nil }
func (m *Manager) ClearNATPoolIPs() error                                            { return nil }

// --- SNAT egress IPs (interface-mode SNAT) ---

func (m *Manager) SetSNATEgressIP(key dataplane.SNATEgressKey, val dataplane.SNATEgressValue) error {
	return nil
}
func (m *Manager) ClearSNATEgressIPs() error { return nil }

// --- Static NAT ---

func (m *Manager) SetStaticNATEntryV4(ip uint32, direction uint8, translated uint32) error {
	return nil
}

func (m *Manager) SetStaticNATEntryV6(ip [16]byte, direction uint8, translated [16]byte) error {
	return nil
}

func (m *Manager) ClearStaticNATEntries() error { return nil }

// --- NPTv6 ---

func (m *Manager) SetNPTv6Rule(key dataplane.NPTv6Key, val dataplane.NPTv6Value) error { return nil }
func (m *Manager) DeleteStaleNPTv6(_ map[dataplane.NPTv6Key]bool)                      {}

// --- NAT64 ---

func (m *Manager) SetNAT64Config(index uint32, cfg dataplane.NAT64Config) error { return nil }
func (m *Manager) SetNAT64Count(count uint32) error                             { return nil }
func (m *Manager) ClearNAT64Configs() error                                     { return nil }

// --- Screen ---

func (m *Manager) SetScreenConfig(profileID uint32, cfg dataplane.ScreenConfig) error { return nil }
func (m *Manager) ClearScreenConfigs() error                                          { return nil }

// --- Session count maps ---

func (m *Manager) UpdateSessionCountSrc(key dataplane.SessionCountKey, count uint32) error {
	return nil
}
func (m *Manager) UpdateSessionCountDst(key dataplane.SessionCountKey, count uint32) error {
	return nil
}
func (m *Manager) ClearSessionCounts() error { return nil }

// --- Port mirroring ---

func (m *Manager) SetMirrorConfig(ifindex int, mirrorIfindex int, rate uint32) error { return nil }
func (m *Manager) ClearMirrorConfigs() error                                         { return nil }

// --- Flow ---

func (m *Manager) SetFlowTimeout(idx, seconds uint32) error          { return nil }
func (m *Manager) SetFlowConfig(cfg dataplane.FlowConfigValue) error { return nil }

// --- Fabric cross-chassis forwarding ---

func (m *Manager) UpdateFabricFwd(info dataplane.FabricFwdInfo) error  { return nil }
func (m *Manager) UpdateFabricFwd1(info dataplane.FabricFwdInfo) error { return nil }
func (m *Manager) UpdateRGActive(rgID int, active bool) error          { return nil }
func (m *Manager) UpdateHAWatchdog(rgID int, timestamp uint64) error   { return nil }

// --- Firewall filters ---

func (m *Manager) SetIfaceFilter(key dataplane.IfaceFilterKey, filterID uint32) error { return nil }
func (m *Manager) ClearIfaceFilterMap() error                                         { return nil }
func (m *Manager) SetFilterConfig(filterID uint32, cfg dataplane.FilterConfig) error  { return nil }

func (m *Manager) ReadFilterConfig(filterID uint32) (dataplane.FilterConfig, error) {
	return dataplane.FilterConfig{}, nil
}

func (m *Manager) SetFilterRule(index uint32, rule dataplane.FilterRule) error { return nil }
func (m *Manager) ClearFilterConfigs() error                                   { return nil }

// --- Policers ---

func (m *Manager) SetPolicerConfig(id uint32, cfg dataplane.PolicerConfig) error { return nil }
func (m *Manager) ClearPolicerConfigs() error                                    { return nil }

// --- Counters ---

func (m *Manager) ReadGlobalCounter(index uint32) (uint64, error) { return 0, nil }

func (m *Manager) ReadFloodCounters(zoneID uint16) (dataplane.FloodState, error) {
	return dataplane.FloodState{}, nil
}

func (m *Manager) ReadInterfaceCounters(ifindex int) (dataplane.InterfaceCounterValue, error) {
	return dataplane.InterfaceCounterValue{}, nil
}

func (m *Manager) ReadZoneCounters(zoneID uint16, direction int) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}

func (m *Manager) ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}

func (m *Manager) ReadFilterCounters(ruleIdx uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}

func (m *Manager) ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, nil
}

func (m *Manager) ReadNATPortCounter(poolID uint32) (uint64, error) { return 0, nil }
func (m *Manager) SeedNATPortCounters()                             {}
func (m *Manager) SeedSessionIDCounter(_ int)                       {}

func (m *Manager) IncrementGlobalCounter(_ uint32, _ uint64) error { return nil }
func (m *Manager) ClearGlobalCounters() error                      { return nil }
func (m *Manager) ClearInterfaceCounters() error                   { return nil }
func (m *Manager) ClearZoneCounters() error                        { return nil }
func (m *Manager) ClearPolicyCounters() error                      { return nil }
func (m *Manager) ClearFilterCounters() error                      { return nil }
func (m *Manager) ClearAllCounters() error                         { return nil }
func (m *Manager) ClearNATRuleCounters() error                     { return nil }

// --- Events ---

func (m *Manager) NewEventSource() (dataplane.EventSource, error) { return nil, nil }

// --- FIB ---

func (m *Manager) StartFIBSync(_ context.Context) {}
func (m *Manager) BumpFIBGeneration() uint32      { return 0 }
func (m *Manager) NotifyLinkCycle()               {}
func (m *Manager) SyncFabricState()               {}

// --- Map statistics ---

func (m *Manager) GetMapStats() []dataplane.MapStats { return nil }

// --- Hitless restart: delete stale entries ---

func (m *Manager) DeleteStaleIfaceZone(_ map[dataplane.IfaceZoneKey]bool)       {}
func (m *Manager) DeleteStaleVlanIface(_ map[uint32]bool)                       {}
func (m *Manager) DeleteStaleZonePairPolicies(_ map[dataplane.ZonePairKey]bool) {}
func (m *Manager) DeleteStaleApplications(_ map[dataplane.AppKey]bool)          {}
func (m *Manager) DeleteStaleSNATRules(_ map[dataplane.SNATKey]bool)            {}
func (m *Manager) DeleteStaleSNATRulesV6(_ map[dataplane.SNATKey]bool)          {}
func (m *Manager) DeleteStaleDNATStatic(_ map[dataplane.DNATKey]bool)           {}
func (m *Manager) DeleteStaleDNATStaticV6(_ map[dataplane.DNATKeyV6]bool)       {}
func (m *Manager) DeleteStaleStaticNAT(_ map[dataplane.StaticNATKeyV4]bool, _ map[dataplane.StaticNATKeyV6]bool) {
}
func (m *Manager) DeleteStaleNAT64(_ uint32, _ map[dataplane.NAT64PrefixKey]bool) {}
func (m *Manager) ZeroStaleScreenConfigs(_ uint32)                                {}
func (m *Manager) ZeroStaleNATPoolConfigs(_ uint32)                               {}
func (m *Manager) DeleteStaleIfaceFilter(_ map[dataplane.IfaceFilterKey]bool)     {}
func (m *Manager) ZeroStaleFilterConfigs(_ uint32)                                {}
