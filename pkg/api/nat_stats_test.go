package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type natApplyResultAPIDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
	calls  int
}

func (d *natApplyResultAPIDP) IsLoaded() bool {
	return true
}

func (d *natApplyResultAPIDP) LastApplyResult() *dataplane.ApplyResult {
	d.calls++
	return d.result.Clone()
}

func (d *natApplyResultAPIDP) ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{Packets: uint64(counterID), Bytes: uint64(counterID) * 100}, nil
}

func newNATStatsAPIStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(`set security nat source rule-set trust-to-untrust from zone trust
set security nat source rule-set trust-to-untrust to zone untrust
set security nat source rule-set trust-to-untrust rule r1 match source-address 10.0.0.0/8
set security nat source rule-set trust-to-untrust rule r1 then source-nat interface
set security nat source rule-set trust-to-untrust rule r2 match source-address 172.16.0.0/12
set security nat source rule-set trust-to-untrust rule r2 then source-nat interface`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// natRuntimeStatusAPIDP exposes a fixed userspace ProcessStatus plus a
// deliberately MISLEADING legacy port counter, so a test can prove which
// source the REST NAT pool stats handler reads from.
type natRuntimeStatusAPIDP struct {
	*dataplane.Manager
	status      dpuserspace.ProcessStatus
	legacyCount uint64
	result      *dataplane.ApplyResult
}

func (d *natRuntimeStatusAPIDP) IsLoaded() bool { return true }

func (d *natRuntimeStatusAPIDP) Status() (dpuserspace.ProcessStatus, error) {
	return d.status, nil
}

func (d *natRuntimeStatusAPIDP) ReadNATPortCounter(uint32) (uint64, error) {
	return d.legacyCount, nil
}

func (d *natRuntimeStatusAPIDP) LastApplyResult() *dataplane.ApplyResult {
	return d.result.Clone()
}

func newNATPoolStatsAPIStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	// Pool config text declares ONE address and the default port window. The
	// runtime helper will report a DIFFERENT (authoritative) view.
	if _, err := store.LoadSet(`set security nat source pool p1 address 203.0.113.10/32
set security nat source pool p1 port range low 1024 high 2023
set security nat source rule-set rs from zone trust
set security nat source rule-set rs to zone untrust
set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8
set security nat source rule-set rs rule r1 then source-nat pool p1`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestNATPoolStatsHandlerUsesRuntimeStatus is a FAIL-ON-REVERT guard for
// #2938: the REST NAT pool stats handler must report in-use / capacity /
// utilization from the userspace helper's live SourceNATPoolStatus, NOT from
// config text (len(pool.Addresses)) + the retired-eBPF port counter.
//
// The fixture is built so the two sources disagree on EVERY field:
//   - config: 1 address, port window 1024..2023  => 1000 total ports
//   - runtime: 3 addresses, port window 1024..1523 (500/addr) => 1500 total,
//     750 used.
//   - legacy ReadNATPortCounter returns 99 (a value the runtime never uses).
//
// If the handler is reverted to the config-derived path, total/used/util all
// change to the config+legacy numbers and the assertions fail.
func TestNATPoolStatsHandlerUsesRuntimeStatus(t *testing.T) {
	dp := &natRuntimeStatusAPIDP{
		Manager:     dataplane.New(),
		legacyCount: 99,
		result:      &dataplane.ApplyResult{PoolIDs: map[string]uint8{"p1": 7}},
		status: dpuserspace.ProcessStatus{
			SourceNATPools: []dpuserspace.SourceNATPoolStatus{
				{
					RuleName:     "r1",
					PoolName:     "p1",
					AddressCount: 3,
					PortLow:      1024,
					PortHigh:     1523,
					UsedPorts:    750,
				},
				// A second rule sharing the same pool reports the SAME
				// occupancy; the handler must dedup (never sum to 1500 used).
				{
					RuleName:     "r2",
					PoolName:     "p1",
					AddressCount: 3,
					PortLow:      1024,
					PortHigh:     1523,
					UsedPorts:    750,
				},
			},
		},
	}
	s := &Server{store: newNATPoolStatsAPIStore(t), dp: dp}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/nat/source/pools", nil)
	s.natPoolStatsHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Success bool               `json:"success"`
		Data    []NATPoolStatsInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}

	var p1 *NATPoolStatsInfo
	for i := range resp.Data {
		if resp.Data[i].Name == "p1" {
			p1 = &resp.Data[i]
		}
	}
	if p1 == nil {
		t.Fatalf("pool p1 not in response: %+v", resp.Data)
	}

	// Runtime SSOT: 3 addresses * 500 ports = 1500 total; 750 used.
	const (
		wantTotal = 1500
		wantUsed  = 750
		wantAvail = 750
		wantUtil  = "50.0%"
	)
	if p1.TotalPorts != wantTotal {
		t.Errorf("TotalPorts = %d, want %d (runtime AddressCount*window, NOT config len()=1 => 1000)",
			p1.TotalPorts, wantTotal)
	}
	if p1.UsedPorts != wantUsed {
		t.Errorf("UsedPorts = %d, want %d (runtime UsedPorts, NOT legacy counter 99)",
			p1.UsedPorts, wantUsed)
	}
	if p1.AvailablePorts != wantAvail {
		t.Errorf("AvailablePorts = %d, want %d", p1.AvailablePorts, wantAvail)
	}
	if p1.Utilization != wantUtil {
		t.Errorf("Utilization = %q, want %q", p1.Utilization, wantUtil)
	}
}

// natIfaceSNATSessionsDP yields a fixed set of forward/reverse SNAT and
// non-SNAT IPv4 sessions across two interface-mode rule-set zone pairs, plus
// an ApplyResult zone map, so the REST handler can attribute each row.
//
// Zone IDs: trust=2, guest=4, wan=5.
//   - 3 forward SNAT sessions trust(2)->wan(5)
//   - 1 forward SNAT session  guest(4)->wan(5)
//   - 1 reverse SNAT session trust->wan (must NOT count)
//   - 1 forward NON-SNAT session trust->wan (must NOT count)
type natIfaceSNATSessionsDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *natIfaceSNATSessionsDP) IsLoaded() bool { return true }

func (d *natIfaceSNATSessionsDP) LastApplyResult() *dataplane.ApplyResult {
	return d.result.Clone()
}

func (d *natIfaceSNATSessionsDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	emit := func(ingress, egress uint16, reverse uint8, flags uint16) {
		fn(dataplane.SessionKey{Protocol: 6}, dataplane.SessionValue{
			IsReverse:   reverse,
			Flags:       flags,
			IngressZone: ingress,
			EgressZone:  egress,
		})
	}
	// 3 forward SNAT trust(2)->wan(5)
	emit(2, 5, 0, dataplane.SessFlagSNAT)
	emit(2, 5, 0, dataplane.SessFlagSNAT)
	emit(2, 5, 0, dataplane.SessFlagSNAT)
	// 1 forward SNAT guest(4)->wan(5)
	emit(4, 5, 0, dataplane.SessFlagSNAT)
	// reverse SNAT trust->wan: must be excluded
	emit(5, 2, 1, dataplane.SessFlagSNAT)
	// forward non-SNAT trust->wan: must be excluded
	emit(2, 5, 0, dataplane.SessFlagDNAT)
	return nil
}

func (d *natIfaceSNATSessionsDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func newIfaceNATStatsAPIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(`set security nat source rule-set trust-to-wan from zone trust
set security nat source rule-set trust-to-wan to zone wan
set security nat source rule-set trust-to-wan rule r1 match source-address 0.0.0.0/0
set security nat source rule-set trust-to-wan rule r1 then source-nat interface
set security nat source rule-set trust-to-wan rule r2 match source-address 10.0.0.0/8
set security nat source rule-set trust-to-wan rule r2 then source-nat interface
set security nat source rule-set guest-to-wan from zone guest
set security nat source rule-set guest-to-wan to zone wan
set security nat source rule-set guest-to-wan rule r1 match source-address 0.0.0.0/0
set security nat source rule-set guest-to-wan rule r1 then source-nat interface`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestNATPoolStatsHandlerInterfaceModePerRuleSet is a FAIL-ON-REVERT guard for
// #3417: each interface-mode source NAT row must report only the SNAT sessions
// that traversed its own from/to zone pair, NOT the firewall-wide SNAT total.
//
// Fixture: 3 SNAT sessions on trust->wan, 1 on guest->wan, plus a reverse and
// a non-SNAT session that must not count. The global SNAT total is 4. If the
// attribution is reverted to counts.total / a global counter, BOTH rows report
// 4 and the per-row assertions fail.
func TestNATPoolStatsHandlerInterfaceModePerRuleSet(t *testing.T) {
	dp := &natIfaceSNATSessionsDP{
		Manager: dataplane.New(),
		result: &dataplane.ApplyResult{
			ZoneIDs: map[string]uint16{"trust": 2, "guest": 4, "wan": 5},
		},
	}
	s := &Server{store: newIfaceNATStatsAPIStore(t), dp: dp}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/nat/source/pools", nil)
	s.natPoolStatsHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool               `json:"success"`
		Data    []NATPoolStatsInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}

	got := map[string]int{}
	for _, p := range resp.Data {
		if !p.IsInterface {
			t.Errorf("unexpected non-interface row %q", p.Name)
			continue
		}
		got[p.Name] = p.UsedPorts
	}
	// trust->wan must report ONLY its 3 sessions; guest->wan ONLY its 1.
	// The firewall-wide SNAT total is 4 — neither row may report it.
	if got["trust->wan"] != 3 {
		t.Errorf("trust->wan UsedPorts = %d, want 3 (per-rule-set, NOT global total 4)", got["trust->wan"])
	}
	if got["guest->wan"] != 1 {
		t.Errorf("guest->wan UsedPorts = %d, want 1 (per-rule-set, NOT global total 4)", got["guest->wan"])
	}
}

// natIfaceSNATDualStackDP emits interface-mode SNAT sessions on BOTH families:
// IPv4 forward SNAT on trust->wan, and IPv6 forward SNAT on trust->wan AND
// guest->wan (plus a reverse and a non-SNAT v6 session that must NOT count).
// It exercises the #5328 (A8-b1-F6) v6 attribution path.
//
// Zone IDs: trust=2, guest=4, wan=5.
//   - 2 forward SNAT v4 trust(2)->wan(5)
//   - 4 forward SNAT v6 trust(2)->wan(5)
//   - 2 forward SNAT v6 guest(4)->wan(5)
//   - 1 reverse SNAT v6 (excluded) + 1 forward non-SNAT v6 (excluded)
type natIfaceSNATDualStackDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *natIfaceSNATDualStackDP) IsLoaded() bool { return true }

func (d *natIfaceSNATDualStackDP) LastApplyResult() *dataplane.ApplyResult {
	return d.result.Clone()
}

func (d *natIfaceSNATDualStackDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	emit := func(ingress, egress uint16, reverse uint8, flags uint16) {
		fn(dataplane.SessionKey{Protocol: 6}, dataplane.SessionValue{
			IsReverse:   reverse,
			Flags:       flags,
			IngressZone: ingress,
			EgressZone:  egress,
		})
	}
	// 2 forward SNAT v4 trust(2)->wan(5)
	emit(2, 5, 0, dataplane.SessFlagSNAT)
	emit(2, 5, 0, dataplane.SessFlagSNAT)
	return nil
}

func (d *natIfaceSNATDualStackDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	emit := func(ingress, egress uint16, reverse uint8, flags uint16) {
		fn(dataplane.SessionKeyV6{Protocol: 6}, dataplane.SessionValueV6{
			IsReverse:   reverse,
			Flags:       flags,
			IngressZone: ingress,
			EgressZone:  egress,
		})
	}
	// 4 forward SNAT v6 trust(2)->wan(5)
	emit(2, 5, 0, dataplane.SessFlagSNAT)
	emit(2, 5, 0, dataplane.SessFlagSNAT)
	emit(2, 5, 0, dataplane.SessFlagSNAT)
	emit(2, 5, 0, dataplane.SessFlagSNAT)
	// 2 forward SNAT v6 guest(4)->wan(5)
	emit(4, 5, 0, dataplane.SessFlagSNAT)
	emit(4, 5, 0, dataplane.SessFlagSNAT)
	// reverse SNAT v6 (excluded) + forward non-SNAT v6 (excluded)
	emit(5, 2, 1, dataplane.SessFlagSNAT)
	emit(2, 5, 0, dataplane.SessFlagDNAT)
	return nil
}

// TestNATPoolStatsHandlerInterfaceModeCountsV6_5328 is a FAIL-ON-REVERT guard
// for #5328 (A8-b1-F6): interface-mode source-NAT usage must include IPv6
// sessions, not just IPv4. trust->wan sees 2 v4 + 4 v6 = 6 forward SNAT
// sessions; guest->wan sees 2 v6 forward SNAT sessions and NO v4.
//
// If the v6 IterateSessionsV6 pass is removed (the pre-fix v4-only tally),
// trust->wan reports 2 and guest->wan reports 0 — both assertions go RED.
func TestNATPoolStatsHandlerInterfaceModeCountsV6_5328(t *testing.T) {
	dp := &natIfaceSNATDualStackDP{
		Manager: dataplane.New(),
		result: &dataplane.ApplyResult{
			ZoneIDs: map[string]uint16{"trust": 2, "guest": 4, "wan": 5},
		},
	}
	s := &Server{store: newIfaceNATStatsAPIStore(t), dp: dp}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/nat/source/pools", nil)
	s.natPoolStatsHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool               `json:"success"`
		Data    []NATPoolStatsInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}

	got := map[string]int{}
	for _, p := range resp.Data {
		if p.IsInterface {
			got[p.Name] = p.UsedPorts
		}
	}
	if got["trust->wan"] != 6 {
		t.Errorf("trust->wan UsedPorts = %d, want 6 (2 v4 + 4 v6 forward SNAT); v6 sessions dropped?", got["trust->wan"])
	}
	if got["guest->wan"] != 2 {
		t.Errorf("guest->wan UsedPorts = %d, want 2 (v6-only forward SNAT); v6 sessions dropped?", got["guest->wan"])
	}
}

func TestNATRuleStatsHandlerReadsApplyResultOnce(t *testing.T) {
	dp := &natApplyResultAPIDP{
		Manager: dataplane.New(),
		result: &dataplane.ApplyResult{
			NATCounterIDs: map[string]uint32{
				dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "trust-to-untrust", "r1"): 31,
				dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "trust-to-untrust", "r2"): 32,
			},
		},
	}
	s := &Server{store: newNATStatsAPIStore(t), dp: dp}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/nat/source/rules", nil)
	s.natRuleStatsHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	if dp.calls != 1 {
		t.Fatalf("LastApplyResult() calls = %d, want 1", dp.calls)
	}

	var resp struct {
		Success bool               `json:"success"`
		Data    []NATRuleStatsInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("success = false; body: %s", rr.Body.String())
	}
	if len(resp.Data) != 2 {
		t.Fatalf("len(resp.Data) = %d, want 2", len(resp.Data))
	}
	hits := make(map[string]uint64, len(resp.Data))
	for _, rule := range resp.Data {
		hits[rule.RuleName] = rule.HitPackets
	}
	if hits["r1"] != 31 || hits["r2"] != 32 {
		t.Fatalf("hit packets = %+v, want r1=31 r2=32", hits)
	}
}
