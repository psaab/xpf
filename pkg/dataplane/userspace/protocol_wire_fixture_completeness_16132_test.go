package userspace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// #16132: fixture-completeness for the Go↔Rust userspace wire.
//
// The Rust golden (`wire_invariant_default_specimens`) serializes default
// and — since this issue — populated specimens into
// userspace-dp/tests/fixtures/protocol_wire_v1.json. This Go cell is the
// independent cross-language oracle for that fixture:
//
//   - it FAILS (never skips) when the fixture is missing or unparsable, so
//     skip-on-missing cannot greenwash coverage;
//   - for every mapped specimen it requires the fixture key set and the Go
//     struct's JSON tag set to agree, modulo the explicit allowlists below
//     (each entry names WHY that side legitimately has no counterpart);
//   - it decodes every mapped fixture specimen into the Go type with
//     DisallowUnknownFields, so a Rust field rename that reaches the
//     fixture (e.g. after a blind regeneration) reds here even though the
//     Rust golden was regenerated green;
//   - it marshals a reflectively populated Go value (every field set to a
//     non-zero sentinel, so `omitempty` cannot elide it) and requires every
//     emitted key to be present in the fixture specimen, so a Go field
//     rename or a new Go wire field with no Rust specimen reds here.
//
// Width note: JSON has no integer widths, so a u16↔u32 drift that keeps the
// same key is not caught by key agreement alone. The Rust populated
// specimens therefore use values that exercise the declared widths, and
// the Rust census gate (`wire_fixture_completeness_16132`) pins the
// declared Rust widths against the source. A width change on either side
// that alters a value's representable range changes a specimen value or
// fails the Go decode below (overflow into a narrower Go field errors).
//
// Deserialize-only secrets are intentionally absent from every specimen:
// `syn_cookie_master_key`, `syn_cookie_key_ring`, `wg_local_privkey_hex`
// and `wg_preshared_key_hex` are `skip_serializing` in Rust, so they can
// never appear in serialized output; asserting their absence here keeps a
// future `skip_serializing` removal from leaking them into this fixture.

// wireSpecimenType maps a fixture specimen name to a prototype Go value
// (pointer to struct) whose JSON tags define the Go side of that specimen.
func wireSpecimenTypes() map[string]any {
	return map[string]any{
		"address_book_snapshot":                         &AddressBookSnapshot{},
		"app_catalog_entry":                             &AppCatalogEntrySnapshot{},
		"binding_control_request":                       &BindingControlRequest{},
		"binding_counters_snapshot":                     &BindingCountersSnapshot{},
		"binding_status":                                &BindingStatus{},
		"binding_status_populated":                      &BindingStatus{},
		"class_of_service_snapshot":                     &ClassOfServiceSnapshot{},
		"config_snapshot":                               &ConfigSnapshot{},
		"config_snapshot_populated":                     &ConfigSnapshot{},
		"control_request":                               &ControlRequest{},
		"control_request_populated":                     &ControlRequest{},
		"control_response":                              &ControlResponse{},
		"control_response_populated":                    &ControlResponse{},
		"cos_active_flow_count_status":                  &CoSActiveFlowCountStatus{},
		"cos_dscp_classifier_entry_snapshot":            &CoSDSCPClassifierEntrySnapshot{},
		"cos_dscp_classifier_snapshot":                  &CoSDSCPClassifierSnapshot{},
		"cos_dscp_rewrite_rule_entry_snapshot":          &CoSDSCPRewriteRuleEntrySnapshot{},
		"cos_dscp_rewrite_rule_snapshot":                &CoSDSCPRewriteRuleSnapshot{},
		"cos_forwarding_class_snapshot":                 &CoSForwardingClassSnapshot{},
		"cos_ieee8021_classifier_entry_snapshot":        &CoSIEEE8021ClassifierEntrySnapshot{},
		"cos_ieee8021_classifier_snapshot":              &CoSIEEE8021ClassifierSnapshot{},
		"cos_inet_precedence_classifier_entry_snapshot": &CoSINetPrecedenceClassifierEntrySnapshot{},
		"cos_inet_precedence_classifier_snapshot":       &CoSINetPrecedenceClassifierSnapshot{},
		"cos_interface_status":                          &CoSInterfaceStatus{},
		"cos_interface_status_populated":                &CoSInterfaceStatus{},
		"cos_queue_status":                              &CoSQueueStatus{},
		"cos_queue_status_populated":                    &CoSQueueStatus{},
		"cos_scheduler_map_entry_snapshot":              &CoSSchedulerMapEntrySnapshot{},
		"cos_scheduler_map_snapshot":                    &CoSSchedulerMapSnapshot{},
		"cos_scheduler_snapshot":                        &CoSSchedulerSnapshot{},
		"cos_scheduler_snapshot_populated":              &CoSSchedulerSnapshot{},
		"destination_nat_rule_snapshot":                 &DestinationNATRuleSnapshot{},
		"display_lease_wire":                            &DisplayLeaseWire{},
		"exception_status":                              &ExceptionStatus{},
		"fabric_snapshot":                               &FabricSnapshot{},
		"fib_next_hop_wire":                             &FibNextHopWire{},
		"fib_route_wire":                                &FibRouteWire{},
		"firewall_filter_snapshot":                      &FirewallFilterSnapshot{},
		"firewall_filter_term_counter_status":           &FirewallFilterTermCounterStatus{},
		"firewall_term_snapshot":                        &FirewallTermSnapshot{},
		"firewall_term_snapshot_populated":              &FirewallTermSnapshot{},
		"flex_match_snapshot":                           &FlexMatchSnapshot{},
		"flow_export_snapshot":                          &FlowExportSnapshot{},
		"flow_snapshot":                                 &FlowSnapshot{},
		"flow_snapshot_time_wait_state_populated":       &FlowSnapshot{},
		"flow_tuple_status":                             &FlowTupleStatus{},
		"flow_worker_status":                            &FlowWorkerStatus{},
		"flow_worker_status_populated":                  &FlowWorkerStatus{},
		"forwarding_control_request":                    &ForwardingControlRequest{},
		"ha_group_status":                               &HAGroupStatus{},
		"ha_group_status_populated":                     &HAGroupStatus{},
		"ha_state_update_request":                       &HAStateUpdateRequest{},
		"idle_lease_wire":                               &IdleLeaseWire{},
		"inject_packet_request":                         &InjectPacketRequest{},
		"lease_export_request":                          &LeaseExportRequest{},
		"interface_address_snapshot":                    &InterfaceAddressSnapshot{},
		"interface_snapshot":                            &InterfaceSnapshot{},
		"interface_snapshot_populated":                  &InterfaceSnapshot{},
		"ipsec_bindless_selector_snapshot":              &IpsecBindlessSelectorSnapshot{},
		"ipsec_main_route_next_hop_snapshot":            &IpsecMainRouteNextHopSnapshot{},
		"ipsec_main_route_snapshot":                     &IpsecMainRouteSnapshot{},
		"ipsec_pmech_inventory_snapshot":                &IpsecPMechInventorySnapshot{},
		"ipsec_pmech_tunnel_row_snapshot":               &IpsecPMechTunnelRowSnapshot{},
		"ipsec_traffic_selector_snapshot":               &IpsecTrafficSelectorSnapshot{},
		"ipsec_tunnel_row_snapshot":                     &IpsecTunnelRowSnapshot{},
		"map_pins":                                      &UserspaceMapPins{},
		"mirror_config_snapshot":                        &MirrorConfigSnapshot{},
		"nat64_rule_snapshot":                           &NAT64RuleSnapshot{},
		"nat_app_term_wire":                             &NatAppTermWire{},
		"nat_port_range_wire":                           &NatPortRangeWire{},
		"nat_rule_counter_status":                       &NATRuleCounterStatus{},
		"neighbor_snapshot":                             &NeighborSnapshot{},
		"nptv6_rule_snapshot":                           &Nptv6RuleSnapshot{},
		"packet_resolution":                             &PacketResolution{},
		"permitted_remote_wire":                         &PersistentNatRemote{},
		"policer_snapshot":                              &PolicerSnapshot{},
		"policy_application_snapshot":                   &PolicyApplicationSnapshot{},
		"policy_application_snapshot_populated":         &PolicyApplicationSnapshot{},
		"policy_rename_ancestry":                        &PolicyRenameAncestry{},
		"policy_rule_counter_status":                    &PolicyRuleCounterStatus{},
		"policy_rule_snapshot":                          &PolicyRuleSnapshot{},
		"policy_session_rebind":                         &PolicySessionRebind{},
		"process_status":                                &ProcessStatus{},
		"process_status_linked_lib_versions":            &ProcessStatus{},
		"process_status_populated":                      &ProcessStatus{},
		"process_status_unzoned_policy_denials":         &ProcessStatus{},
		"queue_control_request":                         &QueueControlRequest{},
		"queue_epoch_snapshot":                          &QueueEpochSnapshot{},
		"queue_status":                                  &QueueStatus{},
		"queue_status_populated":                        &QueueStatus{},
		"route_snapshot":                                &RouteSnapshot{},
		"route_snapshot_populated":                      &RouteSnapshot{},
		"route_snapshot_weighted":                       &RouteSnapshot{},
		"route_table_identity_snapshot":                 &RouteTableIdentitySnapshot{},
		"s5_reinject_provenance":                        &S5ReinjectProvenance{},
		"s5_reinject_status":                            &S5ReinjectStatus{},
		"screen_missing_profile_ref":                    &ScreenMissingProfileRef{},
		"screen_profile_snapshot":                       &ScreenProfileSnapshot{},
		"screen_profile_snapshot_populated":             &ScreenProfileSnapshot{},
		"session_counter_query_request":                 &SessionCounterQuery{},
		"session_counter_row_wire":                      &SessionCounterRow{},
		"session_delta_drain_request":                   &SessionDeltaDrainRequest{},
		"session_delta_info":                            &SessionDeltaInfo{},
		"session_export_request":                        &SessionExportRequest{},
		"session_policy_list_request":                   &SessionPolicyListRequest{},
		"session_policy_match":                          &SessionPolicyMatch{},
		"session_policy_tuple":                          &SessionPolicyTuple{},
		"session_sync_request":                          &SessionSyncRequest{},
		"session_sync_request_populated":                &SessionSyncRequest{},
		"slow_path_status":                              &SlowPathStatus{},
		"snapshot_summary":                              &SnapshotSummary{},
		"syn_cookie_key_base_snapshot":                  &SYNCookieKeyBaseSnapshot{},
		"syn_cookie_key_ring_snapshot":                  &SYNCookieKeyRingSnapshot{},
		"source_nat_pool_status":                        &SourceNATPoolStatus{},
		"source_nat_rule_snapshot":                      &SourceNATRuleSnapshot{},
		"static_nat_rule_snapshot":                      &StaticNATRuleSnapshot{},
		"three_color_policer_snapshot":                  &ThreeColorPolicerSnapshot{},
		"three_color_policer_status":                    &ThreeColorPolicerStatus{},
		"three_color_policer_status_populated":          &ThreeColorPolicerStatus{},
		"tunnel_endpoint_snapshot":                      &TunnelEndpointSnapshot{},
		"tunnel_endpoint_snapshot_populated":            &TunnelEndpointSnapshot{},
		"tunnel_wg_peer_snapshot":                       &TunnelWgPeerWire{},
		"userspace_capabilities":                        &UserspaceCapabilities{},
		"wg_peer_status":                                &WgPeerStatus{},
		"wg_tunnel_status":                              &WgTunnelStatus{},
		"worker_runtime_status":                         &WorkerRuntimeStatus{},
		"worker_runtime_status_populated":               &WorkerRuntimeStatus{},
		"zone_flood_counter_status":                     &ZoneFloodCounterStatus{},
		"zone_snapshot":                                 &ZoneSnapshot{},
		"zone_traffic_counter_status":                   &ZoneTrafficCounterStatus{},
	}
}

// fixtureOnlyKeys are wire keys present in a fixture specimen but with no
// Go struct field: Rust-only telemetry the Go side intentionally ignores
// (unknown-field tolerant decode in production). Keyed by Go type name.
var fixtureOnlyKeys = map[string][]string{
	// Rust-only debug/reconcile counters on ProcessStatus; Go never
	// declared them and production decode ignores unknown keys.
	"ProcessStatus": {
		"debug_identity_slots", "debug_live_slots", "debug_planned_bindings",
		"debug_planned_workers", "debug_reconcile_calls", "debug_reconcile_stage",
		"debug_worker_threads", "ipsec_inner_worker_queue_busy_total",
	},
	// Rust BindingStatus carries socket/debug fields Go does not mirror.
	"BindingStatus": {
		"drain_sent_bytes_shaped_unconditional", "post_drain_backup_bytes",
		"socket_bind_flags", "socket_ifindex", "socket_queue_id",
	},
}

// goOnlyKeys are Go JSON keys with no Rust wire counterpart: manager-owned
// fields stamped by the Go control plane after the helper status decode
// (never reported by the helper), or Go-side-only spellings. Keyed by Go
// type name. Every entry must stay justified; a new Go wire field that
// belongs on the Rust wire must NOT be allowlisted here — it needs a Rust
// specimen instead.
var goOnlyKeys = map[string][]string{
	"ProcessStatus": {
		// Manager-owned, stamped by recordHelperStatusLocked; the helper
		// cannot report these (see protocol_status.go field comments).
		"bindings_watchdog_errors_total", "bindings_watchdog_repairs_total",
		"configured_mode", "dataplane_mode", "degraded_path_counters",
		"entry_programs", "event_stream", "last_snapshot_reject_reasons",
		"local_address_prune_skipped_total", "rst_suppression_degraded",
		"rst_suppression_failures_total", "snapshot_retry_debt",
		"snapshot_retry_debt_generation", "xdp_branch_counters",
		"zone_id_collisions",
	},
	"ConfigSnapshot":         {"mirror_exclusions", "syn_cookie_key_ring", "syn_cookie_master_key"},
	"InterfaceSnapshot":      {"logical_only"},
	"PolicerSnapshot":        {"logical_interface_policer", "then_action"},
	"TunnelEndpointSnapshot": {"wg_local_privkey_hex"},
	"TunnelWgPeerWire":       {"wg_preshared_key_hex"},
	"UserspaceCapabilities":  {"policy_content_rejected"},
	"WorkerRuntimeStatus": {
		"cold_path_alias_seen", "cold_path_first_key", "cold_path_hist",
		"cold_path_samples", "cold_path_sum_ns",
	},
}

// marshalEmittedKeys are keys emitted by a custom MarshalJSON that are
// not struct tags (ProcessStatus emits the legacy `fallback_counters`
// alias when DegradedPathCounters is non-empty). They are coverage-checked
// like Go-only keys but validated against this list, not the tag census.
var marshalEmittedKeys = map[string][]string{
	"ProcessStatus": {"fallback_counters"},
}

// secretWireKeys must never appear anywhere in the fixture: they are
// deserialize-only in Rust (`skip_serializing`), so their presence would
// mean a secret leaked into serialized output.
var secretWireKeys = []string{
	"syn_cookie_master_key",
	"wg_local_privkey_hex", "wg_preshared_key_hex",
}

func loadWireFixture16132(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	path := filepath.Join("..", "..", "..", "userspace-dp", "tests", "fixtures",
		"protocol_wire_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("wire fixture must exist (no skip-on-missing): %s: %v", path, err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(fixture) < 100 {
		t.Fatalf("wire fixture has only %d specimens; completeness gate is vacuous", len(fixture))
	}
	return fixture
}

func jsonTagKeys(t reflect.Type) map[string]bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	out := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(st reflect.Type) {
		for i := range st.NumField() {
			f := st.Field(i)
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name := strings.Split(tag, ",")[0]
			if name == "" && f.Anonymous {
				et := f.Type
				for et.Kind() == reflect.Pointer {
					et = et.Elem()
				}
				if et.Kind() == reflect.Struct {
					walk(et)
				}
				continue
			}
			if name == "" {
				name = f.Name
			}
			out[name] = true
		}
	}
	walk(t)
	for _, k := range marshalEmittedKeys[t.Name()] {
		out[k] = true
	}
	return out
}

func populateWireValue(v reflect.Value, depth int) {
	if depth > 6 || !v.CanSet() {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		populateWireValue(p.Elem(), depth+1)
		v.Set(p)
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			v.Set(reflect.ValueOf(time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)))
			return
		}
		for i := range v.NumField() {
			if v.Type().Field(i).PkgPath != "" { // unexported / json:"-" bookkeeping
				continue
			}
			populateWireValue(v.Field(i), depth+1)
		}
	case reflect.Slice:
		elem := reflect.New(v.Type().Elem()).Elem()
		populateWireValue(elem, depth+1)
		v.Set(reflect.Append(v, elem))
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		k := reflect.New(v.Type().Key()).Elem()
		populateWireValue(k, depth+1)
		elem := reflect.New(v.Type().Elem()).Elem()
		populateWireValue(elem, depth+1)
		m.SetMapIndex(k, elem)
		v.Set(m)
	case reflect.String:
		v.SetString("x16132")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(7)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1.5)
	case reflect.Interface:
		// e.g. serde_json::Value mirrors (json.RawMessage / any): a
		// non-empty object so the key is emitted.
		if v.Type().NumMethod() == 0 {
			v.Set(reflect.ValueOf(map[string]any{"x16132": true}))
		}
	}
}

// auditWireAllowlists16132 re-validates every allowlist entry against the
// live Go schema and the fixture, so an exception cannot become a stale,
// permanent blind spot (fold review on #16238):
//
//   - goOnlyKeys[T] entry: the key MUST still be declared on Go type T
//     (else stale — the field was renamed/removed and the exception is
//     masking nothing), and MUST still be absent from every fixture
//     specimen of T (else it now has a Rust counterpart — the stated
//     one-sidedness no longer holds and coverage must be required);
//   - fixtureOnlyKeys[T] entry: the key MUST still be present in at least
//     one fixture specimen of T (else stale — the Rust field is gone) and
//     MUST still be undeclared on Go type T (else the Go side grew the
//     mirror and the exception would mask a now-shared field);
//   - every allowlist type must have at least one mapped specimen, and
//     duplicate entries fail.
//
// Justifications that cannot be machine-checked (e.g. "manager-owned,
// stamped after decode") are enforced indirectly: if such a field ever
// appears in a Rust specimen, the absence check above fails and the entry
// must be removed rather than left suppressing coverage.
func auditWireAllowlists16132(t *testing.T, fixture map[string]json.RawMessage, specimens map[string]any) {
	t.Helper()

	typesByName := map[string]reflect.Type{}
	specimensByType := map[string][]string{}
	for name, proto := range specimens {
		typ := reflect.TypeOf(proto)
		typeName := typ.Elem().Name()
		typesByName[typeName] = typ
		specimensByType[typeName] = append(specimensByType[typeName], name)
	}

	fixtureKeysByType := map[string]map[string]bool{}
	for typeName, names := range specimensByType {
		set := map[string]bool{}
		for _, name := range names {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(fixture[name], &obj); err != nil {
				t.Errorf("allowlist audit: specimen %q does not parse: %v", name, err)
				continue
			}
			for k := range obj {
				set[k] = true
			}
		}
		fixtureKeysByType[typeName] = set
	}

	for _, lst := range []struct {
		name string
		m    map[string][]string
	}{{"goOnlyKeys", goOnlyKeys}, {"fixtureOnlyKeys", fixtureOnlyKeys}} {
		for typeName, keys := range lst.m {
			typ, ok := typesByName[typeName]
			if !ok {
				t.Errorf("%s: type %s has no mapped specimen — exception is unauditable and stale", lst.name, typeName)
				continue
			}
			seen := map[string]bool{}
			for _, k := range keys {
				if seen[k] {
					t.Errorf("%s[%s]: duplicate entry %q", lst.name, typeName, k)
				}
				seen[k] = true
				_ = typ
				_ = k
			}
		}
	}

	goKeysByType := map[string]map[string]bool{}
	for typeName, typ := range typesByName {
		goKeysByType[typeName] = jsonTagKeys(typ)
	}

	for typeName, keys := range goOnlyKeys {
		if _, ok := typesByName[typeName]; !ok {
			continue // already reported above
		}
		for _, k := range keys {
			if !goKeysByType[typeName][k] {
				t.Errorf("goOnlyKeys[%s]: %q is no longer declared on the Go type — stale exception, remove it", typeName, k)
			}
			if fixtureKeysByType[typeName][k] {
				t.Errorf("goOnlyKeys[%s]: %q now appears in a fixture specimen of that type — one-sidedness no longer holds, remove the exception and require coverage", typeName, k)
			}
		}
	}
	for typeName, keys := range fixtureOnlyKeys {
		if _, ok := typesByName[typeName]; !ok {
			continue // already reported above
		}
		for _, k := range keys {
			if !fixtureKeysByType[typeName][k] {
				t.Errorf("fixtureOnlyKeys[%s]: %q no longer appears in any fixture specimen of that type — stale exception, remove it", typeName, k)
			}
			if goKeysByType[typeName][k] {
				t.Errorf("fixtureOnlyKeys[%s]: %q is now declared on the Go type — one-sidedness no longer holds, remove the exception and require agreement", typeName, k)
			}
		}
	}

	// The deserialize-only secrets are allowlisted as Go-only on their Go
	// types; their absence from the fixture is separately asserted by the
	// secret scan. Re-validate here that the Go declarations still exist,
	// so removing a Go secret field cannot silently retire the guard.
	for typeName, keys := range map[string][]string{
		"ConfigSnapshot":         {"syn_cookie_master_key", "syn_cookie_key_ring"},
		"TunnelEndpointSnapshot": {"wg_local_privkey_hex"},
		"TunnelWgPeerWire":       {"wg_preshared_key_hex"},
	} {
		for _, k := range keys {
			if !goKeysByType[typeName][k] {
				t.Errorf("secret guard: Go key %q no longer declared on %s — secret-absence justification is stale", k, typeName)
			}
		}
	}
}

func TestWireFixtureCompleteness16132(t *testing.T) {
	fixture := loadWireFixture16132(t)
	specimens := wireSpecimenTypes()
	auditWireAllowlists16132(t, fixture, specimens)

	// Every fixture specimen must be mapped, and every mapped specimen
	// must exist: an unmapped specimen is uncovered wire, a missing one
	// is a deleted golden.
	for name := range fixture {
		if _, ok := specimens[name]; !ok {
			t.Errorf("fixture specimen %q has no Go type mapping in wireSpecimenTypes (uncovered wire type)", name)
		}
	}
	for name := range specimens {
		if _, ok := fixture[name]; !ok {
			t.Errorf("mapped specimen %q missing from fixture (golden deleted or renamed)", name)
		}
	}

	// Secrets must never be serialized into the fixture, at any depth.
	var checkSecrets func(string, any)
	checkSecrets = func(path string, v any) {
		switch vv := v.(type) {
		case map[string]any:
			for k, child := range vv {
				for _, s := range secretWireKeys {
					if k == s {
						t.Errorf("secret wire key %q present at %s (deserialize-only field leaked into fixture)", s, path)
					}
				}
				checkSecrets(path+"."+k, child)
			}
		case []any:
			for i, child := range vv {
				checkSecrets(fmt.Sprintf("%s[%d]", path, i), child)
			}
		}
	}
	for name, raw := range fixture {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("specimen %q does not parse: %v", name, err)
		}
		checkSecrets(name, v)
	}

	// Coverage is per Go TYPE, unioned across all specimens of that type:
	// the default specimen pins always-emitted keys, the *_populated
	// specimens pin the skip-on-default keys, and neither alone is
	// complete. A key is covered iff it appears in at least one specimen
	// of its type (fixture side) — and, symmetrically, every fixture key
	// must be declared by the Go type.
	coverageByType := map[string]map[string]bool{}
	for name, proto := range specimens {
		raw, ok := fixture[name]
		if !ok {
			continue
		}
		typeName := reflect.TypeOf(proto).Elem().Name()
		if coverageByType[typeName] == nil {
			coverageByType[typeName] = map[string]bool{}
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err == nil {
			for k := range obj {
				coverageByType[typeName][k] = true
			}
		}
	}

	totalFields := 0
	for name, proto := range specimens {
		raw, ok := fixture[name]
		if !ok {
			continue
		}
		typ := reflect.TypeOf(proto)
		typeName := typ.Elem().Name()

		var fixtureObj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fixtureObj); err != nil {
			t.Errorf("specimen %q: not a JSON object: %v", name, err)
			continue
		}
		if len(fixtureObj) == 0 {
			t.Errorf("specimen %q: empty object — positive control failed (zero-field specimen)", name)
			continue
		}

		// Strict decode: any fixture key the Go type does not declare
		// (outside the explicit Rust-only allowlist) is a rename/drift.
		allowedFixtureOnly := map[string]bool{}
		for _, k := range fixtureOnlyKeys[typeName] {
			allowedFixtureOnly[k] = true
		}
		// Specimens of the same Go type share the allowlist; strict-decode
		// check is done manually so allowlisted keys do not fail it.
		goKeys := jsonTagKeys(typ)
		for key := range fixtureObj {
			if !goKeys[key] && !allowedFixtureOnly[key] {
				t.Errorf("specimen %q: fixture key %q has no Go field on %s (Rust rename or missing Go mirror)", name, key, typeName)
			}
		}
		// Decode into a fresh value ignoring allowlisted keys, with
		// unknown-field rejection for everything else.
		filtered := map[string]json.RawMessage{}
		for k, v := range fixtureObj {
			if !allowedFixtureOnly[k] {
				filtered[k] = v
			}
		}
		filteredRaw, _ := json.Marshal(filtered)
		dst := reflect.New(typ.Elem()).Interface()
		dec := json.NewDecoder(bytes.NewReader(filteredRaw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(dst); err != nil {
			t.Errorf("specimen %q: strict Go decode into %s failed: %v", name, typeName, err)
		}

		// Marshal a fully populated Go value: every emitted key must be
		// present in this fixture specimen (or be an explicitly Go-only
		// manager-owned key). This catches Go renames and new Go wire
		// fields with no Rust specimen.
		populated := reflect.New(typ.Elem())
		populateWireValue(populated.Elem(), 0)
		goRaw, err := json.Marshal(populated.Interface())
		if err != nil {
			t.Errorf("specimen %q: marshal populated %s: %v", name, typeName, err)
			continue
		}
		var goObj map[string]json.RawMessage
		if err := json.Unmarshal(goRaw, &goObj); err != nil {
			t.Errorf("specimen %q: parse populated Go JSON: %v", name, err)
			continue
		}
		if len(goObj) == 0 {
			t.Errorf("specimen %q: populated Go %s marshaled to empty object — positive control failed", name, typeName)
			continue
		}
		allowedGoOnly := map[string]bool{}
		for _, k := range goOnlyKeys[typeName] {
			allowedGoOnly[k] = true
		}
		for _, k := range marshalEmittedKeys[typeName] {
			allowedGoOnly[k] = true
		}
		for key := range goObj {
			if !coverageByType[typeName][key] && !allowedGoOnly[key] {
				t.Errorf("specimen %q: Go key %q (on %s) absent from every fixture specimen of that type (Go rename, or Rust specimen not populated for this field)", name, key, typeName)
			}
		}
		totalFields += len(fixtureObj)
	}

	// Zero-field guard: the gate must have compared a substantial census,
	// not a handful of specimens that happen to be green.
	if totalFields < 1000 {
		t.Fatalf("wire fixture completeness compared only %d specimen fields; census is vacuous (want >= 1000)", totalFields)
	}
	t.Logf("wire fixture completeness: %d specimens, %d top-level specimen fields compared", len(specimens), totalFields)
}
