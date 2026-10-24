package config

import (
	"reflect"
	"testing"
)

// #16143: NATMatch *List() accessors are the single plural-aware read path.
// Plural supersedes scalar; scalar-only (older-peer) still yields one value;
// neither yields nil ("criterion absent"). No scalar field is retired.

func TestNATMatchAccessorsPluralSupersedesScalar16143(t *testing.T) {
	m := NATMatch{
		SourceAddress:           "10.0.0.1/32",
		SourceAddresses:         []string{"10.0.0.1/32", "10.0.0.2/32"},
		DestinationAddress:      "203.0.113.1/32",
		DestinationAddresses:    []string{"203.0.113.1/32", "203.0.113.2/32"},
		SourceAddressName:       "a1",
		SourceAddressNames:      []string{"a1", "a2"},
		DestinationAddressName:  "d1",
		DestinationAddressNames: []string{"d1", "d2"},
		Application:             "app-a",
		Applications:            []string{"app-a", "app-b"},
		Protocol:                "tcp",
		Protocols:               []string{"tcp", "udp"},
		DestinationPort:         80,
		DestinationPorts:        []int{80, 443},
	}
	if got, want := m.SourceAddressList(), []string{"10.0.0.1/32", "10.0.0.2/32"}; !reflect.DeepEqual(got, want) {
		t.Errorf("SourceAddressList = %v, want %v", got, want)
	}
	if got, want := m.DestinationAddressList(), []string{"203.0.113.1/32", "203.0.113.2/32"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DestinationAddressList = %v, want %v", got, want)
	}
	if got, want := m.SourceAddressNameList(), []string{"a1", "a2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("SourceAddressNameList = %v, want %v", got, want)
	}
	if got, want := m.DestinationAddressNameList(), []string{"d1", "d2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DestinationAddressNameList = %v, want %v", got, want)
	}
	if got, want := m.ApplicationList(), []string{"app-a", "app-b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ApplicationList = %v, want %v", got, want)
	}
	if got, want := m.ProtocolList(), []string{"tcp", "udp"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ProtocolList = %v, want %v", got, want)
	}
	if got, want := m.DestinationPortList(), []int{80, 443}; !reflect.DeepEqual(got, want) {
		t.Errorf("DestinationPortList = %v, want %v", got, want)
	}
	// Scalars retained (no retirement, #16143 narrowed form).
	if m.SourceAddress != "10.0.0.1/32" || m.DestinationAddress != "203.0.113.1/32" ||
		m.Application != "app-a" || m.DestinationPort != 80 {
		t.Errorf("scalar back-compat fields must remain populated: %+v", m)
	}
}

func TestNATMatchAccessorsScalarOnlyFallback16143(t *testing.T) {
	m := NATMatch{
		SourceAddress:          "10.0.0.1/32",
		DestinationAddress:     "203.0.113.1/32",
		SourceAddressName:      "a1",
		DestinationAddressName: "d1",
		Application:            "app-a",
		Protocol:               "tcp",
		DestinationPort:        443,
	}
	if got := m.SourceAddressList(); !reflect.DeepEqual(got, []string{"10.0.0.1/32"}) {
		t.Errorf("scalar-only SourceAddressList = %v", got)
	}
	if got := m.DestinationAddressList(); !reflect.DeepEqual(got, []string{"203.0.113.1/32"}) {
		t.Errorf("scalar-only DestinationAddressList = %v", got)
	}
	if got := m.DestinationPortList(); !reflect.DeepEqual(got, []int{443}) {
		t.Errorf("scalar-only DestinationPortList = %v", got)
	}
	if got := m.ApplicationList(); !reflect.DeepEqual(got, []string{"app-a"}) {
		t.Errorf("scalar-only ApplicationList = %v", got)
	}
}

func TestNATMatchAccessorsEmptyIsNil16143(t *testing.T) {
	m := NATMatch{}
	if m.SourceAddressList() != nil || m.DestinationAddressList() != nil ||
		m.SourceAddressNameList() != nil || m.DestinationAddressNameList() != nil ||
		m.ApplicationList() != nil || m.ProtocolList() != nil || m.DestinationPortList() != nil {
		t.Errorf("empty NATMatch accessors must be nil (criterion absent): %+v", m)
	}
}
