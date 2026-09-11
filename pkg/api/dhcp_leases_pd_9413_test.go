package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/grpcapi"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func fixtureLeases9413() ([]*dhcp.Lease, []dhcp.DelegatedPrefix) {
	obtained := time.Date(2026, 9, 11, 1, 0, 0, 0, time.UTC)
	leases := []*dhcp.Lease{
		{Interface: "ge-0-0-1", Family: dhcp.AFInet, Address: netip.MustParsePrefix("192.0.2.10/24"),
			Gateway: netip.MustParseAddr("192.0.2.1"), DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")},
			LeaseTime: time.Hour, Obtained: obtained},
		{Interface: "ge-0-0-3", Family: dhcp.AFInet6, Address: netip.MustParsePrefix("2001:db8:3::10/128"),
			LeaseTime: 2 * time.Hour, Obtained: obtained},
	}
	pds := []dhcp.DelegatedPrefix{
		// PD-only interface: no IA_NA lease at all on ge-0-0-2.
		{Interface: "ge-0-0-2", Prefix: netip.MustParsePrefix("2001:db8:2::/56"),
			PreferredLifetime: 30 * time.Minute, ValidLifetime: time.Hour, Obtained: obtained},
		// Attaches to ge-0-0-3's inet6 address lease.
		{Interface: "ge-0-0-3", Prefix: netip.MustParsePrefix("2001:db8:30::/60"),
			PreferredLifetime: 45 * time.Minute, ValidLifetime: 90 * time.Minute, Obtained: obtained},
	}
	return leases, pds
}

// #9413: a prefix-delegation-only interface must produce a usable REST row that
// carries its delegation, not an empty lease table.
func TestRESTDHCPLeasesReportsPDOnlyInterface_9413(t *testing.T) {
	_, pds := fixtureLeases9413()
	rows := restDHCPLeases(nil, pds[:1])
	if len(rows) != 1 {
		t.Fatalf("#9413: a PD-only interface must yield one REST row, got %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.Interface != "ge-0-0-2" || r.Family != "inet6" || len(r.DelegatedPrefixes) != 1 || r.DelegatedPrefixes[0].Prefix != "2001:db8:2::/56" {
		t.Fatalf("#9413: PD-only row must be inet6 on ge-0-0-2 carrying 2001:db8:2::/56, got %+v", r)
	}
	body, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"delegated_prefixes":[{"interface":"ge-0-0-2","prefix":"2001:db8:2::/56"`) {
		t.Fatalf("#9413: REST JSON does not carry the delegation: %s", body)
	}
}

// #9413: a delegation on an interface that also has an inet6 address lease is
// attached to that row, and an unrelated inet lease is unchanged.
func TestRESTDHCPLeasesAttachesPDToInet6Lease_9413(t *testing.T) {
	leases, pds := fixtureLeases9413()
	rows := restDHCPLeases(leases, pds[1:])
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (inet + inet6-with-PD), got %d: %+v", len(rows), rows)
	}
	if rows[0].Interface != "ge-0-0-1" || rows[0].Address != "192.0.2.10/24" || rows[0].Gateway != "192.0.2.1" || len(rows[0].DelegatedPrefixes) != 0 {
		t.Fatalf("the inet lease row changed: %+v", rows[0])
	}
	if rows[1].Interface != "ge-0-0-3" || rows[1].Address != "2001:db8:3::10/128" || len(rows[1].DelegatedPrefixes) != 1 || rows[1].DelegatedPrefixes[0].Prefix != "2001:db8:30::/60" {
		t.Fatalf("#9413: the delegation must attach to ge-0-0-3's inet6 lease: %+v", rows[1])
	}
}

// #9413 acceptance: PD-only and mixed leases render identically on REST and gRPC,
// modulo the envelope. Compared by value, row for row.
func TestRESTAndGRPCDHCPLeasesAgree_9413(t *testing.T) {
	leases, pds := fixtureLeases9413()
	rest := restDHCPLeases(leases, pds)
	grpc := grpcapi.BuildDHCPLeasesResponse(leases, pds).Leases
	if len(rest) != len(grpc) || len(rest) != 3 {
		t.Fatalf("row counts differ or wrong: rest=%d grpc=%d (want 3)", len(rest), len(grpc))
	}
	for i := range rest {
		r, g := rest[i], grpc[i]
		if r.Interface != g.Interface || r.Family != g.Family || r.Address != g.Address || r.Gateway != g.Gateway ||
			r.LeaseTime != g.LeaseTime || r.Obtained != g.Obtained || !reflect.DeepEqual(r.DNS, g.Dns) ||
			len(r.DelegatedPrefixes) != len(g.DelegatedPrefixes) {
			t.Fatalf("#9413: row %d differs between REST and gRPC:\n rest=%+v\n grpc=%+v", i, r, g)
		}
		for j := range r.DelegatedPrefixes {
			rd, gd := r.DelegatedPrefixes[j], g.DelegatedPrefixes[j]
			if rd.Interface != gd.Interface || rd.Prefix != gd.Prefix || rd.PreferredLifetime != gd.PreferredLifetime ||
				rd.ValidLifetime != gd.ValidLifetime || rd.Obtained != gd.Obtained {
				t.Fatalf("#9413: row %d delegation %d differs:\n rest=%+v\n grpc=%+v", i, j, rd, gd)
			}
		}
	}
}

// #9413 field-parity contract: every field of the gRPC lease messages must have a
// REST JSON counterpart, so a field added to the proto and not to REST reds here
// instead of drifting silently the way delegated_prefixes did.
func TestRESTDHCPLeaseTypesMirrorEveryProtoField_9413(t *testing.T) {
	for _, tc := range []struct {
		msg  protoreflect.MessageDescriptor
		rest reflect.Type
	}{
		{(&pb.DHCPLeaseInfo{}).ProtoReflect().Descriptor(), reflect.TypeOf(DHCPLeaseInfo{})},
		{(&pb.DHCPDelegatedPrefix{}).ProtoReflect().Descriptor(), reflect.TypeOf(DHCPDelegatedPrefixInfo{})},
	} {
		tags := map[string]bool{}
		for i := 0; i < tc.rest.NumField(); i++ {
			tags[strings.Split(tc.rest.Field(i).Tag.Get("json"), ",")[0]] = true
		}
		fields := tc.msg.Fields()
		for i := 0; i < fields.Len(); i++ {
			name := string(fields.Get(i).Name())
			if !tags[name] {
				t.Errorf("#9413: gRPC %s.%s has no REST JSON field in %s", tc.msg.Name(), name, tc.rest.Name())
			}
		}
	}
}

// #9413 wiring: the cells above drive restDHCPLeases directly, so they cannot see
// the handler passing nil instead of DelegatedPrefixes(). This one goes through the
// real handler with a Manager holding a PD-only delegation.
func TestRESTDHCPLeasesHandlerWiresDelegatedPrefixes_9413(t *testing.T) {
	_, pds := fixtureLeases9413()
	m := dhcp.NewManagerForTesting(nil)
	m.SeedDelegatedPrefixesForTesting("ge-0-0-2", pds[:1])
	s := &Server{dhcp: m}
	rec := httptest.NewRecorder()
	s.dhcpLeasesHandler(rec, httptest.NewRequest(http.MethodGet, "/api/v1/dhcp/leases", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("handler status = %d, body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"delegated_prefixes":[{"interface":"ge-0-0-2","prefix":"2001:db8:2::/56"`) {
		t.Fatalf("#9413: the REST handler dropped the PD-only interface's delegation: %s", rec.Body.String())
	}
}
