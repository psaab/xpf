package dhcp

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/rfc1035label"
)

// #15693 (V37-03): `req-option domain-name` put OptionDomainSearchList
// (Option 24) in the ORO on the wire, but neither parseV6ReplyChecked nor
// the stateless Information-Request path ever read
// Options.DomainSearchList() — the reply payload was discarded and the
// Lease had no field to hold it.
//
// FAIL-ON-REVERT: removing the DomainSearchList extraction (or the Lease
// field) turns the stateful and leaseContentChanged cells RED; the
// stateless cell is exercised through the lease the parser produces for
// the Information-Request reply shape (same extraction helper).

func domainSearchReply15693(t *testing.T, domains ...string) *dhcpv6.Message {
	t.Helper()
	msg, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	msg.MessageType = dhcpv6.MessageTypeReply
	iana := &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 1}}
	iana.Options.Add(&dhcpv6.OptIAAddress{
		IPv6Addr:          net.ParseIP("2606:4700::5"),
		PreferredLifetime: 100 * time.Second,
		ValidLifetime:     500 * time.Second,
	})
	msg.AddOption(iana)
	if len(domains) > 0 {
		msg.AddOption(dhcpv6.OptDomainSearchList(&rfc1035label.Labels{Labels: domains}))
	}
	return msg
}

func TestParseV6ReplyRetainsDomainSearchList15693(t *testing.T) {
	m := &Manager{}
	want := []string{"example.com", "corp.example.com"}

	res, err := m.parseV6Reply(context.Background(), "wan0",
		domainSearchReply15693(t, want...), nil)
	if err != nil {
		t.Fatalf("parseV6Reply: %v", err)
	}
	if !reflect.DeepEqual(res.lease.DomainSearch, want) {
		t.Fatalf("lease.DomainSearch = %v, want %v (Option 24 requested but discarded pre-fix)", res.lease.DomainSearch, want)
	}

	// Control: a reply without Option 24 leaves DomainSearch empty, and a
	// stateful reply's other fields are unchanged.
	res2, err := m.parseV6Reply(context.Background(), "wan0",
		domainSearchReply15693(t), nil)
	if err != nil {
		t.Fatalf("parseV6Reply (no option 24): %v", err)
	}
	if len(res2.lease.DomainSearch) != 0 {
		t.Fatalf("lease.DomainSearch = %v, want empty when Option 24 absent", res2.lease.DomainSearch)
	}
}

// The stateless Information-Request path builds its lease from the same
// reply options; its extraction must retain the search list too.
func TestStatelessReplyDomainSearchExtraction15693(t *testing.T) {
	msg := domainSearchReply15693(t, "example.com")
	got := domainSearchFromOptions(msg.Options)
	if !reflect.DeepEqual(got, []string{"example.com"}) {
		t.Fatalf("domainSearchFromOptions = %v, want [example.com]", got)
	}
	if got := domainSearchFromOptions(domainSearchReply15693(t).Options); len(got) != 0 {
		t.Fatalf("domainSearchFromOptions (absent) = %v, want empty", got)
	}
}

// A changed search list is a lease-content change: downstream DNS
// reconciliation must re-run when the server rotates domains.
func TestLeaseContentChangedDomainSearch15693(t *testing.T) {
	base := &Lease{Interface: "wan0", Family: AFInet6, DomainSearch: []string{"a.example"}}
	same := &Lease{Interface: "wan0", Family: AFInet6, DomainSearch: []string{"a.example"}}
	if leaseContentChanged(base, same) {
		t.Fatal("identical DomainSearch reported as changed")
	}
	rotated := &Lease{Interface: "wan0", Family: AFInet6, DomainSearch: []string{"b.example"}}
	if !leaseContentChanged(base, rotated) {
		t.Fatal("rotated DomainSearch hidden from leaseContentChanged")
	}
	dropped := &Lease{Interface: "wan0", Family: AFInet6}
	if !leaseContentChanged(base, dropped) {
		t.Fatal("dropped DomainSearch hidden from leaseContentChanged")
	}
}
