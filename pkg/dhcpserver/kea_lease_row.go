package dhcpserver

import (
	"strconv"
	"time"
)

// keaLeaseRow is the authoritative projection of one lease as Kea reports it
// in lease{4,6}-get-all or stores it in the memfile. It carries the complete
// lease data needed by both HA lease sync and the DDNS view; consumers derive
// their own narrower model with toSync or toDDNS rather than projecting one
// consumer's type into the other.
type keaLeaseRow struct {
	Family int

	Address     string
	HWAddress   string
	ClientID    string
	DUID        string
	IAID        uint32
	IAIDRaw     string
	IAIDOK      bool
	LeaseType   string
	LeaseTypeOK bool
	PrefixLen   int
	SubnetID    int
	SubnetIDRaw string

	Hostname string
	FQDNFwd  bool
	FQDNRev  bool

	Expire         int64
	ValidLifetime  int
	PrefLifetime   int
	PrefLifetimeOK bool
	State          State
}

// toSync builds the portable HA contract from the authoritative lease fields.
// Both transport decoders use this conversion so their SyncLease outputs cannot
// drift by silently omitting columns that the other consumer does not need.
func (r keaLeaseRow) toSync(now time.Time) SyncLease {
	leaseType := r.LeaseType
	if r.Family != 6 {
		leaseType = ""
	}

	l := SyncLease{
		Family:    r.Family,
		Address:   r.Address,
		SubnetID:  r.SubnetID,
		HWAddress: r.HWAddress,
		ClientID:  r.ClientID,
		DUID:      r.DUID,
		IAID:      r.IAID,
		LeaseType: leaseType,
		PrefixLen: r.PrefixLen,
		Hostname:  r.Hostname,
		FQDNFwd:   r.FQDNFwd,
		FQDNRev:   r.FQDNRev,
		ValidLife: r.ValidLifetime,
		State:     int(r.State),
	}
	if r.Family == 6 && (r.LeaseType == "IA_NA" || r.LeaseType == "IA_TA") {
		// SyncLease documents IA_NA/IA_TA bindings as PrefixLen=0. The
		// memfile writer stores /128; Kea's socket omits prefix_len for non-PD.
		// Normalize both readers to the portable contract, including synthetic
		// socket responses that unexpectedly supply a value.
		l.PrefixLen = 0
	}

	rem := r.Expire - now.Unix()
	if rem < 0 {
		rem = 0
	}
	l.Remaining = int(rem)
	l.PreferredRemaining = l.Remaining
	if r.Family == 6 && r.PrefLifetimeOK {
		l.PreferredRemaining = clampPreferredRemaining(
			l.Remaining-(r.ValidLifetime-r.PrefLifetime), l.Remaining)
	}
	return l
}

// toDDNS derives the narrower lease shape used by the DDNS reconciler. HA-only
// fields remain solely on keaLeaseRow and never become baggage on ddnsLease.
func (r keaLeaseRow) toDDNS() ddnsLease {
	hostName, clientFQDN := r.Hostname, ""
	if r.FQDNFwd {
		hostName, clientFQDN = "", r.Hostname
	}
	identity := ""
	if r.Family == 6 {
		identity = identity6(r.DUID, r.IAIDRaw)
	} else {
		identity = identity4(r.ClientID, r.HWAddress)
	}

	leaseType, leaseTypeOK := keaLeaseTypeIANA, r.LeaseTypeOK
	if r.Family == 6 && leaseTypeOK {
		switch r.LeaseType {
		case "IA_NA":
			leaseType = keaLeaseTypeIANA
		case "IA_TA":
			leaseType = keaLeaseTypeIATA
		case "IA_PD":
			leaseType = keaLeaseTypeIAPD
		default:
			if value, err := strconv.Atoi(r.LeaseType); err == nil {
				leaseType = value
			} else {
				leaseTypeOK = false
			}
		}
	}
	return ddnsLease{
		Family:      r.Family,
		Address:     r.Address,
		Identity:    identity,
		SubnetID:    r.SubnetIDRaw,
		HostName:    hostName,
		ClientFQDN:  clientFQDN,
		LeaseType:   leaseType,
		LeaseTypeOK: leaseTypeOK,
	}
}

func keaLeaseRowFromSocket(kl keaLeaseJSON, family int) keaLeaseRow {
	r := keaLeaseRow{
		Family:        family,
		Address:       kl.IPAddress,
		HWAddress:     kl.HWAddress,
		ClientID:      kl.ClientID,
		DUID:          kl.DUID,
		SubnetID:      kl.SubnetID,
		LeaseType:     kl.Type,
		LeaseTypeOK:   true,
		PrefixLen:     kl.PrefixLen,
		Hostname:      kl.Hostname,
		FQDNFwd:       kl.FQDNFwd,
		FQDNRev:       kl.FQDNRev,
		ValidLifetime: kl.ValidLft,
		Expire:        kl.Expire,
		State:         State(kl.State),
	}
	if kl.IAID != nil {
		r.IAID = *kl.IAID
	}
	if kl.PreferredLft != nil {
		r.PrefLifetime = *kl.PreferredLft
		r.PrefLifetimeOK = true
	}
	if r.Expire == 0 {
		r.Expire = kl.CLTT + int64(kl.ValidLft)
	}
	return r
}
