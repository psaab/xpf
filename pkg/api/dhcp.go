package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/grpcapi"
)

func (s *Server) dhcpLeasesHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dhcp == nil {
		writeOK(w, []DHCPLeaseInfo{})
		return
	}
	writeOK(w, restDHCPLeases(s.dhcp.Leases(), s.dhcp.DelegatedPrefixes()))
}

// restDHCPLeases renders the REST lease table from the SAME aggregation the gRPC
// GetDHCPLeases RPC uses (grpcapi.BuildDHCPLeasesResponse), so the two surfaces
// cannot disagree about a lease again (#9413). Before this, REST built its rows
// from Leases() alone and never consulted DelegatedPrefixes(), so a DHCPv6
// prefix-delegation-only interface reported an empty lease table over REST while
// gRPC and the CLI showed the delegation. Pure, so it is testable without a live
// dhcp.Manager.
func restDHCPLeases(leases []*dhcp.Lease, pds []dhcp.DelegatedPrefix) []DHCPLeaseInfo {
	resp := grpcapi.BuildDHCPLeasesResponse(leases, pds)
	result := make([]DHCPLeaseInfo, 0, len(resp.Leases))
	for _, l := range resp.Leases {
		info := DHCPLeaseInfo{
			Interface: l.Interface,
			Family:    l.Family,
			Address:   l.Address,
			Gateway:   l.Gateway,
			DNS:       l.Dns,
			LeaseTime: l.LeaseTime,
			Obtained:  l.Obtained,
		}
		if info.DNS == nil {
			info.DNS = []string{}
		}
		for _, dp := range l.DelegatedPrefixes {
			info.DelegatedPrefixes = append(info.DelegatedPrefixes, DHCPDelegatedPrefixInfo{
				Interface:         dp.Interface,
				Prefix:            dp.Prefix,
				PreferredLifetime: dp.PreferredLifetime,
				ValidLifetime:     dp.ValidLifetime,
				Obtained:          dp.Obtained,
			})
		}
		result = append(result, info)
	}
	return result
}

func (s *Server) dhcpIdentifiersHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dhcp == nil {
		writeOK(w, []DHCPClientIdentifierInfo{})
		return
	}

	duids := s.dhcp.DUIDs()
	result := make([]DHCPClientIdentifierInfo, len(duids))
	for i, d := range duids {
		result[i] = DHCPClientIdentifierInfo{
			Interface: d.Interface,
			Type:      d.Type,
			Display:   d.Display,
			Hex:       d.HexBytes,
		}
	}
	writeOK(w, result)
}

func (s *Server) clearDHCPIdentifiersHandler(w http.ResponseWriter, r *http.Request) {
	if s.dhcp == nil {
		writeOK(w, map[string]string{"message": "No DHCP clients running"})
		return
	}

	var req ClearDHCPIdentifierRequest
	// #4794: gate on ContentLength != 0, not > 0. A chunked-encoded request
	// (Transfer-Encoding: chunked) reports ContentLength == -1 (unknown
	// length), so the old "> 0" gate skipped the body decode entirely and
	// fell through to ClearAllDUIDs() below even when the operator's body
	// asked to clear a single interface -- wiping every DHCPv6 DUID instead.
	// ContentLength == 0 (a genuinely empty body, no Transfer-Encoding) still
	// skips the decode, matching the documented "no interface = clear all"
	// contract. A chunked request that happens to carry zero bytes hits
	// io.EOF on Decode, which is tolerated below (not a 400) for the same
	// reason.
	if r.ContentLength != 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}

	if req.Interface != "" {
		if err := s.dhcp.ClearDUID(req.Interface); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeOK(w, map[string]string{"message": fmt.Sprintf("DHCPv6 DUID cleared for %s", req.Interface)})
		return
	}

	if err := s.dhcp.ClearAllDUIDs(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]string{"message": "All DHCPv6 DUIDs cleared"})
}
