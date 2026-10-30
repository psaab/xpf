package daemon

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"slices"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// #18374: every daemon ownership install goes through this builder, so the
// session-sync generation advances only when something a bulk reconcile reads
// actually changed (see pkg/cluster/sync_zone_ownership_18374.go).
//
// The ingress fold closure (ingressFoldFromNames) captures exactly two
// things: the compiled config, through ClusterStableIfaceName, and the
// ifindex->name table read from the kernel. The digest hashes those same two
// things, from the same table the closure was built from:
//
//   - the config by the store's canonical text digest (ActiveDigestFor). It is
//     "" unless cfg IS the store's compiled active config, and "" makes the
//     whole digest unknown, so an apply of anything else (a candidate, a test
//     double) keeps the pre-#18374 always-advance behaviour. A DNS-refreshed
//     clone shares the text digest; DNS answers are runtime address-book state
//     (json:"-") that the fold does not read.
//   - the ifindex->name table, the map the closure looks names up in. Link
//     state, flags, MTU and addresses are not in it and do not change a fold;
//     a recreated netdev (#15263) changes its ifindex, which does.
//
// The NAT-scope folder is built from the same table so the two folders cannot
// disagree about the device set, but it is not part of the digest: no bulk
// reconcile reads it (SetNatScopeFoldFn).

// ingressFoldNameTable is the ifindex->name table the ingress fold closes
// over. buildIngressFoldFnWithIfaces and ingressFoldDigest both use it, so the
// digest cannot describe a different table than the closure captured.
func ingressFoldNameTable(ifaces []net.Interface) map[uint32]string {
	nameByIndex := make(map[uint32]string, len(ifaces))
	for _, ifc := range ifaces {
		if ifc.Index > 0 {
			nameByIndex[uint32(ifc.Index)] = ifc.Name
		}
	}
	return nameByIndex
}

// ingressFoldDigest fingerprints an ingress fold closure built from cfg and
// nameByIndex. cfgDigest is the store's canonical text digest for cfg; an
// empty one yields the zero (unknown) digest.
func ingressFoldDigest(cfgDigest string, nameByIndex map[uint32]string) cluster.ResolverDigest {
	if cfgDigest == "" {
		return cluster.ResolverDigest{}
	}
	h := sha256.New()
	var n [4]byte
	writeField := func(b []byte) {
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	writeField([]byte("xpf/18374/ingress-fold/v1"))
	writeField([]byte(cfgDigest))
	indexes := make([]uint32, 0, len(nameByIndex))
	for idx := range nameByIndex {
		indexes = append(indexes, idx)
	}
	slices.Sort(indexes)
	for _, idx := range indexes {
		binary.BigEndian.PutUint32(n[:], idx)
		h.Write(n[:])
		writeField([]byte(nameByIndex[idx]))
	}
	var out cluster.ResolverDigest
	copy(out[:], h.Sum(nil))
	return out
}

// zoneOwnershipFromIfaces builds one ownership install for cfg from ONE
// interface table. cfgDigest is ActiveDigestFor(cfg) ("" = unknown).
func zoneOwnershipFromIfaces(cfg *config.Config, zoneRG cluster.ZoneRGMap, cfgDigest string, ifaces []net.Interface) cluster.ZoneOwnership {
	own := cluster.ZoneOwnership{ZoneRG: zoneRG, FoldRG: buildZoneFoldRGMap(cfg)}
	if cfg == nil {
		return own
	}
	names := ingressFoldNameTable(ifaces)
	own.IngressFold = ingressFoldFromNames(cfg, names)
	own.NatScopeFold = buildNatScopeFoldFnWithIfaces(cfg, ifaces)
	own.ResolverDigest = ingressFoldDigest(cfgDigest, names)
	return own
}

// zoneOwnershipInstall builds the install for cfg against the live kernel
// interface table (listIfaces nil) or an injected one (tests). A table read
// error installs no resolvers and an unknown digest, matching
// buildIngressFoldFn's error arm.
func (d *Daemon) zoneOwnershipInstall(cfg *config.Config, zoneRG cluster.ZoneRGMap, listIfaces func() ([]net.Interface, error)) cluster.ZoneOwnership {
	if listIfaces == nil {
		listIfaces = net.Interfaces
	}
	ifaces, err := listIfaces()
	if err != nil {
		return cluster.ZoneOwnership{ZoneRG: zoneRG, FoldRG: buildZoneFoldRGMap(cfg)}
	}
	var cfgDigest string
	if d.store != nil && cfg != nil {
		cfgDigest = d.store.ActiveDigestFor(cfg)
	}
	return zoneOwnershipFromIfaces(cfg, zoneRG, cfgDigest, ifaces)
}
