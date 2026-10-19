package config

// OSPFMD5Key12186 is one OSPFv2 message-digest key. Key is never included in
// conflict diagnostics.
type OSPFMD5Key12186 struct {
	ID  int
	Key Secret
}

// OSPFInterfaceUnion12186 accumulates disjoint OSPFv2 interface fragments.
// The first present value wins on conflict so tolerant rendering is stable.
type OSPFInterfaceUnion12186 struct {
	OSPFInterface
	MD5Keys []OSPFMD5Key12186
}

// OSPFv3InterfaceUnion12186 accumulates disjoint OSPFv3 interface fragments.
// The first present value wins on conflict so tolerant rendering is stable.
type OSPFv3InterfaceUnion12186 struct {
	OSPFv3Interface
}

func appendOSPFConflict12186(conflicts []string, field string) []string {
	for _, existing := range conflicts {
		if existing == field {
			return conflicts
		}
	}
	return append(conflicts, field)
}

func mergeOSPFInt12186(dst *int, src int, field string, conflicts []string) []string {
	if src == 0 {
		return conflicts
	}
	if *dst == 0 {
		*dst = src
	} else if *dst != src {
		conflicts = appendOSPFConflict12186(conflicts, field)
	}
	return conflicts
}

func mergeOSPFString12186(dst *string, src string, field string, conflicts []string) []string {
	if src == "" {
		return conflicts
	}
	if *dst == "" {
		*dst = src
	} else if *dst != src {
		conflicts = appendOSPFConflict12186(conflicts, field)
	}
	return conflicts
}

func (u *OSPFInterfaceUnion12186) mergeMD5Key12186(key OSPFMD5Key12186, conflicts []string) []string {
	for i := range u.MD5Keys {
		if u.MD5Keys[i].ID != key.ID {
			continue
		}
		if u.MD5Keys[i].Key == "" {
			u.MD5Keys[i].Key = key.Key
			if u.AuthKeyID == key.ID && u.AuthKey == "" {
				u.AuthKey = key.Key
			}
		} else if key.Key != "" && u.MD5Keys[i].Key != key.Key {
			conflicts = appendOSPFConflict12186(conflicts, "authentication md5 key")
		}
		return conflicts
	}
	u.MD5Keys = append(u.MD5Keys, key)
	if u.AuthKeyID == key.ID && u.AuthKey == "" {
		u.AuthKey = key.Key
	}
	return conflicts
}

// Merge adds the non-default settings in src without retaining aliases to its
// slices. It returns field names only; secrets and configured values never
// appear in diagnostics.
func (u *OSPFInterfaceUnion12186) Merge(src *OSPFInterface) []string {
	if src == nil {
		return nil
	}
	var conflicts []string
	if u.Name == "" {
		u.Name = src.Name
	}
	u.Passive = u.Passive || src.Passive
	u.NoPassive = u.NoPassive || src.NoPassive
	conflicts = mergeOSPFInt12186(&u.Cost, src.Cost, "cost", conflicts)
	conflicts = mergeOSPFInt12186(&u.HelloInterval, src.HelloInterval, "hello-interval", conflicts)
	conflicts = mergeOSPFInt12186(&u.DeadInterval, src.DeadInterval, "dead-interval", conflicts)
	conflicts = mergeOSPFInt12186(&u.RetransmitInt, src.RetransmitInt, "retransmit-interval", conflicts)
	if src.HasPriority {
		if !u.HasPriority {
			u.Priority = src.Priority
			u.HasPriority = true
		} else if u.Priority != src.Priority {
			conflicts = appendOSPFConflict12186(conflicts, "priority")
		}
	}
	conflicts = mergeOSPFString12186(&u.NetworkType, src.NetworkType, "interface-type", conflicts)
	u.BFD = u.BFD || src.BFD
	conflicts = mergeOSPFInt12186(&u.BFDInterval, src.BFDInterval, "bfd-liveness-detection minimum-interval", conflicts)
	conflicts = mergeOSPFInt12186(&u.BFDMultiplier, src.BFDMultiplier, "bfd-liveness-detection multiplier", conflicts)

	firstAuthType := u.AuthType
	if u.AuthType == "" {
		u.AuthType = src.AuthType
	} else if src.AuthType != "" && u.AuthType != src.AuthType {
		conflicts = appendOSPFConflict12186(conflicts, "authentication-type")
	}
	if src.AuthType != "" && src.AuthType == u.AuthType {
		switch src.AuthType {
		case "simple":
			if src.AuthKey != "" {
				if u.AuthKey == "" {
					u.AuthKey = src.AuthKey
				} else if u.AuthKey != src.AuthKey {
					conflicts = appendOSPFConflict12186(conflicts, "authentication simple-password")
				}
			}
		case "md5":
			if firstAuthType == "" {
				u.AuthKeyID = src.AuthKeyID
				u.AuthKey = src.AuthKey
			}
			if len(src.AuthMD5Keys) == 0 {
				conflicts = u.mergeMD5Key12186(
					OSPFMD5Key12186{ID: src.AuthKeyID, Key: src.AuthKey}, conflicts)
			} else {
				for _, key := range src.AuthMD5Keys {
					conflicts = u.mergeMD5Key12186(key, conflicts)
				}
			}
		}
	}
	// #15014 (A12-02): a key carried with NO type must survive the
	// union as auth-configured evidence. The switch above only copies
	// AuthKey under a matched simple/md5 type, so a typeless key was
	// dropped here and the FRR renderer's fail-closed guard
	// (`AuthType == "" && AuthKey != ""`, #14977) could never see it —
	// the interface rendered `ip ospf area` with zero auth lines.
	// Preserve the first such key (a differing second key is a
	// conflict; values are never logged) without inventing a type.
	// This arm only runs while the unioned AuthType is still "", so
	// typed fragments keep their own key handling above; if a later
	// fragment supplies a type, that type's key handling governs and
	// the renderer then requires a renderable typed key (#14977).
	if u.AuthType == "" && src.AuthKey != "" {
		if u.AuthKey == "" {
			u.AuthKey = src.AuthKey
		} else if u.AuthKey != src.AuthKey {
			conflicts = appendOSPFConflict12186(conflicts, "authentication-key")
		}
	}
	return conflicts
}

// Merge adds the non-default settings in src without retaining aliases to its
// slices. It returns field names only; secrets and configured values never
// appear in diagnostics.
func (u *OSPFv3InterfaceUnion12186) Merge(src *OSPFv3Interface) []string {
	if src == nil {
		return nil
	}
	var conflicts []string
	if u.Name == "" {
		u.Name = src.Name
	}
	u.Passive = u.Passive || src.Passive
	conflicts = mergeOSPFInt12186(&u.Cost, src.Cost, "cost", conflicts)
	conflicts = mergeOSPFInt12186(&u.HelloInterval, src.HelloInterval, "hello-interval", conflicts)
	conflicts = mergeOSPFInt12186(&u.DeadInterval, src.DeadInterval, "dead-interval", conflicts)
	conflicts = mergeOSPFInt12186(&u.RetransmitInt, src.RetransmitInt, "retransmit-interval", conflicts)
	if src.HasPriority {
		if !u.HasPriority {
			u.Priority = src.Priority
			u.HasPriority = true
		} else if u.Priority != src.Priority {
			conflicts = appendOSPFConflict12186(conflicts, "priority")
		}
	}
	u.BFD = u.BFD || src.BFD
	conflicts = mergeOSPFInt12186(&u.BFDInterval, src.BFDInterval, "bfd-liveness-detection minimum-interval", conflicts)
	conflicts = mergeOSPFInt12186(&u.BFDMultiplier, src.BFDMultiplier, "bfd-liveness-detection multiplier", conflicts)
	return conflicts
}
