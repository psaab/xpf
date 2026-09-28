package daemon

import "github.com/psaab/xpf/pkg/config"

// These test-only adapters keep established daemon behavior cells focused on
// their input/output contracts while production ownership resolution lives in
// pkg/config and is shared with validators and userspace maps.
func riMemberLinuxName(cfg *config.Config, tunnelNames map[string]string, member string) string {
	keys := config.RoutingInstanceMemberDeviceKeys(cfg, tunnelNames, member)
	if len(keys) == 0 {
		return ""
	}
	return keys[0].LinuxName
}

func riMemberLinuxNames(cfg *config.Config, tunnelNames map[string]string, member string) []string {
	return config.RoutingInstanceMemberLinuxNames(cfg, tunnelNames, member)
}

func logicalUnitDeviceKey(base string, unitNum int, unit *config.InterfaceUnit) string {
	return config.LogicalUnitDeviceKey(base, unitNum, unit)
}

func logicalUnitDeviceKeyForRef(cfg *config.Config, ref string) string {
	return config.LogicalUnitDeviceKeyForRef(cfg, ref)
}

type memberDeclaredBase struct {
	base    string
	unit    int
	hasUnit bool
	ok      bool
}

func resolveMemberDeclaredBase(cfg *config.Config, member string) memberDeclaredBase {
	claim := config.ResolveRoutingInstanceMemberBase(cfg, member)
	unit := claim.Unit
	if claim.OK && !claim.HasUnit {
		// The former daemon-local shape used zero as an inert whole-device
		// value; keep old test assertions independent of the shared API.
		unit = 0
	}
	return memberDeclaredBase{
		base: claim.Base, unit: unit, hasUnit: claim.HasUnit, ok: claim.OK,
	}
}
