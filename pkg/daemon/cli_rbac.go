package daemon

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/cli"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/osident"
)

// userClassSetter is the SetUserClass seam applyCLILoginClass writes through.
// Production passes the real *cli.CLI; the test passes a recorder, so the
// daemon-side wiring is asserted without standing up a shell.
type userClassSetter interface {
	SetUserClass(class string)
}

// applyCLILoginClass sets the RBAC login class on the in-process console shell
// from the invoking process's OS credential (#6701).
//
// It replaces:
//
//	osUser := os.Getenv("USER")
//	found := false
//	for _, u := range cfg.System.Login.Users {
//	    if u.Name == osUser { shell.SetUserClass(u.Class); found = true; break }
//	}
//	if !found { shell.SetUserClass("super-user") }
//
// Two independent holes, either sufficient on its own:
//
//   - `$USER` is attacker-controlled. Before #6701 it was used to find the
//     login class, so a caller could spoof another account or unset it. The
//     kernel real uid now supplies identity instead: pkg/osident resolves that
//     uid through passwd and the caller's environment cannot rewrite it. #10833
//     separately closes the old direct-bash path by assigning class-specific
//     OS login shells; identity still must not depend on the environment.
//
//   - the `!found` default PROMOTED. An OS account that exists on the box but
//     is absent from `system login` — and, before the fix, any caller at all —
//     received the highest class in the system. cli.ResolveLoginClass defaults
//     DOWN to cli.ClassUnidentified (`unauthorized`: an empty-but-PRESENT
//     permission set, so checkPermission denies every command by name and
//     showConfigRedacted masks secrets). uid 0 keeps the Junos-parity
//     super-user default, but only when `system login` says nothing about it —
//     an explicit `system login user root class <c>` still wins, because a
//     configured restriction silently ignored is the very defect being removed.
//
// The `cfg.System.Login == nil` early return is deliberate and is NOT a
// fail-open FOR A CONFIG THAT NEVER CONFIGURED RBAC: the class is left UNSET,
// which is pkg/cli's documented legacy allow-everything mode (permissions.go
// checkPermission / showConfigRedacted both short-circuit on the empty class).
// That contract is unchanged here.
//
// It IS a fail-open for the OTHER config that arrives as `Login == nil`, and
// that is what LoginDroppedByPacking separates (#6706 review). A `system login`
// path packed onto an ancestor line compiles the stanza away entirely:
//
//	system login user alice class ops;      -> System.Login == nil
//
// Strict commit REJECTS that (#6662), so an operator typing it never gets here.
// The tolerant ingress does not: Store.Load at boot and Store.SyncApply from a
// peer downgrade the finding to a warning and KEEP the config (#1960 no-brick),
// so a node can boot — or a standby can inherit — a config that reads as
// restrictive and lands in legacy allow-everything, with IKE PSKs, SNMP
// communities and authentication-keys rendered in CLEARTEXT. Taking the early
// return on that config is the RBAC hole, not the legacy contract.
//
// The same flag closes a second, quieter divergence. `system login;` written
// packed compiles nil (permit everyone) while the NESTED `system { login; }`
// compiles a non-nil empty LoginConfig (deny every non-root caller). The packed
// gate stays silent on that prefix on purpose — rejecting it would reject
// config master accepts — so the flag is what makes the two spellings agree
// where it matters, at runtime, without inventing a commit rejection.
//
// Resolving a DROPPED login through ResolveLoginClass with the nil config is
// exactly right rather than a special case: identity.go documents nil as
// "nothing is configured about root", so every non-root caller takes
// ClassUnidentified and uid 0 keeps the console lifeline — which is precisely
// what the nested spelling of the same text produces.
//
// Every resolution is logged once, at shell startup — not in a loop — so an
// operator locked out by their own config can see exactly why in the journal.
func applyCLILoginClass(shell userClassSetter, cfg *config.Config, id osident.Identity) {
	if shell == nil || cfg == nil {
		return
	}
	if cfg.System.Login == nil && !cfg.System.LoginDroppedByPacking {
		return
	}
	if cfg.System.Login == nil {
		slog.Warn("CLI RBAC: `system login` was authored packed onto an ancestor "+
			"statement line and compiled away; refusing the legacy unset-class mode",
			"identity", id.String(), "uid", id.UID)
	}
	class, reason := cli.ResolveLoginClass(cfg.System.Login, id)
	if class == cli.ClassUnidentified {
		slog.Warn("CLI RBAC: caller is not authorized by `system login`",
			"identity", id.String(), "uid", id.UID, "class", class, "reason", reason)
	} else {
		slog.Info("CLI RBAC: resolved login class",
			"identity", id.String(), "uid", id.UID, "class", class, "reason", reason)
	}
	shell.SetUserClass(class)
}
