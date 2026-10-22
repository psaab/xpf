package config

// #8939 at `system dataplane` and its `shared-umem` sub-container: a packed run
// set only its FIRST option.
//
//	set system dataplane binary /usr/sbin/x claim-host-tunables true
//	  -> Binary set; ClaimHostTunables DROPPED
//
// Both compile loops switch on `child.Name()`, and the packed spelling is ONE
// child node carrying the whole run on its Keys.
//
// `control-socket` is the loss worth naming: when it is dropped the daemon falls
// back to a default path, and #9003 records what that default was — a socket in
// /tmp that MkdirAll would adopt with no peer check. An operator who moved the
// socket off /tmp in the same statement as another option did not move it.
func systemDataplaneSchema8939() *schemaNode {
	return refSystemDataplane.resolve()
}

// systemDataplaneSharedUMEMSchema8939 resolves the `shared-umem` body.
func systemDataplaneSharedUMEMSchema8939() *schemaNode {
	return refSystemDataplaneSharedUMEM.resolve()
}
