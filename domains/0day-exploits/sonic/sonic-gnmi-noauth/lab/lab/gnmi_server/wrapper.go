package gnmi

import "context"

// Authenticate is the exported lab entry that calls production authenticate()
// with writeAccess=true (gNMI Set / gNOI write path).
func Authenticate(config *Config, ctx context.Context, target string, writeAccess bool) (context.Context, error) {
	return authenticate(config, ctx, target, writeAccess)
}
