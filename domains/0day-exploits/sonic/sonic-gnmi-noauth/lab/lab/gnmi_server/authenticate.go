package gnmi

import (
	"context"
	"net"

	"github.com/sonic-net/sonic-gnmi/common_utils"
	log "github.com/golang/glog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func authenticate(config *Config, ctx context.Context, target string, writeAccess bool) (context.Context, error) {
	var err error
	success := false
	rc, ctx := common_utils.GetContext(ctx)

	// Skip authentication for UDS (Unix Domain Socket) connections.
	// UDS security is enforced at the file-system level via socket permissions.
	if isUnixPeer(ctx) {
		rc.Auth.AuthEnabled = false
		return ctx, nil
	}

	if !config.UserAuth.Any() {
		//No Auth enabled
		rc.Auth.AuthEnabled = false
		return ctx, nil
	}

	rc.Auth.AuthEnabled = true
	if config.UserAuth.Enabled("password") {
		ctx, err = BasicAuthenAndAuthor(ctx)
		if err == nil {
			success = true
		}
	}
	if !success && config.UserAuth.Enabled("jwt") {
		_, ctx, err = JwtAuthenAndAuthor(ctx)
		if err == nil {
			success = true
		}
	}
	if !success && config.UserAuth.Enabled("cert") {
		ctx, err = ClientCertAuthenAndAuthor(ctx, config.ConfigTableName, config.EnableCrl)
		if err == nil {
			success = true
		}
	}

	//Allow for future authentication mechanisms here...

	if !success {
		return ctx, status.Error(codes.Unauthenticated, "Unauthenticated")
	}

	// Role-based authorization: applied uniformly to whichever mechanism
	// succeeded. Historically this check was nested inside the cert branch,
	// which allowed password- and JWT-authenticated callers to bypass the
	// readonly/readwrite gate for gNOI RPCs.
	//
	// Guarded by ConfigTableName to preserve existing behavior for
	// deployments that do not configure a role source (e.g. TACACS-only
	// setups or upgrade paths where GNMI_CLIENT_CERT is empty).
	if config.ConfigTableName != "" {
		if err := checkRoleAccess(&rc.Auth, target, writeAccess); err != nil {
			return ctx, err
		}
	}

	log.V(5).Infof("authenticate user %v, roles %v", rc.Auth.User, rc.Auth.Roles)

	return ctx, nil
}

func isUnixPeer(ctx context.Context) bool {
	pr, ok := peer.FromContext(ctx)
	if !ok || pr.Addr == nil {
		return false
	}
	_, ok = pr.Addr.(*net.UnixAddr)
	return ok
}
