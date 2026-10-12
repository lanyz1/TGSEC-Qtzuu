package gnmi

import (
	"context"

	"github.com/sonic-net/sonic-gnmi/common_utils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// BasicAuthenAndAuthor is the production-shaped password path used by
// authenticate() when UserAuth has password enabled. Missing username /
// password metadata is Unauthenticated — the lab negative oracle.
func BasicAuthenAndAuthor(ctx context.Context) (context.Context, error) {
	_, ctx = common_utils.GetContext(ctx)
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, status.Errorf(codes.Unknown, "Invalid context")
	}
	if _, ok := md["username"]; !ok {
		return ctx, status.Errorf(codes.Unauthenticated, "No Username Provided")
	}
	if _, ok := md["password"]; !ok {
		return ctx, status.Errorf(codes.Unauthenticated, "No Password Provided")
	}
	return ctx, status.Errorf(codes.Unauthenticated, "Unauthenticated")
}

func JwtAuthenAndAuthor(ctx context.Context) (any, context.Context, error) {
	return nil, ctx, status.Error(codes.Unauthenticated, "Unauthenticated")
}

func ClientCertAuthenAndAuthor(ctx context.Context, serviceConfigTableName string, enableCrl bool) (context.Context, error) {
	return ctx, status.Error(codes.Unauthenticated, "Unauthenticated")
}

func checkRoleAccess(auth *common_utils.AuthInfo, target string, writeAccess bool) error {
	return status.Errorf(codes.PermissionDenied, "%s does not have write access, target %s", auth.User, target)
}
