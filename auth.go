package custodian

import "context"

// AuthClaims is the caller identity custodian operates under. It is populated
// from the cwb-* gRPC metadata the interchange gateway injects (see
// mdident.go); custodian has no embedded token path of its own — identity is
// always gateway-derived. The Org is the cryptographic boundary: every
// credential is sealed under that org's DEK and every query is org-scoped.
type AuthClaims struct {
	Sub string // cwb-subject: the calling service/aspect identity
	Org string // cwb-org: the tenant; the DEK + every store call scope to it
}

type contextKey string

const authClaimsKey contextKey = "auth"

// AuthFromContext returns the claims carried by ctx, or nil.
func AuthFromContext(ctx context.Context) *AuthClaims {
	claims, _ := ctx.Value(authClaimsKey).(*AuthClaims)
	return claims
}

// ContextWithAuth returns ctx carrying the given auth claims, retrievable via
// AuthFromContext. It is the seam the gRPC handlers use to thread the
// gateway-derived identity into the org-scoped store calls.
func ContextWithAuth(ctx context.Context, claims *AuthClaims) context.Context {
	return context.WithValue(ctx, authClaimsKey, claims)
}
