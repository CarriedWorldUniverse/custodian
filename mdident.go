package custodian

import (
	"context"
	"strings"

	"google.golang.org/grpc/metadata"
)

// identityFromMD reads the cwb-* gRPC metadata keys injected by interchange and
// returns AuthClaims + scopes. Returns (nil, nil, false) if either cwb-subject
// or cwb-org is absent (the gateway always sets both for authed requests; their
// absence means the request didn't transit the gateway). The org is taken ONLY
// from here — never from a request body — so org isolation can't be bypassed
// by a crafted payload.
func identityFromMD(ctx context.Context) (claims *AuthClaims, scopes []string, ok bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, nil, false
	}
	get := func(k string) string {
		v := md.Get(k)
		if len(v) == 0 {
			return ""
		}
		return v[0]
	}
	sub := get("cwb-subject")
	org := get("cwb-org")
	if sub == "" || org == "" {
		return nil, nil, false
	}
	c := &AuthClaims{Sub: sub, Org: org}
	sc := strings.Fields(get("cwb-scopes"))
	return c, sc, true
}

// custodian scope vocabulary.
//
//	cred:read  → Fetch / ListCredentials
//	cred:write → SetCredential
//	admin:write → superset of cred:* (a convenience for platform admins)
const (
	scopeCredRead   = "cred:read"
	scopeCredWrite  = "cred:write"
	scopeAdminWrite = "admin:write"
)

// hasScope reports whether the caller holds the required scope. admin:write is
// a superset for the ordinary cred:* scopes.
func hasScope(have []string, need string) bool {
	for _, s := range have {
		if s == need {
			return true
		}
		if s == scopeAdminWrite {
			return true
		}
	}
	return false
}
