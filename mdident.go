package custodian

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/CarriedWorldUniverse/cwb-proto/authz"
	"google.golang.org/grpc/metadata"
)

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

// peerCommonName returns the verified peer TLS client certificate's Common
// Name, or "" if unavailable (no peer, no TLS, or no verified chain). Used
// only to attribute denial audit rows to the cert-derived identity — never
// to authorize a request (that's authz.Identify's job).
func peerCommonName(ctx context.Context) string {
	cn, err := authz.PeerCommonName(ctx)
	if err != nil {
		return ""
	}
	return cn
}

// requestedOrgMD returns the cwb-org value asserted in ctx's incoming
// metadata, or "" if absent. Used for audit attribution on identity denials
// — never trusted for authorization.
func requestedOrgMD(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	v := md.Get("cwb-org")
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// claimedMDSummary renders a short, secret-free summary of the cwb-subject/
// cwb-org/cwb-scopes metadata a caller asserted, for inclusion in a denial
// audit reason (e.g. `sub="anvil" org="testorg"`). Values are %q-quoted —
// they are caller-supplied and otherwise could inject fake-looking
// "key=value" tokens (e.g. a subject of `evil org=carriedworld`) into the
// human-read audit reason.
func claimedMDSummary(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	get := func(k string) string {
		v := md.Get(k)
		if len(v) == 0 {
			return ""
		}
		return v[0]
	}
	var parts []string
	if v := get("cwb-subject"); v != "" {
		parts = append(parts, fmt.Sprintf("sub=%q", v))
	}
	if v := get("cwb-org"); v != "" {
		parts = append(parts, fmt.Sprintf("org=%q", v))
	}
	if v := get("cwb-scopes"); v != "" {
		parts = append(parts, fmt.Sprintf("scopes=%q", v))
	}
	// Caller-supplied values; cap the summary so a hostile client can't bloat
	// audit rows (gRPC caps headers anyway — this is table hygiene). Truncate
	// on a rune boundary so a multi-byte rune straddling the cutoff isn't split.
	return truncateRunes(strings.Join(parts, " "), 200)
}

// truncateRunes returns s if it's at most n bytes, else the longest prefix
// of s that is both <= n bytes and ends on a rune boundary, plus an
// ellipsis marker.
func truncateRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
