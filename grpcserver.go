package custodian

import (
	"context"
	"errors"

	"github.com/CarriedWorldUniverse/cwb-proto/authz"
	cwbv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// credentialServer implements cwbv1.CredentialServiceServer. Identity is
// derived via authz.Identify per authzCfg — "metadata" mode trusts the cwb-*
// gRPC metadata interchange injects (legacy); "cert" mode derives it from
// the verified mTLS peer certificate and cross-checks any asserted metadata
// against a grant table (see mdident.go / cwb-proto/authz). The org is
// always taken from the derived claims, never the request body. Scopes:
// cred:read gates Fetch/List, cred:write gates SetCredential.
type credentialServer struct {
	cwbv1.UnimplementedCredentialServiceServer
	svc      *Service
	authzCfg authz.Config
}

// NewCredentialServer wraps svc in the gRPC credential service implementation,
// deriving caller identity per authzCfg (see authz.Config).
func NewCredentialServer(svc *Service, authzCfg authz.Config) *credentialServer {
	return &credentialServer{svc: svc, authzCfg: authzCfg}
}

// identify derives the caller's AuthClaims + scopes for the given request
// (kind/name only used for denial-audit attribution). On failure it audits
// mismatch/unknown-identity denials (attributed to the cert-derived peer
// identity, never the unproven metadata) and returns a ready-to-return gRPC
// status error; a missing/absent identity (metadata mode with no cwb-*
// headers, or cert mode with no peer cert) is Unauthenticated with no audit
// row, matching the legacy identityFromMD(ctx) !ok behavior.
func (s *credentialServer) identify(ctx context.Context, kind, name string) (*AuthClaims, []string, error) {
	claims, scopes, err := authz.Identify(ctx, s.authzCfg)
	if err == nil {
		return &AuthClaims{Sub: claims.Sub, Org: claims.Org}, scopes, nil
	}

	switch {
	case errors.Is(err, authz.ErrMismatch):
		reason := "ident-mismatch"
		if extra := claimedMDSummary(ctx); extra != "" {
			reason += ": claimed " + extra
		}
		s.svc.AuditDenied(ctx, &AuthClaims{Sub: peerCommonName(ctx), Org: requestedOrgMD(ctx)}, kind, name, reason)
		return nil, nil, status.Error(codes.PermissionDenied, "identity denied")
	case errors.Is(err, authz.ErrUnknownIdentity):
		s.svc.AuditDenied(ctx, &AuthClaims{Sub: peerCommonName(ctx), Org: requestedOrgMD(ctx)}, kind, name, "unknown-identity")
		return nil, nil, status.Error(codes.PermissionDenied, "identity denied")
	default: // ErrNoPeerCert, ErrNoIdentity, ErrBadMode
		return nil, nil, status.Error(codes.Unauthenticated, "missing identity")
	}
}

// Fetch returns the decrypted credential bundle for (kind, name). Requires
// cred:read. Every call is audited — the store audits success/miss, and this
// handler audits a scope denial. Dispatches on kind: "git" → GitBundle,
// "oauth" → OAuthBundle, "secret" → SecretBundle.
func (s *credentialServer) Fetch(ctx context.Context, r *cwbv1.FetchRequest) (*cwbv1.FetchResponse, error) {
	claims, scopes, err := s.identify(ctx, r.GetKind(), r.GetName())
	if err != nil {
		return nil, err
	}
	if !hasScope(scopes, scopeCredRead) {
		s.svc.AuditDenied(ctx, claims, r.GetKind(), r.GetName(), "missing scope "+scopeCredRead)
		return nil, status.Error(codes.PermissionDenied, "missing scope "+scopeCredRead)
	}
	authCtx := ContextWithAuth(ctx, claims)
	switch r.GetKind() {
	case KindOAuth:
		ob, meta, err := s.svc.FetchOAuth(authCtx, r.GetKind(), r.GetName())
		if err != nil {
			return nil, toStatus(err)
		}
		return &cwbv1.FetchResponse{
			Kind: meta.Kind,
			Name: meta.Name,
			Bundle: &cwbv1.FetchResponse_OauthBundle{OauthBundle: &cwbv1.OAuthBundle{
				ClientId:     ob.ClientID,
				ClientSecret: ob.ClientSecret,
				RefreshToken: ob.RefreshToken,
				TokenUri:     ob.TokenURI,
				Scope:        ob.Scope,
			}},
		}, nil
	case KindSecret:
		sb, meta, err := s.svc.FetchSecret(authCtx, r.GetKind(), r.GetName())
		if err != nil {
			return nil, toStatus(err)
		}
		return &cwbv1.FetchResponse{
			Kind: meta.Kind,
			Name: meta.Name,
			Bundle: &cwbv1.FetchResponse_SecretBundle{SecretBundle: &cwbv1.SecretBundle{
				Value:    sb.Value,
				Host:     sb.Host,
				Username: sb.Username,
			}},
		}, nil
	default:
		gb, meta, err := s.svc.Fetch(authCtx, r.GetKind(), r.GetName())
		if err != nil {
			return nil, toStatus(err)
		}
		return &cwbv1.FetchResponse{
			Kind: meta.Kind,
			Name: meta.Name,
			Bundle: &cwbv1.FetchResponse_GitBundle{GitBundle: &cwbv1.GitBundle{
				Username: gb.Username,
				Password: gb.Password,
				Host:     gb.Host,
			}},
		}, nil
	}
}

// SetCredential seals and stores a credential bundle. Requires cred:write.
// Dispatches on kind: "oauth" → SetOAuthCredential, "secret" →
// SetSecretCredential, default → SetCredential (git). The bundle field in the
// request must match the kind.
func (s *credentialServer) SetCredential(ctx context.Context, r *cwbv1.SetCredentialRequest) (*cwbv1.SetCredentialResponse, error) {
	claims, scopes, err := s.identify(ctx, r.GetKind(), r.GetName())
	if err != nil {
		return nil, err
	}
	if !hasScope(scopes, scopeCredWrite) {
		s.svc.AuditDenied(ctx, claims, r.GetKind(), r.GetName(), "missing scope "+scopeCredWrite)
		return nil, status.Error(codes.PermissionDenied, "missing scope "+scopeCredWrite)
	}
	authCtx := ContextWithAuth(ctx, claims)
	switch r.GetKind() {
	case KindOAuth:
		pob := r.GetOauthBundle()
		if pob == nil {
			return nil, status.Error(codes.InvalidArgument, "oauth_bundle is required for kind=oauth")
		}
		m, err := s.svc.SetOAuthCredential(authCtx, r.GetKind(), r.GetName(), OAuthBundle{
			ClientID:     pob.GetClientId(),
			ClientSecret: pob.GetClientSecret(),
			RefreshToken: pob.GetRefreshToken(),
			TokenURI:     pob.GetTokenUri(),
			Scope:        pob.GetScope(),
		})
		if err != nil {
			return nil, toStatus(err)
		}
		return &cwbv1.SetCredentialResponse{Item: toProtoMeta(m)}, nil
	case KindSecret:
		psb := r.GetSecretBundle()
		if psb == nil {
			return nil, status.Error(codes.InvalidArgument, "secret_bundle is required for kind=secret")
		}
		m, err := s.svc.SetSecretCredential(authCtx, r.GetKind(), r.GetName(), SecretBundle{
			Value:    psb.GetValue(),
			Host:     psb.GetHost(),
			Username: psb.GetUsername(),
		})
		if err != nil {
			return nil, toStatus(err)
		}
		return &cwbv1.SetCredentialResponse{Item: toProtoMeta(m)}, nil
	default:
		pgb := r.GetGitBundle()
		if pgb == nil {
			return nil, status.Error(codes.InvalidArgument, "git_bundle is required")
		}
		m, err := s.svc.SetCredential(authCtx, r.GetKind(), r.GetName(), GitBundle{
			Username: pgb.GetUsername(),
			Password: pgb.GetPassword(),
			Host:     pgb.GetHost(),
		})
		if err != nil {
			return nil, toStatus(err)
		}
		return &cwbv1.SetCredentialResponse{Item: toProtoMeta(m)}, nil
	}
}

// ListCredentials lists credential metadata — never secret material. Requires
// cred:read.
func (s *credentialServer) ListCredentials(ctx context.Context, r *cwbv1.ListCredentialsRequest) (*cwbv1.ListCredentialsResponse, error) {
	claims, scopes, err := s.identify(ctx, r.GetKind(), "")
	if err != nil {
		return nil, err
	}
	if !hasScope(scopes, scopeCredRead) {
		s.svc.AuditDenied(ctx, claims, r.GetKind(), "", "missing scope "+scopeCredRead)
		return nil, status.Error(codes.PermissionDenied, "missing scope "+scopeCredRead)
	}
	metas, err := s.svc.ListCredentials(ContextWithAuth(ctx, claims), r.GetKind())
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*cwbv1.CredentialMeta, 0, len(metas))
	for i := range metas {
		out = append(out, toProtoMeta(&metas[i]))
	}
	return &cwbv1.ListCredentialsResponse{Items: out}, nil
}

// DeleteCredential removes the credential for (kind, name) in the caller's
// org. Requires cred:write. Idempotent: a missing row returns deleted=false,
// not an error.
func (s *credentialServer) DeleteCredential(ctx context.Context, r *cwbv1.DeleteCredentialRequest) (*cwbv1.DeleteCredentialResponse, error) {
	claims, scopes, err := s.identify(ctx, r.GetKind(), r.GetName())
	if err != nil {
		return nil, err
	}
	if !hasScope(scopes, scopeCredWrite) {
		s.svc.AuditDenied(ctx, claims, r.GetKind(), r.GetName(), "missing scope "+scopeCredWrite)
		return nil, status.Error(codes.PermissionDenied, "missing scope "+scopeCredWrite)
	}
	deleted, err := s.svc.DeleteCredential(ContextWithAuth(ctx, claims), r.GetKind(), r.GetName())
	if err != nil {
		return nil, toStatus(err)
	}
	return &cwbv1.DeleteCredentialResponse{Deleted: deleted}, nil
}

// toProtoMeta converts internal CredentialMeta to the wire type.
func toProtoMeta(m *CredentialMeta) *cwbv1.CredentialMeta {
	if m == nil {
		return nil
	}
	return &cwbv1.CredentialMeta{
		Kind:      m.Kind,
		Name:      m.Name,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
		Writer:    m.Writer,
	}
}

// toStatus maps custodian error sentinels to gRPC status codes.
func toStatus(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ErrInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ErrKindUnsup):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ErrNoSeed):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
