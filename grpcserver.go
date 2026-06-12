package custodian

import (
	"context"
	"errors"

	cwbv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// credentialServer implements cwbv1.CredentialServiceServer. Identity comes
// from the cwb-* gRPC metadata; the org is taken only from there. Scopes:
// cred:read gates Fetch/List, cred:write gates SetCredential.
type credentialServer struct {
	cwbv1.UnimplementedCredentialServiceServer
	svc *Service
}

// NewCredentialServer wraps svc in the gRPC credential service implementation.
func NewCredentialServer(svc *Service) *credentialServer { return &credentialServer{svc: svc} }

// Fetch returns the decrypted credential bundle for (kind, name). Requires
// cred:read. Every call is audited — the store audits success/miss, and this
// handler audits a scope denial. Dispatches on kind: "git" → GitBundle,
// "oauth" → OAuthBundle.
func (s *credentialServer) Fetch(ctx context.Context, r *cwbv1.FetchRequest) (*cwbv1.FetchResponse, error) {
	claims, scopes, ok := identityFromMD(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing identity")
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
// Dispatches on kind: "oauth" → SetOAuthCredential, default → SetCredential
// (git). The bundle field in the request must match the kind.
func (s *credentialServer) SetCredential(ctx context.Context, r *cwbv1.SetCredentialRequest) (*cwbv1.SetCredentialResponse, error) {
	claims, scopes, ok := identityFromMD(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing identity")
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
	claims, scopes, ok := identityFromMD(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing identity")
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
