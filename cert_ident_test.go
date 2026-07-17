package custodian

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/CarriedWorldUniverse/cwb-proto/authz"
	cwbv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// ---- test PKI (mirrors cwb-proto/authz's authz_test.go helpers) ----------

type certTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCertTestCA(t *testing.T) *certTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &certTestCA{cert: cert, key: key, pool: pool}
}

func (ca *certTestCA) leaf(t *testing.T, cn string, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key for %s: %v", cn, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf cert for %s: %v", cn, err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ---- test harness: real custodian gRPC server over mTLS/bufconn ----------

const certTestBufSize = 1024 * 1024

// startCertModeServer starts the real custodian gRPC server (grpcserver.go
// handlers, backed by a temp sqlite store) requiring and verifying client
// certificates, running in cert mode per authzCfg.
func startCertModeServer(t *testing.T, ca *certTestCA, authzCfg authz.Config) (svc *Service, dial func(context.Context, string) (net.Conn, error)) {
	t.Helper()
	svc = newTestService(t)

	lis := bufconn.Listen(certTestBufSize)
	serverCert := ca.leaf(t, "test-server", true)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool,
		MinVersion:   tls.VersionTLS12,
	}

	grpcSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	cwbv1.RegisterCredentialServiceServer(grpcSrv, NewCredentialServer(svc, authzCfg))

	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	return svc, func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	}
}

func dialCertMode(t *testing.T, ca *certTestCA, dial func(context.Context, string) (net.Conn, error), clientCert tls.Certificate) cwbv1.CredentialServiceClient {
	t.Helper()
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ca.pool,
		ServerName:   "localhost",
	}
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(dial),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return cwbv1.NewCredentialServiceClient(conn)
}

func certModeSetReq(kind, name string) *cwbv1.SetCredentialRequest {
	return &cwbv1.SetCredentialRequest{
		Kind: kind, Name: name,
		Bundle: &cwbv1.SetCredentialRequest_SecretBundle{SecretBundle: &cwbv1.SecretBundle{
			Value: "s3cr3t", Host: "db.example.com", Username: "app",
		}},
	}
}

// certModeGrants used across the tests below:
//
//	croft          — orgs:testorg;   scopes:cred:read,cred:write
//	reader-only    — orgs:testorg;   scopes:cred:read   (used for the scope-escalation case)
//	trusted-proxy  — no grant entry; listed in TrustedProxies instead
//	(stranger has no grant entry at all, and is not a trusted proxy)
func certModeGrants(t *testing.T) map[string]authz.Grant {
	t.Helper()
	grants, err := authz.ParseGrants(
		"croft=orgs:testorg;scopes:cred:read,cred:write|" +
			"reader-only=orgs:testorg;scopes:cred:read")
	if err != nil {
		t.Fatalf("ParseGrants: %v", err)
	}
	return grants
}

func TestCertModeRoundTrip(t *testing.T) {
	ca := newCertTestCA(t)
	cfg := authz.Config{
		Mode:           "cert",
		Grants:         certModeGrants(t),
		TrustedProxies: authz.ParseProxies("trusted-proxy"),
	}
	svc, dial := startCertModeServer(t, ca, cfg)
	client := dialCertMode(t, ca, dial, ca.leaf(t, "croft", false))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.SetCredential(ctx, certModeSetReq("secret", "db-pass")); err != nil {
		t.Fatalf("SetCredential: %v", err)
	}
	resp, err := client.Fetch(ctx, &cwbv1.FetchRequest{Kind: "secret", Name: "db-pass"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	sb := resp.GetSecretBundle()
	if sb == nil || sb.GetValue() != "s3cr3t" {
		t.Fatalf("unexpected bundle: %+v", resp)
	}
	if n := auditCount(t, svc, "testorg", "denied"); n != 0 {
		t.Fatalf("expected no denials, got %d", n)
	}
}

func TestCertModeOrgMismatch(t *testing.T) {
	ca := newCertTestCA(t)
	cfg := authz.Config{Mode: "cert", Grants: certModeGrants(t)}
	svc, dial := startCertModeServer(t, ca, cfg)
	client := dialCertMode(t, ca, dial, ca.leaf(t, "croft", false))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("cwb-org", "some-other-org"))

	_, err := client.SetCredential(ctx, certModeSetReq("secret", "db-pass"))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	reason := auditReason(t, svc, "some-other-org", "denied")
	if !hasPrefix(reason, "ident-mismatch") {
		t.Fatalf("want reason prefixed ident-mismatch, got %q", reason)
	}
}

func TestCertModeSubjectMismatch(t *testing.T) {
	ca := newCertTestCA(t)
	cfg := authz.Config{Mode: "cert", Grants: certModeGrants(t)}
	svc, dial := startCertModeServer(t, ca, cfg)
	client := dialCertMode(t, ca, dial, ca.leaf(t, "croft", false))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("cwb-subject", "other"))

	_, err := client.SetCredential(ctx, certModeSetReq("secret", "db-pass"))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	reason := auditReason(t, svc, "", "denied")
	if !hasPrefix(reason, "ident-mismatch") {
		t.Fatalf("want reason prefixed ident-mismatch, got %q", reason)
	}
}

func TestCertModeUnknownIdentity(t *testing.T) {
	ca := newCertTestCA(t)
	cfg := authz.Config{Mode: "cert", Grants: certModeGrants(t)}
	svc, dial := startCertModeServer(t, ca, cfg)
	client := dialCertMode(t, ca, dial, ca.leaf(t, "stranger", false))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.Fetch(ctx, &cwbv1.FetchRequest{Kind: "secret", Name: "db-pass"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	reason := auditReason(t, svc, "", "denied")
	if reason != "unknown-identity" {
		t.Fatalf("want reason %q, got %q", "unknown-identity", reason)
	}
}

func TestCertModeTrustedProxyHonored(t *testing.T) {
	ca := newCertTestCA(t)
	cfg := authz.Config{
		Mode:           "cert",
		Grants:         certModeGrants(t),
		TrustedProxies: authz.ParseProxies("trusted-proxy"),
	}
	_, dial := startCertModeServer(t, ca, cfg)
	client := dialCertMode(t, ca, dial, ca.leaf(t, "trusted-proxy", false))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(
		"cwb-subject", "proxied-user",
		"cwb-org", "arbitrary-org",
		"cwb-scopes", "cred:read cred:write",
	))

	if _, err := client.SetCredential(ctx, certModeSetReq("secret", "db-pass")); err != nil {
		t.Fatalf("SetCredential: %v", err)
	}
	resp, err := client.Fetch(ctx, &cwbv1.FetchRequest{Kind: "secret", Name: "db-pass"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if resp.GetSecretBundle().GetValue() != "s3cr3t" {
		t.Fatalf("unexpected bundle: %+v", resp)
	}
}

func TestCertModeScopeEscalation(t *testing.T) {
	ca := newCertTestCA(t)
	cfg := authz.Config{Mode: "cert", Grants: certModeGrants(t)}
	svc, dial := startCertModeServer(t, ca, cfg)
	client := dialCertMode(t, ca, dial, ca.leaf(t, "reader-only", false))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("cwb-scopes", "cred:write"))

	_, err := client.SetCredential(ctx, certModeSetReq("secret", "db-pass"))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	// No cwb-org was asserted (org was implied by the single-org grant), so
	// the audit row's org is "" — only what was actually asserted/proven is
	// recorded.
	reason := auditReason(t, svc, "", "denied")
	if !hasPrefix(reason, "ident-mismatch") {
		t.Fatalf("want reason prefixed ident-mismatch, got %q", reason)
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
