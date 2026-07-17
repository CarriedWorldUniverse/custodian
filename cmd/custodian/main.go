// Command custodian is the CWB external-credential vault gRPC service. It runs
// behind interchange-gateway over mTLS.
//
// Config (env):
//
//	CUSTODIAN_GRPC_ADDR       listen address (default :8085)
//	CUSTODIAN_DB              sqlite path (default /var/lib/cwb/custodian.db)
//	CUSTODIAN_ORG_SEED        base64 org base seed (single-org dev/deploy; see seed.go)
//	CUSTODIAN_TLS_CERT        path to server TLS certificate (PEM)
//	CUSTODIAN_TLS_KEY         path to server TLS private key (PEM)
//	CUSTODIAN_TLS_CA          path to client CA certificate (PEM) for mTLS
//	CUSTODIAN_DEV_INSECURE    set to "1" to skip mTLS / allow an ephemeral seed (local dev only)
//	CUSTODIAN_IDENT_MODE      "cert" (default: identity is derived from the
//	                          verified mTLS peer certificate's Common Name and
//	                          cross-checked against CUSTODIAN_GRANTS — fails
//	                          CLOSED, so a missing/dropped env var never
//	                          silently reopens the legacy hole) or "metadata"
//	                          (legacy: identity comes from self-asserted cwb-*
//	                          gRPC metadata the gateway injects; explicit
//	                          opt-out/rollback only)
//	CUSTODIAN_GRANTS          cert-mode grant table, see authz.ParseGrants for
//	                          syntax; a malformed value is FATAL at startup
//	                          (fail closed). Ignored in metadata mode. Empty is
//	                          legal in cert mode (only trusted proxies can act).
//	CUSTODIAN_TRUSTED_PROXIES comma-separated peer Common Names, in cert mode,
//	                          whose asserted cwb-* metadata is trusted as-is
//	                          (e.g. gateways acting on behalf of other callers).
//	                          Default "interchange,nexus-broker" when unset.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"sort"

	"github.com/CarriedWorldUniverse/custodian"
	"github.com/CarriedWorldUniverse/cwb-proto/authz"
	cwbv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	addr := env("CUSTODIAN_GRPC_ADDR", ":8085")
	dbPath := env("CUSTODIAN_DB", "/var/lib/cwb/custodian.db")

	authzCfg, err := loadAuthzConfig()
	if err != nil {
		log.Fatalf("custodian: %v", err)
	}
	logAuthzConfig(authzCfg)

	svc, err := custodian.New(context.Background(), custodian.Config{
		DBPath: dbPath,
	})
	if err != nil {
		log.Fatalf("custodian: open %q: %v", dbPath, err)
	}
	defer svc.Close()

	grpcSrv := grpc.NewServer(serverOptions()...)
	cwbv1.RegisterCredentialServiceServer(grpcSrv, custodian.NewCredentialServer(svc, authzCfg))

	healthSrv := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcSrv, healthSrv)
	healthSrv.SetServingStatus("cwb.v1.CredentialService", grpc_health_v1.HealthCheckResponse_SERVING)

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("custodian: listen %s: %v", addr, err)
	}
	log.Printf("custodian gRPC listening on %s (db=%s)", addr, dbPath)
	if err := grpcSrv.Serve(lis); err != nil {
		log.Fatalf("custodian: serve: %v", err)
	}
}

// serverOptions builds the gRPC server options. When the TLS env vars are set
// the server enforces mTLS (RequireAndVerifyClientCert). Insecure mode requires
// an explicit CUSTODIAN_DEV_INSECURE=1 opt-in; missing certs without the opt-in
// cause a fatal startup error.
func serverOptions() []grpc.ServerOption {
	certFile := os.Getenv("CUSTODIAN_TLS_CERT")
	keyFile := os.Getenv("CUSTODIAN_TLS_KEY")
	caFile := os.Getenv("CUSTODIAN_TLS_CA")
	if certFile == "" || keyFile == "" || caFile == "" {
		if os.Getenv("CUSTODIAN_DEV_INSECURE") == "1" {
			log.Printf("custodian: CUSTODIAN_DEV_INSECURE=1 — starting WITHOUT mTLS (dev only)")
			return nil
		}
		log.Fatalf("custodian: mTLS required — set CUSTODIAN_TLS_CERT/_KEY/_CA (or CUSTODIAN_DEV_INSECURE=1 for local dev)")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("custodian: tls: load cert/key: %v", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("custodian: tls: read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		log.Fatalf("custodian: tls: no certs parsed from CA file %s", caFile)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}
	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsCfg))}
}

// loadAuthzConfig builds the authz.Config from CUSTODIAN_IDENT_MODE /
// CUSTODIAN_GRANTS / CUSTODIAN_TRUSTED_PROXIES. Factored out of main so
// startup config validation (in particular, that a malformed CUSTODIAN_GRANTS
// is fatal — fail closed) is directly testable. Any returned error is fatal
// at startup.
func loadAuthzConfig() (authz.Config, error) {
	// Default "cert", not "metadata": the deploy manifest sets this
	// explicitly, so the binary default only matters when the env var is
	// missing (dropped manifest field, refactor, local run, ...) — and it
	// must fail CLOSED (cert mode, empty grants ⇒ only trusted proxies can
	// act) rather than silently falling back to the legacy self-asserted
	// metadata trust model NEX-774 closed. "metadata" remains available as
	// an explicit rollback.
	mode := env("CUSTODIAN_IDENT_MODE", "cert")
	if mode != "metadata" && mode != "cert" {
		return authz.Config{}, fmt.Errorf("invalid CUSTODIAN_IDENT_MODE %q (want %q or %q)", mode, "metadata", "cert")
	}

	grants, err := authz.ParseGrants(os.Getenv("CUSTODIAN_GRANTS"))
	if err != nil {
		return authz.Config{}, fmt.Errorf("parse CUSTODIAN_GRANTS: %w", err)
	}

	proxiesRaw := env("CUSTODIAN_TRUSTED_PROXIES", "interchange,nexus-broker")
	proxies := authz.ParseProxies(proxiesRaw)

	return authz.Config{Mode: mode, Grants: grants, TrustedProxies: proxies}, nil
}

// logAuthzConfig logs the resolved identity trust model at startup — mode,
// grant count, and trusted-proxy Common Names (names only, never grant
// contents/org/scope details) — so a metadata-mode boot (the legacy,
// self-asserted trust model) is always visible in logs.
func logAuthzConfig(cfg authz.Config) {
	proxies := make([]string, 0, len(cfg.TrustedProxies))
	for cn := range cfg.TrustedProxies {
		proxies = append(proxies, cn)
	}
	sort.Strings(proxies)
	log.Printf("custodian: identity mode=%s grants=%d trusted_proxies=%v", cfg.Mode, len(cfg.Grants), proxies)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
