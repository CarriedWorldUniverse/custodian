// Command custodian is the CWB external-credential vault gRPC service. It runs
// behind interchange-gateway over mTLS; identity comes from cwb-* gRPC metadata
// injected by the gateway.
//
// Config (env):
//
//	CUSTODIAN_GRPC_ADDR    listen address (default :8085)
//	CUSTODIAN_DB           sqlite path (default /var/lib/cwb/custodian.db)
//	CUSTODIAN_ORG_SEED     base64 org base seed (single-org dev/deploy; see seed.go)
//	CUSTODIAN_TLS_CERT     path to server TLS certificate (PEM)
//	CUSTODIAN_TLS_KEY      path to server TLS private key (PEM)
//	CUSTODIAN_TLS_CA       path to client CA certificate (PEM) for mTLS
//	CUSTODIAN_DEV_INSECURE set to "1" to skip mTLS / allow an ephemeral seed (local dev only)
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"os"

	"github.com/CarriedWorldUniverse/custodian"
	cwbv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	addr := env("CUSTODIAN_GRPC_ADDR", ":8085")
	dbPath := env("CUSTODIAN_DB", "/var/lib/cwb/custodian.db")

	svc, err := custodian.New(context.Background(), custodian.Config{
		DBPath: dbPath,
	})
	if err != nil {
		log.Fatalf("custodian: open %q: %v", dbPath, err)
	}
	defer svc.Close()

	grpcSrv := grpc.NewServer(serverOptions()...)
	cwbv1.RegisterCredentialServiceServer(grpcSrv, custodian.NewCredentialServer(svc))

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

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
