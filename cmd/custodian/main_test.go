package main

import (
	"testing"
)

func TestLoadAuthzConfigDefaults(t *testing.T) {
	t.Setenv("CUSTODIAN_IDENT_MODE", "")
	t.Setenv("CUSTODIAN_GRANTS", "")
	t.Setenv("CUSTODIAN_TRUSTED_PROXIES", "")

	cfg, err := loadAuthzConfig()
	if err != nil {
		t.Fatalf("loadAuthzConfig: %v", err)
	}
	if cfg.Mode != "metadata" {
		t.Fatalf("default mode: got %q, want %q", cfg.Mode, "metadata")
	}
	if len(cfg.Grants) != 0 {
		t.Fatalf("expected empty grants, got %#v", cfg.Grants)
	}
	want := map[string]bool{"interchange": true, "nexus-broker": true}
	if len(cfg.TrustedProxies) != len(want) || !cfg.TrustedProxies["interchange"] || !cfg.TrustedProxies["nexus-broker"] {
		t.Fatalf("default trusted proxies: got %#v, want %#v", cfg.TrustedProxies, want)
	}
}

func TestLoadAuthzConfigCertMode(t *testing.T) {
	t.Setenv("CUSTODIAN_IDENT_MODE", "cert")
	t.Setenv("CUSTODIAN_GRANTS", "croft=orgs:testorg;scopes:cred:read,cred:write")
	t.Setenv("CUSTODIAN_TRUSTED_PROXIES", "gateway-a")

	cfg, err := loadAuthzConfig()
	if err != nil {
		t.Fatalf("loadAuthzConfig: %v", err)
	}
	if cfg.Mode != "cert" {
		t.Fatalf("mode: got %q, want cert", cfg.Mode)
	}
	if _, ok := cfg.Grants["croft"]; !ok {
		t.Fatalf("expected grant for croft, got %#v", cfg.Grants)
	}
	if !cfg.TrustedProxies["gateway-a"] {
		t.Fatalf("expected trusted proxy gateway-a, got %#v", cfg.TrustedProxies)
	}
}

// CertModeEmptyGrantsLegal — cert mode with no grants is legal: only
// trusted proxies can act, everyone else is ErrUnknownIdentity at request
// time (not a startup failure).
func TestLoadAuthzConfigCertModeEmptyGrantsLegal(t *testing.T) {
	t.Setenv("CUSTODIAN_IDENT_MODE", "cert")
	t.Setenv("CUSTODIAN_GRANTS", "")
	t.Setenv("CUSTODIAN_TRUSTED_PROXIES", "")

	cfg, err := loadAuthzConfig()
	if err != nil {
		t.Fatalf("loadAuthzConfig: %v", err)
	}
	if cfg.Mode != "cert" {
		t.Fatalf("mode: got %q, want cert", cfg.Mode)
	}
	if len(cfg.Grants) != 0 {
		t.Fatalf("expected empty grants, got %#v", cfg.Grants)
	}
}

// TestLoadAuthzConfigMalformedGrantsFatal — a malformed CUSTODIAN_GRANTS must
// surface as an error from loadAuthzConfig (main treats this as fatal —
// fail closed rather than boot with a partially-parsed/absent grant table).
func TestLoadAuthzConfigMalformedGrantsFatal(t *testing.T) {
	t.Setenv("CUSTODIAN_IDENT_MODE", "cert")
	t.Setenv("CUSTODIAN_GRANTS", "not-a-valid-grant-entry")
	t.Setenv("CUSTODIAN_TRUSTED_PROXIES", "")

	if _, err := loadAuthzConfig(); err == nil {
		t.Fatal("expected error for malformed CUSTODIAN_GRANTS, got nil")
	}
}

func TestLoadAuthzConfigBadMode(t *testing.T) {
	t.Setenv("CUSTODIAN_IDENT_MODE", "bogus")
	t.Setenv("CUSTODIAN_GRANTS", "")
	t.Setenv("CUSTODIAN_TRUSTED_PROXIES", "")

	if _, err := loadAuthzConfig(); err == nil {
		t.Fatal("expected error for invalid CUSTODIAN_IDENT_MODE, got nil")
	}
}
