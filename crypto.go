package custodian

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	casket "github.com/CarriedWorldUniverse/casket-go"
	"golang.org/x/crypto/hkdf"
)

// orgDEKInfoPrefix namespaces custodian's per-org DEK derivation. Distinct
// `info` strings keep custodian's derivations from colliding with any other
// pillar's derivations off the same org seed (domain separation — the security
// design's §3 discipline).
const orgDEKInfoPrefix = "custodian-org-dek-v1:"

// deriveOrgDEK derives the 32-byte per-org data-encryption key from the org
// base seed: HKDF-SHA256(orgSeed, info="custodian-org-dek-v1:"+org). Every
// credential in an org is sealed under this single per-org DEK; the org-id in
// the info string is the first domain-separation level (security design §4 —
// org A literally cannot derive org B's key).
func deriveOrgDEK(orgSeed []byte, org string) ([]byte, error) {
	if len(orgSeed) == 0 {
		return nil, fmt.Errorf("custodian: deriveOrgDEK: empty org seed")
	}
	if org == "" {
		return nil, fmt.Errorf("custodian: deriveOrgDEK: empty org")
	}
	r := hkdf.New(sha256.New, orgSeed, nil, []byte(orgDEKInfoPrefix+org))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("custodian: deriveOrgDEK: %w", err)
	}
	return key, nil
}

// objectPath is the path-bound AAD component for a credential: kind+"/"+name.
// Binding the seal to this path (alongside the org as RepoIdentity) gives
// entry-swap protection — a sealed credential only opens at its own
// (org, kind, name) coordinate.
func objectPath(kind, name string) string { return kind + "/" + name }

// sealCredential seals plaintext for (org, kind, name) under the per-org DEK.
// Returns the casket envelope and the opaque 16-byte KeyRef (both base64-stored).
// casket's path-bound AAD — RepoIdentity=org, ObjectPath=kind/name — means a
// sealed value only opens at its own coordinate in its own org.
func sealCredential(orgSeed []byte, org, kind, name string, plaintext []byte) (envelope []byte, keyRef [16]byte, err error) {
	key, err := deriveOrgDEK(orgSeed, org)
	if err != nil {
		return nil, keyRef, err
	}
	if _, err := io.ReadFull(rand.Reader, keyRef[:]); err != nil {
		return nil, keyRef, fmt.Errorf("custodian: sealCredential: keyref: %w", err)
	}
	path := objectPath(kind, name)
	env, err := casket.Seal(key, plaintext, casket.SealOptions{
		KeyType:      casket.KeyTypeDerivedRepo,
		KeyRef:       keyRef,
		RepoIdentity: []byte(org),
		ObjectPath:   []byte(path),
	})
	if err != nil {
		return nil, keyRef, fmt.Errorf("custodian: sealCredential: %w", err)
	}
	return env, keyRef, nil
}

// openCredential decrypts a sealed envelope for (org, kind, name). The AAD
// (org, kind/name) must match what it was sealed under; a wrong org or path
// fails to open — cryptographically enforcing org isolation and entry-swap
// protection.
func openCredential(orgSeed []byte, org, kind, name string, envelope []byte) ([]byte, error) {
	key, err := deriveOrgDEK(orgSeed, org)
	if err != nil {
		return nil, err
	}
	path := objectPath(kind, name)
	plaintext, _, err := casket.Open(key, envelope, []byte(org), []byte(path))
	if err != nil {
		return nil, fmt.Errorf("custodian: openCredential: %w", err)
	}
	return plaintext, nil
}
