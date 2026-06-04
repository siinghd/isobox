// Package auth resolves a request's API key to an opaque, server-side tenant ID.
//
// The single security invariant of isobox multi-tenancy:
//
//	tenant_id is derived SERVER-SIDE from the API key the authMiddleware already
//	sees (X-API-Key / Bearer). It is NEVER read from a request body, query string,
//	path segment, or any other client-controlled field.
//
// tenant_id = hex(sha256(apiKey)): a 64-char hex string. It is stable (same key
// => same tenant forever), opaque (does not reveal the key), and path-safe by
// construction (only [0-9a-f]), so it can be used directly as a directory name
// (/var/lib/isobox/vol/<tenant>/...) and a bbolt filename (<tenant>.bolt) with no
// escaping.
//
// Modes:
//   - EMPTY keystore (no keys configured) => Resolve returns ("public", true).
//     This is open / demo mode: a single shared "public" tenant. The service still
//     works with no auth configured, and all of its data lands under one tenant.
//   - NON-EMPTY keystore => only keys whose hash is in the allowlist resolve;
//     an unknown key returns ("", false) and the caller must answer 401.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// PublicTenant is the single shared tenant used in open/demo mode (empty keystore).
// It is deliberately NOT a valid sha256 hex string (it is too short and not hex),
// so it can never collide with a real key-derived tenant ID.
const PublicTenant = "public"

// KeyStore is an allowlist of authorized tenants. It stores only the DERIVED
// tenant IDs (hex(sha256(key))), never the raw keys — keeping plaintext secrets
// out of long-lived process memory, and making Resolve a uniform constant-time
// comparison against fixed-width (64-char) hex strings.
//
// A KeyStore is immutable after construction and safe for concurrent use.
type KeyStore struct {
	tenants []string // each is a 64-char hex(sha256(key)); empty slice => open mode
}

// NewKeyStore builds a KeyStore from raw API keys. Surrounding whitespace is
// trimmed and blank entries are skipped (so a file with trailing newlines or an
// env var with stray spaces behaves sensibly). Duplicate keys collapse to one
// tenant. An empty/whitespace-only input yields an EMPTY keystore => open mode.
//
// Callers that explicitly configured a key source but got zero keys back should
// treat that as a misconfiguration and fail closed (see cmd/isoboxd wiring) —
// NewKeyStore itself does not distinguish "nothing configured" from "configured
// but empty"; that decision belongs to the wiring, which knows the source.
func NewKeyStore(rawKeys []string) *KeyStore {
	seen := make(map[string]struct{}, len(rawKeys))
	tenants := make([]string, 0, len(rawKeys))
	for _, k := range rawKeys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		tid := deriveTenant(k)
		if _, dup := seen[tid]; dup {
			continue
		}
		seen[tid] = struct{}{}
		tenants = append(tenants, tid)
	}
	return &KeyStore{tenants: tenants}
}

// Len reports the number of distinct configured keys (0 => open mode). Used by
// the wiring to log the mode and by tests; never affects Resolve's contract.
func (k *KeyStore) Len() int { return len(k.tenants) }

// Resolve maps an API key to its tenant ID.
//
//   - Empty keystore => ("public", true): open/demo mode, one shared tenant.
//   - Non-empty keystore, key present => (hex(sha256(key)), true).
//   - Non-empty keystore, key absent  => ("", false): caller must 401.
//
// The comparison is constant-time with respect to the configured secrets: we
// derive the candidate tenant ID, then compare it against EVERY configured
// tenant ID, OR-accumulating the result without an early return. Every operand
// is a fixed 64-char hex string, so the per-iteration work is uniform and the
// loop length depends only on the number of keys (public information), never on
// the key bytes themselves.
func (k *KeyStore) Resolve(apiKey string) (string, bool) {
	if len(k.tenants) == 0 {
		return PublicTenant, true // open mode — NOT hex(sha256("")).
	}
	tid := deriveTenant(apiKey)
	cand := []byte(tid)
	var matched int
	for _, t := range k.tenants {
		// All operands are 64-char hex strings => ConstantTimeCompare runs in
		// time independent of where (or whether) a match occurs.
		matched |= subtle.ConstantTimeCompare(cand, []byte(t))
	}
	if matched == 1 {
		return tid, true
	}
	return "", false
}

// deriveTenant is the one and only place the tenant ID is computed from a key.
func deriveTenant(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:]) // 64 lowercase hex chars: [0-9a-f]
}

// --- request-context plumbing ----------------------------------------------
//
// The tenant is written into the request context ONCE, by authMiddleware, and
// read everywhere downstream via TenantFrom. Handlers must never re-derive it or
// read it from the request — they take it from the context the middleware set.

type ctxKey struct{}

// WithTenant returns a copy of ctx carrying the resolved tenant ID. Called only
// by authMiddleware after a successful Resolve.
func WithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, ctxKey{}, tenant)
}

// TenantFrom returns the tenant ID placed in ctx by authMiddleware. ok is false
// if no tenant is present — which means the request bypassed authMiddleware, a
// programming error: a handler that needs a tenant must 500 (NOT silently fall
// back to "public") so a routing mistake can never leak across tenants.
func TenantFrom(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(ctxKey{}).(string)
	return t, ok && t != ""
}
