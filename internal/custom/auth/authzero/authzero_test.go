package authzero

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

// helper to base64url encode big int without padding
func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// buildJWKS creates a JWKS JSON for the provided RSA public key and kid.
func buildJWKS(pub *rsa.PublicKey, kid string) []byte {
	n := pub.N.Bytes()
	var eBytes []byte
	// Public exponent is small (likely 65537); convert to big-endian bytes
	e := pub.E
	if e == 65537 { // common case
		eBytes = []byte{0x01, 0x00, 0x01}
	} else {
		// generic encode
		eBytes = []byte{byte(e >> 16), byte(e >> 8), byte(e)}
	}
	jwk := map[string]any{
		"kty": "RSA",
		"kid": kid,
		"n":   b64u(n),
		"e":   b64u(eBytes),
		"alg": "RS256",
		"use": "sig",
	}
	jwks := map[string]any{"keys": []any{jwk}}
	b, _ := json.Marshal(jwks)
	return b
}

// signToken returns a signed JWT with given algorithm and claims using provided RSA key.
func signToken(t *testing.T, priv *rsa.PrivateKey, kid, alg string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.GetSigningMethod(alg), claims)
	token.Header["kid"] = kid
	s, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

// newService constructs an AuthService with a supplied JWKS JSON (bypassing Initialize for testability).
func newService(t *testing.T, jwksJSON []byte, allowed []string) *AuthService {
	t.Helper()
	// Serve the JWKS JSON via an in-memory HTTP server so we can use keyfunc.Get (mirrors production code path).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	t.Cleanup(ts.Close)

	jwks, err := keyfunc.Get(ts.URL, keyfunc.Options{})
	if err != nil {
		t.Fatalf("create jwks: %v", err)
	}
	if len(allowed) == 0 {
		allowed = []string{"RS256"}
	}
	return &AuthService{
		Config: Config{
			Name:     "test",
			Kind:     AuthServiceKind,
			Domain:   "tenant.example.com",
			Audience: "https://api.example.com",
		},
		Domain:      "tenant.example.com",
		Audience:    "https://api.example.com",
		JWKS:        jwks,
		allowedAlgs: allowed,
		leeway:      30 * time.Second,
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestAuthZero_ValidToken(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := buildJWKS(&priv.PublicKey, "kid1")
	svc := newService(t, jwks, []string{"RS256"})

	claims := jwt.MapClaims{
		"iss": "https://tenant.example.com/",
		"aud": []string{"https://api.example.com"},
		"sub": "user-123",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	tok := signToken(t, priv, "kid1", "RS256", claims)
	hdr := http.Header{"Authorization": []string{"Bearer " + tok}}
	got, err := svc.GetClaimsFromHeader(context.Background(), hdr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatalf("expected claims map, got nil")
	}
	if got["sub"] != "user-123" {
		t.Fatalf("expected sub=user-123 got %v", got["sub"])
	}
}

func TestAuthZero_MissingHeader(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	svc := newService(t, buildJWKS(&priv.PublicKey, "kid"), nil)
	got, err := svc.GetClaimsFromHeader(context.Background(), http.Header{})
	if err != nil || got != nil {
		t.Fatalf("expected (nil,nil), got (%v,%v)", got, err)
	}
}

func TestAuthZero_ExpiredToken(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	svc := newService(t, buildJWKS(&priv.PublicKey, "kid"), nil)
	claims := jwt.MapClaims{
		"iss": "https://tenant.example.com/",
		"aud": "https://api.example.com",
		"sub": "user-123",
		"exp": time.Now().Add(-1 * time.Minute).Unix(),
		"iat": time.Now().Add(-2 * time.Minute).Unix(),
	}
	tok := signToken(t, priv, "kid", "RS256", claims)
	hdr := http.Header{"Authorization": []string{"Bearer " + tok}}
	_, err := svc.GetClaimsFromHeader(context.Background(), hdr)
	if !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken got %v", err)
	}
}

func TestAuthZero_AudienceMismatch(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	svc := newService(t, buildJWKS(&priv.PublicKey, "kid"), nil)
	claims := jwt.MapClaims{
		"iss": "https://tenant.example.com/",
		"aud": "https://other.example.com",
		"sub": "user-123",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	tok := signToken(t, priv, "kid", "RS256", claims)
	hdr := http.Header{"Authorization": []string{"Bearer " + tok}}
	_, err := svc.GetClaimsFromHeader(context.Background(), hdr)
	if !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("expected ErrAudienceMismatch got %v", err)
	}
}

func TestAuthZero_AlgorithmNotAllowed(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	// Build JWKS but only allow RS256; sign with RS512 to trigger ErrAlgorithmNotAllowed
	svc := newService(t, buildJWKS(&priv.PublicKey, "kid"), []string{"RS256"})
	claims := jwt.MapClaims{
		"iss": "https://tenant.example.com/",
		"aud": "https://api.example.com",
		"sub": "user-123",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	tok := signToken(t, priv, "kid", "RS512", claims)
	hdr := http.Header{"Authorization": []string{"Bearer " + tok}}
	_, err := svc.GetClaimsFromHeader(context.Background(), hdr)
	if !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("expected ErrAlgorithmNotAllowed got %v", err)
	}
}

// (Optional) Ensure private key generation didn't produce weak modulus (basic sanity)
func TestAuthZero_KeySize(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	size := priv.N.BitLen()
	if size < 2048 {
		t.Fatalf("expected key size >=2048 got %d", size)
	}
	// Also check fingerprint generation as an internal integrity example
	der := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	sum := sha256.Sum256(der)
	// Referencing first byte so staticcheck recognizes usage beyond composite literal.
	if len(sum) != 32 || sum[0] == 0xFF { // extremely unlikely second condition; just to use sum
		t.Fatalf("unexpected fingerprint characteristics len=%d firstByte=%x", len(sum), sum[0])
	}
}
