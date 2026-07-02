package jwtmiddleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
)

func generateRSAKey(kid string) (*rsa.PrivateKey, jose.JSONWebKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	jwk := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     kid,
		Algorithm: "RS256",
		Use:       "sig",
	}
	return privateKey, jwk
}

func createSignedToken(privateKey *rsa.PrivateKey, kid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  time.Now().Unix(),
	})
	token.Header["kid"] = kid
	return token.SignedString(privateKey)
}

func validateToken(tokenStr string, provider *JWKSKeyProvider) (*jwt.Token, error) {
	return jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing kid")
		}
		key, err := provider.GetKey(kid)
		if err != nil {
			return nil, err
		}
		return key.Key, nil
	})
}

func TestCacheExpiration(t *testing.T) {
	privKey, jwk := generateRSAKey("key-1")
	tokenStr, err := createSignedToken(privKey, "key-1")
	if err != nil {
		tt(t.Fatalf("failed to create token: %v", err))
	}

	var fetchCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetchCount, 1)
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{jwk},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	mockTime := time.Now()
	provider := NewJWKSKeyProvider(server.URL, 10*time.Minute, 1*time.Minute)
	provider.now = func() time.Time { return mockTime }

	// First validation (triggers fetch)
	token, err := validateToken(tokenStr, provider)
	if err != nil || !token.Valid {
		t.Fatalf("expected valid token, got err: %v", err)
	}
	if atomic.LoadInt32(&fetchCount) != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount)
	}

	// Second validation (should hit cache)
	token, err = validateToken(tokenStr, provider)
	if err != nil || !token.Valid {
		t.Fatalf("expected valid token, got err: %v", err)
	}
	if atomic.LoadInt32(&fetchCount) != 1 {
		t.Errorf("expected cache hit (1 fetch), got %d", fetchCount)
	}

	// Advance time past TTL (10 minutes)
	mockTime = mockTime.Add(11 * time.Minute)

	// Third validation (should trigger refresh)
	token, err = validateToken(tokenStr, provider)
	if err != nil || !token.Valid {
		t.Fatalf("expected valid token, got err: %v", err)
	}
	if atomic.LoadInt32(&fetchCount) != 2 {
		t.Errorf("expected 2 fetches after expiration, got %d", fetchCount)
	}
}

func TestDynamicRefreshOnNewKid(t *testing.T) {
	privKeyA, jwkA := generateRSAKey("key-A")
	privKeyB, jwkB := generateRSAKey("key-B")

	tokenA, err := createSignedToken(privKeyA, "key-A")
	if err != nil {
		t.Fatalf("failed to create token A: %v", err)
	}
	tokenB, err := createSignedToken(privKeyB, "key-B")
	if err != nil {
		t.Fatalf("failed to create token B: %v", err)
	}

	var currentKeys []jose.JSONWebKey
	currentKeys = append(currentKeys, jwkA)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{
			Keys: currentKeys,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	mockTime := time.Now()
	provider := NewJWKSKeyProvider(server.URL, 10*time.Minute, 1*time.Second)
	provider.now = func() time.Time { return mockTime }

	// Validate token A (should succeed)
	tok, err := validateToken(tokenA, provider)
	if err != nil || !tok.Valid {
		t.Fatalf("expected valid token A, got err: %v", err)
	}

	// Validate token B (should fail initially because it's not in cache and not on server yet)
	_, err = validateToken(tokenB, provider)
	if err == nil {
		t.Fatal("expected error for token B, got nil")
	}

	// Update server to return both keys
	currentKeys = append(currentKeys, jwkB)

	// Advance time past minRefreshInterval (1 second)
	mockTime = mockTime.Add(2 * time.Second)

	// Validate token B (should trigger dynamic refresh and succeed)
	tok, err = validateToken(tokenB, provider)
	if err != nil || !tok.Valid {
		t.Fatalf("expected valid token B after update, got err: %v", err)
	}
}

func TestRateLimitedRefresh(t *testing.T) {
	_, jwk := generateRSAKey("key-1")

	var fetchCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetchCount, 1)
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{jwk},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	mockTime := time.Now()
	provider := NewJWKSKeyProvider(server.URL, 10*time.Minute, 5*time.Minute)
	provider.now = func() time.Time { return mockTime }

	// Request non-existent key-2 (triggers fetch)
	_, err := provider.GetKey("key-2")
	if err == nil {
		t.Fatal("expected error for key-2, got nil")
	}
	if atomic.LoadInt32(&fetchCount) != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount)
	}

	// Request non-existent key-3 immediately (should be rate limited, no fetch)
	_, err = provider.GetKey("key-3")
	if err == nil {
		t.Fatal("expected error for key-3, got nil")
	}
	if atomic.LoadInt32(&fetchCount) != 1 {
		t.Errorf("expected still 1 fetch due to rate limit, got %d", fetchCount)
	}

	// Advance time past minRefreshInterval (5 minutes)
	mockTime = mockTime.Add(6 * time.Minute)

	// Request non-existent key-4 (should trigger fetch again)
	_, err = provider.GetKey("key-4")
	if err == nil {
		t.Fatal("expected error for key-4, got nil")
	}
	if atomic.LoadInt32(&fetchCount) != 2 {
		t.Errorf("expected 2 fetches after cooldown, got %d", fetchCount)
	}
}

func TestGracefulFallback(t *testing.T) {
	privKey, jwk := generateRSAKey("key-1")
	tokenStr, err := createSignedToken(privKey, "key-1")
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	var shouldFail int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&shouldFail) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{jwk},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	mockTime := time.Now()
	provider := NewJWKSKeyProvider(server.URL, 10*time.Minute, 1*time.Minute)
	provider.now = func() time.Time { return mockTime }

	// First fetch (succeeds, cached)
	token, err := validateToken(tokenStr, provider)
	if err != nil || !token.Valid {
		t.Fatalf("expected valid token, got err: %v", err)
	}

	// Make server fail
	atomic.StoreInt32(&shouldFail, 1)

	// Advance time past TTL (10 minutes) but within hard limit (20 minutes)
	mockTime = mockTime.Add(11 * time.Minute)

	// Fetch again (should attempt refresh, fail, but fall back to cached key)
	token, err = validateToken(tokenStr, provider)
	if err != nil || !token.Valid {
		t.Fatalf("expected valid token (graceful fallback), got err: %v", err)
	}

	// Advance time past hard limit (21 minutes total)
	mockTime = mockTime.Add(11 * time.Minute)

	// Fetch again (should fail because it exceeded hard limit)
	_, err = validateToken(tokenStr, provider)
	if err == nil {
		t.Fatal("expected error (exceeded hard limit), got nil")
	}
}
