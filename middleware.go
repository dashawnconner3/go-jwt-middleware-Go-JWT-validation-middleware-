package jwtmiddleware

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const (
	ClaimsContextKey contextKey = "claims"
)

type Options struct {
	JWKSUri                string
	JWKSCacheTTL           time.Duration
	JWKSMinRefreshInterval time.Duration
}

type JWKSMiddleware struct {
	options  Options
	provider *JWKSKeyProvider
}

func New(opts Options) *JWKSMiddleware {
	if opts.JWKSCacheTTL <= 0 {
		opts.JWKSCacheTTL = 24 * time.Hour
	}
	if opts.JWKSMinRefreshInterval <= 0 {
		opts.JWKSMinRefreshInterval = 5 * time.Minute
	}
	return &JWKSMiddleware{
		options:  opts,
		provider: NewJWKSKeyProvider(opts.JWKSUri, opts.JWKSCacheTTL, opts.JWKSMinRefreshInterval),
	}
}

func (m *JWKSMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Required authorization token not found", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "Authorization header format must be Bearer {token}", http.StatusUnauthorized)
			return
		}

		tokenStr := parts[1]
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, errors.New("missing kid in token header")
			}

			key, err := m.provider.GetKey(kid)
			if err != nil {
				return nil, err
			}
			return key.Key, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ClaimsContextKey, token.Claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
