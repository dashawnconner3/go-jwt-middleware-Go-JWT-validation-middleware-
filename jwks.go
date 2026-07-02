package jwtmiddleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
)

type jwksCache struct {
	sync.RWMutex
	keys        map[string]jose.JSONWebKey
	lastFetched time.Time
	expiresAt   time.Time
}

type JWKSKeyProvider struct {
	jwksURI            string
	cacheTTL           time.Duration
	minRefreshInterval time.Duration
	client             *http.Client
	cache              jwksCache
	now                func() time.Time
}

func NewJWKSKeyProvider(jwksURI string, cacheTTL, minRefreshInterval time.Duration) *JWKSKeyProvider {
	if cacheTTL <= 0 {
		cacheTTL = 24 * time.Hour
	}
	if minRefreshInterval <= 0 {
		minRefreshInterval = 5 * time.Minute
	}
	return &JWKSKeyProvider{
		jwksURI:            jwksURI,
		cacheTTL:           cacheTTL,
		minRefreshInterval: minRefreshInterval,
		client:             &http.Client{Timeout: 10 * time.Second},
		cache: jwksCache{
			keys: make(map[string]jose.JSONWebKey),
		},
		now: time.Now,
	}
}

func (p *JWKSKeyProvider) fetchJWKS() (map[string]jose.JSONWebKey, error) {
	resp, err := p.client.Get(p.jwksURI)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch JWKS: non-200 status code")
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	keys := make(map[string]jose.JSONWebKey)
	for _, key := range jwks.Keys {
		keys[key.KeyID] = key
	}
	return keys, nil
}

func (p *JWKSKeyProvider) GetKey(kid string) (jose.JSONWebKey, error) {
	now := p.now()

	p.cache.RLock()
	key, found := p.cache.keys[kid]
	expiresAt := p.cache.expiresAt
	lastFetched := p.cache.lastFetched
	p.cache.RUnlock()

	if found {
		if now.After(expiresAt) {
			hardLimit := expiresAt.Add(p.cacheTTL)
			if now.After(hardLimit) {
				if now.Sub(lastFetched) > p.minRefreshInterval {
					p.cache.Lock()
					if p.now().Sub(p.cache.lastFetched) > p.minRefreshInterval {
						newKeys, err := p.fetchJWKS()
						if err == nil {
							p.cache.keys = newKeys
							p.cache.lastFetched = p.now()
							p.cache.expiresAt = p.now().Add(p.cacheTTL)
						}
					}
					p.cache.Unlock()
				}
				p.cache.RLock()
				key, found = p.cache.keys[kid]
				expiresAt = p.cache.expiresAt
				p.cache.RUnlock()
				if found && !p.now().After(expiresAt.Add(p.cacheTTL)) {
					return key, nil
				}
				return jose.JSONWebKey{}, errors.New("key expired and exceeded hard limit")
			}

			if now.Sub(lastFetched) > p.minRefreshInterval {
				p.cache.Lock()
				if p.now().After(p.cache.expiresAt) && p.now().Sub(p.cache.lastFetched) > p.minRefreshInterval {
					newKeys, err := p.fetchJWKS()
					if err == nil {
						p.cache.keys = newKeys
						p.cache.lastFetched = p.now()
						p.cache.expiresAt = p.now().Add(p.cacheTTL)
					}
				}
				p.cache.Unlock()
			}
		}
		p.cache.RLock()
		key, found = p.cache.keys[kid]
		p.cache.RUnlock()
		return key, nil
	}

	if now.Sub(lastFetched) > p.minRefreshInterval {
		p.cache.Lock()
		if p.now().Sub(p.cache.lastFetched) > p.minRefreshInterval {
			newKeys, err := p.fetchJWKS()
			if err == nil {
				p.cache.keys = newKeys
				p.cache.lastFetched = p.now()
				p.cache.expiresAt = p.now().Add(p.cacheTTL)
				if k, ok := p.cache.keys[kid]; ok {
					p.cache.Unlock()
					return k, nil
				}
			}
		}
		p.cache.Unlock()
	}

	p.cache.RLock()
	key, found = p.cache.keys[kid]
	p.cache.RUnlock()
	if found {
		return key, nil
	}

	return jose.JSONWebKey{}, errors.New("key ID not found")
}
