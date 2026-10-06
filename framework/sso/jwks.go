package sso

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// JWK represents a single JSON Web Key per RFC 7517.
type JWK struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use,omitempty"`
	Alg string   `json:"alg,omitempty"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	Crv string   `json:"crv,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
	X5c []string `json:"x5c,omitempty"`
}

// JWKSResponse represents a JWKS keyset JSON response.
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWKSCache provides a thread-safe in-memory cache of public keys fetched from an IdP JWKS endpoint.
type JWKSCache struct {
	mu          sync.RWMutex
	keys        map[string]crypto.PublicKey // kid -> public key
	jwksURI     string
	httpClient  *http.Client
	ttl         time.Duration
	lastFetched time.Time
	cooldown    time.Duration
	sfGroup     singleflight.Group
	stopChan    chan struct{}
	closeOnce   sync.Once
}

// NewJWKSCache creates a new JWKSCache for the given JWKS URI.
func NewJWKSCache(jwksURI string, httpClient *http.Client, ttl time.Duration) *JWKSCache {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	return &JWKSCache{
		keys:       make(map[string]crypto.PublicKey),
		jwksURI:    jwksURI,
		httpClient: httpClient,
		ttl:        ttl,
		cooldown:   10 * time.Second,
		stopChan:   make(chan struct{}),
	}
}

// AddKey manually registers a public key with a specific kid (e.g. for testing or static config).
func (c *JWKSCache) AddKey(kid string, key crypto.PublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys[kid] = key
}

// FetchKeys downloads and parses the JWKS keyset using singleflight to prevent cache stampedes.
func (c *JWKSCache) FetchKeys(ctx context.Context) error {
	if c.jwksURI == "" {
		return fmt.Errorf("jwks uri is not configured")
	}

	_, err, _ := c.sfGroup.Do("fetch_jwks", func() (interface{}, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURI, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch jwks: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("jwks endpoint returned HTTP %d", resp.StatusCode)
		}

		var jwks JWKSResponse
		if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
			return nil, fmt.Errorf("failed to decode jwks response: %w", err)
		}

		newKeys := make(map[string]crypto.PublicKey)
		for _, k := range jwks.Keys {
			pubKey, err := parsePublicKeyFromJWK(k)
			if err == nil && pubKey != nil {
				newKeys[k.Kid] = pubKey
			}
		}

		c.mu.Lock()
		c.keys = newKeys
		c.lastFetched = time.Now()
		c.mu.Unlock()

		return nil, nil
	})

	return err
}

// GetKey retrieves a public key by kid. If the kid is unknown and cooldown has elapsed,
// an on-demand refresh is triggered. If kid is empty and exactly one key exists, returns it.
func (c *JWKSCache) GetKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	c.mu.RLock()
	if kid != "" {
		if key, ok := c.keys[kid]; ok {
			c.mu.RUnlock()
			return key, nil
		}
	} else if len(c.keys) == 1 {
		for _, k := range c.keys {
			c.mu.RUnlock()
			return k, nil
		}
	}
	last := c.lastFetched
	c.mu.RUnlock()

	// If jwksURI is configured and cooldown elapsed, perform on-demand fetch
	if c.jwksURI != "" && time.Since(last) >= c.cooldown {
		if err := c.FetchKeys(ctx); err == nil {
			c.mu.RLock()
			defer c.mu.RUnlock()
			if kid != "" {
				if key, ok := c.keys[kid]; ok {
					return key, nil
				}
			} else if len(c.keys) == 1 {
				for _, k := range c.keys {
					return k, nil
				}
			}
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if kid != "" {
		if key, ok := c.keys[kid]; ok {
			return key, nil
		}
		return nil, fmt.Errorf("public key not found for kid %q", kid)
	}
	if len(c.keys) == 1 {
		for _, k := range c.keys {
			return k, nil
		}
	}
	return nil, fmt.Errorf("no matching public key found in jwks cache")
}

// StartBackgroundRefresh starts a background worker that periodically refreshes keys.
func (c *JWKSCache) StartBackgroundRefresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = c.ttl
	}
	if interval < 1*time.Minute {
		interval = 1 * time.Minute
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.stopChan:
				return
			case <-ticker.C:
				_ = c.FetchKeys(ctx)
			}
		}
	}()
}

// Close gracefully stops any background refresh operations.
func (c *JWKSCache) Close() {
	c.closeOnce.Do(func() {
		close(c.stopChan)
	})
}

// parsePublicKeyFromJWK parses RSA or ECDSA public keys from a JWK struct.
func parsePublicKeyFromJWK(k JWK) (crypto.PublicKey, error) {
	// 1. Check x5c certificate chain if present
	if len(k.X5c) > 0 {
		certClean := strings.ReplaceAll(k.X5c[0], "\n", "")
		certClean = strings.ReplaceAll(certClean, " ", "")
		certDER, err := base64.StdEncoding.DecodeString(certClean)
		if err == nil {
			cert, err := x509.ParseCertificate(certDER)
			if err == nil && cert.PublicKey != nil {
				return cert.PublicKey, nil
			}
		}
	}

	// 2. Parse based on kty
	switch strings.ToUpper(k.Kty) {
	case "RSA":
		return parseRSAPublicKey(k.N, k.E)
	case "EC":
		return parseECDSAPublicKey(k.Crv, k.X, k.Y)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", k.Kty)
	}
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	if nStr == "" || eStr == "" {
		return nil, fmt.Errorf("missing modulus or exponent")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		nBytes, err = base64.URLEncoding.DecodeString(nStr)
		if err != nil {
			return nil, fmt.Errorf("invalid RSA modulus encoding: %w", err)
		}
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		eBytes, err = base64.URLEncoding.DecodeString(eStr)
		if err != nil {
			return nil, fmt.Errorf("invalid RSA exponent encoding: %w", err)
		}
	}
	var eInt int
	for _, b := range eBytes {
		eInt = (eInt << 8) | int(b)
	}
	if eInt == 0 {
		return nil, fmt.Errorf("invalid RSA exponent value")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}, nil
}

func parseECDSAPublicKey(crvStr, xStr, yStr string) (*ecdsa.PublicKey, error) {
	if crvStr == "" || xStr == "" || yStr == "" {
		return nil, fmt.Errorf("missing curve, x, or y coordinates")
	}
	var curve elliptic.Curve
	switch strings.ToUpper(crvStr) {
	case "P-256", "PRIME256V1":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported elliptic curve: %s", crvStr)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("invalid EC X coordinate encoding: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("invalid EC Y coordinate encoding: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
