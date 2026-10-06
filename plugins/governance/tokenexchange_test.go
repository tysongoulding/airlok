package governance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestJWT(claims map[string]interface{}) string {
	headerJSON := `{"alg":"HS256","typ":"JWT"}`
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))

	payloadJSON, _ := json.Marshal(claims)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	sigB64 := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	return fmt.Sprintf("%s.%s.%s", headerB64, payloadB64, sigB64)
}

func TestTokenExchanger_BasicAndIdempotency(t *testing.T) {
	exchanger := NewFederatedTokenExchanger()
	ctx := context.Background()

	subjectToken := "user-jwt-bearer-xyz789"
	audience := "https://api.slack.com"

	// First exchange
	downstreamToken, err := exchanger.ExchangeToken(ctx, subjectToken, audience)
	require.NoError(t, err)
	assert.NotEmpty(t, downstreamToken)
	assert.Contains(t, downstreamToken, audience)

	// Second exchange (idempotent, cached)
	cachedToken, err := exchanger.ExchangeToken(ctx, subjectToken, audience)
	require.NoError(t, err)
	assert.Equal(t, downstreamToken, cachedToken)

	// Different audience gets distinct token
	otherToken, err := exchanger.ExchangeToken(ctx, subjectToken, "https://api.github.com")
	require.NoError(t, err)
	assert.NotEqual(t, downstreamToken, otherToken)
}

func TestTokenExchanger_ValidationErrors(t *testing.T) {
	exchanger := NewFederatedTokenExchanger()
	ctx := context.Background()

	// Missing subject token
	_, err := exchanger.ExchangeToken(ctx, "", "https://api.slack.com")
	require.ErrorIs(t, err, ErrMissingSubjectToken)

	_, err = exchanger.ExchangeToken(ctx, "   ", "https://api.slack.com")
	require.ErrorIs(t, err, ErrMissingSubjectToken)

	// Expired subject token sentinel
	_, err = exchanger.ExchangeToken(ctx, "expired-token-123", "https://api.slack.com")
	require.ErrorIs(t, err, ErrExpiredSubjectToken)

	// Malformed subject token sentinel
	_, err = exchanger.ExchangeToken(ctx, "malformed-token-xyz", "https://api.slack.com")
	require.ErrorIs(t, err, ErrMalformedSubjectToken)

	// Missing audience
	_, err = exchanger.ExchangeToken(ctx, "valid-token", "")
	require.ErrorIs(t, err, ErrMissingAudience)

	_, err = exchanger.ExchangeToken(ctx, "valid-token", "   ")
	require.ErrorIs(t, err, ErrMissingAudience)

	// Token with control characters
	_, err = exchanger.ExchangeToken(ctx, "token\nwith\nnewlines", "https://api.slack.com")
	require.ErrorIs(t, err, ErrMalformedSubjectToken)
}

func TestTokenExchanger_JWTValidation(t *testing.T) {
	exchanger := NewFederatedTokenExchanger()
	ctx := context.Background()

	// 1. Valid JWT
	now := time.Now().Unix()
	validJWT := createTestJWT(map[string]interface{}{
		"sub": "user_12345",
		"iss": "https://auth.company.com",
		"aud": "https://api.company.com",
		"exp": now + 3600,
		"iat": now,
	})

	claims, err := exchanger.ValidateSubjectToken(validJWT)
	require.NoError(t, err)
	assert.True(t, claims.IsJWT)
	assert.Equal(t, "user_12345", claims.Subject)
	assert.Equal(t, "https://auth.company.com", claims.Issuer)

	token, err := exchanger.ExchangeToken(ctx, validJWT, "https://api.company.com")
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// 2. Expired JWT
	expiredJWT := createTestJWT(map[string]interface{}{
		"sub": "user_12345",
		"exp": now - 300,
	})
	_, err = exchanger.ExchangeToken(ctx, expiredJWT, "https://api.company.com")
	require.ErrorIs(t, err, ErrExpiredSubjectToken)

	// 3. Not yet valid JWT (nbf in future)
	futureJWT := createTestJWT(map[string]interface{}{
		"sub": "user_12345",
		"nbf": now + 600,
	})
	_, err = exchanger.ExchangeToken(ctx, futureJWT, "https://api.company.com")
	require.ErrorIs(t, err, ErrTokenNotYetValid)

	// 4. Malformed JWT parts
	_, err = exchanger.ValidateSubjectToken("not.a.valid.jwt.four.parts")
	require.ErrorIs(t, err, ErrMalformedSubjectToken)

	_, err = exchanger.ValidateSubjectToken("header.invalid-base64-payload!@#$.sig")
	require.ErrorIs(t, err, ErrMalformedSubjectToken)
}

func TestTokenExchanger_InvalidationAndFlush(t *testing.T) {
	exchanger := NewFederatedTokenExchanger()
	ctx := context.Background()

	subjectToken := "user-token-abc"
	audience := "https://api.slack.com"

	token1, err := exchanger.ExchangeToken(ctx, subjectToken, audience)
	require.NoError(t, err)

	// Invalidate specific token
	exchanger.InvalidateToken(subjectToken, audience)

	token2, err := exchanger.ExchangeToken(ctx, subjectToken, audience)
	require.NoError(t, err)
	// Because token1 was evicted, a new token is minted
	assert.NotEqual(t, token1, token2)

	// Flush all cache
	exchanger.FlushCache()
	token3, err := exchanger.ExchangeToken(ctx, subjectToken, audience)
	require.NoError(t, err)
	assert.NotEqual(t, token2, token3)
}

func TestTokenExchanger_ConcurrencyAndSingleFlight(t *testing.T) {
	exchanger := NewFederatedTokenExchanger()
	ctx := context.Background()

	subjectToken := "concurrent-user-token"
	audience := "https://api.slack.com"

	concurrency := 100
	var wg sync.WaitGroup
	wg.Add(concurrency)

	tokens := make([]string, concurrency)
	errors := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			tokens[idx], errors[idx] = exchanger.ExchangeToken(ctx, subjectToken, audience)
		}(i)
	}

	wg.Wait()

	firstToken := tokens[0]
	assert.NotEmpty(t, firstToken)

	for i := 0; i < concurrency; i++ {
		require.NoError(t, errors[i], "goroutine %d failed", i)
		assert.Equal(t, firstToken, tokens[i], "goroutine %d got different token", i)
	}
}
