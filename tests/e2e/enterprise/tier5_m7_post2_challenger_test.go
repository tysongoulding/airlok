package enterprise

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/framework/audit"
	"github.com/maximhq/bifrost/framework/diagnostics"
	"github.com/maximhq/bifrost/framework/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// CHALLENGER 2: ADVERSARIAL DEFECT REMEDIATION VERIFICATION
// ============================================================================

// --- DEFECT 1: SANITIZER CIRCULAR REFERENCES & EXTREME RECURSION ---

func TestChallenger2_Defect1_CircularReferences_ExtremeAdversarial(t *testing.T) {
	// Case 1: Extreme self-referencing map
	t.Run("SelfReferencingMap", func(t *testing.T) {
		m := make(map[string]interface{})
		m["self"] = m
		m["secret_token"] = "sk-live-secret-999"
		m["plain_text"] = "hello world"

		res := diagnostics.SanitizeSecretFields(m)
		require.NotNil(t, res)
		resMap, ok := res.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "[REDACTED]", resMap["secret_token"])
		assert.Equal(t, "hello world", resMap["plain_text"])

		// Verify depth bound reaches [MAX_DEPTH_EXCEEDED] at exactly depth 32
		cur := resMap
		var foundDepthExceeded bool
		depthCount := 0
		for i := 0; i < 40; i++ {
			val, exists := cur["self"]
			if !exists {
				break
			}
			if s, isStr := val.(string); isStr && s == "[MAX_DEPTH_EXCEEDED]" {
				foundDepthExceeded = true
				depthCount = i + 1
				break
			}
			nextMap, isMap := val.(map[string]interface{})
			if !isMap {
				break
			}
			cur = nextMap
		}
		assert.True(t, foundDepthExceeded, "must terminate with [MAX_DEPTH_EXCEEDED]")
		assert.Equal(t, 32, depthCount, "recursion must be exactly 32 frames deep")
	})

	// Case 2: Extreme self-referencing slice
	t.Run("SelfReferencingSlice", func(t *testing.T) {
		s := make([]interface{}, 2)
		s[0] = "secret_key_value_sk-secret"
		s[1] = s

		res := diagnostics.SanitizeSecretFields(s)
		require.NotNil(t, res)
		resSlice, ok := res.([]interface{})
		require.True(t, ok)
		assert.Equal(t, 2, len(resSlice))

		curSlice := resSlice
		var foundDepthExceeded bool
		for i := 0; i < 40; i++ {
			if len(curSlice) < 2 {
				break
			}
			val := curSlice[1]
			if strVal, isStr := val.(string); isStr && strVal == "[MAX_DEPTH_EXCEEDED]" {
				foundDepthExceeded = true
				break
			}
			next, isSlice := val.([]interface{})
			if !isSlice {
				break
			}
			curSlice = next
		}
		assert.True(t, foundDepthExceeded, "circular slice must terminate with [MAX_DEPTH_EXCEEDED]")
	})

	// Case 3: Multi-node cyclic graph (A -> B -> C -> D -> A)
	t.Run("MultiNodeCyclicGraph", func(t *testing.T) {
		nodeA := map[string]interface{}{"name": "A", "key": "secret-a"}
		nodeB := map[string]interface{}{"name": "B", "key": "secret-b"}
		nodeC := map[string]interface{}{"name": "C", "key": "secret-c"}
		nodeD := map[string]interface{}{"name": "D", "key": "secret-d"}

		nodeA["next"] = nodeB
		nodeB["next"] = nodeC
		nodeC["next"] = nodeD
		nodeD["next"] = nodeA

		res := diagnostics.SanitizeSecretFields(nodeA)
		require.NotNil(t, res)
		resMap, ok := res.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "A", resMap["name"])
		assert.Equal(t, "[REDACTED]", resMap["key"])

		cur := resMap
		var foundDepthExceeded bool
		for i := 0; i < 50; i++ {
			val := cur["next"]
			if s, isStr := val.(string); isStr && s == "[MAX_DEPTH_EXCEEDED]" {
				foundDepthExceeded = true
				break
			}
			nextMap, isMap := val.(map[string]interface{})
			if !isMap {
				break
			}
			cur = nextMap
		}
		assert.True(t, foundDepthExceeded, "cyclic graph must terminate with [MAX_DEPTH_EXCEEDED]")
	})

	// Case 4: Deep nesting beyond 60 levels without cycle
	t.Run("DeepNestingBeyond60Levels", func(t *testing.T) {
		root := map[string]interface{}{"level": 0}
		curr := root
		for i := 1; i <= 60; i++ {
			next := map[string]interface{}{
				"level": i,
			}
			if i == 15 {
				next["password"] = "hidden-secret-pass"
			}
			if i == 50 {
				next["deep_secret_token"] = "deep-secret-token"
			}
			curr["child"] = next
			curr = next
		}

		res := diagnostics.SanitizeSecretFields(root)
		require.NotNil(t, res)

		// Check level 15 password was redacted
		currRes := res.(map[string]interface{})
		for i := 1; i <= 15; i++ {
			currRes = currRes["child"].(map[string]interface{})
		}
		assert.Equal(t, "[REDACTED]", currRes["password"])

		// Check level 32 returns [MAX_DEPTH_EXCEEDED]
		currRes = res.(map[string]interface{})
		var exceeded bool
		for i := 1; i <= 35; i++ {
			childVal := currRes["child"]
			if s, isStr := childVal.(string); isStr && s == "[MAX_DEPTH_EXCEEDED]" {
				exceeded = true
				break
			}
			nextMap, ok := childVal.(map[string]interface{})
			if !ok {
				break
			}
			currRes = nextMap
		}
		assert.True(t, exceeded, "levels beyond 32 must be cut off with [MAX_DEPTH_EXCEEDED]")
	})

	// Case 5: Custom depth limits via SanitizeSecretFieldsWithDepth
	t.Run("CustomMaxDepth", func(t *testing.T) {
		cycle := make(map[string]interface{})
		cycle["loop"] = cycle

		res5 := diagnostics.SanitizeSecretFieldsWithDepth(cycle, 5)
		cur := res5.(map[string]interface{})
		depth := 0
		for {
			val := cur["loop"]
			if val == "[MAX_DEPTH_EXCEEDED]" {
				depth++
				break
			}
			cur = val.(map[string]interface{})
			depth++
		}
		assert.Equal(t, 5, depth, "should terminate at custom depth 5")

		// Test non-positive custom depth defaults to maxSanitizerDepth (32)
		resDefault := diagnostics.SanitizeSecretFieldsWithDepth(cycle, 0)
		curDef := resDefault.(map[string]interface{})
		depthDef := 0
		for {
			val := curDef["loop"]
			if val == "[MAX_DEPTH_EXCEEDED]" {
				depthDef++
				break
			}
			curDef = val.(map[string]interface{})
			depthDef++
		}
		assert.Equal(t, 32, depthDef, "0 maxDepth must default to 32")
	})

	// Case 6: Struct pointer cycle (Go typed struct with cycle)
	t.Run("StructPointerCycle", func(t *testing.T) {
		type RecursiveNode struct {
			Name string
			Next *RecursiveNode
		}
		node := &RecursiveNode{Name: "first"}
		node.Next = node // Pointer cycle

		// json.Marshal returns cycle error; sanitizer must gracefully return struct without panic
		assert.NotPanics(t, func() {
			out := diagnostics.SanitizeSecretFields(node)
			assert.NotNil(t, out)
		})
	})
}

// --- DEFECT 2: JWKS KEY ROTATION AND REVOCATION ---

func TestChallenger2_Defect2_JWKSKeyRotationAndRevocation_Adversarial(t *testing.T) {
	// Generate 4 RSA keys
	keys := make([]*rsa.PrivateKey, 4)
	for i := 0; i < 4; i++ {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		keys[i] = k
	}

	var activeKeysMu sync.RWMutex
	activeKeyMap := make(map[string]*rsa.PublicKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activeKeysMu.RLock()
		defer activeKeysMu.RUnlock()

		jwksList := make([]sso.JWK, 0, len(activeKeyMap))
		for kid, pubKey := range activeKeyMap {
			jwksList = append(jwksList, sso.JWK{
				Kty: "RSA",
				Kid: kid,
				Use: "sig",
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sso.JWKSResponse{Keys: jwksList})
	}))
	defer server.Close()

	signToken := func(kid string, priv *rsa.PrivateKey) string {
		hB64 := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":"RS256","kid":%q,"typ":"JWT"}`, kid)))
		pB64 := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"adversary","iss":"https://idp.test","aud":"bifrost","exp":%d}`, time.Now().Add(time.Hour).Unix())))
		input := hB64 + "." + pB64
		h := sha256.Sum256([]byte(input))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, 0, h[:])
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	cache := sso.NewJWKSCache(server.URL, server.Client(), 10*time.Minute)
	validator := sso.NewOIDCValidatorWithCache(sso.OIDCConfig{
		IssuerURL:          "https://idp.test",
		Audience:           "bifrost",
		ClockSkewTolerance: 30 * time.Second,
	}, cache)

	ctx := context.Background()

	// Step 1: Add 3 keys (kid-0, kid-1, kid-2)
	activeKeysMu.Lock()
	activeKeyMap["kid-0"] = &keys[0].PublicKey
	activeKeyMap["kid-1"] = &keys[1].PublicKey
	activeKeyMap["kid-2"] = &keys[2].PublicKey
	activeKeysMu.Unlock()

	require.NoError(t, cache.FetchKeys(ctx))

	// Verify all 3 keys are accepted
	for i := 0; i < 3; i++ {
		kid := fmt.Sprintf("kid-%d", i)
		k, err := cache.GetKey(ctx, kid)
		require.NoError(t, err, "kid %s must exist in cache", kid)
		require.NotNil(t, k)

		tok := signToken(kid, keys[i])
		claims, valErr := validator.ValidateToken(ctx, tok)
		require.NoError(t, valErr, "token for kid %s must be valid", kid)
		assert.Equal(t, "adversary", claims.Subject)
	}

	// Step 2: Rotate IdP: Revoke 2 keys (kid-0, kid-1), retain kid-2, add kid-3
	activeKeysMu.Lock()
	delete(activeKeyMap, "kid-0")
	delete(activeKeyMap, "kid-1")
	activeKeyMap["kid-3"] = &keys[3].PublicKey
	activeKeysMu.Unlock()

	// Proactively fetch keyset
	require.NoError(t, cache.FetchKeys(ctx))

	// Verify revoked keys (kid-0, kid-1) are rejected immediately
	for _, revokedKid := range []string{"kid-0", "kid-1"} {
		revKey, err := cache.GetKey(ctx, revokedKid)
		require.Error(t, err, "revoked kid %s must be rejected by GetKey", revokedKid)
		assert.Nil(t, revKey)

		var revokedPriv *rsa.PrivateKey
		if revokedKid == "kid-0" {
			revokedPriv = keys[0]
		} else {
			revokedPriv = keys[1]
		}
		tok := signToken(revokedKid, revokedPriv)
		_, valErr := validator.ValidateToken(ctx, tok)
		require.Error(t, valErr, "token signed with revoked kid %s must be rejected", revokedKid)
	}

	// Verify active keys (kid-2, kid-3) remain valid
	for _, activeKid := range []string{"kid-2", "kid-3"} {
		k, err := cache.GetKey(ctx, activeKid)
		require.NoError(t, err, "active kid %s must exist", activeKid)
		require.NotNil(t, k)

		var activePriv *rsa.PrivateKey
		if activeKid == "kid-2" {
			activePriv = keys[2]
		} else {
			activePriv = keys[3]
		}
		tok := signToken(activeKid, activePriv)
		claims, valErr := validator.ValidateToken(ctx, tok)
		require.NoError(t, valErr, "token for active kid %s must validate", activeKid)
		assert.Equal(t, "adversary", claims.Subject)
	}

	// Step 3: Complete Revocation (empty JWKS keyset)
	activeKeysMu.Lock()
	activeKeyMap = make(map[string]*rsa.PublicKey)
	activeKeysMu.Unlock()

	require.NoError(t, cache.FetchKeys(ctx))

	for i := 0; i < 4; i++ {
		kid := fmt.Sprintf("kid-%d", i)
		k, err := cache.GetKey(ctx, kid)
		require.Error(t, err, "kid %s must be revoked in empty keyset", kid)
		assert.Nil(t, k)
	}

	// Step 4: Concurrency and Race Detector test under continuous key mutation
	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half goroutines call FetchKeys
	for i := 0; i < goroutines; i++ {
		go func(iter int) {
			defer wg.Done()
			activeKeysMu.Lock()
			if iter%2 == 0 {
				activeKeyMap["kid-2"] = &keys[2].PublicKey
			} else {
				delete(activeKeyMap, "kid-2")
			}
			activeKeysMu.Unlock()
			_ = cache.FetchKeys(ctx)
		}(i)
	}

	// Half goroutines call GetKey and ValidateToken
	for i := 0; i < goroutines; i++ {
		go func(iter int) {
			defer wg.Done()
			_, _ = cache.GetKey(ctx, "kid-2")
			tok := signToken("kid-2", keys[2])
			_, _ = validator.ValidateToken(ctx, tok)
		}(i)
	}

	wg.Wait()
}

// --- DEFECT 3: AUDIT LEDGER TAIL TRUNCATION & BOUNDARY CONDITIONS ---

func TestChallenger2_Defect3_LedgerBoundaryConditions_Adversarial(t *testing.T) {
	key := "test-secret-hmac-key-of-at-least-32-bytes!"

	// 1. Boundary conditions on EMPTY ledger
	t.Run("EmptyLedger", func(t *testing.T) {
		ledger, err := audit.NewLedger(audit.Config{HMACKey: key})
		require.NoError(t, err)

		// VerifyChain(1, 0) on empty ledger -> valid=true, brokenAt=0
		valid, broken := ledger.VerifyChain(1, 0)
		assert.True(t, valid, "empty ledger with to=0 must report valid")
		assert.Equal(t, int64(0), broken)

		// VerifyChain(0, 0) on empty ledger -> valid=true, brokenAt=0
		valid0, broken0 := ledger.VerifyChain(0, 0)
		assert.True(t, valid0)
		assert.Equal(t, int64(0), broken0)

		// VerifyChain(-1, 0) on empty ledger -> valid=true, brokenAt=0
		validNeg, brokenNeg := ledger.VerifyChain(-1, 0)
		assert.True(t, validNeg)
		assert.Equal(t, int64(0), brokenNeg)

		// VerifyChain(1, 10) on empty ledger -> valid=false, brokenAt=1
		validTrunc, brokenTrunc := ledger.VerifyChain(1, 10)
		assert.False(t, validTrunc, "empty ledger with positive 'to' must detect truncation")
		assert.Equal(t, int64(1), brokenTrunc)

		// VerifyChain(5, 10) on empty ledger -> valid=false, brokenAt=1
		valid5, broken5 := ledger.VerifyChain(5, 10)
		assert.False(t, valid5)
		assert.Equal(t, int64(1), broken5)

		// VerifyChain(10, 5) on empty ledger -> valid=false, brokenAt=1
		validRev, brokenRev := ledger.VerifyChain(10, 5)
		assert.False(t, validRev)
		assert.Equal(t, int64(1), brokenRev)
	})

	// 2. Boundary conditions on SINGLE-EVENT ledger
	t.Run("SingleEventLedger", func(t *testing.T) {
		ledger, err := audit.NewLedger(audit.Config{HMACKey: key})
		require.NoError(t, err)

		_, err = ledger.RecordEvent("action", "target", "id-1", "user", "127.0.0.1", "{}")
		require.NoError(t, err)

		// VerifyChain(1, 1) -> valid=true, brokenAt=0
		v1, b1 := ledger.VerifyChain(1, 1)
		assert.True(t, v1)
		assert.Equal(t, int64(0), b1)

		// VerifyChain(1, 0) -> valid=true, brokenAt=0
		vHead, bHead := ledger.VerifyChain(1, 0)
		assert.True(t, vHead)
		assert.Equal(t, int64(0), bHead)

		// VerifyChain(1, 2) -> valid=false, brokenAt=2 (tail truncation!)
		v2, b2 := ledger.VerifyChain(1, 2)
		assert.False(t, v2)
		assert.Equal(t, int64(2), b2, "truncation past sequence 1 must break at 2")

		// VerifyChain(2, 2) -> valid=false, brokenAt=2 (from > lastSequenceID)
		v22, b22 := ledger.VerifyChain(2, 2)
		assert.False(t, v22)
		assert.Equal(t, int64(2), b22)

		// VerifyChain(2, 1) -> valid=false, brokenAt=2 (from > to)
		v21, b21 := ledger.VerifyChain(2, 1)
		assert.False(t, v21)
		assert.Equal(t, int64(2), b21)
	})

	// 3. Boundary conditions on MULTI-EVENT ledger (10 events)
	t.Run("MultiEventLedgerBoundaries", func(t *testing.T) {
		ledger, err := audit.NewLedger(audit.Config{HMACKey: key})
		require.NoError(t, err)

		for i := 1; i <= 10; i++ {
			_, err := ledger.RecordEvent("action", "target", fmt.Sprintf("id-%d", i), "user", "127.0.0.1", fmt.Sprintf(`{"i":%d}`, i))
			require.NoError(t, err)
		}

		// Baseline: full chain 1..10
		vFull, bFull := ledger.VerifyChain(1, 10)
		assert.True(t, vFull)
		assert.Equal(t, int64(0), bFull)

		// Full chain to head via to=0
		vHead, bHead := ledger.VerifyChain(1, 0)
		assert.True(t, vHead)
		assert.Equal(t, int64(0), bHead)

		// to > lastSequenceID: VerifyChain(1, 15) must report brokenAt=11
		vTrunc, bTrunc := ledger.VerifyChain(1, 15)
		assert.False(t, vTrunc, "must detect truncation")
		assert.Equal(t, int64(11), bTrunc, "brokenAt must be lastSequenceID + 1")

		// to > lastSequenceID with sub-window: VerifyChain(5, 15) must report brokenAt=11
		vTruncSub, bTruncSub := ledger.VerifyChain(5, 15)
		assert.False(t, vTruncSub)
		assert.Equal(t, int64(11), bTruncSub)

		// from > to: VerifyChain(8, 5) must report brokenAt=8
		vRev, bRev := ledger.VerifyChain(8, 5)
		assert.False(t, vRev)
		assert.Equal(t, int64(8), bRev)

		// from > lastSequenceID: VerifyChain(15, 20) must report brokenAt=15
		vPast, bPast := ledger.VerifyChain(15, 20)
		assert.False(t, vPast)
		assert.Equal(t, int64(15), bPast)

		// from > to AND from > lastSequenceID: VerifyChain(15, 12) must report brokenAt=15
		vBoth, bBoth := ledger.VerifyChain(15, 12)
		assert.False(t, vBoth)
		assert.Equal(t, int64(15), bBoth)

		// Valid sub-window: VerifyChain(3, 7) must succeed
		vSub, bSub := ledger.VerifyChain(3, 7)
		assert.True(t, vSub)
		assert.Equal(t, int64(0), bSub)
	})

	// 4. Simulated forensic tamper & truncation detection
	t.Run("ForensicTamperScenarios", func(t *testing.T) {
		ledger, err := audit.NewLedger(audit.Config{HMACKey: key})
		require.NoError(t, err)

		for i := 1; i <= 8; i++ {
			_, err := ledger.RecordEvent("action", "target", fmt.Sprintf("id-%d", i), "user", "127.0.0.1", fmt.Sprintf(`{"i":%d}`, i))
			require.NoError(t, err)
		}

		// VerifyChain detects expected events if caller expects 10 records
		vExpect10, bExpect10 := ledger.VerifyChain(1, 10)
		assert.False(t, vExpect10)
		assert.Equal(t, int64(9), bExpect10, "brokenAt must indicate first missing sequence (9)")
	})
}
