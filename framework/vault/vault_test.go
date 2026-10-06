package vault

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestVault_ReferenceResolution_CanonicalAndFragment(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/openai", map[string]string{
		"token":   "sk-live-secret-openai-key-12345",
		"org_id":  "org-enterprise-corp",
		"project": "proj-default",
	})

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled: true,
		Prefix:  "bifrost",
	}, driver)

	// 1. Canonical dot notation
	val1, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/openai")
	if err != nil {
		t.Fatalf("canonical dot resolution failed: %v", err)
	}
	if val1 != "sk-live-secret-openai-key-12345" {
		t.Errorf("expected token value, got: %s", val1)
	}

	// 2. Fragment dot notation
	val2, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/openai#org_id")
	if err != nil {
		t.Fatalf("fragment dot resolution failed: %v", err)
	}
	if val2 != "org-enterprise-corp" {
		t.Errorf("expected org_id value, got: %s", val2)
	}

	// 3. URI scheme notation
	val3, err := resolver.Resolve(context.Background(), "vault://bifrost/keys/openai")
	if err != nil {
		t.Fatalf("canonical URI resolution failed: %v", err)
	}
	if val3 != "sk-live-secret-openai-key-12345" {
		t.Errorf("expected token value from URI scheme, got: %s", val3)
	}

	// 4. URI fragment notation
	val4, err := resolver.Resolve(context.Background(), "vault://bifrost/keys/openai#project")
	if err != nil {
		t.Fatalf("fragment URI resolution failed: %v", err)
	}
	if val4 != "proj-default" {
		t.Errorf("expected project value from URI fragment, got: %s", val4)
	}
}

func TestVault_TTL_CachingAndFlush(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/anthropic", map[string]string{
		"token": "sk-ant-live-token",
	})

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		CacheTTL: 1 * time.Hour,
	}, driver)

	// First resolution
	val1, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/anthropic")
	if err != nil || val1 != "sk-ant-live-token" {
		t.Fatalf("first resolution failed: %v", err)
	}
	if driver.BackendCalls() != 1 {
		t.Fatalf("expected 1 backend call, got %d", driver.BackendCalls())
	}

	// Second resolution within TTL -> must use cache
	val2, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/anthropic")
	if err != nil || val2 != "sk-ant-live-token" {
		t.Fatalf("cached resolution failed: %v", err)
	}
	if driver.BackendCalls() != 1 {
		t.Fatalf("expected backend calls to remain 1 due to cache, got %d", driver.BackendCalls())
	}

	// Rotate secret in store
	driver.PutSecret(context.Background(), "bifrost/keys/anthropic", map[string]string{
		"token": "sk-ant-rotated-token",
	})

	// Flush cache
	resolver.FlushCache()

	// Third resolution after flush -> re-fetches from store
	val3, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/anthropic")
	if err != nil || val3 != "sk-ant-rotated-token" {
		t.Fatalf("fresh resolution failed: %v, val=%s", err, val3)
	}
	if driver.BackendCalls() != 2 {
		t.Fatalf("expected 2 backend calls after flush, got %d", driver.BackendCalls())
	}
}

func TestVault_StaleFallback_OnUpstreamOutage(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/cohere", map[string]string{
		"token": "cohere-key-1",
	})

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		CacheTTL: 10 * time.Millisecond,
	}, driver)

	// Populate cache
	val, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/cohere")
	if err != nil || val != "cohere-key-1" {
		t.Fatalf("initial resolution failed: %v", err)
	}

	// Wait for TTL to expire
	time.Sleep(20 * time.Millisecond)

	// Trigger simulated upstream outage
	driver.SetOutage(true)

	// Resolve expired secret past TTL under outage -> stale fallback returns last known secret
	staleVal, err := resolver.Resolve(context.Background(), "vault.bifrost/keys/cohere")
	if err != nil {
		t.Fatalf("expected stale fallback success, got err: %v", err)
	}
	if staleVal != "cohere-key-1" {
		t.Fatalf("expected cached stale secret, got: %s", staleVal)
	}

	// Resolve non-existent secret under outage -> must fail
	_, err = resolver.Resolve(context.Background(), "vault.bifrost/keys/nonexistent")
	if err == nil {
		t.Fatalf("expected error for non-existent secret during outage")
	}
}

func TestVault_ConcurrentSingleflightStampedeGuard(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/concurrent/key", map[string]string{
		"value": "threaded-secret",
	})

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:  true,
		CacheTTL: 1 * time.Hour,
	}, driver)

	var wg sync.WaitGroup
	errCh := make(chan error, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			val, err := resolver.Resolve(context.Background(), "vault.bifrost/concurrent/key")
			if err != nil {
				errCh <- err
				return
			}
			if val != "threaded-secret" {
				errCh <- fmt.Errorf("unexpected value: %s", val)
				return
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent resolution error: %v", err)
	}

	// Singleflight should coalesce almost all concurrent queries into 1 backend call
	if driver.BackendCalls() > 5 {
		t.Errorf("expected singleflight coalescing to limit backend calls, got %d", driver.BackendCalls())
	}
}

func TestVault_MissingSecretAndMissingField(t *testing.T) {
	driver := NewMockVaultDriver()
	resolver := NewVaultResolver(VaultStoreConfig{Enabled: true}, driver)

	// Missing path
	_, err := resolver.Resolve(context.Background(), "vault.nonexistent/path/key")
	if err == nil {
		t.Fatalf("expected error for non-existent path")
	}

	// Missing field
	driver.PutSecret(context.Background(), "bifrost/keys/test", map[string]string{"foo": "bar"})
	_, err = resolver.Resolve(context.Background(), "vault.bifrost/keys/test#missing_field")
	if err == nil {
		t.Fatalf("expected error for missing field")
	}
}

func TestVault_WireHooks(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/hook/test", map[string]string{
		"token": "hook-secret-value",
	})

	resolver := NewVaultResolver(VaultStoreConfig{
		Enabled:    true,
		AccessMode: AccessModeReadAndWrite,
		Prefix:     "bifrost",
	}, driver)

	resolver.WireHooks()
	defer resolver.UnwireHooks()

	// Verify schemas.LookupVault
	resolved, ok := schemas.LookupVault("vault.bifrost/hook/test")
	if !ok || resolved != "hook-secret-value" {
		t.Fatalf("schemas.LookupVault failed: got %q (ok=%v)", resolved, ok)
	}

	// Verify StoreString
	var valToStore = "new-plaintext-token"
	if err := schemas.VaultStoreHook(context.Background(), "bifrost/hook/stored", &valToStore); err != nil {
		t.Fatalf("store hook failed: %v", err)
	}
	if valToStore != "vault.bifrost/hook/stored" {
		t.Fatalf("expected rewritten vault reference, got: %s", valToStore)
	}

	// Verify read back stored value
	readBack, ok := schemas.LookupVault(valToStore)
	if !ok || readBack != "new-plaintext-token" {
		t.Fatalf("expected new-plaintext-token, got: %s", readBack)
	}
}

func TestVault_BindProviderKeys(t *testing.T) {
	driver := NewMockVaultDriver()
	driver.PutSecret(context.Background(), "bifrost/keys/openai", map[string]string{
		"token": "resolved-openai-key",
	})

	resolver := NewVaultResolver(VaultStoreConfig{Enabled: true}, driver)

	secVar := schemas.NewSecretVar("vault.bifrost/keys/openai")
	key := schemas.Key{
		ID:    "key-1",
		Value: *secVar,
		AzureKeyConfig: &schemas.AzureKeyConfig{
			ClientSecret: schemas.NewSecretVar("vault.bifrost/keys/openai#token"),
		},
	}

	if err := BindKey(context.Background(), resolver, &key); err != nil {
		t.Fatalf("bind key failed: %v", err)
	}

	if key.Value.Val != "resolved-openai-key" {
		t.Errorf("key.Value not resolved: %s", key.Value.Val)
	}
	if key.AzureKeyConfig.ClientSecret.Val != "resolved-openai-key" {
		t.Errorf("azure client secret not resolved: %s", key.AzureKeyConfig.ClientSecret.Val)
	}
}

func TestVault_BindProviderKeys_SubKeyErrorPropagation(t *testing.T) {
	driver := NewMockVaultDriver()
	resolver := NewVaultResolver(VaultStoreConfig{Enabled: true}, driver)

	// Azure failing subkey
	keyAzureFail := schemas.Key{
		ID:    "key-azure",
		Value: *schemas.NewSecretVar("plain-val"),
		AzureKeyConfig: &schemas.AzureKeyConfig{
			ClientSecret: schemas.NewSecretVar("vault.nonexistent/path"),
		},
	}
	if err := BindKey(context.Background(), resolver, &keyAzureFail); err == nil {
		t.Errorf("expected error on failing Azure ClientSecret, got nil")
	}

	// Bedrock failing subkey
	keyBedrockFail := schemas.Key{
		ID:    "key-bedrock",
		Value: *schemas.NewSecretVar("plain-val"),
		BedrockKeyConfig: &schemas.BedrockKeyConfig{
			SecretKey: *schemas.NewSecretVar("vault.nonexistent/path"),
		},
	}
	if err := BindKey(context.Background(), resolver, &keyBedrockFail); err == nil {
		t.Errorf("expected error on failing Bedrock SecretKey, got nil")
	}
}
