package vault

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// BindKey resolves any vault-backed secret references in a Key definition.
func BindKey(ctx context.Context, resolver *VaultResolver, key *schemas.Key) error {
	if resolver == nil || !resolver.IsEnabled() || key == nil {
		return nil
	}

	// 1. Primary key value resolution
	if key.Value.IsFromVault() || strings.HasPrefix(key.Value.GetRawRef(), "vault.") || strings.HasPrefix(key.Value.GetRawRef(), "vault://") {
		resolved, err := resolver.Resolve(ctx, key.Value.GetRawRef())
		if err != nil {
			return err
		}
		key.Value.Val = resolved
	}

	// 2. Azure Key Config resolution
	if key.AzureKeyConfig != nil {
		if key.AzureKeyConfig.ClientSecret != nil && (key.AzureKeyConfig.ClientSecret.IsFromVault() ||
			strings.HasPrefix(key.AzureKeyConfig.ClientSecret.GetRawRef(), "vault.") ||
			strings.HasPrefix(key.AzureKeyConfig.ClientSecret.GetRawRef(), "vault://")) {
			res, err := resolver.Resolve(ctx, key.AzureKeyConfig.ClientSecret.GetRawRef())
			if err != nil {
				return err
			}
			key.AzureKeyConfig.ClientSecret.Val = res
		}
		if key.AzureKeyConfig.Endpoint.IsFromVault() ||
			strings.HasPrefix(key.AzureKeyConfig.Endpoint.GetRawRef(), "vault.") ||
			strings.HasPrefix(key.AzureKeyConfig.Endpoint.GetRawRef(), "vault://") {
			res, err := resolver.Resolve(ctx, key.AzureKeyConfig.Endpoint.GetRawRef())
			if err != nil {
				return err
			}
			key.AzureKeyConfig.Endpoint.Val = res
		}
	}

	// 3. Bedrock Key Config resolution
	if key.BedrockKeyConfig != nil {
		if key.BedrockKeyConfig.SecretKey.IsFromVault() ||
			strings.HasPrefix(key.BedrockKeyConfig.SecretKey.GetRawRef(), "vault.") ||
			strings.HasPrefix(key.BedrockKeyConfig.SecretKey.GetRawRef(), "vault://") {
			res, err := resolver.Resolve(ctx, key.BedrockKeyConfig.SecretKey.GetRawRef())
			if err != nil {
				return err
			}
			key.BedrockKeyConfig.SecretKey.Val = res
		}
		if key.BedrockKeyConfig.AccessKey.IsFromVault() ||
			strings.HasPrefix(key.BedrockKeyConfig.AccessKey.GetRawRef(), "vault.") ||
			strings.HasPrefix(key.BedrockKeyConfig.AccessKey.GetRawRef(), "vault://") {
			res, err := resolver.Resolve(ctx, key.BedrockKeyConfig.AccessKey.GetRawRef())
			if err != nil {
				return err
			}
			key.BedrockKeyConfig.AccessKey.Val = res
		}
	}

	return nil
}

// BindKeys iterates over a slice of Keys and resolves all vault references in-place.
func BindKeys(ctx context.Context, resolver *VaultResolver, keys []schemas.Key) ([]schemas.Key, error) {
	if resolver == nil || !resolver.IsEnabled() {
		return keys, nil
	}

	for i := range keys {
		if err := BindKey(ctx, resolver, &keys[i]); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// BindProviderKeysMap resolves all vault references across a provider key map.
func BindProviderKeysMap(ctx context.Context, resolver *VaultResolver, keysMap map[string][]schemas.Key) error {
	if resolver == nil || !resolver.IsEnabled() {
		return nil
	}

	for prov, keys := range keysMap {
		bound, err := BindKeys(ctx, resolver, keys)
		if err != nil {
			return err
		}
		keysMap[prov] = bound
	}
	return nil
}

// AutoRotationWorker runs periodic background re-binding of vault keys.
type AutoRotationWorker struct {
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// Stop terminates the auto-rotation worker.
func (w *AutoRotationWorker) Stop() {
	if w.stopCh != nil {
		close(w.stopCh)
		w.wg.Wait()
	}
}

// WatchAndRebind starts a background worker that periodically re-resolves vault keys.
func WatchAndRebind(ctx context.Context, resolver *VaultResolver, rebindFn func() error, interval time.Duration) *AutoRotationWorker {
	if interval <= 0 {
		interval = 1 * time.Hour
	}

	w := &AutoRotationWorker{
		stopCh: make(chan struct{}),
	}

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-w.stopCh:
				return
			case <-ticker.C:
				if rebindFn != nil {
					_ = rebindFn()
				}
			}
		}
	}()

	return w
}
