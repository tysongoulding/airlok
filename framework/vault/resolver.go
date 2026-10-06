package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// ParseReference parses a vault URI reference (canonical dot notation or URI scheme)
// into path, field fragment, and boolean indicating if it is a vault reference.
func ParseReference(ref string) (path string, field string, isVault bool) {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "vault://") {
		ref = strings.TrimPrefix(ref, "vault://")
		isVault = true
	} else if strings.HasPrefix(ref, "vault.") {
		ref = strings.TrimPrefix(ref, "vault.")
		isVault = true
	} else {
		return "", "", false
	}

	if idx := strings.IndexByte(ref, '#'); idx >= 0 {
		return ref[:idx], ref[idx+1:], true
	}
	return ref, "", true
}

// VaultResolver handles resolution of vault references to plaintext secrets.
type VaultResolver struct {
	config   VaultStoreConfig
	provider VaultProvider
	cache    *SecretCache
}

// NewVaultResolver initializes a VaultResolver.
func NewVaultResolver(cfg VaultStoreConfig, provider VaultProvider) *VaultResolver {
	if cfg.Prefix == "" {
		cfg.Prefix = "bifrost"
	}
	if cfg.AccessMode == "" {
		cfg.AccessMode = AccessModeReadOnly
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}

	cache := NewSecretCache(provider, cfg.CacheTTL, nil)
	return &VaultResolver{
		config:   cfg,
		provider: provider,
		cache:    cache,
	}
}

// Cache returns the underlying SecretCache.
func (r *VaultResolver) Cache() *SecretCache {
	return r.cache
}

// Provider returns the underlying VaultProvider.
func (r *VaultResolver) Provider() VaultProvider {
	return r.provider
}

// IsEnabled reports whether vault integration is enabled.
func (r *VaultResolver) IsEnabled() bool {
	return r.config.Enabled
}

// Prefix returns the configured vault path prefix.
func (r *VaultResolver) Prefix() string {
	if r.config.Prefix != "" {
		return r.config.Prefix
	}
	return "bifrost"
}

// FlushCache purges all cached secrets immediately.
func (r *VaultResolver) FlushCache() {
	if r.cache != nil {
		r.cache.Flush()
	}
}

// Resolve resolves a vault reference (e.g. "vault.bifrost/keys/openai" or "vault://bifrost/keys/openai#token").
func (r *VaultResolver) Resolve(ctx context.Context, ref string) (string, error) {
	path, field, isVault := ParseReference(ref)
	if !isVault {
		return ref, nil
	}

	data, err := r.cache.Get(ctx, path)
	if err != nil {
		return "", err
	}

	// 1. Explicit field fragment specified
	if field != "" {
		val, exists := data[field]
		if !exists {
			return "", fmt.Errorf("%w: field %q in %s", ErrFieldNotFound, field, path)
		}
		return val, nil
	}

	// 2. Default field precedence: token -> value -> api_key -> single field -> json
	if val, ok := data["token"]; ok {
		return val, nil
	}
	if val, ok := data["value"]; ok {
		return val, nil
	}
	if val, ok := data["api_key"]; ok {
		return val, nil
	}
	if len(data) == 1 {
		for _, val := range data {
			return val, nil
		}
	}

	// Fallback to JSON serialization of whole map
	b, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal secret data: %w", err)
	}
	return string(b), nil
}

// ResolveString resolves a pointer to a string in-place if it contains a vault reference.
func (r *VaultResolver) ResolveString(ctx context.Context, value *string) error {
	if value == nil || *value == "" {
		return nil
	}

	_, _, isVault := ParseReference(*value)
	if !isVault {
		return nil
	}

	resolved, err := r.Resolve(ctx, *value)
	if err != nil {
		return err
	}
	*value = resolved
	return nil
}

// StoreString stores a secret at path and converts *value to a vault reference.
func (r *VaultResolver) StoreString(ctx context.Context, path string, value *string) error {
	if r.config.AccessMode != AccessModeReadAndWrite {
		return ErrWriteNotPermitted
	}
	if value == nil || *value == "" {
		return nil
	}

	data := map[string]string{
		"value": *value,
		"token": *value,
	}

	if err := r.cache.Put(ctx, path, data); err != nil {
		return err
	}

	*value = "vault." + path
	return nil
}

// RemoveString deletes a secret at path.
func (r *VaultResolver) RemoveString(ctx context.Context, path string) error {
	if r.config.AccessMode != AccessModeReadAndWrite {
		return ErrWriteNotPermitted
	}
	return r.cache.Delete(ctx, path)
}

// WireHooks connects this resolver to the core/schemas global vault hooks.
func (r *VaultResolver) WireHooks() {
	schemas.VaultResolveHook = r.ResolveString
	if r.config.AccessMode == AccessModeReadAndWrite {
		schemas.VaultStoreHook = r.StoreString
		schemas.VaultRemoveHook = r.RemoveString
	}
	schemas.VaultPrefixHook = r.Prefix
}

// UnwireHooks detaches the global vault hooks.
func (r *VaultResolver) UnwireHooks() {
	schemas.VaultResolveHook = nil
	schemas.VaultStoreHook = nil
	schemas.VaultRemoveHook = nil
	schemas.VaultPrefixHook = nil
}
