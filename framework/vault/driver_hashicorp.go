package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// HashiCorpDriver implements VaultProvider for HashiCorp Vault KV v2.
type HashiCorpDriver struct {
	config     HashiCorpConfig
	httpClient *http.Client
	mu         sync.RWMutex
	token      string
}

// NewHashiCorpDriver initializes a HashiCorp Vault driver.
func NewHashiCorpDriver(cfg HashiCorpConfig) (*HashiCorpDriver, error) {
	if cfg.Address == "" {
		cfg.Address = os.Getenv("VAULT_ADDR")
	}
	if cfg.Address == "" {
		return nil, fmt.Errorf("hashicorp vault address is required")
	}
	cfg.Address = strings.TrimSuffix(cfg.Address, "/")

	if cfg.MountPath == "" {
		cfg.MountPath = "secret"
	}
	cfg.MountPath = strings.Trim(cfg.MountPath, "/")

	token := cfg.Token
	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}

	driver := &HashiCorpDriver{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		token: token,
	}

	// If no static token but AppRole credentials provided, perform login
	if driver.token == "" && cfg.RoleID != "" && cfg.SecretID != "" {
		if err := driver.loginAppRole(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to login via approle: %w", err)
		}
	}

	return driver, nil
}

func (d *HashiCorpDriver) loginAppRole(ctx context.Context) error {
	loginURL := fmt.Sprintf("%s/v1/auth/approle/login", d.config.Address)
	payload, _ := json.Marshal(map[string]string{
		"role_id":   d.config.RoleID,
		"secret_id": d.config.SecretID,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if d.config.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", d.config.Namespace)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: approle login returned HTTP %d", ErrUnauthorized, resp.StatusCode)
	}

	var authResp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return err
	}

	d.mu.Lock()
	d.token = authResp.Auth.ClientToken
	d.mu.Unlock()
	return nil
}

func (d *HashiCorpDriver) getToken() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.token
}

// GetSecret reads a KV v2 secret at the specified path.
func (d *HashiCorpDriver) GetSecret(ctx context.Context, path string) (map[string]string, error) {
	path = strings.TrimPrefix(path, "/")
	apiURL := fmt.Sprintf("%s/v1/%s/data/%s", d.config.Address, d.config.MountPath, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}

	token := d.getToken()
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if d.config.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", d.config.Namespace)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnreachable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// OK
	case http.StatusNotFound:
		return nil, ErrSecretNotFound
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, ErrUnauthorized
	default:
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: vault returned HTTP %d: %s", ErrProviderUnreachable, resp.StatusCode, string(body))
	}

	var vaultResp struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&vaultResp); err != nil {
		return nil, fmt.Errorf("failed to decode vault kv2 response: %w", err)
	}

	result := make(map[string]string)
	for k, v := range vaultResp.Data.Data {
		switch val := v.(type) {
		case string:
			result[k] = val
		default:
			b, _ := json.Marshal(val)
			result[k] = string(b)
		}
	}
	return result, nil
}

// PutSecret writes or updates a KV v2 secret at the specified path.
func (d *HashiCorpDriver) PutSecret(ctx context.Context, path string, data map[string]string) error {
	path = strings.TrimPrefix(path, "/")
	apiURL := fmt.Sprintf("%s/v1/%s/data/%s", d.config.Address, d.config.MountPath, path)

	payload, err := json.Marshal(map[string]interface{}{
		"data": data,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	token := d.getToken()
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if d.config.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", d.config.Namespace)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("%w: vault write returned HTTP %d", ErrProviderUnreachable, resp.StatusCode)
	}
	return nil
}

// DeleteSecret permanently destroys a KV v2 secret and its metadata.
func (d *HashiCorpDriver) DeleteSecret(ctx context.Context, path string) error {
	path = strings.TrimPrefix(path, "/")
	apiURL := fmt.Sprintf("%s/v1/%s/metadata/%s", d.config.Address, d.config.MountPath, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, apiURL, nil)
	if err != nil {
		return err
	}

	token := d.getToken()
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if d.config.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", d.config.Namespace)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("%w: vault delete returned HTTP %d", ErrProviderUnreachable, resp.StatusCode)
	}
	return nil
}

// Ping verifies health and connectivity with HashiCorp Vault.
func (d *HashiCorpDriver) Ping(ctx context.Context) error {
	apiURL := fmt.Sprintf("%s/v1/sys/health", d.config.Address)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnreachable, err)
	}
	defer resp.Body.Close()

	// 200 (initialized, unsealed, active) or 429 (standby) indicates vault is reachable
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusTooManyRequests {
		return nil
	}
	return fmt.Errorf("%w: sys/health returned HTTP %d", ErrProviderUnreachable, resp.StatusCode)
}

// Close gracefully closes the driver.
func (d *HashiCorpDriver) Close() error {
	return nil
}
