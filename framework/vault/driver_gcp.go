package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// GCPDriver implements VaultProvider for Google Cloud Secret Manager REST API.
type GCPDriver struct {
	config     GCPConfig
	httpClient *http.Client
	baseURL    string
}

// NewGCPDriver initializes a Google Cloud Secret Manager driver.
func NewGCPDriver(cfg GCPConfig) (*GCPDriver, error) {
	if cfg.ProjectID == "" {
		cfg.ProjectID = os.Getenv("GCP_PROJECT_ID")
		if cfg.ProjectID == "" {
			cfg.ProjectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
		}
	}

	baseURL := cfg.Endpoint
	if baseURL == "" {
		baseURL = "https://secretmanager.googleapis.com/v1"
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &GCPDriver{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		baseURL: baseURL,
	}, nil
}

// GetSecret retrieves a secret version payload from GCP Secret Manager.
func (d *GCPDriver) GetSecret(ctx context.Context, path string) (map[string]string, error) {
	cleanPath := strings.Trim(path, "/")
	// Convert bifrost/keys/openai -> bifrost_keys_openai if contains slashes, or direct secret name
	secretName := strings.ReplaceAll(cleanPath, "/", "_")

	url := fmt.Sprintf("%s/projects/%s/secrets/%s/versions/latest:access", d.baseURL, d.config.ProjectID, secretName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	d.applyAuth(req)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrSecretNotFound
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: GCP HTTP %d: %s", ErrProviderUnreachable, resp.StatusCode, string(body))
	}

	var accessResp struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&accessResp); err != nil {
		return nil, fmt.Errorf("failed to decode GCP secret payload: %w", err)
	}

	rawBytes, err := base64.StdEncoding.DecodeString(accessResp.Payload.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 secret data: %w", err)
	}

	// If payload is JSON map, unpack it
	var kvMap map[string]interface{}
	if err := json.Unmarshal(rawBytes, &kvMap); err == nil && len(kvMap) > 0 {
		out := make(map[string]string, len(kvMap))
		for k, v := range kvMap {
			switch val := v.(type) {
			case string:
				out[k] = val
			default:
				b, _ := json.Marshal(val)
				out[k] = string(b)
			}
		}
		return out, nil
	}

	// Raw string: return as value and token
	rawStr := string(rawBytes)
	return map[string]string{
		"value": rawStr,
		"token": rawStr,
	}, nil
}

// PutSecret creates or updates a secret version in GCP Secret Manager.
func (d *GCPDriver) PutSecret(ctx context.Context, path string, data map[string]string) error {
	cleanPath := strings.Trim(path, "/")
	secretName := strings.ReplaceAll(cleanPath, "/", "_")

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	b64Data := base64.StdEncoding.EncodeToString(jsonBytes)

	// Add new version
	versionURL := fmt.Sprintf("%s/projects/%s/secrets/%s:addVersion", d.baseURL, d.config.ProjectID, secretName)
	payload, _ := json.Marshal(map[string]interface{}{
		"payload": map[string]string{
			"data": b64Data,
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, versionURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	d.applyAuth(req)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Secret container doesn't exist -> create it
		createURL := fmt.Sprintf("%s/projects/%s/secrets?secretId=%s", d.baseURL, d.config.ProjectID, secretName)
		createPayload, _ := json.Marshal(map[string]interface{}{
			"replication": map[string]interface{}{
				"automatic": map[string]interface{}{},
			},
		})
		createReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, createURL, bytes.NewReader(createPayload))
		createReq.Header.Set("Content-Type", "application/json")
		d.applyAuth(createReq)

		cResp, cErr := d.httpClient.Do(createReq)
		if cErr == nil {
			cResp.Body.Close()
			// Retry addVersion
			reqRetry, _ := http.NewRequestWithContext(ctx, http.MethodPost, versionURL, bytes.NewReader(payload))
			reqRetry.Header.Set("Content-Type", "application/json")
			d.applyAuth(reqRetry)
			if rResp, rErr := d.httpClient.Do(reqRetry); rErr == nil {
				defer rResp.Body.Close()
				if rResp.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: GCP write returned HTTP %d", ErrProviderUnreachable, resp.StatusCode)
	}
	return nil
}

// DeleteSecret permanently removes a secret in GCP Secret Manager.
func (d *GCPDriver) DeleteSecret(ctx context.Context, path string) error {
	cleanPath := strings.Trim(path, "/")
	secretName := strings.ReplaceAll(cleanPath, "/", "_")

	url := fmt.Sprintf("%s/projects/%s/secrets/%s", d.baseURL, d.config.ProjectID, secretName)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	d.applyAuth(req)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("%w: GCP delete returned HTTP %d", ErrProviderUnreachable, resp.StatusCode)
	}
	return nil
}

// Ping checks connectivity with GCP Secret Manager.
func (d *GCPDriver) Ping(ctx context.Context) error {
	url := fmt.Sprintf("%s/projects/%s/secrets?pageSize=1", d.baseURL, d.config.ProjectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	d.applyAuth(req)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("%w: ping returned HTTP %d", ErrProviderUnreachable, resp.StatusCode)
}

// Close is a no-op for the GCP driver.
func (d *GCPDriver) Close() error {
	return nil
}

func (d *GCPDriver) applyAuth(req *http.Request) {
	if d.config.CredentialsJSON != "" {
		// If credentials json contains a token or API key
		var creds struct {
			Token  string `json:"token"`
			APIKey string `json:"api_key"`
		}
		if err := json.Unmarshal([]byte(d.config.CredentialsJSON), &creds); err == nil {
			if creds.Token != "" {
				req.Header.Set("Authorization", "Bearer "+creds.Token)
				return
			}
			if creds.APIKey != "" {
				req.Header.Set("X-Goog-Api-Key", creds.APIKey)
				return
			}
		}
	}
	if token := os.Getenv("GOOGLE_OAUTH_ACCESS_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}
