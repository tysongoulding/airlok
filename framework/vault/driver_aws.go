package vault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// AWSDriver implements VaultProvider for AWS Secrets Manager using standard AWS REST API / SigV4.
type AWSDriver struct {
	config     AWSConfig
	httpClient *http.Client
	endpoint   string
}

// NewAWSDriver initializes an AWS Secrets Manager driver.
func NewAWSDriver(cfg AWSConfig) (*AWSDriver, error) {
	if cfg.Region == "" {
		cfg.Region = os.Getenv("AWS_REGION")
		if cfg.Region == "" {
			cfg.Region = os.Getenv("AWS_DEFAULT_REGION")
		}
		if cfg.Region == "" {
			cfg.Region = "us-east-1"
		}
	}
	if cfg.AccessKeyID == "" {
		cfg.AccessKeyID = os.Getenv("AWS_ACCESS_KEY_ID")
	}
	if cfg.SecretAccessKey == "" {
		cfg.SecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}
	if cfg.SessionToken == "" {
		cfg.SessionToken = os.Getenv("AWS_SESSION_TOKEN")
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://secretsmanager.%s.amazonaws.com", cfg.Region)
	}
	endpoint = strings.TrimSuffix(endpoint, "/")

	return &AWSDriver{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		endpoint: endpoint,
	}, nil
}

// GetSecret retrieves a secret from AWS Secrets Manager.
func (d *AWSDriver) GetSecret(ctx context.Context, path string) (map[string]string, error) {
	payload, _ := json.Marshal(map[string]string{
		"SecretId": path,
	})

	respBody, err := d.callAPI(ctx, "secretsmanager.GetSecretValue", payload)
	if err != nil {
		if strings.Contains(err.Error(), "ResourceNotFoundException") {
			return nil, ErrSecretNotFound
		}
		if strings.Contains(err.Error(), "AccessDeniedException") || strings.Contains(err.Error(), "UnrecognizedClientException") {
			return nil, ErrUnauthorized
		}
		return nil, fmt.Errorf("%w: %v", ErrProviderUnreachable, err)
	}

	var result struct {
		SecretString string `json:"SecretString"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to decode AWS secret response: %w", err)
	}

	if result.SecretString == "" {
		return nil, ErrSecretNotFound
	}

	// If SecretString is JSON map, unpack it
	var kvMap map[string]interface{}
	if err := json.Unmarshal([]byte(result.SecretString), &kvMap); err == nil && len(kvMap) > 0 {
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
	return map[string]string{
		"value": result.SecretString,
		"token": result.SecretString,
	}, nil
}

// PutSecret creates or updates a secret in AWS Secrets Manager.
func (d *AWSDriver) PutSecret(ctx context.Context, path string, data map[string]string) error {
	secretJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"SecretId":     path,
		"SecretString": string(secretJSON),
	})

	_, err = d.callAPI(ctx, "secretsmanager.PutSecretValue", payload)
	if err != nil && strings.Contains(err.Error(), "ResourceNotFoundException") {
		// Secret does not exist yet -> create it
		createPayload, _ := json.Marshal(map[string]interface{}{
			"Name":         path,
			"SecretString": string(secretJSON),
		})
		_, err = d.callAPI(ctx, "secretsmanager.CreateSecret", createPayload)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnreachable, err)
	}
	return nil
}

// DeleteSecret marks a secret for deletion in AWS Secrets Manager.
func (d *AWSDriver) DeleteSecret(ctx context.Context, path string) error {
	payload, _ := json.Marshal(map[string]interface{}{
		"SecretId":                   path,
		"RecoveryWindowInDays":       7,
		"ForceDeleteWithoutRecovery": true,
	})

	_, err := d.callAPI(ctx, "secretsmanager.DeleteSecret", payload)
	if err != nil && !strings.Contains(err.Error(), "ResourceNotFoundException") {
		return fmt.Errorf("%w: %v", ErrProviderUnreachable, err)
	}
	return nil
}

// Ping verifies connectivity with AWS Secrets Manager.
func (d *AWSDriver) Ping(ctx context.Context) error {
	payload, _ := json.Marshal(map[string]interface{}{
		"MaxResults": 1,
	})
	_, err := d.callAPI(ctx, "secretsmanager.ListSecrets", payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProviderUnreachable, err)
	}
	return nil
}

// Close is a no-op for the AWS driver.
func (d *AWSDriver) Close() error {
	return nil
}

func (d *AWSDriver) callAPI(ctx context.Context, target string, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)

	// If access key and secret key provided, sign request with basic SigV4 headers
	if d.config.AccessKeyID != "" && d.config.SecretAccessKey != "" {
		signAWSv4(req, d.config.Region, "secretsmanager", d.config.AccessKeyID, d.config.SecretAccessKey, d.config.SessionToken, payload)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func signAWSv4(req *http.Request, region, service, accessKey, secretKey, sessionToken string, payload []byte) {
	now := time.Now().UTC()
	dateStamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	req.Header.Set("X-Amz-Date", amzDate)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}

	hPayload := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(hPayload[:])

	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\nx-amz-date:%s\nx-amz-target:%s\n",
		req.Header.Get("Content-Type"), req.Host, amzDate, req.Header.Get("X-Amz-Target"))
	signedHeaders := "content-type;host;x-amz-date;x-amz-target"

	canonicalRequest := fmt.Sprintf("POST\n/\n\n%s\n%s\n%s", canonicalHeaders, signedHeaders, payloadHash)
	hCanon := sha256.Sum256([]byte(canonicalRequest))

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", amzDate, credentialScope, hex.EncodeToString(hCanon[:]))

	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")

	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
