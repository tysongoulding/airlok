package vault

import "time"

// VaultStoreConfig configures the vault secret storage provider.
type VaultStoreConfig struct {
	Enabled         bool             `json:"enabled"`
	Type            ProviderType     `json:"type"`
	Prefix          string           `json:"prefix"`                     // default: "bifrost"
	AccessMode      AccessMode       `json:"access_mode"`                // default: "read_only"
	CacheTTL        time.Duration    `json:"cache_ttl,omitempty"`        // default: 5m
	RefreshInterval time.Duration    `json:"refresh_interval,omitempty"` // default: 1m
	AWS             *AWSConfig       `json:"aws,omitempty"`
	GCP             *GCPConfig       `json:"gcp,omitempty"`
	HashiCorp       *HashiCorpConfig `json:"hashicorp,omitempty"`
}

// AWSConfig configures AWS Secrets Manager connectivity.
type AWSConfig struct {
	Region          string `json:"region"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
	RoleARN         string `json:"role_arn,omitempty"`
	KMSKeyID        string `json:"kms_key_id,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"` // For localstack or testing
}

// GCPConfig configures Google Cloud Secret Manager connectivity.
type GCPConfig struct {
	ProjectID       string `json:"project_id"`
	CredentialsJSON string `json:"credentials_json,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"` // For testing
}

// HashiCorpConfig configures HashiCorp Vault KV v2 connectivity.
type HashiCorpConfig struct {
	Address   string `json:"address"`
	Token     string `json:"token,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	MountPath string `json:"mount_path,omitempty"` // default: "secret"
	RoleID    string `json:"role_id,omitempty"`
	SecretID  string `json:"secret_id,omitempty"`
}
