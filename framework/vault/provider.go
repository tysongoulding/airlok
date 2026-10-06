package vault

import (
	"context"
	"errors"
)

var (
	ErrSecretNotFound      = errors.New("vault: secret not found")
	ErrFieldNotFound       = errors.New("vault: field not found in secret")
	ErrProviderUnreachable = errors.New("vault: provider unreachable")
	ErrUnauthorized        = errors.New("vault: unauthorized access to vault")
	ErrInvalidReference    = errors.New("vault: invalid secret reference")
	ErrWriteNotPermitted   = errors.New("vault: write not permitted in read_only mode")
	ErrVaultDisabled       = errors.New("vault: vault integration is not enabled")
)

type ProviderType string

const (
	ProviderTypeHashiCorp ProviderType = "hashicorp-vault"
	ProviderTypeAWS       ProviderType = "aws-secrets-manager"
	ProviderTypeGCP       ProviderType = "gcp-secret-manager"
	ProviderTypeMock      ProviderType = "mock"
)

type AccessMode string

const (
	AccessModeReadOnly     AccessMode = "read_only"
	AccessModeReadAndWrite AccessMode = "read_and_write"
)

// VaultProvider defines the pluggable driver contract for external secret backends.
type VaultProvider interface {
	// GetSecret retrieves secret data for a given path as key-value pairs.
	GetSecret(ctx context.Context, path string) (map[string]string, error)
	// PutSecret creates or updates secret data at the given path.
	PutSecret(ctx context.Context, path string, data map[string]string) error
	// DeleteSecret permanently removes the secret at the given path.
	DeleteSecret(ctx context.Context, path string) error
	// Ping validates credentials and connectivity with the vault backend.
	Ping(ctx context.Context) error
	// Close gracefully terminates open connections and background workers.
	Close() error
}
