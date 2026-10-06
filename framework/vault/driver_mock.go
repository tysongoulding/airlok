package vault

import (
	"context"
	"sync"
	"time"
)

// MockVaultDriver provides a deterministic in-memory VaultProvider implementation with fault injection.
type MockVaultDriver struct {
	mu           sync.RWMutex
	store        map[string]map[string]string
	backendCalls int
	outage       bool
	latency      time.Duration
	customErrors map[string]error
}

// NewMockVaultDriver creates a new MockVaultDriver.
func NewMockVaultDriver() *MockVaultDriver {
	return &MockVaultDriver{
		store:        make(map[string]map[string]string),
		customErrors: make(map[string]error),
	}
}

// SetOutage toggles simulated upstream outage.
func (d *MockVaultDriver) SetOutage(outage bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.outage = outage
}

// SetLatency sets simulated network delay.
func (d *MockVaultDriver) SetLatency(latency time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.latency = latency
}

// SetCustomError registers an error to return when accessing a specific path.
func (d *MockVaultDriver) SetCustomError(path string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err == nil {
		delete(d.customErrors, path)
	} else {
		d.customErrors[path] = err
	}
}

// BackendCalls returns the number of times GetSecret was invoked on the backend.
func (d *MockVaultDriver) BackendCalls() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.backendCalls
}

// GetSecret retrieves the secret data map for path.
func (d *MockVaultDriver) GetSecret(ctx context.Context, path string) (map[string]string, error) {
	d.mu.Lock()
	d.backendCalls++
	outage := d.outage
	latency := d.latency
	customErr := d.customErrors[path]
	d.mu.Unlock()

	if latency > 0 {
		select {
		case <-time.After(latency):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if outage {
		return nil, ErrProviderUnreachable
	}
	if customErr != nil {
		return nil, customErr
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	data, exists := d.store[path]
	if !exists {
		return nil, ErrSecretNotFound
	}

	// Return a copy to prevent concurrent map access mutations
	res := make(map[string]string, len(data))
	for k, v := range data {
		res[k] = v
	}
	return res, nil
}

// PutSecret stores secret data at path.
func (d *MockVaultDriver) PutSecret(ctx context.Context, path string, data map[string]string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.outage {
		return ErrProviderUnreachable
	}

	copied := make(map[string]string, len(data))
	for k, v := range data {
		copied[k] = v
	}
	d.store[path] = copied
	return nil
}

// DeleteSecret removes secret data at path.
func (d *MockVaultDriver) DeleteSecret(ctx context.Context, path string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.outage {
		return ErrProviderUnreachable
	}

	delete(d.store, path)
	return nil
}

// Ping verifies connectivity.
func (d *MockVaultDriver) Ping(ctx context.Context) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.outage {
		return ErrProviderUnreachable
	}
	return nil
}

// Close is a no-op for the mock driver.
func (d *MockVaultDriver) Close() error {
	return nil
}
