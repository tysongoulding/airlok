package gitstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanForSecrets(t *testing.T) {
	tmpDir := t.TempDir()

	// Safe file
	safePath := filepath.Join(tmpDir, "safe.txt")
	require.NoError(t, os.WriteFile(safePath, []byte("normal content"), 0600))
	assert.NoError(t, ScanForSecrets(safePath))

	// Leaked Slack token file
	leakPath := filepath.Join(tmpDir, "leak.env")
	require.NoError(t, os.WriteFile(leakPath, []byte("TOKEN=xoxb-999999999"), 0600))
	err := ScanForSecrets(leakPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "xoxb-")
}

func TestGitSyncerDebounce(t *testing.T) {
	tmpDir := t.TempDir()
	syncer := NewGitSyncer(tmpDir, 500*time.Millisecond)

	syncer.lastCommitAt = time.Now()

	// Immediate follow-up commit is debounced
	res, err := syncer.CommitCheckpoint("rapid commit", []string{})
	require.NoError(t, err)
	assert.Equal(t, "debounced", res)
}
