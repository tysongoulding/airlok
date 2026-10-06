package gitstore

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// GitSyncer provides debounced Git commits with pre-flight secret scanning (Mitigations F-02, F-04).
type GitSyncer struct {
	repoPath           string
	minCommitInterval  time.Duration
	lastCommitAt       time.Time
	mu                 sync.Mutex
}

// NewGitSyncer creates a new GitSyncer for the specified repository.
func NewGitSyncer(repoPath string, minCommitInterval time.Duration) *GitSyncer {
	return &GitSyncer{
		repoPath:          repoPath,
		minCommitInterval: minCommitInterval,
	}
}

// ScanForSecrets scans a file for known token signatures to prevent accidental credential commits.
func ScanForSecrets(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	content := string(data)
	forbiddenPrefixes := []string{
		"ya29.",          // Google OAuth access token
		"1//0",           // Google refresh token
		"xoxb-",          // Slack bot token
		"xoxp-",          // Slack user token
		"sk-ant-",        // Anthropic API key
		"gho_",           // GitHub personal access token
		"-----BEGIN RSA", // Private keys
	}

	for _, prefix := range forbiddenPrefixes {
		if strings.Contains(content, prefix) {
			return fmt.Errorf("pre-commit secret scanner: file '%s' contains forbidden secret signature '%s'", filePath, prefix)
		}
	}

	return nil
}

// CommitCheckpoint commits the specified files with debouncing to prevent lock contention.
func (s *GitSyncer) CommitCheckpoint(message string, files []string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Debounce check (Mitigation F-04)
	now := time.Now()
	if !s.lastCommitAt.IsZero() && now.Sub(s.lastCommitAt) < s.minCommitInterval {
		return "debounced", nil
	}
	s.lastCommitAt = now

	// Secret scan pre-flight check
	for _, file := range files {
		fullPath := file
		if !filepath.IsAbs(file) {
			fullPath = filepath.Join(s.repoPath, file)
		}
		if err := ScanForSecrets(fullPath); err != nil {
			return "", err
		}
	}

	// Stage files
	for _, file := range files {
		cmd := exec.Command("git", "add", file)
		cmd.Dir = s.repoPath
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("git add failed for '%s': %w", file, err)
		}
	}

	// Commit
	commitMsg := fmt.Sprintf("[airlok] %s", message)
	cmd := exec.Command("git", "commit", "-m", commitMsg)
	cmd.Dir = s.repoPath
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If nothing to commit, return clean status
		if strings.Contains(string(output), "nothing to commit") {
			return "no-op", nil
		}
		return "", fmt.Errorf("git commit failed: %s (%w)", string(output), err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) > 0 {
		return lines[0], nil
	}
	return "committed", nil
}
