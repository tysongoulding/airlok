package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"sync"
)

// IPSanitizer scrubs or pseudonymizes client IP addresses.
type IPSanitizer struct {
	mu       sync.RWMutex
	mode     IPSanitizationMode
	salt     []byte
	ipv4Mask net.IPMask
	ipv6Mask net.IPMask
}

// NewIPSanitizer creates a new sanitizer from config.
func NewIPSanitizer(mode IPSanitizationMode, salt string) *IPSanitizer {
	if mode == "" {
		mode = IPSanitizationNone
	}
	return &IPSanitizer{
		mode:     mode,
		salt:     []byte(salt),
		ipv4Mask: net.CIDRMask(24, 32),
		ipv6Mask: net.CIDRMask(48, 128),
	}
}

// SetMode dynamically updates the sanitization mode.
func (s *IPSanitizer) SetMode(mode IPSanitizationMode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
}

// Sanitize transforms an IP address according to configured privacy mode.
func (s *IPSanitizer) Sanitize(ipStr string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" || s.mode == IPSanitizationNone {
		return ipStr
	}
	if s.mode == IPSanitizationOmit {
		return ""
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	switch s.mode {
	case IPSanitizationMask:
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.Mask(s.ipv4Mask).String()
		}
		if ipv6 := ip.To16(); ipv6 != nil {
			return ipv6.Mask(s.ipv6Mask).String()
		}
		return ""

	case IPSanitizationHash:
		mac := hmac.New(sha256.New, s.salt)
		mac.Write([]byte(ip.String()))
		return "anon-ip-" + hex.EncodeToString(mac.Sum(nil))[:16]

	default:
		return ipStr
	}
}

// ScrubEventDynamic scrubs ClientIP from event copy if omission is active.
func (s *IPSanitizer) ScrubEventDynamic(e *AuditEvent) *AuditEvent {
	if e == nil {
		return nil
	}
	cp := e.Clone()
	s.mu.RLock()
	mode := s.mode
	s.mu.RUnlock()

	if mode == IPSanitizationOmit {
		cp.ClientIP = ""
	}
	return cp
}
