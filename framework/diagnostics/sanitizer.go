package diagnostics

import (
	"encoding/json"
	"strings"
)

const maxSanitizerDepth = 32

// SanitizeSecretFields recursively scrubs all sensitive credentials and secrets,
// bounded to maxSanitizerDepth (32) to prevent infinite recursion and stack overflow.
func SanitizeSecretFields(input interface{}) interface{} {
	return sanitizeSecretFieldsWithDepth(input, 0, maxSanitizerDepth)
}

// SanitizeSecretFieldsWithDepth recursively scrubs sensitive fields with a caller-specified max depth.
func SanitizeSecretFieldsWithDepth(input interface{}, maxDepth int) interface{} {
	if maxDepth <= 0 {
		maxDepth = maxSanitizerDepth
	}
	return sanitizeSecretFieldsWithDepth(input, 0, maxDepth)
}

func sanitizeSecretFieldsWithDepth(input interface{}, depth int, maxDepth int) interface{} {
	if depth >= maxDepth {
		return "[MAX_DEPTH_EXCEEDED]"
	}

	if input == nil {
		return nil
	}

	switch v := input.(type) {
	case bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, uintptr,
		float32, float64,
		complex64, complex128:
		return v

	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for k, val := range v {
			if isSensitiveKey(k) {
				out[k] = "[REDACTED]"
			} else {
				out[k] = sanitizeSecretFieldsWithDepth(val, depth+1, maxDepth)
			}
		}
		return out

	case []interface{}:
		out := make([]interface{}, len(v))
		for i, val := range v {
			out[i] = sanitizeSecretFieldsWithDepth(val, depth+1, maxDepth)
		}
		return out

	case string:
		if isSensitiveValue(v) {
			return "[REDACTED]"
		}
		return v

	default:
		// Attempt JSON normalization for typed structs, typed slices, and custom maps
		rawBytes, err := json.Marshal(v)
		if err == nil {
			var unmarshaled interface{}
			if err := json.Unmarshal(rawBytes, &unmarshaled); err == nil {
				switch u := unmarshaled.(type) {
				case map[string]interface{}, []interface{}:
					return sanitizeSecretFieldsWithDepth(u, depth+1, maxDepth)
				case string:
					if isSensitiveValue(u) {
						return "[REDACTED]"
					}
					return v
				}
			}
		}
		return v
	}
}

func isSensitiveKey(k string) bool {
	lower := strings.ToLower(k)
	sensitivePatterns := []string{
		"key", "secret", "token", "password", "pwd", "auth",
		"hmac", "credential", "cred", "dsn", "conn_str",
		"private", "cert", "hash", "salt", "signature",
	}
	for _, p := range sensitivePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isSensitiveValue(v string) bool {
	if strings.HasPrefix(v, "sk-") || strings.HasPrefix(v, "ghp_") ||
		strings.HasPrefix(v, "AKIA") || strings.HasPrefix(v, "vault.") ||
		strings.HasPrefix(v, "Bearer ") {
		return true
	}
	return false
}
