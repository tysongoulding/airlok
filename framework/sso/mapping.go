package sso

import (
	"strings"
	"sync"
)

// SystemRoleWeights defines the permission count ranking for highestPermissionCount resolution.
// Admin (54) > Developer (7) > Security Auditor (5) > Operator (4).
var SystemRoleWeights = map[string]int{
	RoleAdmin:           54,
	RoleDeveloper:       7,
	RoleSecurityAuditor: 5,
	RoleOperator:        4,
}

// RoleMapper resolves identity claims or group lists into an authorized system role.
type RoleMapper struct {
	mu       sync.RWMutex
	mappings []AttributeRoleMapping
	strategy RoleResolutionStrategy
}

// NewRoleMapper creates a new RoleMapper with the specified mappings and resolution strategy.
func NewRoleMapper(mappings []AttributeRoleMapping, strategy RoleResolutionStrategy) *RoleMapper {
	if strategy == "" {
		strategy = StrategyHighestPermissionCount
	}
	// Copy mappings slice for safety
	rules := make([]AttributeRoleMapping, len(mappings))
	copy(rules, mappings)
	return &RoleMapper{
		mappings: rules,
		strategy: strategy,
	}
}

// AddMapping appends a new attribute role mapping rule.
func (m *RoleMapper) AddMapping(mapping AttributeRoleMapping) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mappings = append(m.mappings, mapping)
}

// SetStrategy updates the role resolution strategy.
func (m *RoleMapper) SetStrategy(strategy RoleResolutionStrategy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strategy == "" {
		strategy = StrategyHighestPermissionCount
	}
	m.strategy = strategy
}

// ResolveRole maps normalized identity claims to a system role.
func (m *RoleMapper) ResolveRole(claims *IdentityClaims) (string, error) {
	if claims == nil {
		return "", ErrUnmappedRole
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	matchedRoles := make([]string, 0)

	for _, rule := range m.mappings {
		values := extractClaimValues(claims, rule.Attribute)
		for _, val := range values {
			if matchRule(val, rule.Value) {
				if m.strategy == StrategyOrder {
					// Order strategy: First match wins immediately
					return rule.Role, nil
				}
				matchedRoles = append(matchedRoles, rule.Role)
			}
		}
	}

	if len(matchedRoles) == 0 {
		return "", ErrUnmappedRole
	}

	// StrategyHighestPermissionCount: Pick role with maximum weight
	bestRole := ""
	maxWeight := -1
	for _, role := range matchedRoles {
		weight, ok := SystemRoleWeights[role]
		if !ok {
			weight = 0
		}
		if weight > maxWeight {
			maxWeight = weight
			bestRole = role
		}
	}

	if bestRole == "" {
		return "", ErrUnmappedRole
	}
	return bestRole, nil
}

// ResolveRoleFromGroups evaluates groups directly against "groups" attribute mappings.
func (m *RoleMapper) ResolveRoleFromGroups(groups []string) (string, error) {
	dummyClaims := &IdentityClaims{
		Groups: groups,
	}
	return m.ResolveRole(dummyClaims)
}

func extractClaimValues(claims *IdentityClaims, attribute string) []string {
	attrLower := strings.ToLower(attribute)
	if attrLower == "groups" {
		return claims.Groups
	}
	if attrLower == "roles" {
		return claims.Roles
	}

	if len(claims.RawClaims) == 0 {
		return nil
	}

	// Dot-path navigation in claims.RawClaims (e.g. "realm_access.roles")
	parts := strings.Split(attribute, ".")
	var current interface{} = claims.RawClaims
	for _, part := range parts {
		if m, ok := current.(map[string]interface{}); ok {
			current = m[part]
		} else {
			return nil
		}
	}

	switch v := current.(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []interface{}:
		res := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				res = append(res, s)
			}
		}
		return res
	default:
		return nil
	}
}

func matchRule(actual, pattern string) bool {
	if pattern == "*" {
		return true
	}
	return strings.EqualFold(actual, pattern)
}
