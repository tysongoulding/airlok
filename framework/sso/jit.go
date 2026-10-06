package sso

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// SCIMUser represents a SCIM 2.0 user representation for inbound provisioning.
type SCIMUser struct {
	ID          string   `json:"id"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName"`
	Active      bool     `json:"active"`
	Groups      []string `json:"groups"`
}

// Clone returns a deep copy of the User to ensure thread-safe memory isolation.
func (u *User) Clone() *User {
	if u == nil {
		return nil
	}
	clone := *u
	if u.Groups != nil {
		clone.Groups = make([]string, len(u.Groups))
		copy(clone.Groups, u.Groups)
	}
	if u.Teams != nil {
		clone.Teams = make([]string, len(u.Teams))
		copy(clone.Teams, u.Teams)
	}
	if u.BusinessUnits != nil {
		clone.BusinessUnits = make([]string, len(u.BusinessUnits))
		copy(clone.BusinessUnits, u.BusinessUnits)
	}
	if u.ClaimMemory != nil {
		clone.ClaimMemory = make(map[string][]string, len(u.ClaimMemory))
		for k, v := range u.ClaimMemory {
			if v != nil {
				vCopy := make([]string, len(v))
				copy(vCopy, v)
				clone.ClaimMemory[k] = vCopy
			} else {
				clone.ClaimMemory[k] = nil
			}
		}
	}
	return &clone
}

// MemoryUserStore provides an in-memory thread-safe implementation of UserStore.
type MemoryUserStore struct {
	mu     sync.RWMutex
	users  map[string]*User // key: user.ID
	emails map[string]*User // key: lower-cased normalized user.Email
}

// NewMemoryUserStore creates a new empty MemoryUserStore.
func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		users:  make(map[string]*User),
		emails: make(map[string]*User),
	}
}

// GetUser retrieves a user by ID or Subject.
func (s *MemoryUserStore) GetUser(ctx context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if user, ok := s.users[id]; ok {
		return user.Clone(), nil
	}

	// Also search by email case-insensitively via dedicated emails index
	normID := strings.ToLower(strings.TrimSpace(id))
	if user, ok := s.emails[normID]; ok {
		return user.Clone(), nil
	}

	return nil, ErrUserNotFound
}

// GetUserByEmail retrieves a user by email address.
func (s *MemoryUserStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	normEmail := strings.ToLower(strings.TrimSpace(email))
	if user, ok := s.emails[normEmail]; ok {
		return user.Clone(), nil
	}
	return nil, ErrUserNotFound
}

// CreateUser creates a new user record.
func (s *MemoryUserStore) CreateUser(ctx context.Context, user *User) error {
	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.ID]; exists {
		return ErrUserAlreadyExists
	}
	var normEmail string
	if user.Email != "" {
		normEmail = strings.ToLower(strings.TrimSpace(user.Email))
		if _, exists := s.emails[normEmail]; exists {
			return ErrUserAlreadyExists
		}
	}

	cloned := user.Clone()
	s.users[cloned.ID] = cloned
	if normEmail != "" {
		s.emails[normEmail] = cloned
	}
	return nil
}

// UpdateUser updates an existing user record.
func (s *MemoryUserStore) UpdateUser(ctx context.Context, user *User) error {
	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.users[user.ID]
	if !exists {
		return ErrUserNotFound
	}

	var newNormEmail string
	if user.Email != "" {
		newNormEmail = strings.ToLower(strings.TrimSpace(user.Email))
		// Ensure email is not already claimed by a different user
		if otherUser, emailExists := s.emails[newNormEmail]; emailExists && otherUser.ID != user.ID {
			return ErrUserAlreadyExists
		}
	}

	// If old user had an email, and it changed, remove old email index
	if existing.Email != "" {
		oldNormEmail := strings.ToLower(strings.TrimSpace(existing.Email))
		if oldNormEmail != newNormEmail {
			delete(s.emails, oldNormEmail)
		}
	}

	cloned := user.Clone()
	s.users[cloned.ID] = cloned
	if newNormEmail != "" {
		s.emails[newNormEmail] = cloned
	}
	return nil
}

// DeleteUser removes a user record.
func (s *MemoryUserStore) DeleteUser(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, exists := s.users[id]
	if !exists {
		normID := strings.ToLower(strings.TrimSpace(id))
		u, exists = s.emails[normID]
		if !exists {
			return ErrUserNotFound
		}
	}

	delete(s.users, u.ID)
	if u.Email != "" {
		delete(s.emails, strings.ToLower(strings.TrimSpace(u.Email)))
	}
	return nil
}

// ListUsers returns all unique users in the store.
func (s *MemoryUserStore) ListUsers(ctx context.Context) ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		result = append(result, u.Clone())
	}
	return result, nil
}

// JITEngine orchestrates Just-In-Time account provisioning and synchronization.
type JITEngine struct {
	store     UserStore
	scimMode  string   // "both" or "scim" (freeze mode)
	userLocks sync.Map // user id -> *sync.Mutex
}

// NewJITEngine initializes a JITEngine.
func NewJITEngine(store UserStore, scimMode string) *JITEngine {
	if scimMode == "" {
		scimMode = "both"
	}
	return &JITEngine{
		store:    store,
		scimMode: scimMode,
	}
}

// Store returns the underlying UserStore.
func (j *JITEngine) Store() UserStore {
	return j.store
}

// ProvisionUser provisions or synchronizes a user account upon successful SSO login.
func (j *JITEngine) ProvisionUser(ctx context.Context, claims *IdentityClaims, role string) (*User, error) {
	if claims == nil || claims.Subject == "" {
		return nil, fmt.Errorf("invalid claims: missing subject")
	}

	// In SCIM-only freeze mode, OIDC login cannot create new accounts
	if j.scimMode == "scim" {
		existing, err := j.store.GetUser(ctx, claims.Subject)
		if err != nil {
			return nil, fmt.Errorf("scim_only_mode: new users must be provisioned via SCIM API")
		}
		return existing.Clone(), nil
	}

	// Mutex per user to prevent concurrent creation races
	lockVal, _ := j.userLocks.LoadOrStore(claims.Subject, &sync.Mutex{})
	userLock := lockVal.(*sync.Mutex)
	userLock.Lock()
	defer userLock.Unlock()

	now := time.Now()

	// Check if user already exists
	existing, err := j.store.GetUser(ctx, claims.Subject)
	if err == nil && existing != nil {
		// Returning User: Synchronize metadata & claim memory on isolated clone
		updatedUser := existing.Clone()
		updatedUser.LastLoginAt = now
		updatedUser.UpdatedAt = now
		if claims.Email != "" {
			updatedUser.Email = claims.Email
		}
		if claims.Name != "" {
			updatedUser.Name = claims.Name
		}
		if claims.PreferredUsername != "" {
			updatedUser.PreferredUsername = claims.PreferredUsername
		}
		if len(claims.Groups) > 0 {
			groupsCopy := make([]string, len(claims.Groups))
			copy(groupsCopy, claims.Groups)
			updatedUser.Groups = groupsCopy
		}

		// Claim memory reconciliation:
		// If role was explicitly resolved from token, update it.
		// If role was omitted from token, preserve existing role.
		if role != "" {
			updatedUser.Role = role
		}

		if err := j.store.UpdateUser(ctx, updatedUser); err != nil {
			return nil, err
		}
		return updatedUser, nil
	}

	// New User: Must have valid mapped role
	if role == "" {
		return nil, ErrUnmappedRole
	}

	var groups []string
	if len(claims.Groups) > 0 {
		groups = make([]string, len(claims.Groups))
		copy(groups, claims.Groups)
	}

	newUser := &User{
		ID:                claims.Subject,
		Email:             claims.Email,
		Name:              claims.Name,
		PreferredUsername: claims.PreferredUsername,
		Role:              role,
		Groups:            groups,
		Provider:          "oidc",
		Active:            true,
		LastLoginAt:       now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := j.store.CreateUser(ctx, newUser); err != nil {
		return nil, err
	}
	return newUser, nil
}

// ProvisionSCIMUser provisions a user account via inbound SCIM 2.0 API.
func (j *JITEngine) ProvisionSCIMUser(ctx context.Context, scimUser SCIMUser) (*User, error) {
	if scimUser.UserName == "" && scimUser.ID == "" {
		return nil, fmt.Errorf("scim user missing identifier")
	}

	id := scimUser.ID
	if id == "" {
		id = scimUser.UserName
	}

	now := time.Now()
	var groups []string
	if len(scimUser.Groups) > 0 {
		groups = make([]string, len(scimUser.Groups))
		copy(groups, scimUser.Groups)
	}

	user := &User{
		ID:                id,
		Email:             scimUser.UserName,
		Name:              scimUser.DisplayName,
		PreferredUsername: scimUser.UserName,
		Groups:            groups,
		Provider:          "scim",
		Active:            scimUser.Active,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := j.store.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}
