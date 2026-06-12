package services

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const AdminSessionTTL = 7 * 24 * time.Hour

type AdminAuthStatus struct {
	Initialized   bool   `json:"initialized"`
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"userID,omitempty"`
	Username      string `json:"username,omitempty"`
}

type adminSessionRecord struct {
	UserID    string
	Username  string
	ExpiresAt time.Time
}

type AdminAuthService struct {
	appSettings *AppSettingsService
	users       *UserStore
	mu          sync.Mutex
	sessions    map[string]adminSessionRecord
	now         func() time.Time
}

func NewAdminAuthService(appSettings *AppSettingsService) *AdminAuthService {
	return &AdminAuthService{
		appSettings: appSettings,
		users:       NewUserStore(),
		sessions:    make(map[string]adminSessionRecord),
		now:         time.Now,
	}
}

func (s *AdminAuthService) UserStore() *UserStore {
	if s == nil {
		return nil
	}
	return s.users
}

func (s *AdminAuthService) GetStatus(sessionToken string) (*AdminAuthStatus, error) {
	userCount, err := s.users.CountUsers()
	if err != nil {
		return nil, err
	}
	status := &AdminAuthStatus{Initialized: userCount > 0}
	if !status.Initialized {
		return status, nil
	}

	user, ok, err := s.ValidateUserSession(sessionToken)
	if err != nil {
		return nil, err
	}
	if ok {
		status.Authenticated = true
		status.UserID = user.ID
		status.Username = user.Username
	}
	return status, nil
}

// InitializeAdmin is retained for compatibility with existing local tests and
// desktop callers. The web server no longer exposes user creation.
func (s *AdminAuthService) InitializeAdmin(username, password string) (string, *AdminAuthStatus, error) {
	if count, err := s.users.CountUsers(); err != nil {
		return "", nil, err
	} else if count > 0 {
		return "", nil, errors.New("用户已初始化")
	}

	user, err := s.users.AddUser(username, password)
	if err != nil {
		return "", nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = make(map[string]adminSessionRecord)
	token, err := s.issueSessionLocked(user.ID, user.Username)
	if err != nil {
		return "", nil, err
	}
	return token, &AdminAuthStatus{
		Initialized:   true,
		Authenticated: true,
		UserID:        user.ID,
		Username:      user.Username,
	}, nil
}

func (s *AdminAuthService) Login(username, password string) (string, *AdminAuthStatus, error) {
	user, err := s.users.Authenticate(username, password)
	if err != nil {
		return "", nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	token, err := s.issueSessionLocked(user.ID, user.Username)
	if err != nil {
		return "", nil, err
	}
	return token, &AdminAuthStatus{
		Initialized:   true,
		Authenticated: true,
		UserID:        user.ID,
		Username:      user.Username,
	}, nil
}

// UpdateCredentials is kept for compatibility. Operational user management is
// handled by scripts/manage-users.
func (s *AdminAuthService) UpdateCredentials(currentPassword, newUsername, newPassword string) (string, *AdminAuthStatus, error) {
	current, ok, err := s.currentSingleUser()
	if err != nil {
		return "", nil, err
	}
	if !ok {
		return "", nil, errors.New("没有可更新的用户")
	}
	if _, err := s.users.Authenticate(current.Username, currentPassword); err != nil {
		return "", nil, errors.New("当前密码错误")
	}

	nextUsername := strings.TrimSpace(newUsername)
	if nextUsername == "" {
		nextUsername = current.Username
	}
	user, err := s.users.UpdateSingleUserCredentials(current.ID, nextUsername, newPassword)
	if err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = make(map[string]adminSessionRecord)
	token, err := s.issueSessionLocked(user.ID, user.Username)
	if err != nil {
		return "", nil, err
	}
	return token, &AdminAuthStatus{
		Initialized:   true,
		Authenticated: true,
		UserID:        user.ID,
		Username:      user.Username,
	}, nil
}

func (s *AdminAuthService) ValidateSession(sessionToken string) (string, bool, error) {
	user, ok, err := s.ValidateUserSession(sessionToken)
	if err != nil || !ok {
		return "", ok, err
	}
	return user.Username, true, nil
}

func (s *AdminAuthService) ValidateUserSession(sessionToken string) (*AuthenticatedUser, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return nil, false, nil
	}
	s.pruneExpiredSessionsLocked()
	session, ok := s.sessions[sessionToken]
	if !ok {
		return nil, false, nil
	}
	if !session.ExpiresAt.After(s.now()) {
		delete(s.sessions, sessionToken)
		return nil, false, nil
	}

	user, err := s.users.GetEnabledUserByID(session.UserID)
	if err != nil {
		delete(s.sessions, sessionToken)
		return nil, false, nil
	}
	if user == nil {
		delete(s.sessions, sessionToken)
		return nil, false, nil
	}
	if !strings.EqualFold(user.Username, session.Username) {
		session.Username = user.Username
		s.sessions[sessionToken] = session
	}
	return &AuthenticatedUser{ID: user.ID, Username: user.Username}, true, nil
}

func (s *AdminAuthService) Logout(sessionToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return nil
	}
	delete(s.sessions, sessionToken)
	return nil
}

func (s *AdminAuthService) issueSessionLocked(userID, username string) (string, error) {
	userID = strings.TrimSpace(userID)
	username = strings.TrimSpace(username)
	if userID == "" || username == "" {
		return "", errors.New("用户信息不能为空")
	}
	s.pruneExpiredSessionsLocked()
	token, err := generateAdminOpaqueToken()
	if err != nil {
		return "", err
	}
	s.sessions[token] = adminSessionRecord{
		UserID:    userID,
		Username:  username,
		ExpiresAt: s.now().Add(AdminSessionTTL),
	}
	return token, nil
}

func (s *AdminAuthService) pruneExpiredSessionsLocked() {
	now := s.now()
	for token, session := range s.sessions {
		if !session.ExpiresAt.After(now) {
			delete(s.sessions, token)
		}
	}
}

func (s *AdminAuthService) currentSingleUser() (*UserAccount, bool, error) {
	users, err := s.users.ListUsers()
	if err != nil {
		return nil, false, err
	}
	if len(users) != 1 {
		return nil, false, nil
	}
	return &users[0], true, nil
}

func normalizeAdminUsername(username string) (string, error) {
	return NormalizeUsername(username)
}

func validateAdminPassword(password string) error {
	return ValidateUserPassword(password)
}

func hashAdminPassword(password string) (string, error) {
	return HashUserPassword(password)
}

func generateAdminSessionSecret() (string, error) {
	return generateAdminRandomToken(32, "session secret")
}

func generateAdminOpaqueToken() (string, error) {
	return generateAdminRandomToken(32, "session token")
}

func generateAdminRandomToken(size int, name string) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成 %s 失败: %w", name, err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func isAdminConfigured(config AdminAuthConfig) bool {
	return strings.TrimSpace(config.Username) != "" && strings.TrimSpace(config.PasswordHash) != ""
}
