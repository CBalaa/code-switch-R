package services

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	AdminSessionTTL = 7 * 24 * time.Hour
)

type AdminAuthStatus struct {
	Initialized   bool   `json:"initialized"`
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username,omitempty"`
}

type adminSessionRecord struct {
	Username  string
	ExpiresAt time.Time
}

type AdminAuthService struct {
	appSettings *AppSettingsService
	mu          sync.Mutex
	sessions    map[string]adminSessionRecord
	now         func() time.Time
}

func NewAdminAuthService(appSettings *AppSettingsService) *AdminAuthService {
	return &AdminAuthService{
		appSettings: appSettings,
		sessions:    make(map[string]adminSessionRecord),
		now:         time.Now,
	}
}

func (s *AdminAuthService) GetStatus(sessionToken string) (*AdminAuthStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	config, err := s.appSettings.GetAdminAuthConfig()
	if err != nil {
		return nil, err
	}

	status := &AdminAuthStatus{
		Initialized: isAdminConfigured(config),
	}
	if !status.Initialized {
		return status, nil
	}

	username, ok := s.validateSessionLocked(config, sessionToken)
	if ok {
		status.Authenticated = true
		status.Username = username
	}

	return status, nil
}

func (s *AdminAuthService) InitializeAdmin(username, password string) (string, *AdminAuthStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	config, err := s.appSettings.GetAdminAuthConfig()
	if err != nil {
		return "", nil, err
	}
	if isAdminConfigured(config) {
		return "", nil, errors.New("管理员账号已初始化")
	}

	normalizedUsername, err := normalizeAdminUsername(username)
	if err != nil {
		return "", nil, err
	}
	if err := validateAdminPassword(password); err != nil {
		return "", nil, err
	}

	passwordHash, err := hashAdminPassword(password)
	if err != nil {
		return "", nil, err
	}
	sessionSecret, err := generateAdminSessionSecret()
	if err != nil {
		return "", nil, err
	}

	config = AdminAuthConfig{
		Enabled:       true,
		Username:      normalizedUsername,
		PasswordHash:  passwordHash,
		SessionSecret: sessionSecret,
	}
	if err := s.appSettings.SaveAdminAuthConfig(config); err != nil {
		return "", nil, err
	}

	s.sessions = make(map[string]adminSessionRecord)

	token, err := s.issueSessionLocked(normalizedUsername)
	if err != nil {
		return "", nil, err
	}

	return token, &AdminAuthStatus{
		Initialized:   true,
		Authenticated: true,
		Username:      normalizedUsername,
	}, nil
}

func (s *AdminAuthService) Login(username, password string) (string, *AdminAuthStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	config, err := s.appSettings.GetAdminAuthConfig()
	if err != nil {
		return "", nil, err
	}
	if !isAdminConfigured(config) {
		return "", nil, errors.New("管理员账号尚未初始化")
	}

	normalizedUsername, err := normalizeAdminUsername(username)
	if err != nil {
		return "", nil, err
	}
	if subtle.ConstantTimeCompare([]byte(normalizedUsername), []byte(config.Username)) != 1 {
		return "", nil, errors.New("账号或密码错误")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(config.PasswordHash), []byte(password)); err != nil {
		return "", nil, errors.New("账号或密码错误")
	}

	if strings.TrimSpace(config.SessionSecret) == "" {
		config.SessionSecret, err = generateAdminSessionSecret()
		if err != nil {
			return "", nil, err
		}
		if err := s.appSettings.SaveAdminAuthConfig(config); err != nil {
			return "", nil, err
		}
	}

	token, err := s.issueSessionLocked(config.Username)
	if err != nil {
		return "", nil, err
	}

	return token, &AdminAuthStatus{
		Initialized:   true,
		Authenticated: true,
		Username:      config.Username,
	}, nil
}

func (s *AdminAuthService) UpdateCredentials(currentPassword, newUsername, newPassword string) (string, *AdminAuthStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	config, err := s.appSettings.GetAdminAuthConfig()
	if err != nil {
		return "", nil, err
	}
	if !isAdminConfigured(config) {
		return "", nil, errors.New("管理员账号尚未初始化")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(config.PasswordHash), []byte(currentPassword)); err != nil {
		return "", nil, errors.New("当前密码错误")
	}

	nextUsername := config.Username
	changed := false
	if strings.TrimSpace(newUsername) != "" {
		nextUsername, err = normalizeAdminUsername(newUsername)
		if err != nil {
			return "", nil, err
		}
		changed = true
	}

	nextPasswordHash := config.PasswordHash
	if strings.TrimSpace(newPassword) != "" {
		if err := validateAdminPassword(newPassword); err != nil {
			return "", nil, err
		}
		nextPasswordHash, err = hashAdminPassword(newPassword)
		if err != nil {
			return "", nil, err
		}
		changed = true
	}

	if !changed {
		return "", nil, errors.New("没有需要更新的管理员信息")
	}

	nextSecret, err := generateAdminSessionSecret()
	if err != nil {
		return "", nil, err
	}

	config.Enabled = true
	config.Username = nextUsername
	config.PasswordHash = nextPasswordHash
	config.SessionSecret = nextSecret

	if err := s.appSettings.SaveAdminAuthConfig(config); err != nil {
		return "", nil, err
	}

	s.sessions = make(map[string]adminSessionRecord)

	token, err := s.issueSessionLocked(nextUsername)
	if err != nil {
		return "", nil, err
	}

	return token, &AdminAuthStatus{
		Initialized:   true,
		Authenticated: true,
		Username:      nextUsername,
	}, nil
}

func (s *AdminAuthService) ValidateSession(sessionToken string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	config, err := s.appSettings.GetAdminAuthConfig()
	if err != nil {
		return "", false, err
	}
	if !isAdminConfigured(config) {
		return "", false, nil
	}

	username, ok := s.validateSessionLocked(config, sessionToken)
	return username, ok, nil
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

func (s *AdminAuthService) validateSessionLocked(config AdminAuthConfig, sessionToken string) (string, bool) {
	s.pruneExpiredSessionsLocked()

	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return "", false
	}

	session, ok := s.sessions[sessionToken]
	if !ok {
		return "", false
	}
	if session.ExpiresAt.Before(s.now()) || session.ExpiresAt.Equal(s.now()) {
		delete(s.sessions, sessionToken)
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(session.Username), []byte(config.Username)) != 1 {
		delete(s.sessions, sessionToken)
		return "", false
	}

	return session.Username, true
}

func (s *AdminAuthService) issueSessionLocked(username string) (string, error) {
	if strings.TrimSpace(username) == "" {
		return "", errors.New("管理员账号不能为空")
	}

	s.pruneExpiredSessionsLocked()

	token, err := generateAdminOpaqueToken()
	if err != nil {
		return "", err
	}

	s.sessions[token] = adminSessionRecord{
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

func normalizeAdminUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", errors.New("管理员账号不能为空")
	}
	if len([]rune(username)) > 64 {
		return "", errors.New("管理员账号长度不能超过 64 个字符")
	}
	return username, nil
}

func validateAdminPassword(password string) error {
	if len(password) < 8 {
		return errors.New("管理员密码至少需要 8 个字符")
	}
	if len(password) > 256 {
		return errors.New("管理员密码长度不能超过 256 个字符")
	}
	return nil
}

func hashAdminPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("生成管理员密码哈希失败: %w", err)
	}
	return string(hash), nil
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
		return "", fmt.Errorf("生成管理员 %s 失败: %w", name, err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func isAdminConfigured(config AdminAuthConfig) bool {
	return strings.TrimSpace(config.Username) != "" && strings.TrimSpace(config.PasswordHash) != ""
}
