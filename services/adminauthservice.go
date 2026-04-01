package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
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

type adminSessionPayload struct {
	Username  string `json:"username"`
	ExpiresAt int64  `json:"expiresAt"`
}

type AdminAuthService struct {
	appSettings *AppSettingsService
	mu          sync.Mutex
	now         func() time.Time
}

func NewAdminAuthService(appSettings *AppSettingsService) *AdminAuthService {
	return &AdminAuthService{
		appSettings: appSettings,
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

	username, ok, err := s.validateSessionToken(config, sessionToken)
	if err != nil {
		return nil, err
	}
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

	token, err := s.issueSessionToken(config)
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

	token, err := s.issueSessionToken(config)
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
	if strings.TrimSpace(newUsername) != "" {
		nextUsername, err = normalizeAdminUsername(newUsername)
		if err != nil {
			return "", nil, err
		}
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
	}

	if nextUsername == config.Username && nextPasswordHash == config.PasswordHash {
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

	token, err := s.issueSessionToken(config)
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

	return s.validateSessionToken(config, sessionToken)
}

func (s *AdminAuthService) validateSessionToken(config AdminAuthConfig, sessionToken string) (string, bool, error) {
	sessionToken = strings.TrimSpace(sessionToken)
	if sessionToken == "" {
		return "", false, nil
	}
	if strings.TrimSpace(config.SessionSecret) == "" {
		return "", false, nil
	}

	parts := strings.Split(sessionToken, ".")
	if len(parts) != 2 {
		return "", false, nil
	}

	payloadPart := parts[0]
	signaturePart := parts[1]
	expectedSignature := s.signSessionPayload(config.SessionSecret, payloadPart)
	if subtle.ConstantTimeCompare([]byte(signaturePart), []byte(expectedSignature)) != 1 {
		return "", false, nil
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return "", false, nil
	}

	var payload adminSessionPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", false, nil
	}
	if payload.Username != config.Username {
		return "", false, nil
	}
	if payload.ExpiresAt <= s.now().Unix() {
		return "", false, nil
	}

	return payload.Username, true, nil
}

func (s *AdminAuthService) issueSessionToken(config AdminAuthConfig) (string, error) {
	if !isAdminConfigured(config) {
		return "", errors.New("管理员账号尚未初始化")
	}
	if strings.TrimSpace(config.SessionSecret) == "" {
		return "", errors.New("session secret 缺失")
	}

	payload := adminSessionPayload{
		Username:  config.Username,
		ExpiresAt: s.now().Add(AdminSessionTTL).Unix(),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	payloadPart := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signaturePart := s.signSessionPayload(config.SessionSecret, payloadPart)
	return payloadPart + "." + signaturePart, nil
}

func (s *AdminAuthService) signSessionPayload(secret string, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
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
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成管理员 session secret 失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func isAdminConfigured(config AdminAuthConfig) bool {
	return strings.TrimSpace(config.Username) != "" && strings.TrimSpace(config.PasswordHash) != ""
}
