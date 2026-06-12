package services

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const usersFileName = "users.json"

var userIDSafePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type UserAccount struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"passwordHash"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type AuthenticatedUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type userStoreEnvelope struct {
	Users []UserAccount `json:"users"`
}

type UserStore struct {
	path string
	mu   sync.Mutex
}

func NewUserStore() *UserStore {
	home, err := getUserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		home = "."
	}
	return &UserStore{
		path: filepath.Join(home, appSettingsDir, usersFileName),
	}
}

func (s *UserStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

func (s *UserStore) CountUsers() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return 0, err
	}
	return len(store.Users), nil
}

func (s *UserStore) ListUsers() ([]UserAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	users := make([]UserAccount, len(store.Users))
	copy(users, store.Users)
	return users, nil
}

func (s *UserStore) AddUser(username, password string) (*UserAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	username, err := NormalizeUsername(username)
	if err != nil {
		return nil, err
	}
	if err := ValidateUserPassword(password); err != nil {
		return nil, err
	}

	store, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	if findUserByUsername(store.Users, username) >= 0 {
		return nil, fmt.Errorf("用户已存在: %s", username)
	}

	hash, err := HashUserPassword(password)
	if err != nil {
		return nil, err
	}
	id, err := generateUserID()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	user := UserAccount{
		ID:           id,
		Username:     username,
		PasswordHash: hash,
		Enabled:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	store.Users = append(store.Users, user)
	if err := s.saveLocked(store); err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *UserStore) SetUserEnabled(username string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	username, err := NormalizeUsername(username)
	if err != nil {
		return err
	}
	store, err := s.loadLocked()
	if err != nil {
		return err
	}
	index := findUserByUsername(store.Users, username)
	if index < 0 {
		return fmt.Errorf("未找到用户: %s", username)
	}
	store.Users[index].Enabled = enabled
	store.Users[index].UpdatedAt = time.Now().UTC()
	return s.saveLocked(store)
}

func (s *UserStore) ResetPassword(username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	username, err := NormalizeUsername(username)
	if err != nil {
		return err
	}
	if err := ValidateUserPassword(password); err != nil {
		return err
	}
	hash, err := HashUserPassword(password)
	if err != nil {
		return err
	}

	store, err := s.loadLocked()
	if err != nil {
		return err
	}
	index := findUserByUsername(store.Users, username)
	if index < 0 {
		return fmt.Errorf("未找到用户: %s", username)
	}
	store.Users[index].PasswordHash = hash
	store.Users[index].UpdatedAt = time.Now().UTC()
	return s.saveLocked(store)
}

func (s *UserStore) UpdateSingleUserCredentials(userID string, username string, password string) (*UserAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	username, err := NormalizeUsername(username)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(password) != "" {
		if err := ValidateUserPassword(password); err != nil {
			return nil, err
		}
	}

	store, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	target := -1
	for i, user := range store.Users {
		if user.ID == userID {
			target = i
			continue
		}
		if strings.EqualFold(user.Username, username) {
			return nil, fmt.Errorf("用户已存在: %s", username)
		}
	}
	if target < 0 {
		return nil, fmt.Errorf("未找到用户: %s", userID)
	}
	store.Users[target].Username = username
	if strings.TrimSpace(password) != "" {
		hash, err := HashUserPassword(password)
		if err != nil {
			return nil, err
		}
		store.Users[target].PasswordHash = hash
	}
	store.Users[target].UpdatedAt = time.Now().UTC()
	if err := s.saveLocked(store); err != nil {
		return nil, err
	}
	user := store.Users[target]
	return &user, nil
}

func (s *UserStore) Authenticate(username, password string) (*UserAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	username, err := NormalizeUsername(username)
	if err != nil {
		return nil, err
	}
	store, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	index := findUserByUsername(store.Users, username)
	if index < 0 {
		return nil, errors.New("账号或密码错误")
	}
	user := store.Users[index]
	if !user.Enabled {
		return nil, errors.New("用户已禁用")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, errors.New("账号或密码错误")
	}
	return &user, nil
}

func (s *UserStore) GetEnabledUserByID(userID string) (*UserAccount, error) {
	user, err := s.GetUserByID(userID)
	if err != nil || user == nil {
		return user, err
	}
	if !user.Enabled {
		return nil, errors.New("用户已禁用")
	}
	return user, nil
}

func (s *UserStore) GetUserByID(userID string) (*UserAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, nil
	}
	store, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	for _, user := range store.Users {
		if user.ID == userID {
			copyUser := user
			return &copyUser, nil
		}
	}
	return nil, nil
}

func (s *UserStore) loadLocked() (*userStoreEnvelope, error) {
	store := &userStoreEnvelope{Users: []UserAccount{}}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return store, nil
	}
	if err := json.Unmarshal(data, store); err != nil {
		return nil, err
	}
	if store.Users == nil {
		store.Users = []UserAccount{}
	}
	return store, nil
}

func (s *UserStore) saveLocked(store *userStoreEnvelope) error {
	if err := EnsureDir(filepath.Dir(s.path)); err != nil {
		return err
	}
	return AtomicWriteJSON(s.path, store)
}

func NormalizeUsername(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", errors.New("用户名不能为空")
	}
	if len([]rune(username)) > 64 {
		return "", errors.New("用户名长度不能超过 64 个字符")
	}
	return username, nil
}

func ValidateUserPassword(password string) error {
	if len(password) < 8 {
		return errors.New("密码至少需要 8 个字符")
	}
	if len(password) > 256 {
		return errors.New("密码长度不能超过 256 个字符")
	}
	return nil
}

func HashUserPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("生成密码哈希失败: %w", err)
	}
	return string(hash), nil
}

func UserDataDir(userID string) (string, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return "", errors.New("用户 ID 不能为空")
	}
	if !userIDSafePattern.MatchString(userID) {
		return "", fmt.Errorf("无效的用户 ID: %s", userID)
	}
	home, err := getUserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, appSettingsDir, "users", userID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func findUserByUsername(users []UserAccount, username string) int {
	for i, user := range users {
		if strings.EqualFold(user.Username, username) {
			return i
		}
	}
	return -1
}

func generateUserID() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成用户 ID 失败: %w", err)
	}
	return "usr_" + base64.RawURLEncoding.EncodeToString(buf), nil
}
