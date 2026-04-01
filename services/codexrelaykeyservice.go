package services

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	codexRelayKeysFile      = "codex-relay-keys.json"
	defaultCodexRelayKeyTag = "default"
)

type CodexRelayKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Key       string    `json:"key"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
}

type CodexRelayKeyListItem struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	MaskedKey string    `json:"maskedKey"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
}

type CodexRelayKeyCreateResult struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Key       string    `json:"key"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
}

type codexRelayKeyStore struct {
	Keys []CodexRelayKey `json:"keys"`
}

type CodexRelayKeyService struct {
	path string
	mu   sync.Mutex
}

func NewCodexRelayKeyService() *CodexRelayKeyService {
	home, err := getUserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		home = "."
	}

	return &CodexRelayKeyService{
		path: filepath.Join(home, appSettingsDir, codexRelayKeysFile),
	}
}

func (s *CodexRelayKeyService) ListKeys() ([]CodexRelayKeyListItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return nil, err
	}

	keys := make([]CodexRelayKeyListItem, 0, len(store.Keys))
	for _, key := range store.Keys {
		keys = append(keys, CodexRelayKeyListItem{
			ID:        key.ID,
			Name:      key.Name,
			MaskedKey: maskCodexRelayKey(key.Key),
			Enabled:   key.Enabled,
			CreatedAt: key.CreatedAt,
		})
	}

	return keys, nil
}

func (s *CodexRelayKeyService) CreateKey(name string) (*CodexRelayKeyCreateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return nil, err
	}

	value, err := generateCodexRelayKeyValue()
	if err != nil {
		return nil, err
	}

	key := CodexRelayKey{
		ID:        fmt.Sprintf("codex-key-%d", time.Now().UnixNano()),
		Name:      strings.TrimSpace(name),
		Key:       value,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	if key.Name == "" {
		key.Name = fmt.Sprintf("key-%d", len(store.Keys)+1)
	}

	store.Keys = append(store.Keys, key)
	if err := s.saveLocked(store); err != nil {
		return nil, err
	}

	return &CodexRelayKeyCreateResult{
		ID:        key.ID,
		Name:      key.Name,
		Key:       key.Key,
		Enabled:   key.Enabled,
		CreatedAt: key.CreatedAt,
	}, nil
}

func (s *CodexRelayKeyService) DeleteKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return err
	}

	enabledCount := 0
	for _, key := range store.Keys {
		if key.Enabled {
			enabledCount++
		}
	}

	filtered := make([]CodexRelayKey, 0, len(store.Keys))
	found := false
	for _, key := range store.Keys {
		if key.ID == id {
			found = true
			if key.Enabled && enabledCount <= 1 {
				return errors.New("至少需要保留一个可用的 Codex relay key")
			}
			continue
		}
		filtered = append(filtered, key)
	}
	if !found {
		return fmt.Errorf("未找到 Codex relay key: %s", id)
	}

	store.Keys = filtered
	return s.saveLocked(store)
}

func (s *CodexRelayKeyService) GetKeySecret(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return "", err
	}

	for _, key := range store.Keys {
		if key.ID == id {
			return key.Key, nil
		}
	}

	return "", fmt.Errorf("未找到 Codex relay key: %s", id)
}

func (s *CodexRelayKeyService) EnsureDefaultKey() (*CodexRelayKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return nil, err
	}

	for _, key := range store.Keys {
		if key.Enabled {
			copyKey := key
			return &copyKey, nil
		}
	}

	value, err := generateCodexRelayKeyValue()
	if err != nil {
		return nil, err
	}

	key := CodexRelayKey{
		ID:        fmt.Sprintf("codex-key-%d", time.Now().UnixNano()),
		Name:      defaultCodexRelayKeyTag,
		Key:       value,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	store.Keys = append(store.Keys, key)
	if err := s.saveLocked(store); err != nil {
		return nil, err
	}

	return &key, nil
}

func (s *CodexRelayKeyService) ValidateKey(candidate string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return false, nil
	}

	store, err := s.loadLocked()
	if err != nil {
		return false, err
	}

	for _, key := range store.Keys {
		if !key.Enabled {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(key.Key)) == 1 {
			return true, nil
		}
	}

	return false, nil
}

func (s *CodexRelayKeyService) loadLocked() (*codexRelayKeyStore, error) {
	store := &codexRelayKeyStore{
		Keys: []CodexRelayKey{},
	}

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
	if store.Keys == nil {
		store.Keys = []CodexRelayKey{}
	}

	return store, nil
}

func (s *CodexRelayKeyService) saveLocked(store *codexRelayKeyStore) error {
	if err := EnsureDir(filepath.Dir(s.path)); err != nil {
		return err
	}
	return AtomicWriteJSON(s.path, store)
}

func generateCodexRelayKeyValue() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成 Codex relay key 失败: %w", err)
	}
	return "csk_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

func maskCodexRelayKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 12 {
		return value[:4] + "..." + value[len(value)-2:]
	}
	return value[:7] + "..." + value[len(value)-4:]
}
