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

	"github.com/daodao97/xgo/xdb"
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

type CodexRelayKeyMatch struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type CodexRelayKeyUsagePoint struct {
	Bucket          string `json:"bucket"`
	Label           string `json:"label"`
	Calls           int64  `json:"calls"`
	InputTokens     int64  `json:"inputTokens"`
	OutputTokens    int64  `json:"outputTokens"`
	CacheTokens     int64  `json:"cacheTokens"`
	ReasoningTokens int64  `json:"reasoningTokens"`
	TotalTokens     int64  `json:"totalTokens"`
}

type CodexRelayKeyUsageStats struct {
	KeyID       string                    `json:"keyId"`
	Range       string                    `json:"range"`
	TotalCalls  int64                     `json:"totalCalls"`
	TotalTokens int64                     `json:"totalTokens"`
	Points      []CodexRelayKeyUsagePoint `json:"points"`
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

func (s *CodexRelayKeyService) RenameKey(id string, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("密钥名称不能为空")
	}

	store, err := s.loadLocked()
	if err != nil {
		return err
	}

	for index := range store.Keys {
		if store.Keys[index].ID == id {
			store.Keys[index].Name = name
			return s.saveLocked(store)
		}
	}

	return fmt.Errorf("未找到 Codex relay key: %s", id)
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
	match, err := s.ValidateKeyMatch(candidate)
	if err != nil {
		return false, err
	}
	return match != nil, nil
}

func (s *CodexRelayKeyService) ValidateKeyMatch(candidate string) (*CodexRelayKeyMatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return nil, nil
	}

	store, err := s.loadLocked()
	if err != nil {
		return nil, err
	}

	for _, key := range store.Keys {
		if !key.Enabled {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(key.Key)) == 1 {
			return &CodexRelayKeyMatch{ID: key.ID, Name: key.Name}, nil
		}
	}

	return nil, nil
}

func (s *CodexRelayKeyService) GetUsageStats(id string, rangeKey string, startRaw string, endRaw string) (*CodexRelayKeyUsageStats, error) {
	rangeKey, start, end, step, err := resolveRelayKeyUsageWindow(rangeKey, startRaw, endRaw)
	if err != nil {
		return nil, err
	}
	queryEnd := end
	bucketEnd := end.Truncate(step)
	start = start.Truncate(step)

	points := make([]CodexRelayKeyUsagePoint, 0)
	pointByUnix := make(map[int64]int)
	for bucket := start; !bucket.After(bucketEnd); bucket = bucket.Add(step) {
		unix := bucket.Unix()
		pointByUnix[unix] = len(points)
		points = append(points, CodexRelayKeyUsagePoint{
			Bucket: bucket.Format(time.RFC3339),
			Label:  formatRelayKeyUsageLabel(bucket, step),
		})
	}

	db, err := xdb.DB("default")
	if err != nil {
		return nil, err
	}

	rows, err := db.Query(`
		SELECT
			(CAST(strftime('%s', created_at) AS INTEGER) / ?) * ? AS bucket_unix,
			COUNT(*) AS calls,
			COALESCE(SUM(input_tokens), 0) AS input_tokens,
			COALESCE(SUM(output_tokens), 0) AS output_tokens,
			COALESCE(SUM(cache_create_tokens + cache_read_tokens), 0) AS cache_tokens,
			COALESCE(SUM(reasoning_tokens), 0) AS reasoning_tokens
		FROM request_log
		WHERE relay_key_id = ?
			AND created_at >= ?
			AND created_at < ?
		GROUP BY bucket_unix
		ORDER BY bucket_unix
	`, int64(step.Seconds()), int64(step.Seconds()), id, start.Format("2006-01-02 15:04:05"), queryEnd.Format("2006-01-02 15:04:05"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := &CodexRelayKeyUsageStats{
		KeyID:  id,
		Range:  rangeKey,
		Points: points,
	}

	for rows.Next() {
		var bucketUnix int64
		var calls, inputTokens, outputTokens, cacheTokens, reasoningTokens int64
		if err := rows.Scan(&bucketUnix, &calls, &inputTokens, &outputTokens, &cacheTokens, &reasoningTokens); err != nil {
			return nil, err
		}
		index, ok := pointByUnix[bucketUnix]
		if !ok {
			continue
		}
		point := &stats.Points[index]
		point.Calls = calls
		point.InputTokens = inputTokens
		point.OutputTokens = outputTokens
		point.CacheTokens = cacheTokens
		point.ReasoningTokens = reasoningTokens
		point.TotalTokens = inputTokens + outputTokens + cacheTokens + reasoningTokens
		stats.TotalCalls += calls
		stats.TotalTokens += point.TotalTokens
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return stats, nil
}

func resolveRelayKeyUsageWindow(rangeKey string, startRaw string, endRaw string) (string, time.Time, time.Time, time.Duration, error) {
	if strings.TrimSpace(startRaw) != "" || strings.TrimSpace(endRaw) != "" {
		start, err := parseRelayKeyUsageTime(startRaw)
		if err != nil {
			return "", time.Time{}, time.Time{}, 0, fmt.Errorf("无效的开始时间: %w", err)
		}
		end, err := parseRelayKeyUsageTime(endRaw)
		if err != nil {
			return "", time.Time{}, time.Time{}, 0, fmt.Errorf("无效的结束时间: %w", err)
		}
		if !end.After(start) {
			return "", time.Time{}, time.Time{}, 0, errors.New("结束时间必须晚于开始时间")
		}
		return "custom", start.UTC(), end.UTC(), relayKeyUsageStepForDuration(end.Sub(start)), nil
	}

	normalizedRange, start, step := normalizeRelayKeyUsageRange(rangeKey)
	end := time.Now().UTC()
	return normalizedRange, start, end, step, nil
}

func parseRelayKeyUsageTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, errors.New("不能为空")
	}
	if value, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return value, nil
	}
	return time.Parse(time.RFC3339, raw)
}

func relayKeyUsageStepForDuration(duration time.Duration) time.Duration {
	switch {
	case duration <= time.Hour:
		return 5 * time.Minute
	case duration <= 5*time.Hour:
		return 15 * time.Minute
	case duration <= 24*time.Hour:
		return time.Hour
	case duration <= 7*24*time.Hour:
		return 6 * time.Hour
	default:
		return 24 * time.Hour
	}
}

func normalizeRelayKeyUsageRange(rangeKey string) (string, time.Time, time.Duration) {
	now := time.Now().UTC()
	switch strings.TrimSpace(rangeKey) {
	case "5h":
		return "5h", now.Add(-5 * time.Hour), 15 * time.Minute
	case "1d":
		return "1d", now.Add(-24 * time.Hour), time.Hour
	case "1w":
		return "1w", now.Add(-7 * 24 * time.Hour), 6 * time.Hour
	case "1mo":
		return "1mo", now.Add(-30 * 24 * time.Hour), 24 * time.Hour
	default:
		return "1h", now.Add(-time.Hour), 5 * time.Minute
	}
}

func formatRelayKeyUsageLabel(value time.Time, step time.Duration) string {
	if step >= 24*time.Hour {
		return value.Format("01-02")
	}
	return value.Format("15:04")
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
