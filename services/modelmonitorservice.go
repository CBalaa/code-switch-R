package services

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daodao97/xgo/xdb"
)

const (
	ModelMonitorDefaultIntervalSeconds = 300
	ModelMonitorMinIntervalSeconds     = 30
	ModelMonitorDefaultTimeoutMs       = 15000
	ModelMonitorHistoryLimit           = 96
)

type ModelMonitorTarget struct {
	ID              int64      `json:"id"`
	UserID          string     `json:"userId,omitempty"`
	Platform        string     `json:"platform"`
	ProviderID      int64      `json:"providerId"`
	ProviderName    string     `json:"providerName"`
	Model           string     `json:"model"`
	Enabled         bool       `json:"enabled"`
	IntervalSeconds int        `json:"intervalSeconds"`
	TimeoutMs       int        `json:"timeoutMs"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
	LastCheckedAt   *time.Time `json:"lastCheckedAt,omitempty"`
}

type ModelMonitorResult struct {
	ID           int64     `json:"id"`
	TargetID     int64     `json:"targetId"`
	UserID       string    `json:"userId,omitempty"`
	Platform     string    `json:"platform"`
	ProviderID   int64     `json:"providerId"`
	ProviderName string    `json:"providerName"`
	Model        string    `json:"model"`
	Endpoint     string    `json:"endpoint"`
	HTTPCode     int       `json:"httpCode"`
	Status       string    `json:"status"`
	LatencyMs    int       `json:"latencyMs"`
	ErrorMessage string    `json:"errorMessage"`
	Source       string    `json:"source"`
	CheckedAt    time.Time `json:"checkedAt"`
}

type ModelMonitorTimeline struct {
	Target       ModelMonitorTarget   `json:"target"`
	Latest       *ModelMonitorResult  `json:"latest,omitempty"`
	Items        []ModelMonitorResult `json:"items"`
	Uptime       float64              `json:"uptime"`
	AvgLatencyMs int                  `json:"avgLatencyMs"`
}

type ProviderModelList struct {
	Models []string `json:"models"`
	Source string   `json:"source"`
}

type ModelMonitorService struct {
	providerService *ProviderService
	userStore       *UserStore
	client          *http.Client

	mu       sync.Mutex
	running  bool
	stopChan chan struct{}
}

func NewModelMonitorService(providerService *ProviderService, userStore *UserStore) *ModelMonitorService {
	if userStore == nil {
		userStore = NewUserStore()
	}
	return &ModelMonitorService{
		providerService: providerService,
		userStore:       userStore,
		client: &http.Client{
			Timeout: 0,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     30 * time.Second,
				DisableCompression:  true,
			},
		},
	}
}

func (s *ModelMonitorService) Start() error {
	if err := s.ensureTables(); err != nil {
		return err
	}
	s.StartBackgroundPolling()
	return nil
}

func (s *ModelMonitorService) Stop() {
	s.StopBackgroundPolling()
}

func (s *ModelMonitorService) ensureTables() error {
	db, err := xdb.DB("default")
	if err != nil {
		return fmt.Errorf("获取数据库连接失败: %w", err)
	}

	const targetsSQL = `CREATE TABLE IF NOT EXISTS model_monitor_targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL,
		platform TEXT NOT NULL,
		provider_id INTEGER NOT NULL,
		provider_name TEXT NOT NULL,
		model TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		interval_seconds INTEGER NOT NULL DEFAULT 300,
		timeout_ms INTEGER NOT NULL DEFAULT 15000,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(user_id, platform, provider_id, model)
	)`
	if _, err := db.Exec(targetsSQL); err != nil {
		return fmt.Errorf("创建 model_monitor_targets 表失败: %w", err)
	}

	const resultsSQL = `CREATE TABLE IF NOT EXISTS model_monitor_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_id INTEGER NOT NULL,
		user_id TEXT NOT NULL,
		platform TEXT NOT NULL,
		provider_id INTEGER NOT NULL,
		provider_name TEXT NOT NULL,
		model TEXT NOT NULL,
		endpoint TEXT,
		http_code INTEGER,
		status TEXT NOT NULL,
		latency_ms INTEGER,
		error_message TEXT,
		source TEXT NOT NULL,
		checked_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`
	if _, err := db.Exec(resultsSQL); err != nil {
		return fmt.Errorf("创建 model_monitor_results 表失败: %w", err)
	}
	if err := ensureRequestLogColumnNamed(db, "model_monitor_results", "http_code", "INTEGER"); err != nil {
		return err
	}

	const indexesSQL = `
		CREATE INDEX IF NOT EXISTS idx_model_monitor_targets_user ON model_monitor_targets(user_id, platform);
		CREATE INDEX IF NOT EXISTS idx_model_monitor_results_target ON model_monitor_results(target_id, checked_at DESC);
		CREATE INDEX IF NOT EXISTS idx_model_monitor_results_user ON model_monitor_results(user_id, platform, provider_id, model, checked_at DESC);
	`
	if _, err := db.Exec(indexesSQL); err != nil {
		log.Printf("[ModelMonitor] 创建索引警告: %v", err)
	}
	return nil
}

func (s *ModelMonitorService) ListTargetsForUser(userID string) ([]ModelMonitorTarget, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("用户不能为空")
	}
	db, err := xdb.DB("default")
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(`
		SELECT t.id, t.user_id, t.platform, t.provider_id, t.provider_name, t.model,
		       t.enabled, t.interval_seconds, t.timeout_ms, t.created_at, t.updated_at,
		       (SELECT MAX(r.checked_at) FROM model_monitor_results r WHERE r.target_id = t.id) AS last_checked_at
		FROM model_monitor_targets t
		WHERE t.user_id = ?
		ORDER BY t.platform, t.provider_name, t.model
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []ModelMonitorTarget
	for rows.Next() {
		target, err := scanModelMonitorTarget(rows)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (s *ModelMonitorService) ListTimelinesForUser(userID string) ([]ModelMonitorTimeline, error) {
	targets, err := s.ListTargetsForUser(userID)
	if err != nil {
		return nil, err
	}
	timelines := make([]ModelMonitorTimeline, 0, len(targets))
	for _, target := range targets {
		items, err := s.listResultsForTarget(userID, target.ID, ModelMonitorHistoryLimit)
		if err != nil {
			return nil, err
		}
		timeline := ModelMonitorTimeline{
			Target:       target,
			Items:        items,
			Uptime:       calculateModelMonitorUptime(items),
			AvgLatencyMs: calculateModelMonitorAvgLatency(items),
		}
		if len(items) > 0 {
			latest := items[0]
			timeline.Latest = &latest
		}
		timelines = append(timelines, timeline)
	}
	return timelines, nil
}

func (s *ModelMonitorService) SaveTargetForUser(userID string, target ModelMonitorTarget) (*ModelMonitorTarget, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("用户不能为空")
	}
	target.Platform = providerPlatformForPool(target.Platform)
	target.Model = strings.TrimSpace(target.Model)
	target.ProviderName = strings.TrimSpace(target.ProviderName)
	if target.Platform == "" || target.ProviderID == 0 || target.Model == "" {
		return nil, fmt.Errorf("平台、供应商和模型不能为空")
	}
	if target.IntervalSeconds < ModelMonitorMinIntervalSeconds {
		target.IntervalSeconds = ModelMonitorDefaultIntervalSeconds
	}
	if target.TimeoutMs <= 0 {
		target.TimeoutMs = ModelMonitorDefaultTimeoutMs
	}
	provider, err := s.findProviderForUser(userID, target.Platform, target.ProviderID)
	if err != nil {
		return nil, err
	}
	target.ProviderName = provider.Name

	db, err := xdb.DB("default")
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if target.ID > 0 {
		res, err := db.Exec(`
			UPDATE model_monitor_targets
			SET platform = ?, provider_id = ?, provider_name = ?, model = ?, enabled = ?,
			    interval_seconds = ?, timeout_ms = ?, updated_at = ?
			WHERE id = ? AND user_id = ?
		`, target.Platform, target.ProviderID, target.ProviderName, target.Model, boolToInt(target.Enabled),
			target.IntervalSeconds, target.TimeoutMs, now.Format(timeLayout), target.ID, userID)
		if err != nil {
			return nil, err
		}
		if rows, _ := res.RowsAffected(); rows == 0 {
			return nil, fmt.Errorf("监控目标不存在")
		}
		return s.GetTargetForUser(userID, target.ID)
	}

	res, err := db.Exec(`
		INSERT INTO model_monitor_targets (
			user_id, platform, provider_id, provider_name, model, enabled,
			interval_seconds, timeout_ms, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, userID, target.Platform, target.ProviderID, target.ProviderName, target.Model, boolToInt(target.Enabled),
		target.IntervalSeconds, target.TimeoutMs, now.Format(timeLayout), now.Format(timeLayout))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, fmt.Errorf("该供应商模型已在监控列表中")
		}
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return s.GetTargetForUser(userID, id)
}

func (s *ModelMonitorService) GetTargetForUser(userID string, id int64) (*ModelMonitorTarget, error) {
	db, err := xdb.DB("default")
	if err != nil {
		return nil, err
	}
	row := db.QueryRow(`
		SELECT t.id, t.user_id, t.platform, t.provider_id, t.provider_name, t.model,
		       t.enabled, t.interval_seconds, t.timeout_ms, t.created_at, t.updated_at,
		       (SELECT MAX(r.checked_at) FROM model_monitor_results r WHERE r.target_id = t.id) AS last_checked_at
		FROM model_monitor_targets t
		WHERE t.user_id = ? AND t.id = ?
	`, strings.TrimSpace(userID), id)
	target, err := scanModelMonitorTarget(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("监控目标不存在")
		}
		return nil, err
	}
	return &target, nil
}

func (s *ModelMonitorService) DeleteTargetForUser(userID string, id int64) error {
	db, err := xdb.DB("default")
	if err != nil {
		return err
	}
	res, err := db.Exec(`DELETE FROM model_monitor_targets WHERE user_id = ? AND id = ?`, strings.TrimSpace(userID), id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return fmt.Errorf("监控目标不存在")
	}
	_, _ = db.Exec(`DELETE FROM model_monitor_results WHERE user_id = ? AND target_id = ?`, strings.TrimSpace(userID), id)
	return nil
}

func (s *ModelMonitorService) RunTargetCheckForUser(userID string, targetID int64) (*ModelMonitorResult, error) {
	target, err := s.GetTargetForUser(userID, targetID)
	if err != nil {
		return nil, err
	}
	return s.runCheckForTarget(userID, *target, "manual")
}

func (s *ModelMonitorService) RunAllChecksForUser(userID string) ([]ModelMonitorResult, error) {
	targets, err := s.ListTargetsForUser(userID)
	if err != nil {
		return nil, err
	}
	results := make([]ModelMonitorResult, 0, len(targets))
	for _, target := range targets {
		if !target.Enabled {
			continue
		}
		result, err := s.runCheckForTarget(userID, target, "manual")
		if err != nil {
			return results, err
		}
		results = append(results, *result)
	}
	return results, nil
}

func (s *ModelMonitorService) ListProviderModelsForUser(userID string, platform string, providerID int64) (*ProviderModelList, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("用户不能为空")
	}
	platform = providerPlatformForPool(platform)
	provider, err := s.findProviderForUser(userID, platform, providerID)
	if err != nil {
		return nil, err
	}

	models := modelsFromProviderConfig(provider)
	result := &ProviderModelList{Models: models, Source: "config"}

	fetched, err := s.fetchProviderModels(context.Background(), *provider, platform)
	if err != nil {
		if len(models) > 0 {
			return result, nil
		}
		return result, err
	}
	if len(fetched) > 0 {
		result.Models = fetched
		result.Source = "remote"
	}
	return result, nil
}

func (s *ModelMonitorService) StartBackgroundPolling() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}
	s.running = true
	s.stopChan = make(chan struct{})
	go s.pollLoop(s.stopChan)
}

func (s *ModelMonitorService) StopBackgroundPolling() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	stop := s.stopChan
	s.running = false
	s.stopChan = nil
	s.mu.Unlock()
	close(stop)
}

func (s *ModelMonitorService) pollLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.runDueChecks()
		}
	}
}

func (s *ModelMonitorService) runDueChecks() {
	users, err := s.userStore.ListUsers()
	if err != nil {
		log.Printf("[ModelMonitor] 读取用户失败: %v", err)
		return
	}
	for _, user := range users {
		if !user.Enabled {
			continue
		}
		targets, err := s.ListTargetsForUser(user.ID)
		if err != nil {
			log.Printf("[ModelMonitor] 读取用户 %s 监控目标失败: %v", user.ID, err)
			continue
		}
		for _, target := range targets {
			if !target.Enabled || !modelMonitorDue(target) {
				continue
			}
			if _, err := s.runCheckForTarget(user.ID, target, "active"); err != nil {
				log.Printf("[ModelMonitor] 检测 %s/%s/%s 失败: %v", target.Platform, target.ProviderName, target.Model, err)
			}
		}
	}
}

func modelMonitorDue(target ModelMonitorTarget) bool {
	if target.LastCheckedAt == nil {
		return true
	}
	interval := target.IntervalSeconds
	if interval < ModelMonitorMinIntervalSeconds {
		interval = ModelMonitorDefaultIntervalSeconds
	}
	return time.Since(*target.LastCheckedAt) >= time.Duration(interval)*time.Second
}

func (s *ModelMonitorService) runCheckForTarget(userID string, target ModelMonitorTarget, source string) (*ModelMonitorResult, error) {
	provider, err := s.findProviderForUser(userID, target.Platform, target.ProviderID)
	if err != nil {
		return nil, err
	}
	provider.AvailabilityConfig = &AvailabilityConfig{
		TestModel: target.Model,
		Timeout:   target.TimeoutMs,
	}
	endpoint := modelMonitorEndpoint(provider, target.Platform)
	result := &ModelMonitorResult{
		TargetID:     target.ID,
		UserID:       strings.TrimSpace(userID),
		Platform:     target.Platform,
		ProviderID:   provider.ID,
		ProviderName: provider.Name,
		Model:        target.Model,
		Endpoint:     endpoint,
		Status:       HealthStatusFailed,
		Source:       source,
		CheckedAt:    time.Now().UTC(),
	}

	body := buildModelMonitorRequest(target.Platform, endpoint, target.Model)
	if body == nil {
		result.ErrorMessage = "无法构建检测请求"
		_ = s.saveResult(result)
		return result, nil
	}
	targetURL := strings.TrimSuffix(provider.APIURL, "/")
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	targetURL += endpoint

	timeout := target.TimeoutMs
	if timeout <= 0 {
		timeout = ModelMonitorDefaultTimeoutMs
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("创建请求失败: %v", err)
		_ = s.saveResult(result)
		return result, nil
	}
	req.Header.Set("Content-Type", "application/json")
	setModelMonitorAuthHeaders(req.Header, *provider, target.Platform)

	start := time.Now()
	resp, err := s.client.Do(req)
	result.LatencyMs = int(time.Since(start).Milliseconds())
	if err != nil {
		if isTimeoutError(err) {
			result.ErrorMessage = fmt.Sprintf("响应超时 (>%dms)", timeout)
		} else {
			result.ErrorMessage = fmt.Sprintf("网络错误: %v", err)
		}
		_ = s.saveResult(result)
		return result, nil
	}
	defer resp.Body.Close()
	result.HTTPCode = resp.StatusCode
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	result.Status, result.ErrorMessage = modelMonitorStatus(resp.StatusCode, result.LatencyMs, respBody)
	if err := s.saveResult(result); err != nil {
		return result, err
	}
	return result, nil
}

func (s *ModelMonitorService) findProviderForUser(userID, platform string, providerID int64) (*Provider, error) {
	providers, err := s.providerService.LoadProvidersForUser(strings.TrimSpace(userID), platform)
	if err != nil {
		return nil, fmt.Errorf("加载供应商失败: %w", err)
	}
	for i := range providers {
		if providers[i].ID == providerID {
			return &providers[i], nil
		}
	}
	return nil, fmt.Errorf("供应商不存在")
}

func modelMonitorEndpoint(provider *Provider, platform string) string {
	switch providerPlatformForPool(platform) {
	case "claude":
		if provider.APIEndpoint != "" {
			return provider.GetEffectiveEndpoint("")
		}
		return "/v1/messages"
	case "openai-responses":
		if provider.ResponsesEndpoint != "" {
			return provider.ResponsesEndpoint
		}
		return provider.GetEffectiveEndpoint("/responses")
	case "openai-chat":
		if provider.ChatEndpoint != "" {
			return provider.ChatEndpoint
		}
		return provider.GetEffectiveEndpoint("/chat/completions")
	default:
		return provider.GetEffectiveEndpoint("/chat/completions")
	}
}

func modelMonitorModelsEndpoint(provider *Provider) string {
	endpoint := strings.TrimSpace(provider.ModelsEndpoint)
	if endpoint == "" {
		endpoint = "/v1/models"
	}
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return "/v1/models"
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	return endpoint
}

func buildModelMonitorRequest(platform, endpoint, model string) []byte {
	endpoint = strings.ToLower(endpoint)
	if providerPlatformForPool(platform) == "claude" || strings.Contains(endpoint, "/messages") {
		data, _ := json.Marshal(map[string]any{
			"model":      model,
			"max_tokens": 1,
			"messages": []map[string]string{
				{"role": "user", "content": "hi"},
			},
		})
		return data
	}
	if strings.Contains(endpoint, "/responses") {
		data, _ := json.Marshal(map[string]any{
			"model":             model,
			"max_output_tokens": 1,
			"input":             "hi",
			"store":             false,
		})
		return data
	}
	data, _ := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 1,
		"messages": []map[string]string{
			{"role": "user", "content": "hi"},
		},
	})
	return data
}

func setModelMonitorAuthHeaders(headers http.Header, provider Provider, platform string) {
	if provider.APIKey == "" {
		return
	}
	authTypeRaw := strings.TrimSpace(provider.ConnectivityAuthType)
	authType := strings.ToLower(authTypeRaw)
	if authType == "" {
		authType = "bearer"
	}
	switch authType {
	case "x-api-key":
		headers.Set("x-api-key", provider.APIKey)
		if providerPlatformForPool(platform) == "claude" {
			headers.Set("anthropic-version", "2023-06-01")
		}
	case "bearer":
		headers.Set("Authorization", "Bearer "+provider.APIKey)
	default:
		headerName := authTypeRaw
		if headerName == "" || strings.EqualFold(headerName, "custom") {
			headerName = "Authorization"
		}
		headers.Set(headerName, provider.APIKey)
	}
}

func (s *ModelMonitorService) fetchProviderModels(ctx context.Context, provider Provider, platform string) ([]string, error) {
	endpoint := modelMonitorModelsEndpoint(&provider)
	targetURL := strings.TrimSuffix(provider.APIURL, "/") + endpoint
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(ModelMonitorDefaultTimeoutMs)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	setModelMonitorAuthHeaders(req.Header, provider, platform)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("模型列表请求失败: HTTP %d", resp.StatusCode)
	}
	models := parseProviderModels(body)
	if len(models) == 0 {
		return nil, fmt.Errorf("模型列表为空")
	}
	return models, nil
}

func parseProviderModels(body []byte) []string {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var models []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		models = append(models, value)
	}
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			if id, ok := typed["id"].(string); ok {
				add(id)
			} else if name, ok := typed["name"].(string); ok {
				add(name)
			} else if model, ok := typed["model"].(string); ok {
				add(model)
			}
			if data, ok := typed["data"]; ok {
				walk(data)
			}
			if modelsRaw, ok := typed["models"]; ok {
				walk(modelsRaw)
			}
		case string:
			add(typed)
		}
	}
	walk(raw)
	sort.Strings(models)
	return models
}

func modelsFromProviderConfig(provider *Provider) []string {
	seen := make(map[string]struct{})
	var models []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || strings.Contains(value, "*") {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		models = append(models, value)
	}
	for model, enabled := range provider.SupportedModels {
		if enabled {
			add(model)
		}
	}
	for source, target := range provider.ModelMapping {
		add(source)
		add(target)
	}
	sort.Strings(models)
	return models
}

func modelMonitorStatus(statusCode, latencyMs int, body []byte) (string, string) {
	if statusCode == http.StatusOK {
		if latencyMs > DefaultOperationalThresholdMs {
			return HealthStatusDegraded, fmt.Sprintf("响应成功但耗时 %dms", latencyMs)
		}
		return HealthStatusOperational, ""
	}
	bodyText := strings.TrimSpace(string(body))
	if len(bodyText) > 500 {
		bodyText = bodyText[:500]
	}
	prefix := ""
	if bodyText != "" {
		prefix = ": " + bodyText
	}
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return HealthStatusFailed, "认证失败" + prefix
	case http.StatusTooManyRequests:
		return HealthStatusFailed, "请求频率限制" + prefix
	case http.StatusBadRequest:
		return HealthStatusFailed, "请求无效" + prefix
	}
	if statusCode >= 500 {
		return HealthStatusFailed, fmt.Sprintf("服务器错误 (%d)%s", statusCode, prefix)
	}
	if statusCode >= 400 {
		return HealthStatusFailed, fmt.Sprintf("客户端错误 (%d)%s", statusCode, prefix)
	}
	return HealthStatusFailed, fmt.Sprintf("异常状态码 (%d)%s", statusCode, prefix)
}

func (s *ModelMonitorService) saveResult(result *ModelMonitorResult) error {
	db, err := xdb.DB("default")
	if err != nil {
		return err
	}
	if result.CheckedAt.IsZero() {
		result.CheckedAt = time.Now().UTC()
	}
	res, err := db.Exec(`
		INSERT INTO model_monitor_results (
			target_id, user_id, platform, provider_id, provider_name, model,
			endpoint, http_code, status, latency_ms, error_message, source, checked_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, result.TargetID, result.UserID, result.Platform, result.ProviderID, result.ProviderName, result.Model,
		result.Endpoint, result.HTTPCode, result.Status, result.LatencyMs, result.ErrorMessage, result.Source,
		result.CheckedAt.Format(timeLayout))
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err == nil {
		result.ID = id
	}
	return nil
}

func (s *ModelMonitorService) listResultsForTarget(userID string, targetID int64, limit int) ([]ModelMonitorResult, error) {
	if limit <= 0 {
		limit = ModelMonitorHistoryLimit
	}
	db, err := xdb.DB("default")
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(`
		SELECT id, target_id, user_id, platform, provider_id, provider_name, model,
		       endpoint, COALESCE(http_code, 0), status, latency_ms, error_message, source, checked_at
		FROM model_monitor_results
		WHERE user_id = ? AND target_id = ?
		ORDER BY checked_at DESC
		LIMIT ?
	`, strings.TrimSpace(userID), targetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanModelMonitorResults(rows)
}

func scanModelMonitorTarget(scanner interface {
	Scan(dest ...any) error
}) (ModelMonitorTarget, error) {
	var target ModelMonitorTarget
	var enabled int
	var createdRaw, updatedRaw string
	var last sql.NullString
	err := scanner.Scan(
		&target.ID,
		&target.UserID,
		&target.Platform,
		&target.ProviderID,
		&target.ProviderName,
		&target.Model,
		&enabled,
		&target.IntervalSeconds,
		&target.TimeoutMs,
		&createdRaw,
		&updatedRaw,
		&last,
	)
	if err != nil {
		return target, err
	}
	target.Enabled = enabled != 0
	target.CreatedAt = parseDBTime(createdRaw)
	target.UpdatedAt = parseDBTime(updatedRaw)
	if last.Valid && strings.TrimSpace(last.String) != "" {
		parsed := parseDBTime(last.String)
		target.LastCheckedAt = &parsed
	}
	return target, nil
}

func scanModelMonitorResults(rows *sql.Rows) ([]ModelMonitorResult, error) {
	var results []ModelMonitorResult
	for rows.Next() {
		var result ModelMonitorResult
		var checkedRaw string
		if err := rows.Scan(
			&result.ID,
			&result.TargetID,
			&result.UserID,
			&result.Platform,
			&result.ProviderID,
			&result.ProviderName,
			&result.Model,
			&result.Endpoint,
			&result.HTTPCode,
			&result.Status,
			&result.LatencyMs,
			&result.ErrorMessage,
			&result.Source,
			&checkedRaw,
		); err != nil {
			return nil, err
		}
		result.CheckedAt = parseDBTime(checkedRaw)
		results = append(results, result)
	}
	return results, rows.Err()
}

func parseDBTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{timeLayout, time.RFC3339Nano, "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

func calculateModelMonitorUptime(items []ModelMonitorResult) float64 {
	if len(items) == 0 {
		return 0
	}
	ok := 0
	for _, item := range items {
		if item.Status == HealthStatusOperational || item.Status == HealthStatusDegraded {
			ok++
		}
	}
	return float64(ok) / float64(len(items)) * 100
}

func calculateModelMonitorAvgLatency(items []ModelMonitorResult) int {
	total := 0
	count := 0
	for _, item := range items {
		if item.LatencyMs > 0 && (item.Status == HealthStatusOperational || item.Status == HealthStatusDegraded) {
			total += item.LatencyMs
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return total / count
}

func RecordModelMonitorTraffic(requestLog *ReqeustLog) {
	if requestLog == nil {
		return
	}
	userID := strings.TrimSpace(requestLog.UserID)
	platform := providerPlatformForPool(requestLog.Platform)
	providerName := strings.TrimSpace(requestLog.Provider)
	model := strings.TrimSpace(requestLog.Model)
	if userID == "" || platform == "" || providerName == "" || model == "" {
		return
	}
	db, err := xdb.DB("default")
	if err != nil {
		return
	}
	status := HealthStatusFailed
	errorMessage := strings.TrimSpace(requestLog.ErrorMessage)
	latencyMs := int(requestLog.DurationSec * 1000)
	if requestLog.HttpCode == http.StatusOK {
		if latencyMs > DefaultOperationalThresholdMs {
			status = HealthStatusDegraded
			if errorMessage == "" {
				errorMessage = fmt.Sprintf("真实请求成功但耗时 %dms", latencyMs)
			}
		} else {
			status = HealthStatusOperational
		}
	} else if errorMessage == "" {
		errorMessage = fmt.Sprintf("HTTP %d", requestLog.HttpCode)
	}
	now := time.Now().UTC().Format(timeLayout)
	if _, err := db.Exec(`
		INSERT INTO model_monitor_results (
			target_id, user_id, platform, provider_id, provider_name, model,
			endpoint, http_code, status, latency_ms, error_message, source, checked_at
		)
		SELECT id, user_id, platform, provider_id, provider_name, model,
		       '', ?, ?, ?, ?, 'real_traffic', ?
		FROM model_monitor_targets
		WHERE user_id = ? AND platform = ? AND provider_name = ? AND model = ?
	`, requestLog.HttpCode, status, latencyMs, errorMessage, now, userID, platform, providerName, model); err != nil {
		log.Printf("[ModelMonitor] 记录真实流量监控结果失败: %v", err)
	}
}
