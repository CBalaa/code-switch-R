package services

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ========== 数据类型 ==========

// ProviderPoolMode 池子模式
type ProviderPoolMode string

const (
	ProviderPoolModeManaged ProviderPoolMode = "managed" // 托管模式：池子内启用的供应商参与自动选择、重试、降级
	ProviderPoolModeManual  ProviderPoolMode = "manual"  // 手动模式：只使用池子内"直接应用"的供应商
)

// ProviderPoolType 池子类型
type ProviderPoolType string

const (
	ProviderPoolTypeNormal  ProviderPoolType = "normal"
	ProviderPoolTypeAccount ProviderPoolType = "account"
)

// normalizePoolMemberLevel 将 pool member Level 归一化：缺失或 <= 0 时默认为 1
func normalizePoolMemberLevel(level int) int {
	if level <= 0 {
		return 1
	}
	return level
}

// ProviderPool 供应商池
type ProviderPool struct {
	ID                string                  `json:"id"`
	Platform          string                  `json:"platform"`
	Name              string                  `json:"name"`
	PoolType          ProviderPoolType        `json:"poolType"`
	Mode              ProviderPoolMode        `json:"mode"`
	ManualProviderID  *int64                  `json:"manualProviderId,omitempty"`
	Members           []ProviderPoolMember    `json:"members"`
	AccountPoolConfig *AccountPoolConfig      `json:"accountPoolConfig,omitempty"`
	ProxyConfig       *AccountPoolProxyConfig `json:"proxyConfig,omitempty"`
	// ExcludeFromTotalTraffic keeps account-pool request logs but excludes their
	// token usage from aggregate traffic and cost totals.
	ExcludeFromTotalTraffic bool `json:"excludeFromTotalTraffic,omitempty"`
	// HideFromLogs is a UI preference. The relay still records and returns all
	// request logs; the logs page uses this flag to hide account-pool entries.
	HideFromLogs bool   `json:"hideFromLogs,omitempty"`
	CreatedAt    string `json:"createdAt"`
	UpdatedAt    string `json:"updatedAt"`

	// 自动拉黑配置（仅 managed 模式生效）
	AutoBlacklistEnabled         bool                   `json:"autoBlacklistEnabled"`
	AutoBlacklistThreshold       int                    `json:"autoBlacklistThreshold"`
	AutoBlacklistDurationMinutes int                    `json:"autoBlacklistDurationMinutes"`
	SpecialBlacklistRules        []SpecialBlacklistRule `json:"specialBlacklistRules"`
	// 首字超时重试按池隔离。开启后，未收到有效输出的请求按此池配置超时并计入失败。
	FirstTextRetryEnabled        bool `json:"firstTextRetryEnabled"`
	FirstTextRetryTimeoutSeconds int  `json:"firstTextRetryTimeoutSeconds"`
}

// SpecialBlacklistRule applies an independent failure counter to a precise
// upstream HTTP response. Rules are evaluated in list order.
type SpecialBlacklistRule struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	HTTPStatus        int    `json:"httpStatus"`
	JSONPath          string `json:"jsonPath,omitempty"`
	ExpectedJSONValue string `json:"expectedJsonValue,omitempty"`
	Threshold         int    `json:"threshold"`
	DurationMinutes   int    `json:"durationMinutes"`
	// DurationType selects how the blacklist deadline is derived from the
	// trigger moment. "" and "duration" keep the legacy fixed-length block;
	// "until" blacklists until UntilTime on the day UntilDayOffset days from
	// now, using the Beijing clock (Asia/Shanghai) so a configured "00:00"
	// means Beijing midnight regardless of the server's timezone.
	// UntilDayOffset is a pointer so a
	// legitimate 0 (= today) survives JSON round trips; nil means unset.
	DurationType   string `json:"durationType,omitempty"`
	UntilDayOffset *int   `json:"untilDayOffset,omitempty"`
	UntilTime      string `json:"untilTime,omitempty"`
}

// AccountPoolConfig 号池共享的上游配置及密钥列表。
type AccountPoolConfig struct {
	APIURL            string           `json:"apiUrl"`
	ResponsesEndpoint string           `json:"responsesEndpoint"`
	Keys              []AccountPoolKey `json:"keys"`
}

// AccountPoolKey 号池中的单个上游凭据。
type AccountPoolKey struct {
	ID     int64  `json:"id"`
	APIKey string `json:"apiKey"`
}

// ProviderPoolMember 池子成员（Pool 与 Provider 的关联关系）
type ProviderPoolMember struct {
	ProviderID int64 `json:"providerId"`
	Enabled    bool  `json:"enabled"`
	Level      int   `json:"level,omitempty"` // 该 pool 内的优先级，数字越小越先尝试（默认 1，回退到 provider 全局 Level）
	Priority   int   `json:"priority,omitempty"`
	Weight     int   `json:"weight,omitempty"`
}

// DefaultPoolSeed 创建初始池时的种子信息
type DefaultPoolSeed struct {
	Mode             ProviderPoolMode
	ManualProviderID *int64
}

// providerPoolStore 持久化存储格式
type providerPoolStore struct {
	Version int            `json:"version"`
	Pools   []ProviderPool `json:"pools"`
}

const (
	providerPoolsFile                    = "provider-pools.json"
	providerPoolsStoreVersion            = 6 // version 6 = per-pool first-text retry configuration
	providerPoolsBindingMigrationVersion = 2 // version 2 = relay keys explicitly bound
	initialPoolName                      = "初始池"

	defaultAccountPoolBlacklistThreshold       = 3
	defaultAccountPoolBlacklistDurationMinutes = 10
	maxAccountPoolBlacklistThreshold           = 100
	maxAccountPoolBlacklistDurationMinutes     = 1440
	maxSpecialBlacklistDurationMinutes         = 144000
	maxSpecialBlacklistUntilDayOffset          = 99
	maxAccountPoolKeyID                        = int64(1<<52 - 1)
	defaultFirstTextRetryTimeoutSeconds        = 100
	minFirstTextRetryTimeoutSeconds            = 5
	maxFirstTextRetryTimeoutSeconds            = 240
)

var (
	specialBlacklistJSONPathSegment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
	specialBlacklistUntilTimeFormat = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
)

const (
	// SpecialBlacklistDurationTypeDuration blacklists for a fixed number of
	// minutes. It is also the behavior of legacy rules whose DurationType is
	// empty.
	SpecialBlacklistDurationTypeDuration = "duration"
	// SpecialBlacklistDurationTypeUntil blacklists until a wall-clock time on
	// a day offset from the trigger moment (Beijing time, UTC+8).
	SpecialBlacklistDurationTypeUntil = "until"
)

// ========== ProviderPoolService ==========

// PoolBindingChecker 检查 relay key 是否绑定了某个 pool
// ProviderPoolService 通过此接口检查删除安全性
type PoolBindingChecker interface {
	IsPoolBoundToAnyKey(poolID string) (bool, []string, error)
}

type UserPoolBindingChecker interface {
	IsPoolBoundToAnyKeyForUser(userID string, poolID string) (bool, []string, error)
}

// ProviderPoolService 供应商池服务
// 管理 provider-pools.json 的读写、初始池创建、池子查找
type ProviderPoolService struct {
	path           string
	mu             *sync.Mutex
	bindingChecker PoolBindingChecker // 只读引用，用于删除前检查
}

var providerPoolFileLocks sync.Map

func providerPoolMutex(path string) *sync.Mutex {
	if existing, ok := providerPoolFileLocks.Load(path); ok {
		return existing.(*sync.Mutex)
	}
	created := &sync.Mutex{}
	actual, _ := providerPoolFileLocks.LoadOrStore(path, created)
	return actual.(*sync.Mutex)
}

// NewProviderPoolService 创建供应商池服务
// bindingChecker 可以为 nil（删除前不会检查 key 绑定）
func NewProviderPoolService() *ProviderPoolService {
	home, err := getUserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		home = "."
	}

	path := filepath.Join(home, appSettingsDir, providerPoolsFile)
	return &ProviderPoolService{
		path:           path,
		mu:             providerPoolMutex(path),
		bindingChecker: nil,
	}
}

func NewProviderPoolServiceForUser(userID string) (*ProviderPoolService, error) {
	dir, err := UserDataDir(userID)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, providerPoolsFile)
	return &ProviderPoolService{
		path:           path,
		mu:             providerPoolMutex(path),
		bindingChecker: nil,
	}, nil
}

// SetBindingChecker 设置 binding checker（由调用方在初始化时注入）
func (s *ProviderPoolService) SetBindingChecker(checker PoolBindingChecker) {
	s.bindingChecker = checker
}

// ListPools 列出指定 platform 的所有池子
func (s *ProviderPoolService) ListPools(platform string) ([]ProviderPool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return nil, err
	}

	pools := make([]ProviderPool, 0)
	for _, pool := range store.Pools {
		if pool.Platform == platform {
			pools = append(pools, pool)
		}
	}

	return pools, nil
}

func (s *ProviderPoolService) ListPoolsForUser(userID string, platform string) ([]ProviderPool, error) {
	userService, err := NewProviderPoolServiceForUser(userID)
	if err != nil {
		return nil, err
	}
	userService.bindingChecker = s.bindingChecker
	return userService.ListPools(platform)
}

// ListAllPools 列出所有池子（不按 platform 过滤）
func (s *ProviderPoolService) ListAllPools() ([]ProviderPool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return nil, err
	}

	return store.Pools, nil
}

func (s *ProviderPoolService) ListAllPoolsForUser(userID string) ([]ProviderPool, error) {
	userService, err := NewProviderPoolServiceForUser(userID)
	if err != nil {
		return nil, err
	}
	userService.bindingChecker = s.bindingChecker
	return userService.ListAllPools()
}

// GetPool 根据 ID 获取池子
func (s *ProviderPoolService) GetPool(poolID string) (*ProviderPool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return nil, err
	}

	for _, pool := range store.Pools {
		if pool.ID == poolID {
			copy := pool
			return &copy, nil
		}
	}

	return nil, nil
}

func (s *ProviderPoolService) GetPoolForUser(userID string, poolID string) (*ProviderPool, error) {
	userService, err := NewProviderPoolServiceForUser(userID)
	if err != nil {
		return nil, err
	}
	userService.bindingChecker = s.bindingChecker
	return userService.GetPool(poolID)
}

// SavePool 保存或更新池子
// 如果 pool.ID 为空，自动生成新 ID 并写回 pool.ID
// 返回生成的或已有的 pool ID
func (s *ProviderPoolService) SavePool(pool *ProviderPool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if pool == nil {
		return "", errors.New("池子不能为空")
	}
	pool.ID = strings.TrimSpace(pool.ID)

	if strings.TrimSpace(pool.Platform) == "" {
		return "", errors.New("池子必须指定 platform")
	}

	if strings.TrimSpace(pool.Name) == "" {
		return "", errors.New("池子名称不能为空")
	}

	pool.PoolType = normalizedProviderPoolType(pool.PoolType)
	if pool.PoolType != ProviderPoolTypeNormal && pool.PoolType != ProviderPoolTypeAccount {
		return "", fmt.Errorf("无效的池子类型: %s（必须是 normal 或 account）", pool.PoolType)
	}
	if pool.PoolType == ProviderPoolTypeAccount && pool.Mode == "" {
		pool.Mode = ProviderPoolModeManaged
	}
	if pool.Mode != ProviderPoolModeManaged && pool.Mode != ProviderPoolModeManual {
		return "", fmt.Errorf("无效的池子模式: %s（必须是 managed 或 manual）", pool.Mode)
	}

	store, err := s.loadLocked()
	if err != nil {
		return "", err
	}
	if store.Version > providerPoolsStoreVersion {
		return "", newerProviderPoolStoreVersionError(store.Version)
	}

	var existing *ProviderPool
	for i := range store.Pools {
		if store.Pools[i].ID == pool.ID && strings.TrimSpace(pool.ID) != "" {
			existing = &store.Pools[i]
			break
		}
	}

	if existing != nil {
		// 池子路由身份创建后不可更改。
		if existing.Platform != pool.Platform {
			return "", fmt.Errorf("池子的 platform 不可更改（原: %s, 新: %s）", existing.Platform, pool.Platform)
		}
		if normalizedProviderPoolType(existing.PoolType) != pool.PoolType {
			return "", fmt.Errorf("池子类型不可更改（原: %s, 新: %s）", normalizedProviderPoolType(existing.PoolType), pool.PoolType)
		}
	}

	if err := normalizeAndValidatePoolForSave(pool, existing, store.Pools); err != nil {
		return "", err
	}

	// 手动模式必须指定 direct applied provider（允许 nil 但会在选择时返回"无可用供应商"）
	if pool.Mode == ProviderPoolModeManual && pool.ManualProviderID == nil && len(pool.Members) > 0 {
		// 软警告，不阻塞保存
		fmt.Printf("[WARN] 手动模式池子 %s 未指定直接应用供应商，请求时将返回无可用供应商\n", pool.Name)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if existing == nil && strings.TrimSpace(pool.ID) == "" {
		// 新建池子，生成 ID
		pool.ID = fmt.Sprintf("pool_%s_%d", pool.Platform, time.Now().UnixNano())
		pool.CreatedAt = now
		pool.UpdatedAt = now
		store.Pools = append(store.Pools, *pool)
	} else {
		// 更新已有池子
		found := false
		for i, existing := range store.Pools {
			if existing.ID == pool.ID {
				pool.CreatedAt = existing.CreatedAt // 保留创建时间
				pool.UpdatedAt = now
				store.Pools[i] = *pool
				found = true
				break
			}
		}
		if !found {
			pool.UpdatedAt = now
			if pool.CreatedAt == "" {
				pool.CreatedAt = now
			}
			store.Pools = append(store.Pools, *pool)
		}
	}

	if err := s.saveLocked(store); err != nil {
		return "", err
	}
	return pool.ID, nil
}

func (s *ProviderPoolService) SavePoolForUser(userID string, pool *ProviderPool) (string, error) {
	userService, err := NewProviderPoolServiceForUser(userID)
	if err != nil {
		return "", err
	}
	userService.bindingChecker = s.bindingChecker
	return userService.SavePool(pool)
}

func normalizedProviderPoolType(poolType ProviderPoolType) ProviderPoolType {
	if strings.TrimSpace(string(poolType)) == "" {
		return ProviderPoolTypeNormal
	}
	return ProviderPoolType(strings.TrimSpace(string(poolType)))
}

func normalizeAndValidatePoolForSave(pool *ProviderPool, existing *ProviderPool, pools []ProviderPool) error {
	if err := normalizeAndValidateFirstTextRetry(pool); err != nil {
		return err
	}
	if err := normalizeAndValidateSpecialBlacklistRules(pool); err != nil {
		return err
	}
	if pool.PoolType == ProviderPoolTypeNormal {
		pool.AccountPoolConfig = nil
		pool.ProxyConfig = nil
		pool.ExcludeFromTotalTraffic = false
		pool.HideFromLogs = false
		return nil
	}

	if pool.Platform != "openai-responses" {
		return errors.New("号池仅支持 openai-responses platform")
	}
	if pool.Mode != ProviderPoolModeManaged {
		return errors.New("号池只能使用 managed 托管模式")
	}
	if len(pool.Members) != 0 {
		return errors.New("号池不能添加普通供应商成员")
	}
	if pool.ManualProviderID != nil {
		return errors.New("号池不能指定手动供应商")
	}
	if pool.AccountPoolConfig == nil {
		return errors.New("号池配置不能为空")
	}

	config := pool.AccountPoolConfig
	if pool.ProxyConfig == nil {
		pool.ProxyConfig = &AccountPoolProxyConfig{Selection: AccountPoolProxySelectionNone}
	}
	if !pool.ProxyConfig.Enabled {
		pool.ProxyConfig.Selection = AccountPoolProxySelectionNone
		pool.ProxyConfig.ProxyNodeID = ""
		pool.ProxyConfig.AutoDisableWhenNoAvailable = false
	} else {
		if pool.ProxyConfig.Selection == "" {
			pool.ProxyConfig.Selection = AccountPoolProxySelectionAuto
		}
		if pool.ProxyConfig.Selection != AccountPoolProxySelectionAuto && pool.ProxyConfig.Selection != AccountPoolProxySelectionNode {
			return fmt.Errorf("无效的号池代理选择方式: %s", pool.ProxyConfig.Selection)
		}
		if pool.ProxyConfig.Selection == AccountPoolProxySelectionNode && strings.TrimSpace(pool.ProxyConfig.ProxyNodeID) == "" {
			return errors.New("固定代理模式必须选择代理节点")
		}
		if pool.ProxyConfig.Selection != AccountPoolProxySelectionAuto {
			pool.ProxyConfig.AutoDisableWhenNoAvailable = false
		}
		pool.ProxyConfig.ProxyNodeID = strings.TrimSpace(pool.ProxyConfig.ProxyNodeID)
	}
	config.APIURL = strings.TrimSpace(config.APIURL)
	parsedAPIURL, err := url.Parse(config.APIURL)
	if err != nil || parsedAPIURL.Host == "" || parsedAPIURL.RawQuery != "" || parsedAPIURL.Fragment != "" ||
		(!strings.EqualFold(parsedAPIURL.Scheme, "http") && !strings.EqualFold(parsedAPIURL.Scheme, "https")) {
		return errors.New("号池 Base URL 必须是有效的 HTTP(S) URL")
	}
	config.APIURL = strings.TrimRight(config.APIURL, "/")

	config.ResponsesEndpoint = strings.TrimSpace(config.ResponsesEndpoint)
	parsedEndpoint, err := url.Parse(config.ResponsesEndpoint)
	if err != nil || parsedEndpoint.IsAbs() || parsedEndpoint.Host != "" || parsedEndpoint.Path == "" || parsedEndpoint.Fragment != "" || strings.HasPrefix(config.ResponsesEndpoint, "//") {
		return errors.New("号池 Responses 端点必须是非空相对路径")
	}
	config.ResponsesEndpoint = "/" + strings.TrimLeft(config.ResponsesEndpoint, "/")

	keys, err := normalizeAccountPoolKeys(config.Keys, existing, pools)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("号池至少需要一个有效密钥")
	}
	config.Keys = keys

	pool.Members = []ProviderPoolMember{}
	pool.ManualProviderID = nil
	pool.AutoBlacklistEnabled = true
	if pool.AutoBlacklistThreshold <= 0 {
		pool.AutoBlacklistThreshold = defaultAccountPoolBlacklistThreshold
	} else if pool.AutoBlacklistThreshold > maxAccountPoolBlacklistThreshold {
		return fmt.Errorf("号池连续失败次数阈值不能超过 %d", maxAccountPoolBlacklistThreshold)
	}
	if pool.AutoBlacklistDurationMinutes <= 0 {
		pool.AutoBlacklistDurationMinutes = defaultAccountPoolBlacklistDurationMinutes
	} else if pool.AutoBlacklistDurationMinutes > maxAccountPoolBlacklistDurationMinutes {
		return fmt.Errorf("号池拉黑时长不能超过 %d 分钟", maxAccountPoolBlacklistDurationMinutes)
	}
	return nil
}

func normalizeAndValidateFirstTextRetry(pool *ProviderPool) error {
	if pool == nil {
		return errors.New("池子不能为空")
	}
	if !pool.FirstTextRetryEnabled {
		if pool.FirstTextRetryTimeoutSeconds <= 0 {
			pool.FirstTextRetryTimeoutSeconds = defaultFirstTextRetryTimeoutSeconds
		}
		return nil
	}
	if pool.FirstTextRetryTimeoutSeconds == 0 {
		pool.FirstTextRetryTimeoutSeconds = defaultFirstTextRetryTimeoutSeconds
	}
	if pool.FirstTextRetryTimeoutSeconds < minFirstTextRetryTimeoutSeconds || pool.FirstTextRetryTimeoutSeconds > maxFirstTextRetryTimeoutSeconds {
		return fmt.Errorf("首字重试时间必须在 %d 到 %d 秒之间", minFirstTextRetryTimeoutSeconds, maxFirstTextRetryTimeoutSeconds)
	}
	return nil
}

func normalizeAndValidateSpecialBlacklistRules(pool *ProviderPool) error {
	if pool == nil || len(pool.SpecialBlacklistRules) == 0 {
		if pool != nil {
			pool.SpecialBlacklistRules = []SpecialBlacklistRule{}
		}
		return nil
	}

	seenIDs := make(map[string]struct{}, len(pool.SpecialBlacklistRules))
	seenNames := make(map[string]struct{}, len(pool.SpecialBlacklistRules))
	normalized := make([]SpecialBlacklistRule, 0, len(pool.SpecialBlacklistRules))
	for index, rule := range pool.SpecialBlacklistRules {
		rule.ID = strings.TrimSpace(rule.ID)
		if rule.ID == "" {
			id, err := newSpecialBlacklistRuleID(seenIDs)
			if err != nil {
				return err
			}
			rule.ID = id
		}
		if _, duplicate := seenIDs[rule.ID]; duplicate {
			return fmt.Errorf("高级拉黑规则 ID 重复: %s", rule.ID)
		}
		seenIDs[rule.ID] = struct{}{}

		rule.Name = strings.TrimSpace(rule.Name)
		if rule.Name == "" {
			return fmt.Errorf("高级拉黑规则 #%d 名称不能为空", index+1)
		}
		nameKey := strings.ToLower(rule.Name)
		if _, duplicate := seenNames[nameKey]; duplicate {
			return fmt.Errorf("高级拉黑规则名称重复: %s", rule.Name)
		}
		seenNames[nameKey] = struct{}{}
		if rule.HTTPStatus < 100 || rule.HTTPStatus > 599 {
			return fmt.Errorf("高级拉黑规则 %s 的 HTTP 状态码必须在 100 到 599 之间", rule.Name)
		}
		rule.JSONPath = strings.TrimSpace(rule.JSONPath)
		rule.ExpectedJSONValue = strings.TrimSpace(rule.ExpectedJSONValue)
		if rule.JSONPath == "" && rule.ExpectedJSONValue != "" {
			return fmt.Errorf("高级拉黑规则 %s 设置 JSON 值时必须填写 JSON 路径", rule.Name)
		}
		if rule.JSONPath != "" {
			if rule.ExpectedJSONValue == "" {
				return fmt.Errorf("高级拉黑规则 %s 设置 JSON 路径时必须填写 JSON 值", rule.Name)
			}
			for _, segment := range strings.Split(rule.JSONPath, ".") {
				if !specialBlacklistJSONPathSegment.MatchString(segment) {
					return fmt.Errorf("高级拉黑规则 %s 的 JSON 路径无效", rule.Name)
				}
			}
			var expected interface{}
			if err := json.Unmarshal([]byte(rule.ExpectedJSONValue), &expected); err != nil {
				return fmt.Errorf("高级拉黑规则 %s 的 JSON 值无效: %w", rule.Name, err)
			}
		}
		if rule.Threshold < 1 || rule.Threshold > 100 {
			return fmt.Errorf("高级拉黑规则 %s 的次数阈值必须在 1 到 100 之间", rule.Name)
		}
		switch strings.TrimSpace(strings.ToLower(rule.DurationType)) {
		case "", SpecialBlacklistDurationTypeDuration:
			// Legacy rules persist without an explicit type; clear any stale
			// "until" fields so stored rules stay canonical.
			rule.DurationType = SpecialBlacklistDurationTypeDuration
			rule.UntilDayOffset = nil
			rule.UntilTime = ""
			if rule.DurationMinutes < 1 || rule.DurationMinutes > maxSpecialBlacklistDurationMinutes {
				return fmt.Errorf("高级拉黑规则 %s 的拉黑时长必须在 1 到 %d 分钟之间", rule.Name, maxSpecialBlacklistDurationMinutes)
			}
		case SpecialBlacklistDurationTypeUntil:
			rule.DurationType = SpecialBlacklistDurationTypeUntil
			if rule.UntilDayOffset == nil || *rule.UntilDayOffset < 0 || *rule.UntilDayOffset > maxSpecialBlacklistUntilDayOffset {
				return fmt.Errorf("高级拉黑规则 %s 的目标天数必须在 0 到 %d 之间", rule.Name, maxSpecialBlacklistUntilDayOffset)
			}
			rule.UntilTime = strings.TrimSpace(rule.UntilTime)
			if !specialBlacklistUntilTimeFormat.MatchString(rule.UntilTime) {
				return fmt.Errorf("高级拉黑规则 %s 的目标时间必须是 HH:MM 格式", rule.Name)
			}
		default:
			return fmt.Errorf("高级拉黑规则 %s 的拉黑方式无效: %s", rule.Name, rule.DurationType)
		}
		normalized = append(normalized, rule)
	}
	pool.SpecialBlacklistRules = normalized
	return nil
}

func newSpecialBlacklistRuleID(used map[string]struct{}) (string, error) {
	var randomBytes [8]byte
	for attempt := 0; attempt < 128; attempt++ {
		if _, err := cryptorand.Read(randomBytes[:]); err != nil {
			return "", fmt.Errorf("生成高级拉黑规则 ID 失败: %w", err)
		}
		id := fmt.Sprintf("rule_%x", randomBytes)
		if _, exists := used[id]; !exists {
			return id, nil
		}
	}
	return "", errors.New("生成唯一高级拉黑规则 ID 失败")
}

func normalizeAccountPoolKeys(input []AccountPoolKey, existing *ProviderPool, pools []ProviderPool) ([]AccountPoolKey, error) {
	existingBySecret := make(map[string]int64)
	if existing != nil && existing.AccountPoolConfig != nil {
		for _, key := range existing.AccountPoolConfig.Keys {
			secret := strings.TrimSpace(key.APIKey)
			if secret == "" {
				continue
			}
			if _, ok := existingBySecret[secret]; !ok {
				existingBySecret[secret] = key.ID
			}
		}
	}

	usedIDs := make(map[int64]struct{})
	usedByOtherPools := make(map[int64]struct{})
	for _, candidatePool := range pools {
		if candidatePool.AccountPoolConfig == nil {
			continue
		}
		isExistingPool := existing != nil && candidatePool.ID == existing.ID
		for _, key := range candidatePool.AccountPoolConfig.Keys {
			if !isValidAccountPoolKeyID(key.ID) {
				continue
			}
			usedIDs[key.ID] = struct{}{}
			if !isExistingPool {
				usedByOtherPools[key.ID] = struct{}{}
			}
		}
	}

	normalized := make([]AccountPoolKey, 0, len(input))
	seenSecrets := make(map[string]struct{}, len(input))
	assignedIDs := make(map[int64]struct{}, len(input))
	for _, candidate := range input {
		secret := strings.TrimSpace(candidate.APIKey)
		if secret == "" {
			continue
		}
		if _, duplicate := seenSecrets[secret]; duplicate {
			continue
		}
		seenSecrets[secret] = struct{}{}

		id := existingBySecret[secret]
		_, usedByOther := usedByOtherPools[id]
		_, alreadyAssigned := assignedIDs[id]
		if !isValidAccountPoolKeyID(id) || usedByOther || alreadyAssigned {
			var err error
			id, err = newAccountPoolKeyID(usedIDs)
			if err != nil {
				return nil, err
			}
		}
		usedIDs[id] = struct{}{}
		assignedIDs[id] = struct{}{}
		normalized = append(normalized, AccountPoolKey{ID: id, APIKey: secret})
	}
	return normalized, nil
}

func isValidAccountPoolKeyID(id int64) bool {
	return id < 0 && id >= -maxAccountPoolKeyID
}

func newAccountPoolKeyID(used map[int64]struct{}) (int64, error) {
	var randomBytes [8]byte
	for attempt := 0; attempt < 128; attempt++ {
		if _, err := cryptorand.Read(randomBytes[:]); err != nil {
			return 0, fmt.Errorf("生成号池密钥 ID 失败: %w", err)
		}
		value := int64(binary.BigEndian.Uint64(randomBytes[:]) & uint64(maxAccountPoolKeyID))
		if value == 0 {
			continue
		}
		id := -value
		if _, exists := used[id]; exists {
			continue
		}
		return id, nil
	}
	return 0, errors.New("生成唯一的号池密钥 ID 失败")
}

// DeletePool 删除池子
// 被 relay key 绑定的池子不可删除（需先迁移绑定）
func (s *ProviderPoolService) DeletePool(poolID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return err
	}

	targetPool, _ := s.findPoolInStoreLocked(store, poolID)
	if targetPool == nil {
		return fmt.Errorf("未找到池子: %s", poolID)
	}

	// 被 relay key 绑定的池子不可删除
	if s.bindingChecker != nil {
		isBound, boundKeys, err := s.bindingChecker.IsPoolBoundToAnyKey(poolID)
		if err != nil {
			return fmt.Errorf("检查池子 %s 的密钥绑定失败，已拒绝删除: %w", poolID, err)
		}
		if isBound {
			return fmt.Errorf("池子 %s 被以下密钥绑定，无法删除：%v。请先迁移或删除这些绑定", poolID, boundKeys)
		}
	}

	filtered := make([]ProviderPool, 0, len(store.Pools))
	for _, pool := range store.Pools {
		if pool.ID == poolID {
			continue
		}
		filtered = append(filtered, pool)
	}

	store.Pools = filtered
	return s.saveLocked(store)
}

func (s *ProviderPoolService) DeletePoolForUser(userID string, poolID string) error {
	userService, err := NewProviderPoolServiceForUser(userID)
	if err != nil {
		return err
	}
	userService.bindingChecker = userScopedPoolBindingChecker{
		userID:  userID,
		checker: s.bindingChecker,
	}
	return userService.DeletePool(poolID)
}

// findPoolInStoreLocked 在 store 中查找池子（内部方法，调用方已持有锁）
func (s *ProviderPoolService) findPoolInStoreLocked(store *providerPoolStore, poolID string) (*ProviderPool, error) {
	for _, pool := range store.Pools {
		if pool.ID == poolID {
			copy := pool
			return &copy, nil
		}
	}
	return nil, nil
}

// EnsureDefaultPool 为指定 platform 确保存在初始池
// 如果已有初始池，直接返回；否则根据 seed 创建
func (s *ProviderPoolService) EnsureDefaultPool(platform string, providers []Provider, seed DefaultPoolSeed) (*ProviderPool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	defaultID := defaultPoolIDForPlatform(platform)

	store, err := s.loadLocked()
	if err != nil {
		return nil, err
	}

	// 查找已有初始池
	for _, pool := range store.Pools {
		if pool.ID == defaultID {
			copy := pool
			return &copy, nil
		}
	}

	// 创建初始池
	now := time.Now().UTC().Format(time.RFC3339)
	members := make([]ProviderPoolMember, 0, len(providers))
	for _, p := range providers {
		members = append(members, ProviderPoolMember{
			ProviderID: p.ID,
			Enabled:    p.Enabled, // 托管模式下按原 enabled 状态；手动模式下不使用此字段
			Priority:   0,         // 预留
			Weight:     0,         // 预留
		})
	}

	pool := ProviderPool{
		ID:                    defaultID,
		Platform:              platform,
		Name:                  initialPoolName,
		PoolType:              ProviderPoolTypeNormal,
		Mode:                  seed.Mode,
		ManualProviderID:      seed.ManualProviderID,
		Members:               members,
		CreatedAt:             now,
		UpdatedAt:             now,
		SpecialBlacklistRules: []SpecialBlacklistRule{},
	}

	store.Pools = append(store.Pools, pool)
	if err := s.saveLocked(store); err != nil {
		return nil, err
	}

	fmt.Printf("[ProviderPoolService] 为 %s 创建初始池（模式: %s, 成员: %d）\n", platform, seed.Mode, len(members))
	return &pool, nil
}

func (s *ProviderPoolService) EnsureDefaultPoolForUser(userID string, platform string, providers []Provider, seed DefaultPoolSeed) (*ProviderPool, error) {
	userService, err := NewProviderPoolServiceForUser(userID)
	if err != nil {
		return nil, err
	}
	userService.bindingChecker = s.bindingChecker
	return userService.EnsureDefaultPool(platform, providers, seed)
}

// EnsureDefaultPoolsForAllPlatforms 为所有已有 platform 确保初始池
// seeds 提供 platform -> DefaultPoolSeed 的映射
func (s *ProviderPoolService) EnsureDefaultPoolsForAllPlatforms(seeds map[string]DefaultPoolSeed) error {
	for platform, seed := range seeds {
		providers, err := loadProviderSnapshot(platform)
		if err != nil {
			fmt.Printf("[WARN] 加载 %s providers 失败，跳过初始池创建: %v\n", platform, err)
			continue
		}
		if providers == nil {
			providers = []Provider{}
		}

		if _, err := s.EnsureDefaultPool(platform, providers, seed); err != nil {
			fmt.Printf("[WARN] 为 %s 创建初始池失败: %v\n", platform, err)
			continue
		}
	}
	return nil
}

// ResolvePoolByID 根据 poolID 查找池子（不回退到初始池）
// NeedsMigration 检查是否需要执行一次性迁移（从旧版本升级）
// 返回 true 表示尚未执行 version 2 的 relay key 显式绑定迁移。
func (s *ProviderPoolService) NeedsMigration() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return false
	}
	return store.Version < providerPoolsBindingMigrationVersion
}

// MarkMigrationCompleted 将 store version 写入当前版本，标记迁移完成
// 迁移完成后，EnsureDefaultPoolsAndBindings 不再自动绑定未绑定的 key
func (s *ProviderPoolService) MarkMigrationCompleted() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return err
	}
	if store.Version > providerPoolsStoreVersion {
		return newerProviderPoolStoreVersionError(store.Version)
	}
	store.Version = providerPoolsStoreVersion
	return s.saveLocked(store)
}

func (s *ProviderPoolService) ResolvePoolByID(poolID string) (*ProviderPool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return nil, err
	}

	for _, pool := range store.Pools {
		if pool.ID == poolID {
			copy := pool
			return &copy, nil
		}
	}

	return nil, nil
}

func (s *ProviderPoolService) ResolvePoolByIDForUser(userID string, poolID string) (*ProviderPool, error) {
	userService, err := NewProviderPoolServiceForUser(userID)
	if err != nil {
		return nil, err
	}
	userService.bindingChecker = s.bindingChecker
	return userService.ResolvePoolByID(poolID)
}

type userScopedPoolBindingChecker struct {
	userID  string
	checker PoolBindingChecker
}

func (c userScopedPoolBindingChecker) IsPoolBoundToAnyKey(poolID string) (bool, []string, error) {
	if c.checker == nil {
		return false, nil, nil
	}
	if checker, ok := c.checker.(UserPoolBindingChecker); ok {
		return checker.IsPoolBoundToAnyKeyForUser(c.userID, poolID)
	}
	return c.checker.IsPoolBoundToAnyKey(poolID)
}

// ========== 内部方法 ==========

func (s *ProviderPoolService) loadLocked() (*providerPoolStore, error) {
	store := &providerPoolStore{
		Version: providerPoolsStoreVersion,
		Pools:   []ProviderPool{},
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
		return nil, fmt.Errorf("解析 provider-pools.json 失败: %w", err)
	}
	// Only migrate the immediately preceding schema. Older stores must retain
	// their existing relay-key binding migration flow before any newer fields
	// are written back.
	if store.Version == providerPoolsStoreVersion-1 {
		migrateFirstTextRetryToPools(store)
		store.Version = providerPoolsStoreVersion
		if err := s.saveLocked(store); err != nil {
			return nil, fmt.Errorf("迁移首字重试池配置失败: %w", err)
		}
	}
	for index := range store.Pools {
		if store.Pools[index].SpecialBlacklistRules == nil {
			// Pools persisted before advanced rules are equivalent to an empty list.
			store.Pools[index].SpecialBlacklistRules = []SpecialBlacklistRule{}
		}
	}
	if store.Pools == nil {
		store.Pools = []ProviderPool{}
	}
	for i := range store.Pools {
		store.Pools[i].PoolType = normalizedProviderPoolType(store.Pools[i].PoolType)
		if store.Pools[i].PoolType == ProviderPoolTypeNormal {
			store.Pools[i].AccountPoolConfig = nil
			store.Pools[i].ProxyConfig = nil
			store.Pools[i].ExcludeFromTotalTraffic = false
			store.Pools[i].HideFromLogs = false
		} else if store.Pools[i].ProxyConfig == nil {
			store.Pools[i].ProxyConfig = &AccountPoolProxyConfig{Selection: AccountPoolProxySelectionNone}
		}
	}

	return store, nil
}

// migrateFirstTextRetryToPools preserves the previous global setting once when
// upgrading old pool files. After this migration, each pool owns its setting.
func migrateFirstTextRetryToPools(store *providerPoolStore) {
	if store == nil {
		return
	}
	type legacyAppSettings struct {
		Enabled bool `json:"enable_first_text_retry"`
		Timeout int  `json:"first_text_retry_timeout_seconds"`
	}
	legacy := legacyAppSettings{}
	if home, err := os.UserHomeDir(); err == nil {
		if data, err := os.ReadFile(filepath.Join(home, appSettingsDir, appSettingsFileName)); err == nil {
			_ = json.Unmarshal(data, &legacy)
		}
	}
	timeout := legacy.Timeout
	if timeout < minFirstTextRetryTimeoutSeconds || timeout > maxFirstTextRetryTimeoutSeconds {
		timeout = defaultFirstTextRetryTimeoutSeconds
	}
	for index := range store.Pools {
		store.Pools[index].FirstTextRetryEnabled = legacy.Enabled
		store.Pools[index].FirstTextRetryTimeoutSeconds = timeout
	}
}

func (s *ProviderPoolService) saveLocked(store *providerPoolStore) error {
	if err := EnsureDir(filepath.Dir(s.path)); err != nil {
		return err
	}
	if store.Version > providerPoolsStoreVersion {
		return newerProviderPoolStoreVersionError(store.Version)
	}
	// Do not let routine pool writes suppress the one-time relay-key binding
	// migration. Once version 2 has been reached, writes use the latest schema.
	if store.Version >= providerPoolsBindingMigrationVersion && store.Version < providerPoolsStoreVersion {
		store.Version = providerPoolsStoreVersion
	}
	return AtomicWriteJSON(s.path, store)
}

func newerProviderPoolStoreVersionError(version int) error {
	return fmt.Errorf("provider pool store version %d is newer than supported version %d; refusing to overwrite", version, providerPoolsStoreVersion)
}

// defaultPoolIDForPlatform 生成初始池的 ID
// 格式: pool_<platform>_default
func defaultPoolIDForPlatform(platform string) string {
	return "pool_" + platform + "_default"
}

// ========== 选择辅助方法 ==========

// SelectProvidersFromPool 根据池子模式和成员从 providers 中筛选可用供应商
// managed 模式：只使用 member.Enabled == true 的 provider
// manual 模式：只使用 ManualProviderID
func SelectProvidersFromPool(pool *ProviderPool, allProviders []Provider) ([]Provider, error) {
	if pool == nil {
		return nil, errors.New("池子不存在")
	}
	poolType := normalizedProviderPoolType(pool.PoolType)
	if poolType != ProviderPoolTypeNormal && poolType != ProviderPoolTypeAccount {
		return nil, fmt.Errorf("未知的池子类型: %s", pool.PoolType)
	}
	if poolType == ProviderPoolTypeAccount {
		if pool.Platform != "openai-responses" {
			return nil, errors.New("号池仅支持 openai-responses platform")
		}
		if pool.Mode != ProviderPoolModeManaged {
			return nil, errors.New("号池只能使用 managed 托管模式")
		}
		if pool.AccountPoolConfig == nil {
			return nil, errors.New("号池配置不能为空")
		}

		config := pool.AccountPoolConfig
		selected := make([]Provider, 0, len(config.Keys))
		for _, key := range config.Keys {
			if !isValidAccountPoolKeyID(key.ID) || strings.TrimSpace(key.APIKey) == "" {
				continue
			}
			selected = append(selected, Provider{
				ID:                key.ID,
				Name:              AccountPoolKeyDisplayName(key),
				APIURL:            config.APIURL,
				APIKey:            key.APIKey,
				Enabled:           true,
				ResponsesEndpoint: config.ResponsesEndpoint,
				ModelsEndpoint:    accountPoolModelsEndpoint(config.ResponsesEndpoint),
				Level:             1,
				MaxConcurrency:    defaultProviderMaxConcurrency,
			})
		}
		return selected, nil
	}

	providerByID := make(map[int64]Provider, len(allProviders))
	for _, p := range allProviders {
		providerByID[p.ID] = p
	}

	switch pool.Mode {
	case ProviderPoolModeManual:
		// 手动模式：只使用直接应用的供应商，忽略 enabled 开关
		if pool.ManualProviderID == nil {
			return nil, nil // 无可用供应商
		}
		provider, ok := providerByID[*pool.ManualProviderID]
		if !ok {
			return nil, fmt.Errorf("直接应用供应商 ID %d 不存在", *pool.ManualProviderID)
		}
		// 验证该 provider 是否在 pool members 中
		inPool := false
		for _, m := range pool.Members {
			if m.ProviderID == *pool.ManualProviderID {
				inPool = true
				break
			}
		}
		if !inPool {
			return nil, fmt.Errorf("直接应用供应商 ID %d 不在池子成员中", *pool.ManualProviderID)
		}
		return []Provider{provider}, nil

	case ProviderPoolModeManaged:
		// 托管模式：只使用 member.Enabled == true 的 provider
		// 同时将 pool member 的 Level 写入 provider，供后续分组使用
		selected := make([]Provider, 0)
		for _, member := range pool.Members {
			if !member.Enabled {
				continue
			}
			provider, ok := providerByID[member.ProviderID]
			if !ok {
				fmt.Printf("[WARN] 池子 %s 的成员 ProviderID %d 在 providers 中不存在\n", pool.Name, member.ProviderID)
				continue
			}
			// 使用池内 Level，缺失默认 1
			provider.Level = normalizePoolMemberLevel(member.Level)
			selected = append(selected, provider)
		}
		return selected, nil

	default:
		return nil, fmt.Errorf("未知的池子模式: %s", pool.Mode)
	}
}

// AccountPoolKeyDisplayName returns a stable, unique and secret-safe runtime provider name.
func AccountPoolKeyDisplayName(key AccountPoolKey) string {
	id := key.ID
	if id < 0 {
		id = -id
	}
	return fmt.Sprintf("Account Key %s (#%d)", maskAccountPoolAPIKey(key.APIKey), id)
}

func maskAccountPoolAPIKey(apiKey string) string {
	apiKey = strings.TrimSpace(apiKey)
	if len(apiKey) <= 4 {
		return "****"
	}
	return "****" + apiKey[len(apiKey)-4:]
}

func accountPoolModelsEndpoint(responsesEndpoint string) string {
	parsed, err := url.Parse(strings.TrimSpace(responsesEndpoint))
	if err != nil || strings.TrimSpace(parsed.Path) == "" {
		return "/v1/models"
	}
	endpointPath := strings.TrimRight("/"+strings.TrimLeft(parsed.Path, "/"), "/")
	dir := pathpkg.Dir(endpointPath)
	if dir == "/" || dir == "." {
		return "/models"
	}
	return strings.TrimRight(dir, "/") + "/models"
}
