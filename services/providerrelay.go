package services

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daodao97/xgo/xdb"
	"github.com/daodao97/xgo/xrequest"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// ProviderPoolProviderPenalty 池子内单个 provider 的运行时惩罚状态
type ProviderPoolProviderPenalty struct {
	UserID           string    `json:"userID,omitempty"`
	Platform         string    `json:"platform"`
	PoolID           string    `json:"poolID"`
	ProviderID       int64     `json:"providerID"`
	FailureCount     int       `json:"failureCount"`
	LastFailureAt    time.Time `json:"lastFailureAt"`
	BlacklistedUntil time.Time `json:"blacklistedUntil"`
	LastReason       string    `json:"lastReason"`
}
type LastUsedProvider struct {
	UserID       string `json:"userID,omitempty"`
	Platform     string `json:"platform"`      // 平台
	PoolID       string `json:"pool_id"`       // 池子 ID（pool 维度隔离）
	ProviderName string `json:"provider_name"` // 供应商名称
	UpdatedAt    int64  `json:"updated_at"`    // 更新时间（毫秒）
}

type ProviderRelayService struct {
	providerService     *ProviderService
	poolService         *ProviderPoolService
	codexRelayKeys      *CodexRelayKeyService
	notificationService *NotificationService
	appSettings         *AppSettingsService
	httpClient          *http.Client
	server              *http.Server
	addr                string
	lastUsed            map[string]*LastUsedProvider // 各平台最后使用的供应商
	lastUsedMu          sync.RWMutex                 // 保护 lastUsed 的锁

	// 池子维度 provider 惩罚状态（自动拉黑）
	poolPenaltyMu sync.Mutex
	poolPenalties map[string]*ProviderPoolProviderPenalty
}

// errClientAbort 表示客户端中断连接，不应计入 provider 失败次数
var errClientAbort = errors.New("client aborted, skip failure count")
var errCodexEmptyStream = errors.New("codex upstream stream closed before useful content")
var errProviderEmptyShell = errors.New("provider returned 200 but all token counts are zero")

const codexEmptyStreamRetryDelay = time.Second

func NewProviderRelayService(providerService *ProviderService, poolService *ProviderPoolService, codexRelayKeys *CodexRelayKeyService, notificationService *NotificationService, appSettings *AppSettingsService, addr string) *ProviderRelayService {
	if addr == "" {
		addr = DefaultRelayBindAddr
	}
	if codexRelayKeys == nil {
		codexRelayKeys = NewCodexRelayKeyService()
	}
	if poolService == nil {
		poolService = NewProviderPoolService()
	}

	// 【修复】数据库初始化已移至 main.go 的 InitDatabase()
	// 此处不再调用 xdb.Inits()、ensureRequestLogTable()

	return &ProviderRelayService{
		providerService:     providerService,
		poolService:         poolService,
		codexRelayKeys:      codexRelayKeys,
		notificationService: notificationService,
		appSettings:         appSettings,
		httpClient:          newRelayHTTPClient(),
		addr:                addr,
		lastUsed: map[string]*LastUsedProvider{
			"claude":           nil,
			"openai-responses": nil,
			"openai-chat":      nil,
		},
		poolPenalties: make(map[string]*ProviderPoolProviderPenalty),
	}
}

func newRelayHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{Transport: transport}
}

func lastUsedKey(userID, platform, poolID string) string {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return platform + ":" + poolID
	}
	return userID + ":" + platform + ":" + poolID
}

// setLastUsedProviderForUser 记录最后使用的供应商（user + platform + poolID 维度）
// 不同用户和不同 pool/key 之间不互相影响
func (prs *ProviderRelayService) setLastUsedProviderForUser(userID, platform, poolID, providerName string) {
	key := lastUsedKey(userID, platform, poolID)
	prs.lastUsedMu.Lock()
	defer prs.lastUsedMu.Unlock()
	prs.lastUsed[key] = &LastUsedProvider{
		UserID:       strings.TrimSpace(userID),
		Platform:     platform,
		PoolID:       poolID,
		ProviderName: providerName,
		UpdatedAt:    time.Now().UnixMilli(),
	}
}

// setLastUsedProvider 记录最后使用的供应商（旧兼容 API）。
func (prs *ProviderRelayService) setLastUsedProvider(platform, poolID, providerName string) {
	prs.setLastUsedProviderForUser("", platform, poolID, providerName)
}

// GetLastUsedProvider 获取指定平台最后使用的供应商（兼容旧 API，返回任意 pool 的）
func (prs *ProviderRelayService) GetLastUsedProvider(platform string) *LastUsedProvider {
	prs.lastUsedMu.RLock()
	defer prs.lastUsedMu.RUnlock()
	// 返回该 platform 下任意 pool 的 last used
	for k, v := range prs.lastUsed {
		if strings.HasPrefix(k, platform+":") && v != nil {
			return v
		}
	}
	return prs.lastUsed[platform] // 兼容旧的纯 platform key
}

// GetAllLastUsedProvidersForUser 获取当前用户的最后使用供应商状态。
func (prs *ProviderRelayService) GetAllLastUsedProvidersForUser(userID string) []*LastUsedProvider {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return prs.GetAllLastUsedProviders()
	}
	prefix := userID + ":"
	prs.lastUsedMu.RLock()
	defer prs.lastUsedMu.RUnlock()
	result := make([]*LastUsedProvider, 0, len(prs.lastUsed))
	for key, v := range prs.lastUsed {
		if v != nil && strings.HasPrefix(key, prefix) {
			result = append(result, v)
		}
	}
	return result
}

// GetLastUsedProviderByPool 获取指定平台+池子最后使用的供应商
func (prs *ProviderRelayService) GetLastUsedProviderByPool(platform, poolID string) *LastUsedProvider {
	prs.lastUsedMu.RLock()
	defer prs.lastUsedMu.RUnlock()
	key := platform + ":" + poolID
	return prs.lastUsed[key]
}

// GetAllLastUsedProviders 获取所有最后使用的供应商（返回 pool 维度）
func (prs *ProviderRelayService) GetAllLastUsedProviders() []*LastUsedProvider {
	prs.lastUsedMu.RLock()
	defer prs.lastUsedMu.RUnlock()
	result := make([]*LastUsedProvider, 0, len(prs.lastUsed))
	for _, v := range prs.lastUsed {
		if v != nil {
			result = append(result, v)
		}
	}
	return result
}

// isCodexStreamGuardEnabled 检查 Codex 流式空响应保护是否启用
func (prs *ProviderRelayService) isCodexStreamGuardEnabled() bool {
	if prs.appSettings == nil {
		return true
	}
	settings, err := prs.appSettings.GetAppSettings()
	if err != nil {
		return true
	}
	return settings.EnableCodexStreamGuard
}

func (prs *ProviderRelayService) shouldUseCodexStreamGuard(kind, endpoint string) bool {
	// openai-responses 走 stream guard（Codex 客户端走这个端点）
	// openai-chat 不走 stream guard
	if kind == "openai-responses" {
		return isResponsesEndpoint(endpoint) && prs.isCodexStreamGuardEnabled()
	}
	return strings.EqualFold(kind, "codex") && isResponsesEndpoint(endpoint) && prs.isCodexStreamGuardEnabled()
}

func (prs *ProviderRelayService) shouldRequireProviderEnabled(kind string) bool {
	if kind == "openai-responses" {
		codexSettings := NewCodexSettingsService(prs.Addr(), prs.codexRelayKeys)
		status, err := codexSettings.ProxyStatus()
		if err != nil {
			fmt.Printf("[WARN] 读取 OpenAI Responses 托管状态失败，保守使用 provider 开关: %v\n", err)
			return true
		}
		return status.Enabled
	}
	if kind == "openai-chat" {
		codexSettings := NewCodexSettingsService(prs.Addr(), prs.codexRelayKeys)
		status, err := codexSettings.ProxyStatus()
		if err != nil {
			fmt.Printf("[WARN] 读取 OpenAI Chat 托管状态失败，保守使用 provider 开关: %v\n", err)
			return true
		}
		return status.Enabled
	}
	if !strings.EqualFold(kind, "codex") {
		return true
	}
	codexSettings := NewCodexSettingsService(prs.Addr(), prs.codexRelayKeys)
	status, err := codexSettings.ProxyStatus()
	if err != nil {
		fmt.Printf("[WARN] 读取 Codex 托管状态失败，保守使用 provider 开关: %v\n", err)
		return true
	}
	return status.Enabled
}

func (prs *ProviderRelayService) codexDirectAppliedProviderFilter(kind string, requireProviderEnabled bool) (*int64, bool) {
	if kind == "openai-chat" {
		return nil, false
	}
	if kind != "openai-responses" && !strings.EqualFold(kind, "codex") {
		return nil, false
	}
	if requireProviderEnabled {
		return nil, false
	}
	codexSettings := NewCodexSettingsService(prs.Addr(), prs.codexRelayKeys)
	id, err := codexSettings.GetDirectAppliedProviderID()
	if err != nil {
		fmt.Printf("[WARN] 读取 Codex 直接应用供应商失败，非托管模式下不启用 Codex provider: %v\n", err)
		return nil, true
	}
	return id, true
}

// penaltyKey builds a stable key for user/pool-level provider penalty state.
func penaltyKey(userID, platform, poolID string, providerID int64) string {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Sprintf("%s:%s:%d", platform, poolID, providerID)
	}
	return fmt.Sprintf("%s:%s:%s:%d", userID, platform, poolID, providerID)
}

func penaltyKeyPrefix(userID, platform, poolID string) string {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return platform + ":" + poolID + ":"
	}
	return userID + ":" + platform + ":" + poolID + ":"
}

// getProviderLevelInPool resolves the Level for a provider within a pool.
// Only uses pool member Level; defaults to 1 if not set.
func getProviderLevelInPool(pool *ProviderPool, provider Provider) int {
	if pool != nil {
		for _, m := range pool.Members {
			if m.ProviderID == provider.ID {
				if m.Level > 0 {
					return m.Level
				}
				break
			}
		}
	}
	return 1
}

// isProviderBlacklistedForUser checks whether a provider is currently blacklisted in the given user pool.
func (prs *ProviderRelayService) isProviderBlacklistedForUser(userID, platform, poolID string, providerID int64) bool {
	prs.poolPenaltyMu.Lock()
	defer prs.poolPenaltyMu.Unlock()

	key := penaltyKey(userID, platform, poolID, providerID)
	p, ok := prs.poolPenalties[key]
	if !ok {
		return false
	}
	if p.BlacklistedUntil.IsZero() {
		return false
	}
	if time.Now().After(p.BlacklistedUntil) {
		// 懒清理：过期自动恢复
		delete(prs.poolPenalties, key)
		return false
	}
	return true
}

// isProviderBlacklisted checks whether a provider is currently blacklisted in the given pool.
func (prs *ProviderRelayService) isProviderBlacklisted(platform, poolID string, providerID int64) bool {
	return prs.isProviderBlacklistedForUser("", platform, poolID, providerID)
}

// filterBlacklistedProvidersForUser removes blacklisted providers from a candidate list.
func (prs *ProviderRelayService) filterBlacklistedProvidersForUser(userID, platform, poolID string, providers []Provider) []Provider {
	if len(providers) == 0 {
		return providers
	}
	filtered := make([]Provider, 0, len(providers))
	for _, p := range providers {
		if prs.isProviderBlacklistedForUser(userID, platform, poolID, p.ID) {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered
}

// filterBlacklistedProviders removes blacklisted providers from a candidate list.
func (prs *ProviderRelayService) filterBlacklistedProviders(platform, poolID string, providers []Provider) []Provider {
	return prs.filterBlacklistedProvidersForUser("", platform, poolID, providers)
}

// recordProviderSuccessForUser clears the failure count for a provider in a pool.
func (prs *ProviderRelayService) recordProviderSuccessForUser(userID, platform, poolID string, provider Provider) {
	prs.poolPenaltyMu.Lock()
	defer prs.poolPenaltyMu.Unlock()
	delete(prs.poolPenalties, penaltyKey(userID, platform, poolID, provider.ID))
}

// recordProviderSuccess clears the failure count for a provider in a pool.
func (prs *ProviderRelayService) recordProviderSuccess(platform, poolID string, provider Provider) {
	prs.recordProviderSuccessForUser("", platform, poolID, provider)
}

// recordProviderFailureForUser increments the consecutive failure count and, if the threshold
// is reached, blacklists the provider. Returns true when this failure resulted in a new
// blacklist.
func (prs *ProviderRelayService) recordProviderFailureForUser(userID, platform, poolID string, pool *ProviderPool, provider Provider, reason string) bool {
	if pool == nil {
		return false
	}
	// 自动拉黑仅在托管模式下生效（手动模式只有一个直接应用的 provider，无需拉黑）
	if pool.Mode != ProviderPoolModeManaged {
		return false
	}
	if !pool.AutoBlacklistEnabled {
		return false
	}
	threshold := pool.AutoBlacklistThreshold
	if threshold <= 0 {
		threshold = 3
	}
	durationMinutes := pool.AutoBlacklistDurationMinutes
	if durationMinutes <= 0 {
		durationMinutes = 10
	}

	key := penaltyKey(userID, platform, poolID, provider.ID)
	prs.poolPenaltyMu.Lock()

	p, ok := prs.poolPenalties[key]
	if !ok {
		p = &ProviderPoolProviderPenalty{
			UserID:     strings.TrimSpace(userID),
			Platform:   platform,
			PoolID:     poolID,
			ProviderID: provider.ID,
		}
		prs.poolPenalties[key] = p
	}
	wasBlacklisted := !p.BlacklistedUntil.IsZero() && time.Now().Before(p.BlacklistedUntil)
	p.FailureCount++
	p.LastFailureAt = time.Now()
	p.LastReason = reason

	if p.FailureCount >= threshold {
		p.BlacklistedUntil = time.Now().Add(time.Duration(durationMinutes) * time.Minute)
		penalty := *p
		prs.poolPenaltyMu.Unlock()
		if !wasBlacklisted && prs.notificationService != nil {
			prs.notificationService.NotifyProviderBlacklistChanged(ProviderBlacklistChangedNotification{
				UserID:           penalty.UserID,
				Platform:         penalty.Platform,
				PoolID:           penalty.PoolID,
				ProviderID:       penalty.ProviderID,
				ProviderName:     provider.Name,
				Action:           "blacklisted",
				FailureCount:     penalty.FailureCount,
				LastFailureAt:    penalty.LastFailureAt,
				BlacklistedUntil: penalty.BlacklistedUntil,
				LastReason:       penalty.LastReason,
			})
		}
		return true
	}
	prs.poolPenaltyMu.Unlock()
	return false
}

// recordProviderFailure increments the consecutive failure count and, if the threshold
// is reached, blacklists the provider. Returns true when this failure resulted in a new
// blacklist.
func (prs *ProviderRelayService) recordProviderFailure(platform, poolID string, pool *ProviderPool, provider Provider, reason string) bool {
	return prs.recordProviderFailureForUser("", platform, poolID, pool, provider, reason)
}

// clearProviderBlacklistForUser manually removes the blacklist for a provider in a pool.
func (prs *ProviderRelayService) clearProviderBlacklistForUser(userID, platform, poolID string, providerID int64) {
	prs.poolPenaltyMu.Lock()
	key := penaltyKey(userID, platform, poolID, providerID)
	penalty, existed := prs.poolPenalties[key]
	wasBlacklisted := existed && !penalty.BlacklistedUntil.IsZero() && time.Now().Before(penalty.BlacklistedUntil)
	delete(prs.poolPenalties, key)
	prs.poolPenaltyMu.Unlock()

	if wasBlacklisted && prs.notificationService != nil {
		prs.notificationService.NotifyProviderBlacklistChanged(ProviderBlacklistChangedNotification{
			UserID:        strings.TrimSpace(userID),
			Platform:      platform,
			PoolID:        poolID,
			ProviderID:    providerID,
			Action:        "cleared",
			FailureCount:  penalty.FailureCount,
			LastFailureAt: penalty.LastFailureAt,
			LastReason:    penalty.LastReason,
		})
	}
}

// clearProviderBlacklist manually removes the blacklist for a provider in a pool.
func (prs *ProviderRelayService) clearProviderBlacklist(platform, poolID string, providerID int64) {
	prs.clearProviderBlacklistForUser("", platform, poolID, providerID)
}

// listProviderBlacklistStatusForUser returns penalty entries for providers that are
// currently blacklisted (BlacklistedUntil non-zero and not expired).
func (prs *ProviderRelayService) listProviderBlacklistStatusForUser(userID, platform, poolID string) []ProviderPoolProviderPenalty {
	prs.poolPenaltyMu.Lock()
	defer prs.poolPenaltyMu.Unlock()
	now := time.Now()
	prefix := penaltyKeyPrefix(userID, platform, poolID)

	result := make([]ProviderPoolProviderPenalty, 0)
	for key, p := range prs.poolPenalties {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if p.BlacklistedUntil.IsZero() || now.After(p.BlacklistedUntil) {
			continue
		}
		result = append(result, *p)
	}
	return result
}

// listProviderBlacklistStatus returns penalty entries for providers that are
// currently blacklisted (BlacklistedUntil non-zero and not expired).
func (prs *ProviderRelayService) listProviderBlacklistStatus(platform, poolID string) []ProviderPoolProviderPenalty {
	return prs.listProviderBlacklistStatusForUser("", platform, poolID)
}

// selectProvidersForRequest 从请求上下文解析 pool
// 严格 fail-closed：只接受 relay key 的显式 pool binding
// - 有 binding 且 pool 存在且 platform 匹配：返回该 pool
// - 无 binding / pool 不存在 / platform 不匹配：返回 error
// 不回退默认池子，不回退旧 platform 逻辑
func (prs *ProviderRelayService) resolvePoolFromContext(c *gin.Context, kind string) (*ProviderPool, error) {
	bindings := relayKeyPoolBindingsFromContext(c)

	// 必须有显式 binding
	if bindings == nil {
		return nil, fmt.Errorf("relay key 未绑定任何池子")
	}

	poolID, ok := bindings[kind]
	if !ok || strings.TrimSpace(poolID) == "" {
		return nil, fmt.Errorf("relay key 未绑定 %s 的池子", kind)
	}

	userID := relayUserIDFromContext(c)
	var pool *ProviderPool
	var err error
	if strings.TrimSpace(userID) != "" {
		pool, err = prs.poolService.ResolvePoolByIDForUser(userID, poolID)
	} else {
		pool, err = prs.poolService.ResolvePoolByID(poolID)
	}
	if err != nil {
		return nil, fmt.Errorf("查找池子 %s 失败: %w", poolID, err)
	}
	if pool == nil {
		return nil, fmt.Errorf("relay key 绑定的池子 %s 不存在", poolID)
	}
	if pool.Platform != kind {
		return nil, fmt.Errorf("relay key 绑定的池子 %s 的 platform 不匹配（期望 %s，实际 %s）", poolID, kind, pool.Platform)
	}

	return pool, nil
}

// selectProvidersForRequest 根据池子选择供应商
// 这是 pool 模式下的统一入口，替代旧的 shouldRequireProviderEnabled + codexDirectAppliedProviderFilter
func (prs *ProviderRelayService) selectProvidersForRequestForUser(userID string, kind string, pool *ProviderPool, requestedModel string) ([]Provider, error) {
	if pool == nil {
		return nil, fmt.Errorf("%s 无可用池子", kind)
	}

	var providers []Provider
	var err error
	if strings.TrimSpace(userID) != "" {
		providers, err = prs.providerService.LoadProvidersForUser(userID, kind)
	} else {
		providers, err = prs.providerService.LoadProviders(kind)
	}
	if err != nil {
		return nil, fmt.Errorf("加载 %s providers 失败: %w", kind, err)
	}

	// 使用池子模式过滤供应商
	selected, err := SelectProvidersFromPool(pool, providers)
	if err != nil {
		return nil, err
	}

	// 对选中的供应商做进一步过滤
	active := make([]Provider, 0, len(selected))
	for _, provider := range selected {
		// 基础过滤：必须有 URL 和 Key
		if provider.APIURL == "" || provider.APIKey == "" {
			continue
		}

		// 配置验证
		if errs := provider.ValidateConfiguration(); len(errs) > 0 {
			fmt.Printf("[WARN] Provider %s 配置验证失败，已自动跳过: %v\n", provider.Name, errs)
			continue
		}

		// 模型支持过滤
		if requestedModel != "" && !provider.IsModelSupported(requestedModel) {
			fmt.Printf("[INFO] Provider %s 不支持模型 %s，已跳过\n", provider.Name, requestedModel)
			continue
		}

		active = append(active, provider)
	}

	return active, nil
}

func (prs *ProviderRelayService) selectProvidersForRequest(kind string, pool *ProviderPool, requestedModel string) ([]Provider, error) {
	return prs.selectProvidersForRequestForUser("", kind, pool, requestedModel)
}

// EnsureDefaultPoolsAndBindings 启动时确保默认池子存在
// relay key 绑定只在一次性迁移（version < 2）时执行
// 迁移完成后，新 key 不会被自动绑定，必须由用户显式设置
func (prs *ProviderRelayService) EnsureDefaultPoolsAndBindings() error {
	// 确定每个 platform 的当前模式
	platforms := []string{"claude", "openai-responses", "openai-chat"}
	seeds := make(map[string]DefaultPoolSeed)
	platformDefaults := make(map[string]string)

	for _, platform := range platforms {
		seed := DefaultPoolSeed{Mode: ProviderPoolModeManaged}

		// 根据当前托管状态推导模式
		if prs.shouldRequireProviderEnabled(platform) {
			// 托管模式
			seed.Mode = ProviderPoolModeManaged
		} else {
			// 手动模式（非托管）
			seed.Mode = ProviderPoolModeManual
			// 获取直接应用供应商
			directID, requiresDirect := prs.codexDirectAppliedProviderFilter(platform, false)
			if requiresDirect && directID != nil {
				seed.ManualProviderID = directID
			} else if requiresDirect {
				// 手动模式但无直接应用，记录警告
				fmt.Printf("[WARN] %s 手动模式无直接应用供应商，默认池子将无可用供应商\n", platform)
			}
		}

		seeds[platform] = seed
		platformDefaults[platform] = defaultPoolIDForPlatform(platform)
	}

	// 确保默认池子（每次启动都要保证池子存在）
	if err := prs.poolService.EnsureDefaultPoolsForAllPlatforms(seeds); err != nil {
		fmt.Printf("[WARN] 确保默认池子失败: %v\n", err)
	}

	// relay key 绑定：只在一次性迁移时执行
	// NeedsMigration() 返回 true 表示 store version < 2，即从旧版本升级
	if prs.poolService.NeedsMigration() {
		fmt.Printf("[INFO] 执行一次性迁移：为现有 relay key 绑定默认池子\n")
		if err := prs.codexRelayKeys.EnsureDefaultPoolBindings(platformDefaults); err != nil {
			fmt.Printf("[WARN] 迁移绑定失败: %v\n", err)
		}
		if err := prs.poolService.MarkMigrationCompleted(); err != nil {
			fmt.Printf("[WARN] 标记迁移完成失败: %v\n", err)
		} else {
			fmt.Printf("[INFO] 迁移完成，后续启动不再自动绑定\n")
		}
	}

	return nil
}

// poolIDFromContext 从 gin.Context 获取 poolID
func poolIDFromContext(c *gin.Context) string {
	if c == nil {
		return ""
	}
	value, ok := c.Get(providerPoolIDContextKey)
	if !ok {
		return ""
	}
	id, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(id)
}

func (prs *ProviderRelayService) Start() error {
	// 启动前验证配置
	if warnings := prs.validateConfig(); len(warnings) > 0 {
		fmt.Println("======== Provider 配置验证警告 ========")
		for _, warn := range warnings {
			fmt.Printf("⚠️  %s\n", warn)
		}
		fmt.Println("========================================")
	}

	router := gin.Default()
	prs.registerRoutes(router)

	prs.server = &http.Server{
		Addr:    prs.addr,
		Handler: router,
	}

	fmt.Printf("provider relay server listening on %s\n", prs.addr)

	go func() {
		if err := prs.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("provider relay server error: %v\n", err)
		}
	}()
	return nil
}

// validateConfig 验证所有 provider 的配置
// 返回警告列表（非阻塞性错误）
func (prs *ProviderRelayService) validateConfig() []string {
	warnings := make([]string, 0)

	for _, kind := range []string{"claude", "openai-responses", "openai-chat"} {
		providers, err := prs.providerService.LoadProviders(kind)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("[%s] 加载配置失败: %v", kind, err))
			continue
		}

		enabledCount := 0
		for _, p := range providers {
			if !p.Enabled {
				continue
			}
			enabledCount++

			// 验证每个启用的 provider
			if errs := p.ValidateConfiguration(); len(errs) > 0 {
				for _, errMsg := range errs {
					warnings = append(warnings, fmt.Sprintf("[%s/%s] %s", kind, p.Name, errMsg))
				}
			}

			// 检查是否配置了模型白名单或映射
			if (p.SupportedModels == nil || len(p.SupportedModels) == 0) &&
				(p.ModelMapping == nil || len(p.ModelMapping) == 0) {
				warnings = append(warnings, fmt.Sprintf(
					"[%s/%s] 未配置 supportedModels 或 modelMapping，将假设支持所有模型（可能导致降级失败）",
					kind, p.Name))
			}

			// 检查是否只配置了映射但没有白名单
			if len(p.ModelMapping) > 0 && len(p.SupportedModels) == 0 {
				warnings = append(warnings, fmt.Sprintf(
					"[%s/%s] 配置了 modelMapping 但未配置 supportedModels，映射目标将不做校验，请确认目标模型在供应商处可用",
					kind, p.Name))
			}
		}

		if enabledCount == 0 {
			warnings = append(warnings, fmt.Sprintf("[%s] 没有启用的 provider", kind))
		}
	}

	return warnings
}

func (prs *ProviderRelayService) Stop() error {
	if prs.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return prs.server.Shutdown(ctx)
}

func (prs *ProviderRelayService) Addr() string {
	return prs.addr
}

func (prs *ProviderRelayService) registerRoutes(router gin.IRouter) {
	claudeAuth := prs.claudeRelayAuthMiddleware()
	codexAuth := prs.codexRelayAuthMiddleware()

	router.POST("/v1/messages", claudeAuth, prs.proxyHandler("claude", "/v1/messages"))
	router.POST("/v1/messages/count_tokens", claudeAuth, prs.proxyHandler("claude", "/v1/messages/count_tokens"))
	router.POST("/responses", codexAuth, prs.proxyHandler("openai-responses", "/responses"))
	router.POST("/v1/responses", codexAuth, prs.proxyHandler("openai-responses", "/v1/responses"))
	router.POST("/chat/completions", codexAuth, prs.proxyHandler("openai-chat", "/chat/completions"))
	router.POST("/v1/chat/completions", codexAuth, prs.proxyHandler("openai-chat", "/chat/completions"))

	// /v1/models 端点（OpenAI-compatible API）
	// 支持 Claude 和 Codex 平台
	router.GET("/v1/models", codexAuth, prs.modelsHandler("claude"))

	// 自定义 CLI 工具端点（路由格式: /custom/:toolId/v1/messages）
	// toolId 用于区分不同的 CLI 工具，对应 provider kind 为 "custom:{toolId}"
	router.POST("/custom/:toolId/v1/messages", prs.customCliProxyHandler())

	// 自定义 CLI 工具的 /v1/models 端点
	router.GET("/custom/:toolId/v1/models", prs.customModelsHandler())
}

func (prs *ProviderRelayService) resolveRelayEndpoint(kind string, provider Provider, routeEndpoint string) string {
	return provider.GetEffectiveEndpoint(routeEndpoint)
}

func (prs *ProviderRelayService) proxyHandler(kind string, endpoint string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var bodyBytes []byte
		if c.Request.Body != nil {
			data, err := io.ReadAll(c.Request.Body)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
				return
			}
			bodyBytes = data
			c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		isStream := gjson.GetBytes(bodyBytes, "stream").Bool()
		requestedModel := gjson.GetBytes(bodyBytes, "model").String()

		// 如果未指定模型，记录警告但不拦截
		if requestedModel == "" {
			fmt.Printf("[WARN] 请求未指定模型名，无法执行模型智能降级\n")
		}

		// ========== Pool 维度供应商选择（fail-closed）==========
		// 从请求上下文解析池子，然后只在该池子内选择供应商
		// 不回退默认池子，不回退旧 platform 逻辑
		pool, poolErr := prs.resolvePoolFromContext(c, kind)
		if poolErr != nil {
			fmt.Printf("[ERROR] 解析 %s 的池子失败: %v\n", kind, poolErr)
			c.JSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("relay key 无权访问 %s 的供应商池: %v", kind, poolErr),
			})
			return
		}

		fmt.Printf("[INFO] 池子模式: %s/%s (模式: %s, 成员: %d)\n", kind, pool.Name, pool.Mode, len(pool.Members))
		active, selectErr := prs.selectProvidersForRequestForUser(relayUserIDFromContext(c), kind, pool, requestedModel)
		if selectErr != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": selectErr.Error()})
			return
		}
		if len(active) == 0 {
			if requestedModel != "" {
				c.JSON(http.StatusNotFound, gin.H{
					"error": fmt.Sprintf("没有可用的 provider 支持模型 '%s'（池子: %s/%s）", requestedModel, kind, pool.Name),
				})
			} else {
				c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("no providers available in pool %s/%s", kind, pool.Name)})
			}
			return
		}

		fmt.Printf("[INFO] 池子 %s 找到 %d 个可用的 provider：", pool.Name, len(active))
		for _, p := range active {
			fmt.Printf("%s ", p.Name)
		}
		fmt.Println()

		c.Set("pool_mode", pool.Mode)
		c.Set("pool", pool)
		c.Set(providerPoolIDContextKey, pool.ID)
		poolID := pool.ID
		userID := relayUserIDFromContext(c)

		// 过滤掉当前 pool 下仍在拉黑期的 provider（仅 managed 模式）
		if pool.Mode == ProviderPoolModeManaged {
			active = prs.filterBlacklistedProvidersForUser(userID, kind, poolID, active)
		}

		if len(active) == 0 {
			fmt.Printf("[WARN] 池子 %s 的所有 provider 均在拉黑期，无可用供应商\n", pool.Name)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": fmt.Sprintf("池子 %s 内所有 provider 均在临时拉黑期，请稍后重试或手动解除拉黑", pool.Name),
			})
			return
		}

		fmt.Printf("[INFO] 池子 %s 找到 %d 个可用的 provider（拉黑过滤后）：", pool.Name, len(active))
		for _, p := range active {
			fmt.Printf("%s ", p.Name)
		}
		fmt.Println()

		// 按 Level 分组（使用 pool member Level，回退到 provider 全局 Level）
		levelGroups := make(map[int][]Provider)
		for _, provider := range active {
			level := getProviderLevelInPool(pool, provider)
			levelGroups[level] = append(levelGroups[level], provider)
		}

		// 获取所有 level 并升序排序
		levels := make([]int, 0, len(levelGroups))
		for level := range levelGroups {
			levels = append(levels, level)
		}
		sort.Ints(levels)

		fmt.Printf("[INFO] 共 %d 个 Level 分组：%v\n", len(levels), levels)

		query := flattenQuery(c.Request.URL.Query())
		clientHeaders := cloneHeaders(c.Request.Header)

		// 【降级模式】：按 Level 顺序尝试，Level 小的先用，失败后尝试同 Level 下一个
		fmt.Printf("[INFO] 🔄 降级模式（顺序降级 + 自动拉黑）\n")

		var lastError error
		var lastProvider string
		var lastDuration time.Duration
		totalAttempts := 0

		for _, level := range levels {
			providersInLevel := levelGroups[level]

			fmt.Printf("[INFO] === 尝试 Level %d（%d 个 provider）===\n", level, len(providersInLevel))

			for i, provider := range providersInLevel {
				totalAttempts++

				// 获取实际应该使用的模型名
				effectiveModel := provider.GetEffectiveModel(requestedModel)

				// 如果需要映射，修改请求体
				currentBodyBytes := bodyBytes
				if effectiveModel != requestedModel && requestedModel != "" {
					fmt.Printf("[INFO] Provider %s 映射模型: %s -> %s\n", provider.Name, requestedModel, effectiveModel)

					modifiedBody, err := ReplaceModelInRequestBody(bodyBytes, effectiveModel)
					if err != nil {
						fmt.Printf("[ERROR] 替换模型名失败: %v\n", err)
						// 映射失败不应阻止尝试其他 provider
						continue
					}
					currentBodyBytes = modifiedBody
				}

				fmt.Printf("[INFO]   [%d/%d] Provider: %s | Model: %s\n", i+1, len(providersInLevel), provider.Name, effectiveModel)

				// 尝试发送请求
				// 获取有效的端点（用户配置优先）
				effectiveEndpoint := prs.resolveRelayEndpoint(kind, provider, endpoint)
				startTime := time.Now()
				ok, err := prs.forwardRequest(c, kind, provider, effectiveEndpoint, query, clientHeaders, currentBodyBytes, isStream, effectiveModel)
				duration := time.Since(startTime)
				failedFromEmptyStreamRetry := false
				if !ok && errors.Is(err, errCodexEmptyStream) {
					var retryAttempts int
					var retryDuration time.Duration
					ok, provider, err, retryAttempts, retryDuration, failedFromEmptyStreamRetry = prs.retryCodexEmptyStreamSameProvider(c, kind, poolID, pool, provider, endpoint, query, clientHeaders, bodyBytes, isStream, requestedModel)
					totalAttempts += retryAttempts
					duration += retryDuration
				}

				if ok {
					fmt.Printf("[INFO]   ✓ Level %d 成功: %s | 耗时: %.2fs\n", level, provider.Name, duration.Seconds())

					// 记录最后使用的供应商
					prs.setLastUsedProviderForUser(userID, kind, poolID, provider.Name)
					// 成功：清空该 provider 连续失败计数
					prs.recordProviderSuccessForUser(userID, kind, poolID, provider)

					return // 成功，立即返回
				}

				// 失败：记录错误并尝试下一个
				lastError = err
				lastProvider = provider.Name
				lastDuration = duration

				errorMsg := "未知错误"
				if err != nil {
					errorMsg = err.Error()
				}
				fmt.Printf("[WARN]   ✗ Level %d 失败: %s | 错误: %s | 耗时: %.2fs\n",
					level, provider.Name, errorMsg, duration.Seconds())

				if errors.Is(err, errClientAbort) {
					fmt.Printf("[INFO] 客户端中断，停止重试: %s\n", provider.Name)
					return
				}

				// 记录 provider 失败（自动拉黑逻辑）。空流重试路径已在内部计数，跳过。
				if !failedFromEmptyStreamRetry {
					prs.recordProviderFailureForUser(userID, kind, poolID, pool, provider, errorMsg)
				}

				// 发送切换通知：检查是否有下一个可用的 provider
				if prs.notificationService != nil {
					nextProvider := ""
					// 先查找同级别的下一个
					if i+1 < len(providersInLevel) {
						nextProvider = providersInLevel[i+1].Name
					} else {
						// 查找下一个 level 的第一个 provider
						for _, nextLevel := range levels {
							if nextLevel > level && len(levelGroups[nextLevel]) > 0 {
								nextProvider = levelGroups[nextLevel][0].Name
								break
							}
						}
					}
					if nextProvider != "" {
						prs.notificationService.NotifyProviderSwitch(SwitchNotification{
							FromProvider: provider.Name,
							ToProvider:   nextProvider,
							Reason:       errorMsg,
							Platform:     kind,
						})
					}
				}
			}

			fmt.Printf("[WARN] Level %d 的所有 %d 个 provider 均失败，尝试下一 Level\n", level, len(providersInLevel))
		}

		// 所有 provider 都失败，返回 502
		errorMsg := "未知错误"
		if lastError != nil {
			errorMsg = lastError.Error()
		}
		fmt.Printf("[ERROR] 所有 %d 个 provider 均失败，最后尝试: %s | 错误: %s\n",
			totalAttempts, lastProvider, errorMsg)

		c.JSON(http.StatusBadGateway, gin.H{
			"error":          fmt.Sprintf("所有 %d 个 provider 均失败，最后错误: %s", totalAttempts, errorMsg),
			"last_provider":  lastProvider,
			"last_duration":  fmt.Sprintf("%.2fs", lastDuration.Seconds()),
			"total_attempts": totalAttempts,
		})
	}
}

func (prs *ProviderRelayService) forwardRequest(
	c *gin.Context,
	kind string,
	provider Provider,
	endpoint string,
	query map[string]string,
	clientHeaders map[string]string,
	bodyBytes []byte,
	isStream bool,
	model string,
) (bool, error) {
	targetURL := joinURL(provider.APIURL, endpoint)
	headers := cloneMap(clientHeaders)

	// ========== count_tokens 本地估算（协议转换之前拦截）==========
	if kind == "claude" && strings.HasSuffix(endpoint, "/count_tokens") {
		supportsCountTokens := provider.SupportsCountTokens == nil || *provider.SupportsCountTokens
		if !supportsCountTokens {
			estimatedTokens := estimateInputTokens(bodyBytes)
			c.JSON(http.StatusOK, gin.H{
				"input_tokens": estimatedTokens,
			})
			return true, nil
		}
	}

	if kind == "openai-chat" && isStream {
		bodyBytes = ensureOpenAIChatStreamUsage(bodyBytes)
	}

	removeInboundAuthHeaders(headers)

	// 根据认证方式设置请求头（默认 Bearer，与 v2.2.x 保持一致）
	authType := strings.ToLower(strings.TrimSpace(provider.ConnectivityAuthType))
	switch authType {
	case "x-api-key":
		// 仅当用户显式选择 x-api-key 时使用（Anthropic 官方 API）
		headers["x-api-key"] = provider.APIKey
		if kind == "claude" {
			headers["anthropic-version"] = "2023-06-01"
		}
	case "", "bearer":
		// 默认使用 Bearer token（兼容所有第三方中转）
		headers["Authorization"] = fmt.Sprintf("Bearer %s", provider.APIKey)
	default:
		// 自定义 Header 名
		headerName := strings.TrimSpace(provider.ConnectivityAuthType)
		if headerName == "" || strings.EqualFold(headerName, "custom") {
			headerName = "Authorization"
		}
		headers[headerName] = provider.APIKey
	}

	if _, ok := headers["Accept"]; !ok {
		headers["Accept"] = "application/json"
	}
	if isStream {
		deleteHeaderCaseInsensitive(headers, "Accept")
		deleteHeaderCaseInsensitive(headers, "Accept-Encoding")
		deleteHeaderCaseInsensitive(headers, "Content-Encoding")
		headers["Accept"] = "text/event-stream"
		headers["Accept-Encoding"] = "identity"
	}

	requestLog := &ReqeustLog{
		Platform:   kind,
		Provider:   provider.Name,
		Model:      model,
		UserID:     relayUserIDFromContext(c),
		IsStream:   isStream,
		RelayKeyID: relayKeyIDFromContext(c),
	}
	start := time.Now()
	requestLog.startedAt = start
	defer func() {
		requestLog.DurationSec = time.Since(start).Seconds()

		// 【修复】判空保护：避免队列未初始化时 panic
		if GlobalDBQueueLogs == nil {
			fmt.Printf("⚠️  写入 request_log 失败: 队列未初始化\n")
			return
		}

		// 使用批量队列写入 request_log（高频同构操作，批量提交）
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := GlobalDBQueueLogs.ExecBatchCtx(ctx, `
			INSERT INTO request_log (
				user_id, platform, model, provider, relay_key_id, http_code,
				input_tokens, output_tokens, cache_create_tokens, cache_read_tokens,
				reasoning_tokens, is_stream, duration_sec,
				upstream_header_sec, first_event_sec, first_text_sec, error_message, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			requestLog.UserID,
			requestLog.Platform,
			requestLog.Model,
			requestLog.Provider,
			requestLog.RelayKeyID,
			requestLog.HttpCode,
			requestLog.InputTokens,
			requestLog.OutputTokens,
			requestLog.CacheCreateTokens,
			requestLog.CacheReadTokens,
			requestLog.ReasoningTokens,
			boolToInt(requestLog.IsStream),
			requestLog.DurationSec,
			requestLog.UpstreamHeaderSec,
			requestLog.FirstEventSec,
			requestLog.FirstTextSec,
			requestLog.ErrorMessage,
			time.Now().UTC().Format(timeLayout),
		)

		if err != nil {
			fmt.Printf("写入 request_log 失败: %v\n", err)
		}
		RecordModelMonitorTraffic(requestLog)
	}()

	resp, err := prs.doProviderRequest(c.Request.Context(), targetURL, headers, query, bodyBytes)
	requestLog.markUpstreamHeaders()

	// 无论成功失败，先尝试记录 HttpCode
	if resp != nil {
		requestLog.HttpCode = resp.StatusCode()
	}

	if err != nil {
		// resp 存在但 err != nil：可能是客户端中断，不计入失败
		if resp != nil && requestLog.HttpCode == 0 {
			fmt.Printf("[INFO] Provider %s 响应存在但状态码为0，判定为客户端中断\n", provider.Name)
			return false, fmt.Errorf("%w: %v", errClientAbort, err)
		}
		// 尝试从响应体提取供应商原始错误信息
		if resp != nil {
			if upstreamBody := extractUpstreamError(resp); upstreamBody != "" {
				requestLog.ErrorMessage = summarizeBodyForError(upstreamBody, 1000)
				return false, fmt.Errorf("upstream status %d: %s", resp.StatusCode(), upstreamBody)
			}
		}
		requestLog.ErrorMessage = summarizeBodyForError(err.Error(), 1000)
		return false, err
	}

	if resp == nil {
		return false, fmt.Errorf("empty response")
	}

	status := requestLog.HttpCode

	if resp.Error() != nil {
		// resp 存在、有错误、但状态码为 0：客户端中断，不计入失败
		if status == 0 {
			fmt.Printf("[INFO] Provider %s 响应错误但状态码为0，判定为客户端中断\n", provider.Name)
			return false, fmt.Errorf("%w: %v", errClientAbort, resp.Error())
		}
		// 优先使用 extractUpstreamError 提取完整错误（覆盖 SSE 空 body 场景）
		errMsg := strings.TrimSpace(resp.Error().Error())
		if errMsg == "" {
			if upstreamBody := extractUpstreamError(resp); upstreamBody != "" {
				errMsg = upstreamBody
			}
		}
		if errMsg != "" {
			requestLog.ErrorMessage = summarizeBodyForError(errMsg, 1000)
			return false, fmt.Errorf("upstream status %d: %s", status, errMsg)
		}
		requestLog.ErrorMessage = fmt.Sprintf("upstream status %d", status)
		return false, fmt.Errorf("upstream status %d", status)
	}

	// 状态码为 0 且无错误：当作成功处理
	if status == 0 {
		fmt.Printf("[WARN] Provider %s 返回状态码 0，但无错误，当作成功处理\n", provider.Name)
		var copyErr error
		if isStreamResponse(resp, isStream) {
			if prs.shouldUseCodexStreamGuard(kind, endpoint) {
				var responseWritten bool
				_, responseWritten, copyErr = writeCodexGuardedStreamingResponse(c.Writer, resp, requestLog, ReqeustLogHook(c, kind, requestLog))
				if copyErr != nil && (errors.Is(copyErr, errCodexEmptyStream) || !responseWritten) {
					return false, copyErr
				}
			} else {
				_, copyErr = writeStreamingResponse(c.Writer, resp, requestLog, ReqeustLogHook(c, kind, requestLog))
			}
		} else if kind == "openai-chat" {
			copyErr = writeOpenAIChatJSONResponse(c.Writer, resp, requestLog)
		} else {
			_, copyErr = resp.ToHttpResponseWriter(c.Writer, ReqeustLogHook(c, kind, requestLog))
		}
		if copyErr != nil {
			fmt.Printf("[WARN] 复制响应到客户端失败（不影响provider成功判定）: %v\n", copyErr)
		}
		return true, nil
	}

	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		if isStream {
			if err := upstreamHTMLStreamError(resp); err != nil {
				return false, err
			}
		}

		// 非流式：先读取响应体，解析 token 和内容，确认非空壳后再写给客户端
		if !isStream && !isStreamResponse(resp, isStream) {
			bodyData, readErr := readResponseBody(resp)
			if readErr != nil {
				return false, fmt.Errorf("failed to read response body: %w", readErr)
			}

			// 按路径解析 token 和内容，并准备最终要写的 body
			finalBody := bodyData
			contentType := resp.RawResponse.Header.Get("Content-Type")

			if kind == "openai-chat" {
				// OpenAI Chat：使用正确的 prompt_tokens/completion_tokens 解析
				OpenAIChatParseTokenUsageFromResponse(string(bodyData), requestLog)
				if contentType == "" {
					contentType = "application/json"
				}
			} else if kind == "openai-responses" {
				// OpenAI Responses：解析嵌套缓存/推理字段
				CodexParseTokenUsageFromResponse(string(bodyData), requestLog)
				if contentType == "" {
					contentType = "application/json"
				}
			} else {
				// 通用格式（Anthropic 等）
				parseNonStreamingTokens(bodyData, kind, requestLog)
			}

			// 空壳检测
			if requestLog.isEmptyShell() && !hasContentInResponse(finalBody, kind) {
				fmt.Printf("[WARN] Provider %s 返回 200 空壳响应（无 tokens 且无内容），计为失败\n", provider.Name)
				return false, fmt.Errorf("%w: provider %s returned 200 empty shell", errProviderEmptyShell, provider.Name)
			}

			// 非空壳：复制响应头并写给客户端
			copyResponseHeaders(c.Writer, resp.RawResponse.Header)
			if contentType != "" {
				c.Writer.Header().Set("Content-Type", contentType)
			}
			c.Writer.Header().Del("Content-Length")
			c.Writer.WriteHeader(status)
			if _, writeErr := c.Writer.Write(finalBody); writeErr != nil {
				fmt.Printf("[WARN] 复制响应到客户端失败: %v\n", writeErr)
			}
			return true, nil
		}

		var copyErr error
		if isStreamResponse(resp, isStream) {
			if prs.shouldUseCodexStreamGuard(kind, endpoint) {
				var responseWritten bool
				_, responseWritten, copyErr = writeCodexGuardedStreamingResponse(c.Writer, resp, requestLog, ReqeustLogHook(c, kind, requestLog))
				if copyErr != nil && (errors.Is(copyErr, errCodexEmptyStream) || !responseWritten) {
					return false, copyErr
				}
			} else {
				_, copyErr = writeStreamingResponse(c.Writer, resp, requestLog, ReqeustLogHook(c, kind, requestLog))
			}
		} else if kind == "openai-chat" {
			copyErr = writeOpenAIChatJSONResponse(c.Writer, resp, requestLog)
		} else {
			_, copyErr = resp.ToHttpResponseWriter(c.Writer, ReqeustLogHook(c, kind, requestLog))
		}
		if copyErr != nil {
			fmt.Printf("[WARN] 复制响应到客户端失败（不影响provider成功判定）: %v\n", copyErr)
		}
		// 只要provider返回了2xx状态码，就算成功（复制失败是客户端问题，不是provider问题）
		return true, nil
	}

	// 尝试从响应体提取供应商原始错误信息
	if upstreamBody := extractUpstreamError(resp); upstreamBody != "" {
		requestLog.ErrorMessage = summarizeBodyForError(upstreamBody, 1000)
		return false, fmt.Errorf("upstream status %d: %s", status, upstreamBody)
	}
	requestLog.ErrorMessage = fmt.Sprintf("upstream status %d", status)
	return false, fmt.Errorf("upstream status %d", status)
}

func (prs *ProviderRelayService) doProviderRequest(ctx context.Context, targetURL string, headers map[string]string, query map[string]string, bodyBytes []byte) (*xrequest.Response, error) {
	client := prs.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	const maxAttempts = 2
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		req, err := newProviderHTTPRequest(ctx, targetURL, headers, query, bodyBytes)
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			lastErr = err
			if attempt+1 < maxAttempts && waitBeforeProviderRetry(ctx) == nil {
				continue
			}
			return nil, err
		}

		if resp != nil && resp.StatusCode >= http.StatusInternalServerError && attempt+1 < maxAttempts {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if waitBeforeProviderRetry(ctx) == nil {
				continue
			}
		}

		return xrequest.NewResponse(resp), nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("provider request failed")
}

func newProviderHTTPRequest(ctx context.Context, targetURL string, headers map[string]string, query map[string]string, bodyBytes []byte) (*http.Request, error) {
	requestURL, err := addQueryParams(targetURL, query)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.ContentLength = int64(len(bodyBytes))
	for key, value := range headers {
		if strings.TrimSpace(key) == "" {
			continue
		}
		req.Header.Set(key, value)
	}
	return req, nil
}

func addQueryParams(targetURL string, query map[string]string) (string, error) {
	if len(query) == 0 {
		return targetURL, nil
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}
	values := parsed.Query()
	for key, value := range query {
		if strings.TrimSpace(key) == "" {
			continue
		}
		values.Set(key, value)
	}
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

func waitBeforeProviderRetry(ctx context.Context) error {
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func waitBeforeCodexEmptyStreamRetry(ctx context.Context) error {
	timer := time.NewTimer(codexEmptyStreamRetryDelay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (prs *ProviderRelayService) retryCodexEmptyStreamSameProvider(
	c *gin.Context,
	kind string,
	poolID string,
	pool *ProviderPool,
	initialProvider Provider,
	endpoint string,
	query map[string]string,
	clientHeaders map[string]string,
	originalBodyBytes []byte,
	isStream bool,
	requestedModel string,
) (bool, Provider, error, int, time.Duration, bool) {
	provider := initialProvider
	attempts := 0
	totalDuration := time.Duration(0)
	userID := relayUserIDFromContext(c)

	// 第一次空流已由 forwardRequest 检测到，计入失败
	blacklisted := prs.recordProviderFailureForUser(userID, kind, poolID, pool, provider, "codex empty stream")
	if blacklisted {
		fmt.Printf("[INFO] Codex 空流保护: Provider %s 因空流被自动拉黑，停止同 provider 重试\n", provider.Name)
		return false, provider, fmt.Errorf("provider %s blacklisted after empty stream", provider.Name), attempts, totalDuration, true
	}

	for {
		if err := waitBeforeCodexEmptyStreamRetry(c.Request.Context()); err != nil {
			return false, provider, fmt.Errorf("%w: %v", errClientAbort, err), attempts, totalDuration, false
		}

		nextProvider, ok, err := prs.selectCodexEmptyStreamRetryProviderForUser(userID, kind, poolID, provider.Name, requestedModel)
		if err != nil {
			return false, provider, err, attempts, totalDuration, false
		}
		if !ok {
			fmt.Printf("[INFO] Codex 空流保护: Provider %s 当前不可用，继续等待恢复，不切换到其他 provider\n", provider.Name)
			continue
		}
		provider = nextProvider

		effectiveModel := provider.GetEffectiveModel(requestedModel)
		currentBodyBytes := originalBodyBytes
		if effectiveModel != requestedModel && requestedModel != "" {
			modifiedBody, err := ReplaceModelInRequestBody(originalBodyBytes, effectiveModel)
			if err != nil {
				return false, provider, err, attempts, totalDuration, false
			}
			currentBodyBytes = modifiedBody
		}

		effectiveEndpoint := prs.resolveRelayEndpoint(kind, provider, endpoint)
		attempts++
		fmt.Printf("[INFO] Codex 空流保护: 同 provider 后台重试 #%d | Provider: %s | Model: %s\n",
			attempts, provider.Name, effectiveModel)

		startTime := time.Now()
		requestOK, requestErr := prs.forwardRequest(c, kind, provider, effectiveEndpoint, query, clientHeaders, currentBodyBytes, isStream, effectiveModel)
		duration := time.Since(startTime)
		totalDuration += duration

		if requestOK {
			fmt.Printf("[INFO] Codex 空流保护: 重试成功 | Provider: %s | 后台重试 %d 次 | 耗时: %.2fs\n",
				provider.Name, attempts, totalDuration.Seconds())
			// 成功：清空失败计数
			prs.recordProviderSuccessForUser(userID, kind, poolID, provider)
			return true, provider, nil, attempts, totalDuration, false
		}
		if errors.Is(requestErr, errCodexEmptyStream) {
			fmt.Printf("[WARN] Codex 空流保护: Provider %s 仍返回空流，继续后台重试 | 耗时: %.2fs\n",
				provider.Name, duration.Seconds())
			// 每次空流都计入失败
			if prs.recordProviderFailureForUser(userID, kind, poolID, pool, provider, "codex empty stream") {
				fmt.Printf("[INFO] Codex 空流保护: Provider %s 因连续空流被自动拉黑，停止同 provider 重试\n", provider.Name)
				return false, provider, fmt.Errorf("provider %s blacklisted after repeated empty streams", provider.Name), attempts, totalDuration, true
			}
			continue
		}
		return false, provider, requestErr, attempts, totalDuration, false
	}
}

// selectCodexEmptyStreamRetryProvider 空流重试时查找当前 provider 是否仍然可用
// fail-closed: 必须在当前 pool 内查找，不能跳到其他 pool
// same platform + same pool + same provider
func (prs *ProviderRelayService) selectCodexEmptyStreamRetryProvider(kind, poolID, currentProviderName, requestedModel string) (Provider, bool, error) {
	return prs.selectCodexEmptyStreamRetryProviderForUser("", kind, poolID, currentProviderName, requestedModel)
}

func (prs *ProviderRelayService) selectCodexEmptyStreamRetryProviderForUser(userID, kind, poolID, currentProviderName, requestedModel string) (Provider, bool, error) {
	if prs.providerService == nil || prs.poolService == nil {
		return Provider{}, false, fmt.Errorf("provider/pool service unavailable")
	}

	// 只在当前 pool 内查找
	var pool *ProviderPool
	var err error
	if strings.TrimSpace(userID) != "" {
		pool, err = prs.poolService.ResolvePoolByIDForUser(userID, poolID)
	} else {
		pool, err = prs.poolService.ResolvePoolByID(poolID)
	}
	if err != nil || pool == nil {
		return Provider{}, false, fmt.Errorf("池子 %s 不存在", poolID)
	}

	var providers []Provider
	if strings.TrimSpace(userID) != "" {
		providers, err = prs.providerService.LoadProvidersForUser(userID, kind)
	} else {
		providers, err = prs.providerService.LoadProviders(kind)
	}
	if err != nil {
		return Provider{}, false, err
	}

	selected, selectErr := SelectProvidersFromPool(pool, providers)
	if selectErr != nil {
		return Provider{}, false, selectErr
	}

	for _, provider := range selected {
		if provider.APIURL == "" || provider.APIKey == "" {
			continue
		}
		if errs := provider.ValidateConfiguration(); len(errs) > 0 {
			continue
		}
		if requestedModel != "" && !provider.IsModelSupported(requestedModel) {
			continue
		}
		if provider.Name == currentProviderName {
			return provider, true, nil
		}
	}

	return Provider{}, false, nil
}

func isResponsesEndpoint(endpoint string) bool {
	return strings.Contains(strings.ToLower(endpoint), "/responses")
}

func isStreamResponse(resp *xrequest.Response, requestedStream bool) bool {
	if requestedStream {
		return true
	}
	if resp == nil || resp.RawResponse == nil {
		return false
	}
	return strings.Contains(strings.ToLower(resp.RawResponse.Header.Get("Content-Type")), "text/event-stream")
}

func upstreamHTMLStreamError(resp *xrequest.Response) error {
	if resp == nil || resp.RawResponse == nil {
		return nil
	}
	contentType := strings.ToLower(resp.RawResponse.Header.Get("Content-Type"))
	if !strings.Contains(contentType, "text/html") {
		return nil
	}
	body := summarizeBodyForError(extractUpstreamError(resp), 240)
	if body == "" {
		return fmt.Errorf("upstream returned HTML instead of SSE")
	}
	return fmt.Errorf("upstream returned HTML instead of SSE: %s", body)
}

func summarizeBodyForError(body string, maxLen int) string {
	body = strings.Join(strings.Fields(body), " ")
	if maxLen <= 0 || len(body) <= maxLen {
		return body
	}
	return body[:maxLen] + "..."
}

func writeStreamingResponse(w http.ResponseWriter, resp *xrequest.Response, requestLog *ReqeustLog, hooks ...xrequest.ResponseHook) (int64, error) {
	if resp == nil || resp.RawResponse == nil {
		return 0, fmt.Errorf("empty upstream response")
	}

	raw := resp.RawResponse
	if raw.Body != nil {
		defer raw.Body.Close()
	}

	copyStreamingResponseHeaders(w.Header(), raw.Header)
	normalizeStreamingResponseHeaders(w.Header())
	status := resp.StatusCode()
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)

	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	if raw.Body == nil {
		return 0, nil
	}

	reader := bufio.NewReader(raw.Body)
	totalBytes := int64(0)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			n, writeErr := writeStreamingLine(w, line, requestLog, hooks...)
			totalBytes += n
			if writeErr != nil {
				return totalBytes, writeErr
			}
		}

		if err != nil {
			if err == io.EOF {
				return totalBytes, nil
			}
			return totalBytes, fmt.Errorf("error streaming response: %w", err)
		}
	}
}

const (
	codexStreamGuardMaxInitialBufferBytes = 1024 * 1024
	codexStreamGuardKeepAliveInterval     = 15 * time.Second
)

var codexStreamGuardKeepAliveComment = ":" + strings.Repeat(" ", 1024) + "\n\n"

type codexStreamGuardState struct {
	sawCompleted     bool
	sawFailed        bool
	sawIncomplete    bool
	sawUsefulContent bool
	inputTokens      int64
	outputTokens     int64
	cacheTokens      int64
	reasoningTokens  int64
}

func (s *codexStreamGuardState) observeLine(line []byte) {
	trimmed := strings.TrimSpace(string(line))
	if !strings.HasPrefix(trimmed, "data:") {
		return
	}
	data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
	if data == "" || data == "[DONE]" || !json.Valid([]byte(data)) {
		return
	}

	eventType := gjson.Get(data, "type").String()
	switch eventType {
	case "response.completed":
		s.sawCompleted = true
	case "response.failed":
		s.sawFailed = true
	case "response.incomplete":
		s.sawIncomplete = true
	case "response.output_text.delta":
		if strings.TrimSpace(gjson.Get(data, "delta").String()) != "" {
			s.sawUsefulContent = true
		}
	case "response.function_call_arguments.delta":
		if strings.TrimSpace(gjson.Get(data, "delta").String()) != "" {
			s.sawUsefulContent = true
		}
	}

	usage := gjson.Get(data, "response.usage")
	if usage.Exists() {
		s.inputTokens += usage.Get("input_tokens").Int()
		s.outputTokens += usage.Get("output_tokens").Int()
		s.cacheTokens += usage.Get("input_tokens_details.cached_tokens").Int()
		s.reasoningTokens += usage.Get("output_tokens_details.reasoning_tokens").Int()
	}
}

func (s codexStreamGuardState) shouldRelease() bool {
	return s.sawUsefulContent || s.sawCompleted || s.sawFailed || s.sawIncomplete || s.totalTokens() > 0
}

func (s codexStreamGuardState) totalTokens() int64 {
	return s.inputTokens + s.outputTokens + s.cacheTokens + s.reasoningTokens
}

func (s codexStreamGuardState) isEmptyFailure() bool {
	if s.sawFailed || s.sawIncomplete || s.sawCompleted {
		return false
	}
	return !s.sawUsefulContent && s.totalTokens() == 0
}

func writeCodexGuardedStreamingResponse(w http.ResponseWriter, resp *xrequest.Response, requestLog *ReqeustLog, hooks ...xrequest.ResponseHook) (int64, bool, error) {
	if resp == nil || resp.RawResponse == nil {
		return 0, false, fmt.Errorf("empty upstream response")
	}

	raw := resp.RawResponse
	if raw.Body != nil {
		defer raw.Body.Close()
	}
	if raw.Body == nil {
		return 0, false, errCodexEmptyStream
	}

	var writeMu sync.Mutex
	clientStarted := responseWriterWritten(w)
	released := false
	totalBytes := int64(0)
	state := codexStreamGuardState{}
	var initialBuffer bytes.Buffer

	writeHeaderLocked := func() {
		if clientStarted {
			return
		}
		copyStreamingResponseHeaders(w.Header(), raw.Header)
		normalizeStreamingResponseHeaders(w.Header())
		status := resp.StatusCode()
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		clientStarted = true
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}

	sendKeepAliveLocked := func() error {
		if released {
			return nil
		}
		writeHeaderLocked()
		if _, err := io.WriteString(w, codexStreamGuardKeepAliveComment); err != nil {
			return fmt.Errorf("error writing codex stream keepalive: %w", err)
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		return nil
	}

	flushInitialBuffer := func() error {
		writeMu.Lock()
		defer writeMu.Unlock()
		released = true
		writeHeaderLocked()
		if initialBuffer.Len() == 0 {
			return nil
		}
		n, err := writeStreamingBuffer(w, initialBuffer.Bytes(), requestLog, hooks...)
		totalBytes += n
		initialBuffer.Reset()
		return err
	}

	writeStreamingLineLocked := func(line []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		n, err := writeStreamingLine(w, line, requestLog, hooks...)
		totalBytes += n
		return err
	}

	if err := func() error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return sendKeepAliveLocked()
	}(); err != nil {
		return totalBytes, clientStarted, err
	}

	stopKeepAlive := make(chan struct{})
	keepAliveStopped := make(chan struct{})
	go func() {
		defer close(keepAliveStopped)
		ticker := time.NewTicker(codexStreamGuardKeepAliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				writeMu.Lock()
				err := sendKeepAliveLocked()
				writeMu.Unlock()
				if err != nil {
					fmt.Printf("[WARN] Codex 空流保护: SSE 保活写入失败: %v\n", err)
					return
				}
			case <-stopKeepAlive:
				return
			}
		}
	}()
	defer func() {
		close(stopKeepAlive)
		<-keepAliveStopped
	}()

	reader := bufio.NewReader(raw.Body)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if released {
				if writeErr := writeStreamingLineLocked(line); writeErr != nil {
					return totalBytes, clientStarted, writeErr
				}
			} else {
				initialBuffer.Write(line)
				state.observeLine(line)
				if state.shouldRelease() || initialBuffer.Len() >= codexStreamGuardMaxInitialBufferBytes {
					if writeErr := flushInitialBuffer(); writeErr != nil {
						return totalBytes, clientStarted, writeErr
					}
				}
			}
		}

		if err != nil {
			if err == io.EOF {
				if !released {
					if state.isEmptyFailure() {
						return totalBytes, clientStarted, errCodexEmptyStream
					}
					if writeErr := flushInitialBuffer(); writeErr != nil {
						return totalBytes, clientStarted, writeErr
					}
				}
				return totalBytes, clientStarted, nil
			}
			if !released {
				return totalBytes, clientStarted, fmt.Errorf("error streaming response before useful content: %w", err)
			}
			return totalBytes, clientStarted, fmt.Errorf("error streaming response: %w", err)
		}
	}
}

func responseWriterWritten(w http.ResponseWriter) bool {
	type writtenChecker interface {
		Written() bool
	}
	if checker, ok := w.(writtenChecker); ok {
		return checker.Written()
	}
	return false
}

func writeStreamingBuffer(w http.ResponseWriter, data []byte, requestLog *ReqeustLog, hooks ...xrequest.ResponseHook) (int64, error) {
	reader := bufio.NewReader(bytes.NewReader(data))
	totalBytes := int64(0)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			n, writeErr := writeStreamingLine(w, line, requestLog, hooks...)
			totalBytes += n
			if writeErr != nil {
				return totalBytes, writeErr
			}
		}
		if err != nil {
			if err == io.EOF {
				return totalBytes, nil
			}
			return totalBytes, err
		}
	}
}

func writeStreamingLine(w http.ResponseWriter, line []byte, requestLog *ReqeustLog, hooks ...xrequest.ResponseHook) (int64, error) {
	originalLine := make([]byte, len(line))
	copy(originalLine, line)

	trimmedLine := bytes.TrimRight(line, "\n")
	outputLine := originalLine
	if len(bytes.TrimSpace(trimmedLine)) > 0 {
		if requestLog != nil {
			requestLog.markFirstEvent()
		}
		flush := true
		processedLine := trimmedLine
		for _, hook := range hooks {
			flush, processedLine = hook(processedLine)
		}
		if !flush {
			return 0, nil
		}
		if bytes.HasSuffix(originalLine, []byte("\n")) {
			processedLine = append(processedLine, '\n')
		}
		outputLine = processedLine
	}

	n, err := w.Write(outputLine)
	if err != nil {
		return int64(n), fmt.Errorf("error writing streaming response: %w", err)
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	return int64(n), nil
}

func copyStreamingResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		switch strings.ToLower(key) {
		case "content-length", "content-encoding", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
			"te", "trailer", "transfer-encoding", "upgrade":
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
	dst.Set("X-Accel-Buffering", "no")
	if dst.Get("Cache-Control") == "" {
		dst.Set("Cache-Control", "no-cache")
	}
}

func normalizeStreamingResponseHeaders(header http.Header) {
	header.Set("Content-Type", "text/event-stream; charset=utf-8")
	header.Set("Cache-Control", appendCacheControlDirective(header.Get("Cache-Control"), "no-transform"))
	header.Del("Content-Encoding")
	header.Del("Content-Length")
}

func appendCacheControlDirective(value, directive string) string {
	directive = strings.TrimSpace(directive)
	if directive == "" {
		return value
	}
	if strings.TrimSpace(value) == "" {
		return directive
	}
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), directive) {
			return value
		}
	}
	return value + ", " + directive
}

func writeOpenAIChatJSONResponse(w http.ResponseWriter, resp *xrequest.Response, requestLog *ReqeustLog) error {
	if resp == nil || resp.RawResponse == nil {
		return fmt.Errorf("empty upstream response")
	}

	body := resp.Bytes()
	OpenAIChatParseTokenUsageFromResponse(string(body), requestLog)

	for key, values := range resp.Headers() {
		lowerKey := strings.ToLower(key)
		switch lowerKey {
		case "content-length", "content-encoding", "transfer-encoding", "connection":
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Del("Content-Length")
	status := resp.StatusCode()
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)

	_, err := w.Write(body)
	return err
}

// extractUpstreamError 从供应商响应中提取原始错误信息（最多 512 字节）
func extractUpstreamError(resp *xrequest.Response) string {
	if resp == nil {
		return ""
	}
	// 优先尝试 String()（会自动解压 gzip 等）
	body := resp.String()
	// SSE 流式响应时 String() 返回空，回退到直接读取 RawResponse.Body（带超时防御）
	if body == "" && resp.RawResponse != nil && resp.RawResponse.Body != nil {
		done := make(chan []byte, 1)
		go func() {
			raw, err := io.ReadAll(io.LimitReader(resp.RawResponse.Body, 512))
			if err == nil {
				done <- raw
			} else {
				done <- nil
			}
		}()
		select {
		case raw := <-done:
			if raw != nil {
				body = string(raw)
			}
		case <-time.After(500 * time.Millisecond):
			// 超时放弃，关闭 Body 中断后台读取，避免 goroutine 泄漏
			resp.RawResponse.Body.Close()
		}
	}
	if body == "" {
		return ""
	}
	// 截断过长的错误信息
	if len(body) > 512 {
		body = body[:512] + "..."
	}
	return body
}

func cloneHeaders(header http.Header) map[string]string {
	cloned := make(map[string]string, len(header))
	for key, values := range header {
		if len(values) > 0 {
			cloned[key] = values[len(values)-1]
		}
	}
	return cloned
}

func deleteHeaderCaseInsensitive(headers map[string]string, target string) {
	for key := range headers {
		if strings.EqualFold(key, target) {
			delete(headers, key)
		}
	}
}

func removeInboundAuthHeaders(headers map[string]string) {
	deleteHeaderCaseInsensitive(headers, "authorization")
	deleteHeaderCaseInsensitive(headers, "x-api-key")
	deleteHeaderCaseInsensitive(headers, codexRelayKeyHeader)
}

func cloneMap(m map[string]string) map[string]string {
	cloned := make(map[string]string, len(m))
	for k, v := range m {
		cloned[k] = v
	}
	return cloned
}

func flattenQuery(values map[string][]string) map[string]string {
	query := make(map[string]string, len(values))
	for key, items := range values {
		if len(items) > 0 {
			query[key] = items[len(items)-1]
		}
	}
	return query
}

func joinURL(base string, endpoint string) string {
	base = strings.TrimSuffix(base, "/")
	endpoint = "/" + strings.TrimPrefix(endpoint, "/")
	return base + endpoint
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func ensureRequestLogColumn(db *sql.DB, column string, definition string) error {
	query := fmt.Sprintf("SELECT COUNT(*) FROM pragma_table_info('request_log') WHERE name = '%s'", column)
	var count int
	if err := db.QueryRow(query).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		alter := fmt.Sprintf("ALTER TABLE request_log ADD COLUMN %s %s", column, definition)
		if _, err := db.Exec(alter); err != nil {
			return err
		}
	}
	return nil
}

func ensureRequestLogTable() error {
	db, err := xdb.DB("default")
	if err != nil {
		return err
	}
	return ensureRequestLogTableWithDB(db)
}

func ensureRequestLogTableWithDB(db *sql.DB) error {
	const createTableSQL = `CREATE TABLE IF NOT EXISTS request_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT,
		platform TEXT,
		model TEXT,
		provider TEXT,
		relay_key_id TEXT,
		http_code INTEGER,
		input_tokens INTEGER,
		output_tokens INTEGER,
		cache_create_tokens INTEGER,
		cache_read_tokens INTEGER,
		reasoning_tokens INTEGER,
		is_stream INTEGER DEFAULT 0,
		duration_sec REAL DEFAULT 0,
		upstream_header_sec REAL DEFAULT 0,
		first_event_sec REAL DEFAULT 0,
		first_text_sec REAL DEFAULT 0,
		error_message TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	if _, err := db.Exec(createTableSQL); err != nil {
		return err
	}

	if err := ensureRequestLogColumn(db, "created_at", "DATETIME DEFAULT CURRENT_TIMESTAMP"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "user_id", "TEXT"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "relay_key_id", "TEXT"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "is_stream", "INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "duration_sec", "REAL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "upstream_header_sec", "REAL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "first_event_sec", "REAL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "first_text_sec", "REAL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "error_message", "TEXT"); err != nil {
		return err
	}

	return nil
}

func ReqeustLogHook(c *gin.Context, kind string, usage *ReqeustLog) func(data []byte) (bool, []byte) { // SSE 钩子：累计字节和解析 token 用量
	return func(data []byte) (bool, []byte) {
		payload := strings.TrimSpace(string(data))

		parserFn := ClaudeCodeParseTokenUsageFromResponse
		switch kind {
		case "codex", "openai-responses":
			parserFn = CodexParseTokenUsageFromResponse
		case "openai-chat":
			parserFn = OpenAIChatParseTokenUsageFromResponse
		}
		parseEventPayload(payload, parserFn, usage)
		markFirstTextFromSSEPayload(payload, usage)

		return true, data
	}
}

func parseEventPayload(payload string, parser func(string, *ReqeustLog), usage *ReqeustLog) {
	lines := strings.Split(payload, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data:") {
			parser(strings.TrimPrefix(line, "data: "), usage)
		}
	}
}

func markFirstTextFromSSEPayload(payload string, usage *ReqeustLog) {
	if usage == nil || usage.FirstTextSec > 0 {
		return
	}
	lines := strings.Split(payload, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" || !json.Valid([]byte(data)) {
			continue
		}
		if ssePayloadHasText(data) {
			usage.markFirstText()
			return
		}
	}
}

func ssePayloadHasText(data string) bool {
	textPaths := []string{
		"delta.text",
		"content_block.text",
		"content.0.text",
		"choices.0.delta.content",
		"choices.0.message.content",
	}
	for _, path := range textPaths {
		if gjson.Get(data, path).String() != "" {
			return true
		}
	}

	content := gjson.Get(data, "content")
	if content.IsArray() {
		for _, item := range content.Array() {
			if item.Get("text").String() != "" {
				return true
			}
		}
	}
	return false
}

type ReqeustLog struct {
	ID                          int64   `json:"id"`
	UserID                      string  `json:"user_id"`
	Platform                    string  `json:"platform"` // claude、codex 或自定义 CLI
	Model                       string  `json:"model"`
	Provider                    string  `json:"provider"` // provider name
	RelayKeyID                  string  `json:"relay_key_id"`
	RelayKeyName                string  `json:"relay_key_name"`
	HttpCode                    int     `json:"http_code"`
	InputTokens                 int     `json:"input_tokens"`
	OutputTokens                int     `json:"output_tokens"`
	CacheCreateTokens           int     `json:"cache_create_tokens"`
	CacheReadTokens             int     `json:"cache_read_tokens"`
	ReasoningTokens             int     `json:"reasoning_tokens"`
	IsStream                    bool    `json:"is_stream"`
	DurationSec                 float64 `json:"duration_sec"`
	UpstreamHeaderSec           float64 `json:"upstream_header_sec"`
	FirstEventSec               float64 `json:"first_event_sec"`
	FirstTextSec                float64 `json:"first_text_sec"`
	ErrorMessage                string  `json:"error_message"`
	CreatedAt                   string  `json:"created_at"`
	startedAt                   time.Time
	inputTokensIncludeCacheRead bool
}

func (r *ReqeustLog) elapsedSinceStart() float64 {
	if r == nil || r.startedAt.IsZero() {
		return 0
	}
	return time.Since(r.startedAt).Seconds()
}

func (r *ReqeustLog) markUpstreamHeaders() {
	if r != nil && r.UpstreamHeaderSec == 0 {
		r.UpstreamHeaderSec = r.elapsedSinceStart()
	}
}

// isEmptyShell returns true if the response is an empty shell: all token counts are zero.
func (r *ReqeustLog) isEmptyShell() bool {
	if r == nil {
		return false
	}
	return r.InputTokens == 0 && r.OutputTokens == 0 && r.CacheReadTokens == 0 && r.CacheCreateTokens == 0 && r.ReasoningTokens == 0
}

// readResponseBody reads the full response body from a non-streaming response.
// Closes the underlying body after reading.
func readResponseBody(resp *xrequest.Response) ([]byte, error) {
	if resp == nil || resp.RawResponse == nil || resp.RawResponse.Body == nil {
		return nil, fmt.Errorf("empty response")
	}
	defer resp.RawResponse.Body.Close()
	data, err := io.ReadAll(resp.RawResponse.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// copyResponseHeaders copies upstream response headers to the client writer,
// filtering out hop-by-hop and content-length headers.
func copyResponseHeaders(w http.ResponseWriter, upstream http.Header) {
	for key, values := range upstream {
		lowerKey := strings.ToLower(key)
		switch lowerKey {
		case "content-length", "content-encoding", "transfer-encoding", "connection":
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
}

// parseNonStreamingTokens extracts token usage from a non-streaming response body
// and populates requestLog fields.
func parseNonStreamingTokens(body []byte, kind string, requestLog *ReqeustLog) {
	if requestLog == nil || len(body) == 0 {
		return
	}
	result := gjson.ParseBytes(body)

	// Try common usage paths
	usage := result.Get("usage")
	if usage.Exists() {
		requestLog.InputTokens = int(usage.Get("input_tokens").Int())
		requestLog.OutputTokens = int(usage.Get("output_tokens").Int())
		if ct := usage.Get("cache_read_input_tokens"); ct.Exists() {
			requestLog.CacheReadTokens = int(ct.Int())
		}
		if ct := usage.Get("cache_creation_input_tokens"); ct.Exists() {
			requestLog.CacheCreateTokens = int(ct.Int())
		}
		if rt := usage.Get("reasoning_tokens"); rt.Exists() {
			requestLog.ReasoningTokens = int(rt.Int())
		}
		return
	}

	// Anthropic Messages API format
	if result.Get("type").String() == "message" {
		requestLog.InputTokens = int(result.Get("usage.input_tokens").Int())
		requestLog.OutputTokens = int(result.Get("usage.output_tokens").Int())
		if ct := result.Get("usage.cache_read_input_tokens"); ct.Exists() {
			requestLog.CacheReadTokens = int(ct.Int())
		}
		return
	}
}

// hasContentInResponse checks whether a non-streaming response body contains actual
// text content, tool calls, or reasoning output — beyond just empty JSON structures.
func hasContentInResponse(body []byte, kind string) bool {
	if len(body) == 0 {
		return false
	}
	result := gjson.ParseBytes(body)

	// Anthropic Messages format
	if result.Get("type").String() == "message" {
		content := result.Get("content")
		if content.IsArray() && len(content.Array()) > 0 {
			for _, block := range content.Array() {
				t := block.Get("type").String()
				switch t {
				case "text":
					if strings.TrimSpace(block.Get("text").String()) != "" {
						return true
					}
				case "tool_use":
					return true
				}
			}
		}
		return false
	}

	// OpenAI Chat Completions format
	choices := result.Get("choices")
	if choices.IsArray() && len(choices.Array()) > 0 {
		for _, choice := range choices.Array() {
			msg := choice.Get("message")
			if strings.TrimSpace(msg.Get("content").String()) != "" {
				return true
			}
			if strings.TrimSpace(msg.Get("reasoning_content").String()) != "" {
				return true
			}
			if msg.Get("tool_calls").Exists() && len(msg.Get("tool_calls").Array()) > 0 {
				return true
			}
		}
		return false
	}

	// OpenAI Responses format
	output := result.Get("output")
	if output.IsArray() && len(output.Array()) > 0 {
		for _, item := range output.Array() {
			t := item.Get("type").String()
			switch t {
			case "message":
				for _, c := range item.Get("content").Array() {
					if strings.TrimSpace(c.Get("text").String()) != "" {
						return true
					}
				}
			case "function_call":
				return true
			case "reasoning":
				return true
			}
		}
		return false
	}

	// Unknown format: treat as having content (conservative)
	return true
}

func (r *ReqeustLog) markFirstEvent() {
	if r != nil && r.FirstEventSec == 0 {
		r.FirstEventSec = r.elapsedSinceStart()
	}
}

func (r *ReqeustLog) markFirstText() {
	if r != nil && r.FirstTextSec == 0 {
		r.FirstTextSec = r.elapsedSinceStart()
	}
}

// claude code usage parser
func ClaudeCodeParseTokenUsageFromResponse(data string, usage *ReqeustLog) {
	usage.InputTokens += int(gjson.Get(data, "message.usage.input_tokens").Int())
	usage.OutputTokens += int(gjson.Get(data, "message.usage.output_tokens").Int())
	usage.CacheCreateTokens += int(gjson.Get(data, "message.usage.cache_creation_input_tokens").Int())
	usage.CacheReadTokens += int(gjson.Get(data, "message.usage.cache_read_input_tokens").Int())

	usage.InputTokens += int(gjson.Get(data, "usage.input_tokens").Int())
	usage.OutputTokens += int(gjson.Get(data, "usage.output_tokens").Int())
	usage.CacheCreateTokens += int(gjson.Get(data, "usage.cache_creation_input_tokens").Int())
	cacheReadTokens := gjson.Get(data, "usage.cache_read_input_tokens").Int()
	if cacheReadTokens == 0 {
		cacheReadTokens = gjson.Get(data, "usage.input_tokens_details.cached_tokens").Int()
		if cacheReadTokens > 0 {
			usage.inputTokensIncludeCacheRead = true
		}
	}
	usage.CacheReadTokens += int(cacheReadTokens)
	usage.ReasoningTokens += int(gjson.Get(data, "usage.output_tokens_details.reasoning_tokens").Int())
}

// codex usage parser
func CodexParseTokenUsageFromResponse(data string, usage *ReqeustLog) {
	usage.InputTokens += int(gjson.Get(data, "response.usage.input_tokens").Int())
	usage.OutputTokens += int(gjson.Get(data, "response.usage.output_tokens").Int())
	usage.CacheReadTokens += int(gjson.Get(data, "response.usage.input_tokens_details.cached_tokens").Int())
	if usage.CacheReadTokens > 0 {
		usage.inputTokensIncludeCacheRead = true
	}
	usage.ReasoningTokens += int(gjson.Get(data, "response.usage.output_tokens_details.reasoning_tokens").Int())
}

func OpenAIChatParseTokenUsageFromResponse(data string, usage *ReqeustLog) {
	if usage == nil {
		return
	}
	usageResult := gjson.Get(data, "usage")
	if !usageResult.Exists() {
		return
	}

	usage.InputTokens += int(usageResult.Get("prompt_tokens").Int())
	usage.OutputTokens += int(usageResult.Get("completion_tokens").Int())
	cacheReadTokens := usageResult.Get("prompt_tokens_details.cached_tokens").Int()
	usage.CacheReadTokens += int(cacheReadTokens)
	if cacheReadTokens > 0 {
		usage.inputTokensIncludeCacheRead = true
	}
	usage.ReasoningTokens += int(usageResult.Get("completion_tokens_details.reasoning_tokens").Int())
}

func ensureOpenAIChatStreamUsage(bodyBytes []byte) []byte {
	if !json.Valid(bodyBytes) {
		return bodyBytes
	}
	if gjson.GetBytes(bodyBytes, "stream_options.include_usage").Bool() {
		return bodyBytes
	}
	updated, err := sjson.SetBytes(bodyBytes, "stream_options.include_usage", true)
	if err != nil {
		return bodyBytes
	}
	return updated
}

// ReplaceModelInRequestBody 替换请求体中的模型名
// 使用 gjson + sjson 实现高性能 JSON 操作，避免完整反序列化
func ReplaceModelInRequestBody(bodyBytes []byte, newModel string) ([]byte, error) {
	// 检查请求体中是否存在 model 字段
	result := gjson.GetBytes(bodyBytes, "model")
	if !result.Exists() {
		return bodyBytes, fmt.Errorf("请求体中未找到 model 字段")
	}

	// 使用 sjson.SetBytes 替换模型名（高性能操作）
	modified, err := sjson.SetBytes(bodyBytes, "model", newModel)
	if err != nil {
		return bodyBytes, fmt.Errorf("替换模型名失败: %w", err)
	}

	return modified, nil
}

// customCliProxyHandler 处理自定义 CLI 工具的 API 请求
// 路由格式: /custom/:toolId/v1/messages
// toolId 用于区分不同的 CLI 工具，对应 provider kind 为 "custom:{toolId}"
func (prs *ProviderRelayService) customCliProxyHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从 URL 参数提取 toolId
		toolId := c.Param("toolId")
		if toolId == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "toolId is required"})
			return
		}

		// 构建 provider kind（格式: "custom:{toolId}"）
		kind := "custom:" + toolId
		endpoint := "/v1/messages"
		// custom CLI 目前未实现 key -> pool 路由，仍使用固定 poolID 隔离。
		poolID := "pool_" + kind + "_default"

		fmt.Printf("[CustomCLI] 收到请求: toolId=%s, kind=%s\n", toolId, kind)

		// 读取请求体
		var bodyBytes []byte
		if c.Request.Body != nil {
			data, err := io.ReadAll(c.Request.Body)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
				return
			}
			bodyBytes = data
			c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		isStream := gjson.GetBytes(bodyBytes, "stream").Bool()
		requestedModel := gjson.GetBytes(bodyBytes, "model").String()

		if requestedModel == "" {
			fmt.Printf("[CustomCLI][WARN] 请求未指定模型名，无法执行模型智能降级\n")
		}

		// 加载该 CLI 工具的 providers
		providers, err := prs.providerService.LoadProviders(kind)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to load providers for %s: %v", kind, err)})
			return
		}

		// 过滤可用的 providers
		active := make([]Provider, 0, len(providers))
		skippedCount := 0
		for _, provider := range providers {
			if !provider.Enabled || provider.APIURL == "" || provider.APIKey == "" {
				continue
			}

			if errs := provider.ValidateConfiguration(); len(errs) > 0 {
				fmt.Printf("[CustomCLI][WARN] Provider %s 配置验证失败，已自动跳过: %v\n", provider.Name, errs)
				skippedCount++
				continue
			}

			if requestedModel != "" && !provider.IsModelSupported(requestedModel) {
				fmt.Printf("[CustomCLI][INFO] Provider %s 不支持模型 %s，已跳过\n", provider.Name, requestedModel)
				skippedCount++
				continue
			}

			active = append(active, provider)
		}

		if len(active) == 0 {
			if requestedModel != "" {
				c.JSON(http.StatusNotFound, gin.H{
					"error": fmt.Sprintf("没有可用的 provider 支持模型 '%s'（已跳过 %d 个不兼容的 provider）", requestedModel, skippedCount),
				})
			} else {
				c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("no providers available for %s", kind)})
			}
			return
		}

		fmt.Printf("[CustomCLI][INFO] 找到 %d 个可用的 provider（已过滤 %d 个）：", len(active), skippedCount)
		for _, p := range active {
			fmt.Printf("%s ", p.Name)
		}
		fmt.Println()

		// 按 Level 分组
		levelGroups := make(map[int][]Provider)
		for _, provider := range active {
			level := provider.Level
			if level <= 0 {
				level = 1
			}
			levelGroups[level] = append(levelGroups[level], provider)
		}

		levels := make([]int, 0, len(levelGroups))
		for level := range levelGroups {
			levels = append(levels, level)
		}
		sort.Ints(levels)

		fmt.Printf("[CustomCLI][INFO] 共 %d 个 Level 分组：%v\n", len(levels), levels)

		query := flattenQuery(c.Request.URL.Query())
		clientHeaders := cloneHeaders(c.Request.Header)

		// 【降级模式】：按 Level 顺序尝试
		fmt.Printf("[CustomCLI][INFO] 🔄 降级模式（顺序降级）\n")

		var lastError error
		var lastProvider string
		var lastDuration time.Duration
		totalAttempts := 0

		for _, level := range levels {
			providersInLevel := levelGroups[level]

			fmt.Printf("[CustomCLI][INFO] === 尝试 Level %d（%d 个 provider）===\n", level, len(providersInLevel))

			for i, provider := range providersInLevel {
				totalAttempts++

				effectiveModel := provider.GetEffectiveModel(requestedModel)
				currentBodyBytes := bodyBytes
				if effectiveModel != requestedModel && requestedModel != "" {
					fmt.Printf("[CustomCLI][INFO] Provider %s 映射模型: %s -> %s\n", provider.Name, requestedModel, effectiveModel)
					modifiedBody, err := ReplaceModelInRequestBody(bodyBytes, effectiveModel)
					if err != nil {
						fmt.Printf("[CustomCLI][ERROR] 替换模型名失败: %v\n", err)
						continue
					}
					currentBodyBytes = modifiedBody
				}

				fmt.Printf("[CustomCLI][INFO]   [%d/%d] Provider: %s | Model: %s\n", i+1, len(providersInLevel), provider.Name, effectiveModel)
				// 获取有效的端点（用户配置优先）
				effectiveEndpoint := provider.GetEffectiveEndpoint(endpoint)

				startTime := time.Now()
				ok, err := prs.forwardRequest(c, kind, provider, effectiveEndpoint, query, clientHeaders, currentBodyBytes, isStream, effectiveModel)
				duration := time.Since(startTime)

				if ok {
					fmt.Printf("[CustomCLI][INFO]   ✓ Level %d 成功: %s | 耗时: %.2fs\n", level, provider.Name, duration.Seconds())
					prs.setLastUsedProviderForUser(relayUserIDFromContext(c), kind, poolID, provider.Name)
					return
				}

				lastError = err
				lastProvider = provider.Name
				lastDuration = duration

				errorMsg := "未知错误"
				if err != nil {
					errorMsg = err.Error()
				}
				fmt.Printf("[CustomCLI][WARN]   ✗ Level %d 失败: %s | 错误: %s | 耗时: %.2fs\n",
					level, provider.Name, errorMsg, duration.Seconds())

				if errors.Is(err, errClientAbort) {
					fmt.Printf("[CustomCLI][INFO] 客户端中断，停止重试: %s\n", provider.Name)
					return
				}

				// 发送切换通知
				if prs.notificationService != nil {
					nextProvider := ""
					if i+1 < len(providersInLevel) {
						nextProvider = providersInLevel[i+1].Name
					} else {
						for _, nextLevel := range levels {
							if nextLevel > level && len(levelGroups[nextLevel]) > 0 {
								nextProvider = levelGroups[nextLevel][0].Name
								break
							}
						}
					}
					if nextProvider != "" {
						prs.notificationService.NotifyProviderSwitch(SwitchNotification{
							FromProvider: provider.Name,
							ToProvider:   nextProvider,
							Reason:       errorMsg,
							Platform:     kind,
						})
					}
				}
			}

			fmt.Printf("[CustomCLI][WARN] Level %d 的所有 %d 个 provider 均失败，尝试下一 Level\n", level, len(providersInLevel))
		}

		// 所有 provider 都失败
		errorMsg := "未知错误"
		if lastError != nil {
			errorMsg = lastError.Error()
		}
		fmt.Printf("[CustomCLI][ERROR] 所有 %d 个 provider 均失败，最后尝试: %s | 错误: %s\n",
			totalAttempts, lastProvider, errorMsg)

		c.JSON(http.StatusBadGateway, gin.H{
			"error":          fmt.Sprintf("所有 %d 个 provider 均失败，最后错误: %s", totalAttempts, errorMsg),
			"last_provider":  lastProvider,
			"last_duration":  fmt.Sprintf("%.2fs", lastDuration.Seconds()),
			"total_attempts": totalAttempts,
		})
	}
}

// forwardModelsRequest 共享的 /v1/models 请求转发逻辑
// 返回 (selectedProvider, error)
func (prs *ProviderRelayService) forwardModelsRequest(
	c *gin.Context,
	kind string,
	logPrefix string,
) error {
	fmt.Printf("[%s] 收到 /v1/models 请求, kind=%s\n", logPrefix, kind)

	// 加载 providers
	userID := relayUserIDFromContext(c)
	var providers []Provider
	var err error
	if strings.TrimSpace(userID) != "" {
		providers, err = prs.providerService.LoadProvidersForUser(userID, kind)
	} else {
		providers, err = prs.providerService.LoadProviders(kind)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load providers"})
		return fmt.Errorf("failed to load providers: %w", err)
	}

	// 过滤可用的 providers（托管模式启用 + URL + APIKey）
	requireProviderEnabled := prs.shouldRequireProviderEnabled(kind)
	directAppliedProviderID, requireDirectAppliedProvider := prs.codexDirectAppliedProviderFilter(kind, requireProviderEnabled)
	var activeProviders []Provider
	for _, provider := range providers {
		if (requireProviderEnabled && !provider.Enabled) || provider.APIURL == "" || provider.APIKey == "" {
			continue
		}
		if requireDirectAppliedProvider && directAppliedProviderID == nil {
			continue
		}
		if directAppliedProviderID != nil && provider.ID != *directAppliedProviderID {
			continue
		}

		activeProviders = append(activeProviders, provider)
	}

	if len(activeProviders) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no providers available"})
		return fmt.Errorf("no providers available")
	}

	// 按 Level 分组并排序
	levelGroups := make(map[int][]Provider)
	for _, provider := range activeProviders {
		level := provider.Level
		if level <= 0 {
			level = 1
		}
		levelGroups[level] = append(levelGroups[level], provider)
	}

	levels := make([]int, 0, len(levelGroups))
	for level := range levelGroups {
		levels = append(levels, level)
	}
	sort.Ints(levels)

	// 尝试第一个可用的 provider（按 Level 升序）
	var selectedProvider *Provider
	for _, level := range levels {
		if len(levelGroups[level]) > 0 {
			p := levelGroups[level][0]
			selectedProvider = &p
			break
		}
	}

	if selectedProvider == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no providers available"})
		return fmt.Errorf("no providers available after filtering")
	}

	fmt.Printf("[%s] 使用 Provider: %s | URL: %s\n", logPrefix, selectedProvider.Name, selectedProvider.APIURL)

	// 构建目标 URL（拼接 provider 的 APIURL 和 /v1/models）
	targetURL := joinURL(selectedProvider.APIURL, "/v1/models")

	// 创建 HTTP 请求
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("创建请求失败: %v", err)})
		return fmt.Errorf("failed to create request: %w", err)
	}

	// 复制客户端请求头
	for key, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// 根据认证方式设置请求头（默认 Bearer，与 v2.2.x 保持一致）
	authType := strings.ToLower(strings.TrimSpace(selectedProvider.ConnectivityAuthType))
	switch authType {
	case "x-api-key":
		req.Header.Set("x-api-key", selectedProvider.APIKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	case "", "bearer":
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", selectedProvider.APIKey))
	default:
		headerName := strings.TrimSpace(selectedProvider.ConnectivityAuthType)
		if headerName == "" || strings.EqualFold(headerName, "custom") {
			headerName = "Authorization"
		}
		req.Header.Set(headerName, selectedProvider.APIKey)
	}

	// 设置默认 Accept 头
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}

	// 发送请求
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[%s] ✗ 请求失败: %s | 错误: %v\n", logPrefix, selectedProvider.Name, err)
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("请求失败: %v", err)})
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[%s] ✗ 读取响应失败: %s | 错误: %v\n", logPrefix, selectedProvider.Name, err)
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("读取响应失败: %v", err)})
		return fmt.Errorf("failed to read response: %w", err)
	}

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	fmt.Printf("[%s] ✓ 成功: %s | HTTP %d\n", logPrefix, selectedProvider.Name, resp.StatusCode)

	// 返回响应
	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
	return nil
}

// modelsHandler 处理 /v1/models 请求（OpenAI-compatible API）
// 将请求转发到第一个可用的 provider 并注入 API Key
func (prs *ProviderRelayService) modelsHandler(kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		_ = prs.forwardModelsRequest(c, kind, "Models")
	}
}

// customModelsHandler 处理自定义 CLI 工具的 /v1/models 请求
// 路由格式: /custom/:toolId/v1/models
func (prs *ProviderRelayService) customModelsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从 URL 参数提取 toolId
		toolId := c.Param("toolId")
		if toolId == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "toolId is required"})
			return
		}

		// 构建 provider kind（格式: "custom:{toolId}"）
		kind := "custom:" + toolId

		_ = prs.forwardModelsRequest(c, kind, "CustomModels")
	}
}

// estimateInputTokens 在本地估算 Anthropic Messages 请求的输入 token 数。
// 用于上游不支持 /v1/messages/count_tokens 的场景。
// 中文按每字 1 token，英文按每 4 字符 1 token。
func estimateInputTokens(bodyBytes []byte) int {
	var body struct {
		System   interface{}     `json:"system"`
		Messages []interface{}   `json:"messages"`
		Tools    json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		return 100
	}

	var totalChars int
	var cjkCount int

	extractText := func(v interface{}) string {
		if v == nil {
			return ""
		}
		switch val := v.(type) {
		case string:
			return val
		case []interface{}:
			var parts []string
			for _, item := range val {
				if s, ok := item.(string); ok {
					parts = append(parts, s)
				} else if m, ok := item.(map[string]interface{}); ok {
					if t, ok := m["type"].(string); ok && t == "text" {
						parts = append(parts, fmt.Sprint(m["text"]))
					}
				}
			}
			return strings.Join(parts, "\n")
		default:
			return fmt.Sprint(v)
		}
	}

	systemText := extractText(body.System)
	for _, ch := range systemText {
		if ch >= 0x4e00 && ch <= 0x9fff {
			cjkCount++
		}
		totalChars += len(string(ch))
	}

	for _, raw := range body.Messages {
		if m, ok := raw.(map[string]interface{}); ok {
			txt := fmt.Sprint(m["role"]) + "\n" + extractText(m["content"])
			for _, ch := range txt {
				if ch >= 0x4e00 && ch <= 0x9fff {
					cjkCount++
				}
				totalChars += len(string(ch))
			}
		}
	}

	if body.Tools != nil {
		totalChars += len(body.Tools)
	}

	otherCount := totalChars - cjkCount
	if otherCount < 0 {
		otherCount = 0
	}
	estimated := cjkCount + (otherCount / 4) + 20
	if estimated < 1 {
		estimated = 1
	}
	return estimated
}

// ========== RPC 方法：池子拉黑状态查询和清除 ==========

// ListProviderBlacklistStatus 返回指定池子内所有 provider 的拉黑状态（供前端展示）
func (prs *ProviderRelayService) ListProviderBlacklistStatus(platform, poolID string) []ProviderPoolProviderPenalty {
	return prs.listProviderBlacklistStatus(platform, poolID)
}

// ListProviderBlacklistStatusForUser 返回指定用户池子内所有 provider 的拉黑状态。
func (prs *ProviderRelayService) ListProviderBlacklistStatusForUser(userID, platform, poolID string) []ProviderPoolProviderPenalty {
	return prs.listProviderBlacklistStatusForUser(userID, platform, poolID)
}

// ClearProviderBlacklist 手动清除指定池子内某个 provider 的拉黑状态
func (prs *ProviderRelayService) ClearProviderBlacklist(platform, poolID string, providerID int64) {
	prs.clearProviderBlacklist(platform, poolID, providerID)
}

// ClearProviderBlacklistForUser 手动清除指定用户池子内某个 provider 的拉黑状态。
func (prs *ProviderRelayService) ClearProviderBlacklistForUser(userID, platform, poolID string, providerID int64) {
	prs.clearProviderBlacklistForUser(userID, platform, poolID, providerID)
}
