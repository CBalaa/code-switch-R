package main

import (
	"codeswitch/services"
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

type authenticatedUserContextKey struct{}

func contextWithAuthenticatedUser(ctx context.Context, user *services.AuthenticatedUser) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if user == nil {
		return ctx
	}
	return context.WithValue(ctx, authenticatedUserContextKey{}, user)
}

func authenticatedUserFromContext(ctx context.Context) (*services.AuthenticatedUser, error) {
	user, _ := ctx.Value(authenticatedUserContextKey{}).(*services.AuthenticatedUser)
	if user == nil || strings.TrimSpace(user.ID) == "" {
		return nil, errors.New("authenticated user missing")
	}
	return user, nil
}

type userScopedProviderService struct {
	base *services.ProviderService
}

func (s *userScopedProviderService) LoadProviders(ctx context.Context, kind string) ([]services.Provider, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.LoadProvidersForUser(user.ID, kind)
}

func (s *userScopedProviderService) SaveProviders(ctx context.Context, kind string, providers []services.Provider) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	return s.base.SaveProvidersForUser(user.ID, kind, providers)
}

func (s *userScopedProviderService) DuplicateProvider(ctx context.Context, kind string, sourceID int64) (*services.Provider, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.DuplicateProviderForUser(user.ID, kind, sourceID)
}

// userScopedModelTraceService 把模型真伪检测限定在调用者租户内：
// provider 读取用 userID 隔离，进度/流式事件带上 userID 由 SSE 层过滤。
type userScopedModelTraceService struct {
	base *services.ModelTraceService
}

func (s *userScopedModelTraceService) GetSupportedModels(ctx context.Context) ([]services.ModelTraceModelOption, error) {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return nil, err
	}
	return s.base.GetSupportedModels()
}

func (s *userScopedModelTraceService) VerifyProviderModel(
	ctx context.Context,
	platform string,
	providerID int64,
	expectedModel string,
) services.ModelTraceResult {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return services.ModelTraceResult{Verdict: "error", Message: "登录状态已失效，请重新登录后再试"}
	}
	return s.base.VerifyProviderModel(user.ID, platform, providerID, expectedModel)
}

// userScopedConnectivityTestService 把可用性检测里涉及 provider 的读写限定在调用者租户内。
// 手动探测类方法由前端直接传入 apiURL/apiKey，本来就不读 provider 文件，原样透传。
type userScopedConnectivityTestService struct {
	base *services.ConnectivityTestService
}

func (s *userScopedConnectivityTestService) TestAll(ctx context.Context, platform string) ([]services.ConnectivityResult, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.TestAllForUser(user.ID, platform), nil
}

func (s *userScopedConnectivityTestService) RunSingleTest(ctx context.Context, platform string, providerID int64) (*services.ConnectivityResult, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.RunSingleTestForUser(user.ID, platform, providerID)
}

func (s *userScopedConnectivityTestService) GetResults(ctx context.Context, platform string) ([]services.ConnectivityResult, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.GetResultsForUser(user.ID, platform)
}

func (s *userScopedConnectivityTestService) GetAllResults(ctx context.Context) (map[string][]services.ConnectivityResult, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.GetAllResultsForUser(user.ID)
}

// TestProvider 直接对传入的 provider 配置执行一次探测，不读供应商文件，原样透传。
// 保留它是为了不缩小原有的 RPC 表面（它过去是可达的）。
func (s *userScopedConnectivityTestService) TestProvider(ctx context.Context, provider services.Provider, platform string) *services.ConnectivityResult {
	return s.base.TestProvider(ctx, provider, platform)
}

// Start / Stop 是运行时生命周期钩子，同样保留以免 RPC 表面缩水。
func (s *userScopedConnectivityTestService) Start() error { return s.base.Start() }
func (s *userScopedConnectivityTestService) Stop() error  { return s.base.Stop() }

func (s *userScopedConnectivityTestService) TestProviderManual(
	platform string,
	apiURL string,
	apiKey string,
	model string,
	endpoint string,
	authType string,
) services.ManualTestResult {
	return s.base.TestProviderManual(platform, apiURL, apiKey, model, endpoint, authType)
}

func (s *userScopedConnectivityTestService) TestProviderManualWithMessage(
	platform string,
	apiURL string,
	apiKey string,
	model string,
	endpoint string,
	authType string,
	testMessage string,
) services.ManualTestResult {
	return s.base.TestProviderManualWithMessage(platform, apiURL, apiKey, model, endpoint, authType, testMessage)
}

func (s *userScopedConnectivityTestService) TestModelsEndpointManual(
	apiURL string,
	apiKey string,
	modelsEndpoint string,
	authType string,
	platform string,
) services.ManualTestResult {
	return s.base.TestModelsEndpointManual(apiURL, apiKey, modelsEndpoint, authType, platform)
}

func (s *userScopedConnectivityTestService) ListModelsEndpointManual(
	apiURL string,
	apiKey string,
	modelsEndpoint string,
	authType string,
	platform string,
) (*services.ProviderModelList, error) {
	return s.base.ListModelsEndpointManual(apiURL, apiKey, modelsEndpoint, authType, platform)
}

// SetAutoTestEnabled / GetAutoTestEnabled 是全局后台巡检开关（非租户数据），保持透传。
func (s *userScopedConnectivityTestService) SetAutoTestEnabled(enabled bool) error {
	return s.base.SetAutoTestEnabled(enabled)
}

func (s *userScopedConnectivityTestService) GetAutoTestEnabled() bool {
	return s.base.GetAutoTestEnabled()
}

type userScopedProviderPoolService struct {
	base         *services.ProviderPoolService
	proxyService *services.ProxyService
}

type userScopedProxyService struct {
	base        *services.ProxyService
	poolService *services.ProviderPoolService
	userStore   *services.UserStore
}

func (s *userScopedProxyService) ListProxyConfigs(ctx context.Context) ([]services.ProxyConfigSummary, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.ListProxyConfigsForUser(user.ID)
}

func (s *userScopedProxyService) UploadProxyConfig(ctx context.Context, fileName string, content string) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	return s.base.UploadProxyConfigForUser(fileName, content, user.ID, user.Username)
}

func (s *userScopedProxyService) ImportProxySubscription(ctx context.Context, subscriptionURL string, configName string) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	return s.base.ImportProxySubscriptionForUser(ctx, subscriptionURL, configName, user.ID, user.Username)
}

func (s *userScopedProxyService) RefreshProxyConfigs(ctx context.Context) ([]services.ProxyConfigSummary, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.base.RefreshProxyConfigs(); err != nil {
		return nil, err
	}
	return s.base.ListProxyConfigsForUser(user.ID)
}

func (s *userScopedProxyService) ListHiddenProxyConfigs(ctx context.Context) ([]services.ProxyConfigSummary, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.ListHiddenProxyConfigsForUser(user.ID)
}

func (s *userScopedProxyService) HideProxyConfig(ctx context.Context, configID string) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	return s.base.HideProxyConfigForUser(user.ID, configID)
}

func (s *userScopedProxyService) UnhideProxyConfig(ctx context.Context, configID string) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	return s.base.UnhideProxyConfigForUser(user.ID, configID)
}

func (s *userScopedProxyService) DeleteProxyConfig(ctx context.Context, configID string) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	if s.userStore == nil || s.poolService == nil {
		return errors.New("代理配置删除服务未初始化")
	}
	return s.base.DeleteProxyConfigForUser(user.ID, configID, s.ensureProxyConfigDeletionSafe)
}

func (s *userScopedProxyService) ensureProxyConfigDeletionSafe(nodeIDs []string, remainingNodeCount int) error {
	users, err := s.userStore.ListUsers()
	if err != nil {
		return fmt.Errorf("检查号池代理引用失败: %w", err)
	}
	nodes := make(map[string]struct{}, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		nodes[nodeID] = struct{}{}
	}
	for _, user := range users {
		pools, err := s.poolService.ListAllPoolsForUser(user.ID)
		if err != nil {
			return fmt.Errorf("检查号池代理引用失败: %w", err)
		}
		for _, pool := range pools {
			if services.ProviderPoolType(strings.TrimSpace(string(pool.PoolType))) != services.ProviderPoolTypeAccount || pool.ProxyConfig == nil || !pool.ProxyConfig.Enabled {
				continue
			}
			switch pool.ProxyConfig.Selection {
			case services.AccountPoolProxySelectionNode:
				if _, used := nodes[strings.TrimSpace(pool.ProxyConfig.ProxyNodeID)]; used {
					return errors.New("该代理配置正在被号池固定节点使用，无法删除")
				}
			case "", services.AccountPoolProxySelectionAuto:
				if remainingNodeCount == 0 {
					return errors.New("该代理配置是号池自动选择的最后一个可用节点，无法删除")
				}
			}
		}
	}
	return nil
}

func (s *userScopedProxyService) TestProxy(ctx context.Context, poolID string, nodeID string, responsesURL string) (services.ProxySpeedTestResult, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return services.ProxySpeedTestResult{}, err
	}
	poolID = strings.TrimSpace(poolID)
	autoSelectionURL := ""
	if poolID != "" {
		pool, err := s.poolService.GetPoolForUser(user.ID, poolID)
		if err != nil {
			return services.ProxySpeedTestResult{}, err
		}
		if pool == nil || pool.PoolType != services.ProviderPoolTypeAccount {
			return services.ProxySpeedTestResult{}, errors.New("号池不存在或不是号池模式")
		}
		if pool.AccountPoolConfig != nil {
			autoSelectionURL = pool.AccountPoolConfig.APIURL
		}
	}
	return s.base.TestProxyForUser(ctx, user.ID, poolID, strings.TrimSpace(nodeID), strings.TrimSpace(responsesURL), autoSelectionURL), nil
}

// GetProxySpeedTests returns the shared latest Responses measurements.
// poolID is checked only when this is an existing pool; create-pool preview
// remains supported without exposing any hidden proxy nodes.
func (s *userScopedProxyService) GetProxySpeedTests(ctx context.Context, poolID string, responsesURL string) (services.ProxySpeedTestSnapshot, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return services.ProxySpeedTestSnapshot{}, err
	}
	poolID = strings.TrimSpace(poolID)
	if poolID != "" {
		pool, err := s.poolService.GetPoolForUser(user.ID, poolID)
		if err != nil {
			return services.ProxySpeedTestSnapshot{}, err
		}
		if pool == nil || pool.PoolType != services.ProviderPoolTypeAccount {
			return services.ProxySpeedTestSnapshot{}, errors.New("号池不存在或不是号池模式")
		}
	}
	return s.base.SharedProxySpeedTestsForUser(user.ID, strings.TrimSpace(responsesURL))
}

// TestAllProxyLatencies performs controller health checks for every proxy node
// visible to the authenticated user. poolID is authorization-only: an empty ID
// supports the create-pool preview and never creates a runtime listener.
func (s *userScopedProxyService) TestAllProxyLatencies(ctx context.Context, poolID string) ([]services.ProxyNodeLatencyResult, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	poolID = strings.TrimSpace(poolID)
	if poolID != "" {
		pool, err := s.poolService.GetPoolForUser(user.ID, poolID)
		if err != nil {
			return nil, err
		}
		if pool == nil || pool.PoolType != services.ProviderPoolTypeAccount {
			return nil, errors.New("号池不存在或不是号池模式")
		}
	}
	return s.base.TestAllProxyLatenciesForUser(ctx, user.ID)
}

func (s *userScopedProviderPoolService) ListPools(ctx context.Context, platform string) ([]services.ProviderPool, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.ListPoolsForUser(user.ID, platform)
}

func (s *userScopedProviderPoolService) ListAllPools(ctx context.Context) ([]services.ProviderPool, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.ListAllPoolsForUser(user.ID)
}

func (s *userScopedProviderPoolService) GetPool(ctx context.Context, poolID string) (*services.ProviderPool, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.GetPoolForUser(user.ID, poolID)
}

func (s *userScopedProviderPoolService) SavePool(ctx context.Context, pool *services.ProviderPool) (string, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return "", err
	}
	var id string
	if s.proxyService != nil {
		err = s.proxyService.WithCatalogOperation(func() error {
			if pool != nil && services.ProviderPoolType(strings.TrimSpace(string(pool.PoolType))) == services.ProviderPoolTypeAccount {
				if normalizeErr := s.proxyService.NormalizePoolProxyConfigForUserInOperation(user.ID, pool.ProxyConfig); normalizeErr != nil {
					return normalizeErr
				}
			}
			var saveErr error
			id, saveErr = s.base.SavePoolForUser(user.ID, pool)
			return saveErr
		})
	} else {
		id, err = s.base.SavePoolForUser(user.ID, pool)
	}
	if err != nil {
		return "", err
	}
	if s.proxyService != nil {
		baseURL := ""
		if pool.AccountPoolConfig != nil {
			baseURL = pool.AccountPoolConfig.APIURL
		}
		if err := s.proxyService.SyncPoolProxyWithBaseURL(user.ID, id, pool.ProxyConfig, baseURL); err != nil {
			log.Printf("同步号池代理 listener 失败（池子已保存）: %v", err)
		}
	}
	return id, nil
}

func (s *userScopedProviderPoolService) DeletePool(ctx context.Context, poolID string) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	if err := s.base.DeletePoolForUser(user.ID, poolID); err != nil {
		return err
	}
	if s.proxyService != nil {
		if err := s.proxyService.SyncPoolProxy(user.ID, poolID, nil); err != nil {
			log.Printf("清理号池代理 listener 失败（池子已删除）: %v", err)
		}
	}
	return nil
}

type userScopedCodexRelayKeyService struct {
	base        *services.CodexRelayKeyService
	poolService *services.ProviderPoolService
}

func (s *userScopedCodexRelayKeyService) GetPoolBinding(ctx context.Context, keyID string, platform string) (string, bool, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return "", false, err
	}
	return s.base.GetPoolBindingForUser(user.ID, keyID, platform)
}

func (s *userScopedCodexRelayKeyService) ListKeys(ctx context.Context) ([]services.CodexRelayKeyListItem, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.ListKeysForUser(user.ID)
}

func (s *userScopedCodexRelayKeyService) SetPoolBinding(ctx context.Context, keyID string, platform string, poolID string) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	poolID = strings.TrimSpace(poolID)
	if poolID != "" {
		pool, err := s.poolService.GetPoolForUser(user.ID, poolID)
		if err != nil {
			return err
		}
		if pool == nil || pool.Platform != platform {
			return errors.New("池子不存在或不属于当前用户")
		}
	}
	return s.base.SetPoolBindingForUser(user.ID, keyID, platform, poolID)
}

type userScopedLogService struct {
	base *services.LogService
}

type userScopedTrafficService struct {
	base *services.TrafficService
}

func (s *userScopedTrafficService) Today(ctx context.Context) (services.TrafficSummary, error) {
	if s == nil || s.base == nil {
		return services.TrafficSummary{}, errors.New("流量统计服务不可用")
	}
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return services.TrafficSummary{}, err
	}
	return s.base.SummaryTodayForUser(user.ID)
}

func (s *userScopedLogService) ListActiveRequestLogs(ctx context.Context) ([]services.ReqeustLog, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.ListActiveRequestLogsForUser(user.ID)
}

func (s *userScopedLogService) ListCompletedRequestLogs(ctx context.Context, afterID int64, limit int) ([]services.ReqeustLog, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.ListCompletedRequestLogsForUser(user.ID, afterID, limit)
}

func (s *userScopedLogService) RetryActiveRequest(ctx context.Context, id int64) (services.ActiveRequestRetryResult, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return services.ActiveRequestRetryResult{}, err
	}
	return s.base.RetryActiveRequestForUser(user.ID, id), nil
}

func (s *userScopedLogService) StatsSince(ctx context.Context, platform string) (services.LogStats, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return services.LogStats{}, err
	}
	return s.base.StatsSinceForUser(user.ID, platform)
}

func (s *userScopedLogService) ProviderDailyStats(ctx context.Context, platform string) ([]services.ProviderDailyStat, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.ProviderDailyStatsForUser(user.ID, platform)
}

type userScopedCostService struct {
	base        *services.CostService
	poolService *services.ProviderPoolService
}

func (s *userScopedCostService) TodayUsage(ctx context.Context, platform string, provider string) ([]services.CostUsageItem, error) {
	if s == nil || s.base == nil {
		return []services.CostUsageItem{}, nil
	}
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	items, err := s.base.TodayUsageForUser(user.ID, platform, "")
	if err != nil || s.poolService == nil {
		return items, err
	}
	pools, err := s.poolService.ListAllPoolsForUser(user.ID)
	if err != nil {
		return nil, err
	}
	return aggregateCostUsageByAccountPool(items, pools, strings.TrimSpace(provider)), nil
}

func aggregateCostUsageByAccountPool(items []services.CostUsageItem, pools []services.ProviderPool, providerFilter string) []services.CostUsageItem {
	poolNameByAccountProvider := make(map[string]string)
	for _, pool := range pools {
		if pool.PoolType != services.ProviderPoolTypeAccount || pool.AccountPoolConfig == nil {
			continue
		}
		poolName := strings.TrimSpace(pool.Name)
		if poolName == "" {
			continue
		}
		for _, key := range pool.AccountPoolConfig.Keys {
			poolNameByAccountProvider[services.AccountPoolKeyDisplayName(key)] = poolName
		}
	}

	merged := make(map[string]services.CostUsageItem)
	for _, item := range items {
		if poolName, ok := poolNameByAccountProvider[item.Provider]; ok {
			item.Provider = poolName
		}
		if providerFilter != "" && item.Provider != providerFilter {
			continue
		}
		key := item.Platform + "\x00" + item.Provider + "\x00" + item.Model
		current := merged[key]
		current.Platform = item.Platform
		current.Provider = item.Provider
		current.Model = item.Model
		current.TotalRequests += item.TotalRequests
		current.InputTokens += item.InputTokens
		current.OutputTokens += item.OutputTokens
		current.CacheCreateTokens += item.CacheCreateTokens
		current.CacheReadTokens += item.CacheReadTokens
		current.ReasoningTokens += item.ReasoningTokens
		merged[key] = current
	}

	result := make([]services.CostUsageItem, 0, len(merged))
	for _, item := range merged {
		result = append(result, item)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Platform != result[right].Platform {
			return result[left].Platform < result[right].Platform
		}
		if result[left].Provider != result[right].Provider {
			return result[left].Provider < result[right].Provider
		}
		return result[left].Model < result[right].Model
	})
	return result
}

func (s *userScopedCostService) GetSettings(ctx context.Context) (services.CostSettings, error) {
	if s == nil || s.base == nil {
		return services.CostSettings{}, nil
	}
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return services.CostSettings{}, err
	}
	return s.base.GetSettingsForUser(user.ID)
}

func (s *userScopedCostService) SaveSettings(ctx context.Context, settings services.CostSettings) (services.CostSettings, error) {
	if s == nil || s.base == nil {
		return settings, nil
	}
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return settings, err
	}
	return s.base.SaveSettingsForUser(user.ID, settings)
}

func (s *userScopedCostService) ResetProviderMultiplier(ctx context.Context, platform string, provider string) error {
	if s == nil || s.base == nil {
		return nil
	}
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	return s.base.ResetProviderMultiplierForUser(user.ID, platform, provider)
}

func (s *userScopedCostService) ResetModelOverride(ctx context.Context, platform string, provider string, model string) error {
	if s == nil || s.base == nil {
		return nil
	}
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	return s.base.ResetModelOverrideForUser(user.ID, platform, provider, model)
}

type userScopedHealthCheckService struct {
	base *services.HealthCheckService
}

func (s *userScopedHealthCheckService) GetLatestResults(ctx context.Context) (map[string][]services.ProviderTimeline, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.GetLatestResultsForUser(user.ID)
}

func (s *userScopedHealthCheckService) GetHistory(ctx context.Context, platform string, providerName string, limit int) (*services.HealthCheckHistory, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.GetHistoryForUser(user.ID, platform, providerName, limit)
}

func (s *userScopedHealthCheckService) RunSingleCheck(ctx context.Context, platform string, providerID int64) (*services.HealthCheckResult, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.RunSingleCheckForUser(user.ID, platform, providerID)
}

func (s *userScopedHealthCheckService) RunAllChecks(ctx context.Context) (map[string][]services.HealthCheckResult, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.RunAllChecksForUser(user.ID)
}

func (s *userScopedHealthCheckService) StartBackgroundPolling(ctx context.Context) {
	s.base.StartBackgroundPolling()
}

func (s *userScopedHealthCheckService) StopBackgroundPolling(ctx context.Context) {
	s.base.StopBackgroundPolling()
}

func (s *userScopedHealthCheckService) IsPollingRunning(ctx context.Context) bool {
	return s.base.IsPollingRunning()
}

func (s *userScopedHealthCheckService) SetAvailabilityMonitorEnabled(ctx context.Context, platform string, providerID int64, enabled bool) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	return s.base.SetAvailabilityMonitorEnabledForUser(user.ID, platform, providerID, enabled)
}

func (s *userScopedHealthCheckService) SaveAvailabilityConfig(ctx context.Context, platform string, providerID int64, config *services.AvailabilityConfig) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	return s.base.SaveAvailabilityConfigForUser(user.ID, platform, providerID, config)
}

func (s *userScopedHealthCheckService) CleanupOldRecords(ctx context.Context, daysToKeep int) (int64, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return 0, err
	}
	return s.base.CleanupOldRecordsForUser(user.ID, daysToKeep)
}

func (s *userScopedHealthCheckService) SetAutoAvailabilityPolling(ctx context.Context, enabled bool) {
	s.base.SetAutoAvailabilityPolling(enabled)
}

type userScopedModelMonitorService struct {
	base *services.ModelMonitorService
}

func (s *userScopedModelMonitorService) ListTargets(ctx context.Context) ([]services.ModelMonitorTarget, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.ListTargetsForUser(user.ID)
}

func (s *userScopedModelMonitorService) ListTimelines(ctx context.Context) ([]services.ModelMonitorTimeline, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.ListTimelinesForUser(user.ID)
}

func (s *userScopedModelMonitorService) SaveTarget(ctx context.Context, target services.ModelMonitorTarget) (*services.ModelMonitorTarget, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.SaveTargetForUser(user.ID, target)
}

func (s *userScopedModelMonitorService) DeleteTarget(ctx context.Context, targetID int64) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	return s.base.DeleteTargetForUser(user.ID, targetID)
}

func (s *userScopedModelMonitorService) RunTargetCheck(ctx context.Context, targetID int64) (*services.ModelMonitorResult, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.RunTargetCheckForUser(user.ID, targetID)
}

func (s *userScopedModelMonitorService) RunAllChecks(ctx context.Context) ([]services.ModelMonitorResult, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.RunAllChecksForUser(user.ID)
}

func (s *userScopedModelMonitorService) ListProviderModels(ctx context.Context, platform string, providerID int64) (*services.ProviderModelList, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.ListProviderModelsForUser(user.ID, platform, providerID)
}

type userScopedProviderRelayService struct {
	base        *services.ProviderRelayService
	poolService *services.ProviderPoolService
}

func (s *userScopedProviderRelayService) GetAllLastUsedProviders(ctx context.Context) ([]*services.LastUsedProvider, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.GetAllLastUsedProvidersForUser(user.ID), nil
}

func (s *userScopedProviderRelayService) ListProviderBlacklistStatus(ctx context.Context, platform string, poolID string) ([]services.ProviderPoolProviderPenalty, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.requireUserPool(user.ID, platform, poolID); err != nil {
		return nil, err
	}
	return s.base.ListProviderBlacklistStatusForUser(user.ID, platform, poolID), nil
}

func (s *userScopedProviderRelayService) ClearProviderBlacklist(ctx context.Context, platform string, poolID string, providerID int64) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	if err := s.requireUserPool(user.ID, platform, poolID); err != nil {
		return err
	}
	s.base.ClearProviderBlacklistForUser(user.ID, platform, poolID, providerID)
	return nil
}

func (s *userScopedProviderRelayService) ClearAllProviderBlacklists(ctx context.Context, platform string, poolID string) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}

	pool, err := s.poolService.GetPoolForUser(user.ID, strings.TrimSpace(poolID))
	if err != nil {
		return err
	}
	if pool == nil || pool.Platform != platform {
		return errors.New("池子不存在或不属于当前用户")
	}
	if pool.PoolType != services.ProviderPoolTypeAccount || pool.AccountPoolConfig == nil {
		return errors.New("仅号池支持批量清除拉黑")
	}

	s.base.ClearAllProviderBlacklistsForUser(user.ID, platform, poolID)
	return nil
}

func (s *userScopedProviderRelayService) requireUserPool(userID string, platform string, poolID string) error {
	pool, err := s.poolService.GetPoolForUser(userID, strings.TrimSpace(poolID))
	if err != nil {
		return err
	}
	if pool == nil || pool.Platform != platform {
		return errors.New("池子不存在或不属于当前用户")
	}
	return nil
}

type userScopedClaudeSettingsService struct {
	base *services.ClaudeSettingsService
}

func (s *userScopedClaudeSettingsService) ProxyStatus(ctx context.Context) (services.ClaudeProxyStatus, error) {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return services.ClaudeProxyStatus{}, err
	}
	return s.base.ProxyStatus()
}

func (s *userScopedClaudeSettingsService) EnableProxy(ctx context.Context) error {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return err
	}
	return errors.New("多用户 Web 模式不支持修改服务器 Claude CLI 代理配置")
}

func (s *userScopedClaudeSettingsService) DisableProxy(ctx context.Context) error {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return err
	}
	return errors.New("多用户 Web 模式不支持修改服务器 Claude CLI 代理配置")
}

func (s *userScopedClaudeSettingsService) ApplySingleProvider(ctx context.Context, providerID int) error {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return err
	}
	return errors.New("多用户 Web 模式不支持直接应用服务器 Claude CLI provider")
}

func (s *userScopedClaudeSettingsService) GetDirectAppliedProviderID(ctx context.Context) (*int64, error) {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return nil, err
	}
	return nil, nil
}

type userScopedCodexSettingsService struct {
	base *services.CodexSettingsService
}

func (s *userScopedCodexSettingsService) ProxyStatus(ctx context.Context) (services.ClaudeProxyStatus, error) {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return services.ClaudeProxyStatus{}, err
	}
	return s.base.ProxyStatus()
}

func (s *userScopedCodexSettingsService) EnableProxy(ctx context.Context) error {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return err
	}
	return errors.New("多用户 Web 模式不支持修改服务器 Codex CLI 代理配置")
}

func (s *userScopedCodexSettingsService) DisableProxy(ctx context.Context) error {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return err
	}
	return errors.New("多用户 Web 模式不支持修改服务器 Codex CLI 代理配置")
}

func (s *userScopedCodexSettingsService) ApplySingleProvider(ctx context.Context, providerID int) error {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return err
	}
	return errors.New("多用户 Web 模式不支持直接应用服务器 Codex CLI provider")
}

func (s *userScopedCodexSettingsService) GetDirectAppliedProviderID(ctx context.Context) (*int64, error) {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return nil, err
	}
	return nil, nil
}

type userScopedConsoleService struct {
	logService      *services.LogService
	poolAttemptLogs *services.PoolAttemptLogService
	mu              sync.RWMutex
	clearedAfter    map[string]time.Time
}

func (s *userScopedConsoleService) GetLogs(ctx context.Context) ([]services.ConsoleLog, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.listLogs(user.ID, 200)
}

func (s *userScopedConsoleService) GetRecentLogs(ctx context.Context, count int) ([]services.ConsoleLog, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.listLogs(user.ID, count)
}

func (s *userScopedConsoleService) GetLogUpdates(ctx context.Context, cursor services.ConsoleLogCursor, limit int) (services.ConsoleLogBatch, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return services.ConsoleLogBatch{}, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	since := s.clearTimeForUser(user.ID)
	logs := make([]services.ConsoleLog, 0, limit)
	if s.logService != nil {
		var finalLogs []services.ConsoleLog
		finalLogs, cursor.RequestLogID, err = s.logService.ListHTTPErrorConsoleLogsForUserAfterID(
			user.ID,
			cursor.RequestLogID,
			limit,
			since,
		)
		if err != nil {
			return services.ConsoleLogBatch{}, err
		}
		logs = append(logs, finalLogs...)
	}
	if s.poolAttemptLogs != nil {
		var attemptLogs []services.ConsoleLog
		attemptLogs, cursor.PoolAttemptSequence = s.poolAttemptLogs.ListAfter(
			user.ID,
			cursor.PoolAttemptSequence,
			limit,
			since,
		)
		logs = append(logs, attemptLogs...)
	}
	sort.SliceStable(logs, func(i, j int) bool { return logs[i].Timestamp.Before(logs[j].Timestamp) })
	if len(logs) > limit {
		logs = logs[len(logs)-limit:]
	}
	return services.ConsoleLogBatch{Logs: logs, Cursor: cursor}, nil
}

func (s *userScopedConsoleService) listLogs(userID string, limit int) ([]services.ConsoleLog, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	since := s.clearTimeForUser(userID)
	logs := make([]services.ConsoleLog, 0, limit)
	if s.logService != nil {
		finalLogs, err := s.logService.ListHTTPErrorConsoleLogsForUser(userID, limit, since)
		if err != nil {
			return nil, err
		}
		logs = append(logs, finalLogs...)
	}
	if s.poolAttemptLogs != nil {
		logs = append(logs, s.poolAttemptLogs.List(userID, limit, since)...)
	}
	sort.SliceStable(logs, func(i, j int) bool { return logs[i].Timestamp.Before(logs[j].Timestamp) })
	if len(logs) > limit {
		logs = logs[len(logs)-limit:]
	}
	return logs, nil
}

func (s *userScopedConsoleService) ClearLogs(ctx context.Context) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clearedAfter == nil {
		s.clearedAfter = make(map[string]time.Time)
	}
	s.clearedAfter[user.ID] = time.Now()
	return nil
}

func (s *userScopedConsoleService) clearTimeForUser(userID string) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.clearedAfter == nil {
		return time.Time{}
	}
	return s.clearedAfter[userID]
}

type userScopedCliConfigService struct{}

func (s *userScopedCliConfigService) GetConfig(ctx context.Context, platform string) (*services.CLIConfig, error) {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return nil, err
	}
	return nil, errors.New("多用户 Web 模式不支持读取服务器 CLI 配置")
}

func (s *userScopedCliConfigService) GetConfigSnapshots(ctx context.Context, platform string, apiURL string, apiKey string, previewMode string) (*services.CLIConfigSnapshots, error) {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return nil, err
	}
	return nil, errors.New("多用户 Web 模式不支持预览服务器 CLI 配置")
}

func (s *userScopedCliConfigService) SaveConfig(ctx context.Context, platform string, editable map[string]interface{}) error {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return err
	}
	return errors.New("多用户 Web 模式不支持修改服务器 CLI 配置")
}

func (s *userScopedCliConfigService) SaveConfigFileContent(ctx context.Context, platform string, filePath string, content string) error {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return err
	}
	return errors.New("多用户 Web 模式不支持修改服务器 CLI 配置")
}

func (s *userScopedCliConfigService) GetTemplate(ctx context.Context, platform string) (*services.CLITemplate, error) {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return nil, err
	}
	return nil, errors.New("多用户 Web 模式不支持服务器 CLI 模板")
}

func (s *userScopedCliConfigService) SetTemplate(ctx context.Context, platform string, template map[string]interface{}, isGlobalDefault bool) error {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return err
	}
	return errors.New("多用户 Web 模式不支持修改服务器 CLI 模板")
}

func (s *userScopedCliConfigService) GetLockedFields(ctx context.Context, platform string) []string {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return []string{}
	}
	return []string{}
}

func (s *userScopedCliConfigService) RestoreDefault(ctx context.Context, platform string) error {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return err
	}
	return errors.New("多用户 Web 模式不支持修改服务器 CLI 配置")
}
