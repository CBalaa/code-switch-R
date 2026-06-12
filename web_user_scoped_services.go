package main

import (
	"codeswitch/services"
	"context"
	"errors"
	"strings"
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

type userScopedProviderPoolService struct {
	base *services.ProviderPoolService
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
	return s.base.SavePoolForUser(user.ID, pool)
}

func (s *userScopedProviderPoolService) DeletePool(ctx context.Context, poolID string) error {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return err
	}
	return s.base.DeletePoolForUser(user.ID, poolID)
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

func (s *userScopedLogService) ListRequestLogs(ctx context.Context, platform string, provider string, limit int) ([]services.ReqeustLog, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.ListRequestLogsForUser(user.ID, platform, provider, limit)
}

func (s *userScopedLogService) ListProviders(ctx context.Context, platform string) ([]string, error) {
	user, err := authenticatedUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	return s.base.ListProvidersForUser(user.ID, platform)
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

type userScopedConsoleService struct{}

func (s *userScopedConsoleService) GetLogs(ctx context.Context) ([]services.ConsoleLog, error) {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return nil, err
	}
	return []services.ConsoleLog{}, nil
}

func (s *userScopedConsoleService) GetRecentLogs(ctx context.Context, count int) ([]services.ConsoleLog, error) {
	if _, err := authenticatedUserFromContext(ctx); err != nil {
		return nil, err
	}
	return []services.ConsoleLog{}, nil
}

func (s *userScopedConsoleService) ClearLogs(ctx context.Context) error {
	_, err := authenticatedUserFromContext(ctx)
	return err
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
