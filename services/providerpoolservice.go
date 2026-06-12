package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// normalizePoolMemberLevel 将 pool member Level 归一化：缺失或 <= 0 时默认为 1
func normalizePoolMemberLevel(level int) int {
	if level <= 0 {
		return 1
	}
	return level
}

// ProviderPool 供应商池
type ProviderPool struct {
	ID               string               `json:"id"`
	Platform         string               `json:"platform"`
	Name             string               `json:"name"`
	Mode             ProviderPoolMode     `json:"mode"`
	ManualProviderID *int64               `json:"manualProviderId,omitempty"`
	Members          []ProviderPoolMember `json:"members"`
	CreatedAt        string               `json:"createdAt"`
	UpdatedAt        string               `json:"updatedAt"`

	// 自动拉黑配置（仅 managed 模式生效）
	AutoBlacklistEnabled         bool `json:"autoBlacklistEnabled"`
	AutoBlacklistThreshold       int  `json:"autoBlacklistThreshold"`
	AutoBlacklistDurationMinutes int  `json:"autoBlacklistDurationMinutes"`
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
	providerPoolsFile         = "provider-pools.json"
	providerPoolsStoreVersion = 2     // version 1 = initial pools; version 2 = migration completed (keys explicitly bound)
	initialPoolName           = "初始池" // 迁移时自动创建的池子名称
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
	mu             sync.Mutex
	bindingChecker PoolBindingChecker // 只读引用，用于删除前检查
}

// NewProviderPoolService 创建供应商池服务
// bindingChecker 可以为 nil（删除前不会检查 key 绑定）
func NewProviderPoolService() *ProviderPoolService {
	home, err := getUserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		home = "."
	}

	return &ProviderPoolService{
		path:           filepath.Join(home, appSettingsDir, providerPoolsFile),
		bindingChecker: nil,
	}
}

func NewProviderPoolServiceForUser(userID string) (*ProviderPoolService, error) {
	dir, err := UserDataDir(userID)
	if err != nil {
		return nil, err
	}
	return &ProviderPoolService{
		path:           filepath.Join(dir, providerPoolsFile),
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

	if strings.TrimSpace(pool.Platform) == "" {
		return "", errors.New("池子必须指定 platform")
	}

	if strings.TrimSpace(pool.Name) == "" {
		return "", errors.New("池子名称不能为空")
	}

	if pool.Mode != ProviderPoolModeManaged && pool.Mode != ProviderPoolModeManual {
		return "", fmt.Errorf("无效的池子模式: %s（必须是 managed 或 manual）", pool.Mode)
	}

	// 手动模式必须指定 direct applied provider（允许 nil 但会在选择时返回"无可用供应商"）
	if pool.Mode == ProviderPoolModeManual && pool.ManualProviderID == nil && len(pool.Members) > 0 {
		// 软警告，不阻塞保存
		fmt.Printf("[WARN] 手动模式池子 %s 未指定直接应用供应商，请求时将返回无可用供应商\n", pool.Name)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	store, err := s.loadLocked()
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(pool.ID) == "" {
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
				// 不允许更改 platform
				if existing.Platform != pool.Platform {
					return "", fmt.Errorf("池子的 platform 不可更改（原: %s, 新: %s）", existing.Platform, pool.Platform)
				}
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
		ID:               defaultID,
		Platform:         platform,
		Name:             initialPoolName,
		Mode:             seed.Mode,
		ManualProviderID: seed.ManualProviderID,
		Members:          members,
		CreatedAt:        now,
		UpdatedAt:        now,
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
// 返回 true 表示 store version < providerPoolsStoreVersion，需要迁移
func (s *ProviderPoolService) NeedsMigration() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	store, err := s.loadLocked()
	if err != nil {
		return false
	}
	return store.Version < providerPoolsStoreVersion
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
	if store.Pools == nil {
		store.Pools = []ProviderPool{}
	}

	return store, nil
}

func (s *ProviderPoolService) saveLocked(store *providerPoolStore) error {
	if err := EnsureDir(filepath.Dir(s.path)); err != nil {
		return err
	}
	return AtomicWriteJSON(s.path, store)
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
