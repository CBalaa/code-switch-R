package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProviderPoolServiceDefaultPoolCreation(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: "https://a.example.com", APIKey: "key-a"},
		{ID: 2, Name: "provider-b", Enabled: false, APIURL: "https://b.example.com", APIKey: "key-b"},
		{ID: 3, Name: "provider-c", Enabled: true, APIURL: "https://c.example.com", APIKey: "key-c"},
	}

	pool, err := service.EnsureDefaultPool("openai-chat", providers, DefaultPoolSeed{
		Mode: ProviderPoolModeManaged,
	})
	if err != nil {
		t.Fatalf("EnsureDefaultPool failed: %v", err)
	}

	if pool.ID != "pool_openai-chat_default" {
		t.Fatalf("expected default pool ID 'pool_openai-chat_default', got %q", pool.ID)
	}
	if pool.Name != "初始池" {
		t.Fatalf("expected initial pool name '初始池', got %q", pool.Name)
	}
	if pool.Platform != "openai-chat" {
		t.Fatalf("expected platform 'openai-chat', got %q", pool.Platform)
	}
	if pool.Mode != ProviderPoolModeManaged {
		t.Fatalf("expected mode 'managed', got %q", pool.Mode)
	}
	if len(pool.Members) != 3 {
		t.Fatalf("expected 3 members, got %d", len(pool.Members))
	}

	// 验证成员 enabled 状态
	enabledCount := 0
	for _, m := range pool.Members {
		if m.Enabled {
			enabledCount++
		}
	}
	if enabledCount != 2 {
		t.Fatalf("expected 2 enabled members, got %d", enabledCount)
	}
}

func TestFirstTextRetryIsValidatedPerPool(t *testing.T) {
	pool := &ProviderPool{}
	if err := normalizeAndValidateFirstTextRetry(pool); err != nil {
		t.Fatalf("disabled first-text retry rejected: %v", err)
	}
	if pool.FirstTextRetryEnabled || pool.FirstTextRetryTimeoutSeconds != defaultFirstTextRetryTimeoutSeconds {
		t.Fatalf("disabled pool retry config = %+v, want disabled with default timeout", pool)
	}

	pool.FirstTextRetryEnabled = true
	pool.FirstTextRetryTimeoutSeconds = 0
	if err := normalizeAndValidateFirstTextRetry(pool); err != nil {
		t.Fatalf("enabled retry without explicit timeout rejected: %v", err)
	}
	if pool.FirstTextRetryTimeoutSeconds != defaultFirstTextRetryTimeoutSeconds {
		t.Fatalf("enabled default timeout = %d, want %d", pool.FirstTextRetryTimeoutSeconds, defaultFirstTextRetryTimeoutSeconds)
	}

	pool.FirstTextRetryTimeoutSeconds = minFirstTextRetryTimeoutSeconds - 1
	if err := normalizeAndValidateFirstTextRetry(pool); err == nil {
		t.Fatal("first-text retry timeout below minimum was accepted")
	}
	pool.FirstTextRetryTimeoutSeconds = maxFirstTextRetryTimeoutSeconds + 1
	if err := normalizeAndValidateFirstTextRetry(pool); err == nil {
		t.Fatal("first-text retry timeout above maximum was accepted")
	}
}

func TestMigrateGlobalFirstTextRetryToExistingPools(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	settingsDir := filepath.Join(os.Getenv("HOME"), appSettingsDir)
	if err := os.MkdirAll(settingsDir, 0o700); err != nil {
		t.Fatalf("create settings directory: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(settingsDir, appSettingsFileName),
		[]byte(`{"enable_first_text_retry":true,"first_text_retry_timeout_seconds":5}`),
		0o600,
	); err != nil {
		t.Fatalf("write legacy app settings: %v", err)
	}

	store := &providerPoolStore{
		Version: 5,
		Pools:   []ProviderPool{{ID: "pool-a"}, {ID: "pool-b"}},
	}
	migrateFirstTextRetryToPools(store)
	for _, pool := range store.Pools {
		if !pool.FirstTextRetryEnabled || pool.FirstTextRetryTimeoutSeconds != 5 {
			t.Fatalf("migrated pool = %+v, want enabled 5-second timeout", pool)
		}
	}
}

func TestProviderPoolServiceDefaultPoolIdempotent(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: "https://a.example.com", APIKey: "key-a"},
	}

	pool1, err := service.EnsureDefaultPool("openai-responses", providers, DefaultPoolSeed{
		Mode:             ProviderPoolModeManual,
		ManualProviderID: int64Ptr(1),
	})
	if err != nil {
		t.Fatalf("first EnsureDefaultPool failed: %v", err)
	}

	pool2, err := service.EnsureDefaultPool("openai-responses", providers, DefaultPoolSeed{
		Mode:             ProviderPoolModeManual,
		ManualProviderID: int64Ptr(1),
	})
	if err != nil {
		t.Fatalf("second EnsureDefaultPool failed: %v", err)
	}

	if pool1.ID != pool2.ID {
		t.Fatalf("idempotent call should return same pool, got %q and %q", pool1.ID, pool2.ID)
	}
}

// TestProviderPoolServiceDeleteInitialPoolAllowed 初始池（EnsureDefaultPool 创建的）可以被正常删除
// 默认池不再有删除保护，和普通池子一样
func TestProviderPoolServiceDeleteInitialPoolAllowed(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true},
	}

	_, err := service.EnsureDefaultPool("openai-chat", providers, DefaultPoolSeed{
		Mode: ProviderPoolModeManaged,
	})
	if err != nil {
		t.Fatalf("EnsureDefaultPool failed: %v", err)
	}

	// 初始池可以被删除（不再有删除保护）
	err = service.DeletePool("pool_openai-chat_default")
	if err != nil {
		t.Fatalf("expected deleting initial pool to succeed, got error: %v", err)
	}

	// 验证池子已删除
	found, _ := service.GetPool("pool_openai-chat_default")
	if found != nil {
		t.Fatal("pool should have been deleted")
	}
}

func TestProviderPoolServiceCreateNonDefaultPool(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()

	pool := &ProviderPool{
		Platform: "openai-chat",
		Name:     "RAGFlow 池子",
		Mode:     ProviderPoolModeManual,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true},
			{ProviderID: 2, Enabled: false},
		},
		ManualProviderID: int64Ptr(1),
	}

	id, err := service.SavePool(pool)
	if err != nil {
		t.Fatalf("SavePool failed: %v", err)
	}

	if id == "" {
		t.Fatal("expected auto-generated pool ID")
	}
	if !strings.HasPrefix(id, "pool_openai-chat_") {
		t.Fatalf("expected ID to start with 'pool_openai-chat_', got %q", id)
	}
}

func TestProviderPoolServiceListPools(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()

	// 创建两个 platform 的默认池子
	_, _ = service.EnsureDefaultPool("openai-chat", []Provider{
		{ID: 1, Name: "a", Enabled: true},
	}, DefaultPoolSeed{Mode: ProviderPoolModeManaged})

	_, _ = service.EnsureDefaultPool("openai-responses", []Provider{
		{ID: 2, Name: "b", Enabled: true},
	}, DefaultPoolSeed{Mode: ProviderPoolModeManaged})

	// 再创建一个非默认池子
	_, _ = service.SavePool(&ProviderPool{
		Platform:         "openai-chat",
		Name:             "RAGFlow 池子",
		Mode:             ProviderPoolModeManual,
		Members:          []ProviderPoolMember{{ProviderID: 1, Enabled: true}},
		ManualProviderID: int64Ptr(1),
	})

	// ListPools 应该按 platform 过滤
	chatPools, err := service.ListPools("openai-chat")
	if err != nil {
		t.Fatalf("ListPools failed: %v", err)
	}
	if len(chatPools) != 2 {
		t.Fatalf("expected 2 openai-chat pools, got %d", len(chatPools))
	}

	responsesPools, err := service.ListPools("openai-responses")
	if err != nil {
		t.Fatalf("ListPools failed: %v", err)
	}
	if len(responsesPools) != 1 {
		t.Fatalf("expected 1 openai-responses pool, got %d", len(responsesPools))
	}

	claudePools, err := service.ListPools("claude")
	if err != nil {
		t.Fatalf("ListPools failed: %v", err)
	}
	if len(claudePools) != 0 {
		t.Fatalf("expected 0 claude pools, got %d", len(claudePools))
	}
}

func TestProviderPoolServiceSameNameAcrossPlatforms(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()

	// 不同 platform 可以有同名池子（默认池子都是"默认池子"）
	_, err := service.EnsureDefaultPool("openai-chat", []Provider{}, DefaultPoolSeed{Mode: ProviderPoolModeManaged})
	if err != nil {
		t.Fatalf("first default pool failed: %v", err)
	}
	_, err = service.EnsureDefaultPool("openai-responses", []Provider{}, DefaultPoolSeed{Mode: ProviderPoolModeManaged})
	if err != nil {
		t.Fatalf("second default pool failed: %v", err)
	}
}

func TestProviderPoolServiceSaveExistingPool(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()

	pool := &ProviderPool{
		Platform: "openai-chat",
		Name:     "测试池子",
		Mode:     ProviderPoolModeManaged,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true},
		},
	}

	id, err := service.SavePool(pool)
	if err != nil {
		t.Fatalf("SavePool (create) failed: %v", err)
	}

	// 更新已有池子
	pool.Name = "更新后的池子"
	pool.Mode = ProviderPoolModeManual
	pool.ManualProviderID = int64Ptr(1)

	_, err = service.SavePool(pool)
	if err != nil {
		t.Fatalf("SavePool (update) failed: %v", err)
	}

	found, err := service.GetPool(id)
	if err != nil {
		t.Fatalf("GetPool failed: %v", err)
	}
	if found.Name != "更新后的池子" {
		t.Fatalf("expected updated name, got %q", found.Name)
	}
	if found.Mode != ProviderPoolModeManual {
		t.Fatalf("expected manual mode, got %q", found.Mode)
	}
}

func TestProviderPoolServiceGetPool(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()

	// 空存储
	found, err := service.GetPool("nonexistent")
	if err != nil {
		t.Fatalf("GetPool on empty store failed: %v", err)
	}
	if found != nil {
		t.Fatal("expected nil for nonexistent pool")
	}

	// 创建后查找
	_, _ = service.EnsureDefaultPool("openai-chat", []Provider{
		{ID: 1, Name: "a", Enabled: true},
	}, DefaultPoolSeed{Mode: ProviderPoolModeManaged})

	found, err = service.GetPool("pool_openai-chat_default")
	if err != nil {
		t.Fatalf("GetPool failed: %v", err)
	}
	if found == nil {
		t.Fatal("expected to find default pool")
	}
	if found.Platform != "openai-chat" {
		t.Fatalf("expected platform openai-chat, got %q", found.Platform)
	}
}

func TestProviderPoolServiceDeleteNonDefaultPool(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()

	pool := &ProviderPool{
		Platform: "openai-chat",
		Name:     "可删除的池子",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: 1, Enabled: true}},
	}
	id, _ := service.SavePool(pool)

	err := service.DeletePool(id)
	if err != nil {
		t.Fatalf("deleting non-default pool should succeed: %v", err)
	}

	found, _ := service.GetPool(id)
	if found != nil {
		t.Fatal("expected pool to be deleted")
	}
}

func TestProviderPoolServiceValidation(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()

	// 缺少 platform
	_, err := service.SavePool(&ProviderPool{
		Name: "测试",
		Mode: ProviderPoolModeManaged,
	})
	if err == nil {
		t.Fatal("expected error for missing platform")
	}

	// 缺少 name
	_, err = service.SavePool(&ProviderPool{
		Platform: "openai-chat",
		Mode:     ProviderPoolModeManaged,
	})
	if err == nil {
		t.Fatal("expected error for missing name")
	}

	// 无效 mode
	_, err = service.SavePool(&ProviderPool{
		Platform: "openai-chat",
		Name:     "测试",
		Mode:     "invalid",
	})
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestProviderPoolServiceNormalizesLegacyAndNormalPools(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()
	store := &providerPoolStore{
		Version: providerPoolsBindingMigrationVersion,
		Pools: []ProviderPool{{
			ID:       "pool_openai-responses_legacy",
			Platform: "openai-responses",
			Name:     "legacy",
			Mode:     ProviderPoolModeManaged,
			AccountPoolConfig: &AccountPoolConfig{
				APIURL:            "https://ignored.example.com",
				ResponsesEndpoint: "/responses",
				Keys:              []AccountPoolKey{{ID: -1, APIKey: "ignored"}},
			},
			ExcludeFromTotalTraffic: true,
			HideFromLogs:            true,
		}},
	}
	if err := os.MkdirAll(filepath.Dir(service.path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := AtomicWriteJSON(service.path, store); err != nil {
		t.Fatalf("write legacy store: %v", err)
	}

	pool, err := service.GetPool("pool_openai-responses_legacy")
	if err != nil {
		t.Fatalf("GetPool failed: %v", err)
	}
	if pool == nil || pool.PoolType != ProviderPoolTypeNormal {
		t.Fatalf("legacy pool type = %v, want normal", pool)
	}
	if pool.AccountPoolConfig != nil {
		t.Fatal("normal pool should discard irrelevant account config")
	}
	if pool.ExcludeFromTotalTraffic {
		t.Fatal("normal pool should discard exclude-from-total setting")
	}
	if pool.HideFromLogs {
		t.Fatal("normal pool should discard hide-from-logs setting")
	}

	pool.AccountPoolConfig = &AccountPoolConfig{APIURL: "https://still-ignored.example.com"}
	if _, err := service.SavePool(pool); err != nil {
		t.Fatalf("SavePool failed: %v", err)
	}
	if pool.AccountPoolConfig != nil {
		t.Fatal("saving a normal pool should clear account config")
	}
}

func TestProviderPoolServiceSaveAccountPoolNormalizesConfiguration(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()
	pool := &ProviderPool{
		Platform: "openai-responses",
		Name:     "account pool",
		PoolType: ProviderPoolTypeAccount,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            "  https://api.example.com/v1/  ",
			ResponsesEndpoint: " responses ",
			Keys: []AccountPoolKey{
				{ID: 123, APIKey: "  sk-first-secret-value  "},
				{ID: -99, APIKey: ""},
				{ID: -100, APIKey: "sk-first-secret-value"},
				{ID: -101, APIKey: "\t sk-second-secret-value \t"},
			},
		},
		ExcludeFromTotalTraffic:      true,
		HideFromLogs:                 true,
		AutoBlacklistEnabled:         false,
		AutoBlacklistThreshold:       0,
		AutoBlacklistDurationMinutes: -1,
	}

	id, err := service.SavePool(pool)
	if err != nil {
		t.Fatalf("SavePool failed: %v", err)
	}
	if id == "" {
		t.Fatal("expected generated pool ID")
	}
	if pool.Mode != ProviderPoolModeManaged || !pool.AutoBlacklistEnabled {
		t.Fatalf("account pool mode/blacklist = %q/%v", pool.Mode, pool.AutoBlacklistEnabled)
	}
	if !pool.ExcludeFromTotalTraffic {
		t.Fatal("account pool should retain exclude-from-total setting")
	}
	if !pool.HideFromLogs {
		t.Fatal("account pool should retain hide-from-logs setting")
	}
	if pool.AutoBlacklistThreshold != defaultAccountPoolBlacklistThreshold || pool.AutoBlacklistDurationMinutes != defaultAccountPoolBlacklistDurationMinutes {
		t.Fatalf("blacklist defaults = %d/%d", pool.AutoBlacklistThreshold, pool.AutoBlacklistDurationMinutes)
	}
	if len(pool.Members) != 0 || pool.ManualProviderID != nil {
		t.Fatalf("account pool should not retain normal members/manual provider: %#v", pool)
	}
	if pool.AccountPoolConfig.APIURL != "https://api.example.com/v1" || pool.AccountPoolConfig.ResponsesEndpoint != "/responses" {
		t.Fatalf("normalized config = %#v", pool.AccountPoolConfig)
	}
	if len(pool.AccountPoolConfig.Keys) != 2 {
		t.Fatalf("normalized keys = %#v, want two", pool.AccountPoolConfig.Keys)
	}
	if pool.AccountPoolConfig.Keys[0].APIKey != "sk-first-secret-value" || pool.AccountPoolConfig.Keys[1].APIKey != "sk-second-secret-value" {
		t.Fatalf("key order/normalization = %#v", pool.AccountPoolConfig.Keys)
	}
	seenIDs := make(map[int64]bool)
	for _, key := range pool.AccountPoolConfig.Keys {
		if !isValidAccountPoolKeyID(key.ID) {
			t.Fatalf("key ID %d is not a negative JavaScript-safe ID", key.ID)
		}
		if seenIDs[key.ID] {
			t.Fatalf("duplicate generated key ID: %d", key.ID)
		}
		seenIDs[key.ID] = true
		if key.ID == -100 || key.ID == -101 || key.ID == 123 {
			t.Fatalf("new account pool trusted client key ID %d", key.ID)
		}
	}
	savedPool, err := service.GetPool(id)
	if err != nil || savedPool == nil || !savedPool.ExcludeFromTotalTraffic || !savedPool.HideFromLogs {
		t.Fatalf("saved account-pool display settings = %#v, err = %v", savedPool, err)
	}

	data, err := os.ReadFile(service.path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	var persisted providerPoolStore
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("decode store: %v", err)
	}
	if persisted.Version != providerPoolsStoreVersion {
		t.Fatalf("store version = %d, want %d", persisted.Version, providerPoolsStoreVersion)
	}
}

func TestProviderPoolServiceUpdateAccountPoolPreservesKeyIDs(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()
	pool := validAccountPoolForTest()
	if _, err := service.SavePool(pool); err != nil {
		t.Fatalf("create account pool: %v", err)
	}
	firstID := pool.AccountPoolConfig.Keys[0].ID
	secondID := pool.AccountPoolConfig.Keys[1].ID

	pool.AccountPoolConfig.Keys = []AccountPoolKey{
		{ID: -1, APIKey: "sk-second-secret-value"},
		{ID: secondID, APIKey: "sk-new-secret-value"},
		{ID: -2, APIKey: "sk-first-secret-value"},
	}
	if _, err := service.SavePool(pool); err != nil {
		t.Fatalf("update account pool: %v", err)
	}
	keys := pool.AccountPoolConfig.Keys
	if len(keys) != 3 || keys[0].ID != secondID || keys[2].ID != firstID {
		t.Fatalf("existing key IDs were not preserved by secret: %#v", keys)
	}
	if !isValidAccountPoolKeyID(keys[1].ID) || keys[1].ID == firstID || keys[1].ID == secondID {
		t.Fatalf("new key ID was not freshly allocated: %#v", keys[1])
	}

	pool.PoolType = ProviderPoolTypeNormal
	if _, err := service.SavePool(pool); err == nil {
		t.Fatal("expected pool type mutation to be rejected")
	}
}

func TestProviderPoolServiceRejectsInvalidAccountPools(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	tests := []struct {
		name   string
		mutate func(*ProviderPool)
	}{
		{name: "unknown pool type", mutate: func(pool *ProviderPool) { pool.PoolType = "unknown" }},
		{name: "unsupported platform", mutate: func(pool *ProviderPool) { pool.Platform = "claude" }},
		{name: "manual mode", mutate: func(pool *ProviderPool) { pool.Mode = ProviderPoolModeManual }},
		{name: "normal member", mutate: func(pool *ProviderPool) { pool.Members = []ProviderPoolMember{{ProviderID: 1, Enabled: true}} }},
		{name: "manual provider", mutate: func(pool *ProviderPool) { pool.ManualProviderID = int64Ptr(1) }},
		{name: "missing config", mutate: func(pool *ProviderPool) { pool.AccountPoolConfig = nil }},
		{name: "relative base URL", mutate: func(pool *ProviderPool) { pool.AccountPoolConfig.APIURL = "/v1" }},
		{name: "unsupported base URL scheme", mutate: func(pool *ProviderPool) { pool.AccountPoolConfig.APIURL = "ftp://api.example.com" }},
		{name: "base URL query", mutate: func(pool *ProviderPool) { pool.AccountPoolConfig.APIURL = "https://api.example.com/v1?tenant=a" }},
		{name: "base URL fragment", mutate: func(pool *ProviderPool) { pool.AccountPoolConfig.APIURL = "https://api.example.com/v1#responses" }},
		{name: "absolute responses endpoint", mutate: func(pool *ProviderPool) {
			pool.AccountPoolConfig.ResponsesEndpoint = "https://api.example.com/responses"
		}},
		{name: "network path responses endpoint", mutate: func(pool *ProviderPool) { pool.AccountPoolConfig.ResponsesEndpoint = "//other.example.com/responses" }},
		{name: "fragment responses endpoint", mutate: func(pool *ProviderPool) { pool.AccountPoolConfig.ResponsesEndpoint = "/responses#ignored" }},
		{name: "empty responses endpoint", mutate: func(pool *ProviderPool) { pool.AccountPoolConfig.ResponsesEndpoint = " " }},
		{name: "empty chat endpoint", mutate: func(pool *ProviderPool) {
			pool.Platform = "openai-chat"
			pool.AccountPoolConfig.ChatEndpoint = " "
		}},
		{name: "absolute chat endpoint", mutate: func(pool *ProviderPool) {
			pool.Platform = "openai-chat"
			pool.AccountPoolConfig.ChatEndpoint = "https://api.example.com/v1/chat/completions"
		}},
		{name: "network path chat endpoint", mutate: func(pool *ProviderPool) {
			pool.Platform = "openai-chat"
			pool.AccountPoolConfig.ChatEndpoint = "//other.example.com/v1/chat/completions"
		}},
		{name: "fragment chat endpoint", mutate: func(pool *ProviderPool) {
			pool.Platform = "openai-chat"
			pool.AccountPoolConfig.ChatEndpoint = "/v1/chat/completions#ignored"
		}},
		{name: "empty keys", mutate: func(pool *ProviderPool) { pool.AccountPoolConfig.Keys = []AccountPoolKey{{APIKey: " \t "}} }},
		{name: "blacklist threshold too large", mutate: func(pool *ProviderPool) { pool.AutoBlacklistThreshold = maxAccountPoolBlacklistThreshold + 1 }},
		{name: "blacklist duration too large", mutate: func(pool *ProviderPool) {
			pool.AutoBlacklistDurationMinutes = maxAccountPoolBlacklistDurationMinutes + 1
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewProviderPoolService()
			pool := validAccountPoolForTest()
			test.mutate(pool)
			if _, err := service.SavePool(pool); err == nil {
				t.Fatalf("expected invalid account pool to be rejected: %#v", pool)
			}
		})
	}
}

func validAccountPoolForTest() *ProviderPool {
	return &ProviderPool{
		Platform: "openai-responses",
		Name:     "account pool",
		PoolType: ProviderPoolTypeAccount,
		Mode:     ProviderPoolModeManaged,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            "https://api.example.com",
			ResponsesEndpoint: "/v1/responses",
			Keys: []AccountPoolKey{
				{APIKey: "sk-first-secret-value"},
				{APIKey: "sk-second-secret-value"},
			},
		},
	}
}

func validChatAccountPoolForTest() *ProviderPool {
	return &ProviderPool{
		Platform: "openai-chat",
		Name:     "chat account pool",
		PoolType: ProviderPoolTypeAccount,
		Mode:     ProviderPoolModeManaged,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:       "https://api.example.com",
			ChatEndpoint: "/v1/chat/completions",
			Keys: []AccountPoolKey{
				{APIKey: "sk-first-secret-value"},
				{APIKey: "sk-second-secret-value"},
			},
		},
	}
}

// TestProviderPoolServiceSaveChatAccountPoolNormalizesConfiguration verifies the
// chat protocol is a first-class account-pool platform: the chat endpoint is
// validated/normalized, the platform-foreign endpoint is dropped, and the
// account-pool invariants (managed mode, forced blacklist settings) apply.
func TestProviderPoolServiceSaveChatAccountPoolNormalizesConfiguration(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()
	pool := &ProviderPool{
		Platform: "openai-chat",
		Name:     "chat account pool",
		PoolType: ProviderPoolTypeAccount,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            "  https://api.example.com/v1/  ",
			ResponsesEndpoint: "/v1/responses",
			ChatEndpoint:      " v1/chat/completions ",
			Keys: []AccountPoolKey{
				{APIKey: "sk-chat-secret-value"},
			},
		},
		AutoBlacklistEnabled:         false,
		AutoBlacklistThreshold:       0,
		AutoBlacklistDurationMinutes: -1,
	}

	id, err := service.SavePool(pool)
	if err != nil {
		t.Fatalf("SavePool failed: %v", err)
	}
	if id == "" {
		t.Fatal("expected generated pool ID")
	}
	if pool.Mode != ProviderPoolModeManaged || !pool.AutoBlacklistEnabled {
		t.Fatalf("account pool mode/blacklist = %q/%v", pool.Mode, pool.AutoBlacklistEnabled)
	}
	if pool.AutoBlacklistThreshold != defaultAccountPoolBlacklistThreshold || pool.AutoBlacklistDurationMinutes != defaultAccountPoolBlacklistDurationMinutes {
		t.Fatalf("blacklist defaults = %d/%d", pool.AutoBlacklistThreshold, pool.AutoBlacklistDurationMinutes)
	}
	if pool.AccountPoolConfig.APIURL != "https://api.example.com/v1" {
		t.Fatalf("normalized api url = %q", pool.AccountPoolConfig.APIURL)
	}
	if pool.AccountPoolConfig.ChatEndpoint != "/v1/chat/completions" {
		t.Fatalf("normalized chat endpoint = %q", pool.AccountPoolConfig.ChatEndpoint)
	}
	if pool.AccountPoolConfig.ResponsesEndpoint != "" {
		t.Fatalf("chat pool kept a Responses endpoint: %q", pool.AccountPoolConfig.ResponsesEndpoint)
	}
	if len(pool.AccountPoolConfig.Keys) != 1 || !isValidAccountPoolKeyID(pool.AccountPoolConfig.Keys[0].ID) {
		t.Fatalf("normalized keys = %#v", pool.AccountPoolConfig.Keys)
	}

	savedPool, err := service.GetPool(id)
	if err != nil || savedPool == nil {
		t.Fatalf("read saved chat account pool: %#v, err = %v", savedPool, err)
	}
	if savedPool.Platform != "openai-chat" || savedPool.AccountPoolConfig == nil || savedPool.AccountPoolConfig.ChatEndpoint != "/v1/chat/completions" {
		t.Fatalf("persisted chat account pool = %#v", savedPool)
	}

	// A Responses pool must keep only its own endpoint (round trip of the
	// platform-foreign-field cleanup in the other direction).
	responsesPool := validAccountPoolForTest()
	responsesPool.AccountPoolConfig.ChatEndpoint = "/v1/chat/completions"
	if _, err := service.SavePool(responsesPool); err != nil {
		t.Fatalf("save responses account pool: %v", err)
	}
	if responsesPool.AccountPoolConfig.ResponsesEndpoint != "/v1/responses" || responsesPool.AccountPoolConfig.ChatEndpoint != "" {
		t.Fatalf("responses pool endpoints = %#v", responsesPool.AccountPoolConfig)
	}
}

// ========== SelectProvidersFromPool 测试 ==========

func TestSelectProvidersFromPoolManagedMode(t *testing.T) {
	pool := &ProviderPool{
		ID:       "pool_test",
		Platform: "openai-chat",
		Mode:     ProviderPoolModeManaged,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true},
			{ProviderID: 2, Enabled: false},
			{ProviderID: 3, Enabled: true},
		},
	}

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true},
		{ID: 2, Name: "provider-b", Enabled: true},
		{ID: 3, Name: "provider-c", Enabled: true},
	}

	selected, err := SelectProvidersFromPool(pool, providers)
	if err != nil {
		t.Fatalf("SelectProvidersFromPool failed: %v", err)
	}

	if len(selected) != 2 {
		t.Fatalf("expected 2 selected providers, got %d", len(selected))
	}

	names := make(map[string]bool)
	for _, p := range selected {
		names[p.Name] = true
	}
	if !names["provider-a"] || !names["provider-c"] {
		t.Fatalf("expected provider-a and provider-c, got %v", names)
	}
}

func TestSelectProvidersFromPoolManualMode(t *testing.T) {
	manualID := int64(2)
	pool := &ProviderPool{
		ID:               "pool_test",
		Platform:         "openai-chat",
		Mode:             ProviderPoolModeManual,
		ManualProviderID: &manualID,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true},
			{ProviderID: 2, Enabled: false}, // 手动模式下 enabled 不影响
		},
	}

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true},
		{ID: 2, Name: "provider-b", Enabled: false},
	}

	selected, err := SelectProvidersFromPool(pool, providers)
	if err != nil {
		t.Fatalf("SelectProvidersFromPool failed: %v", err)
	}

	if len(selected) != 1 {
		t.Fatalf("expected 1 selected provider, got %d", len(selected))
	}
	if selected[0].Name != "provider-b" {
		t.Fatalf("expected provider-b, got %q", selected[0].Name)
	}
}

func TestSelectProvidersFromPoolManualModeNoDirectApply(t *testing.T) {
	pool := &ProviderPool{
		ID:               "pool_test",
		Platform:         "openai-chat",
		Mode:             ProviderPoolModeManual,
		ManualProviderID: nil, // 没有指定直接应用
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true},
		},
	}

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true},
	}

	selected, err := SelectProvidersFromPool(pool, providers)
	if err != nil {
		t.Fatalf("SelectProvidersFromPool failed: %v", err)
	}
	if len(selected) != 0 {
		t.Fatalf("expected 0 providers when manual mode has no direct apply, got %d", len(selected))
	}
}

func TestSelectProvidersFromPoolManualModeProviderNotInMembers(t *testing.T) {
	manualID := int64(99)
	pool := &ProviderPool{
		ID:               "pool_test",
		Platform:         "openai-chat",
		Mode:             ProviderPoolModeManual,
		ManualProviderID: &manualID,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true},
		},
	}

	providers := []Provider{
		{ID: 99, Name: "provider-99", Enabled: true},
	}

	_, err := SelectProvidersFromPool(pool, providers)
	if err == nil {
		t.Fatal("expected error when manual provider is not in pool members")
	}
}

func TestSelectProvidersFromPoolManagedModeProviderNotExist(t *testing.T) {
	pool := &ProviderPool{
		ID:       "pool_test",
		Platform: "openai-chat",
		Mode:     ProviderPoolModeManaged,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true},
			{ProviderID: 999, Enabled: true}, // 不存在的 provider
		},
	}

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true},
	}

	selected, err := SelectProvidersFromPool(pool, providers)
	if err != nil {
		t.Fatalf("SelectProvidersFromPool failed: %v", err)
	}

	// 不存在的 provider 被跳过
	if len(selected) != 1 {
		t.Fatalf("expected 1 selected provider (skipping nonexistent), got %d", len(selected))
	}
}

func TestSelectProvidersFromPoolTwoPoolsSameProvider(t *testing.T) {
	// Pool A 和 Pool B 都引用 provider 乙，二者成员关系互不影响
	poolA := &ProviderPool{
		ID:       "pool_a",
		Platform: "openai-chat",
		Mode:     ProviderPoolModeManaged,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true},
			{ProviderID: 2, Enabled: true},
		},
	}

	poolB := &ProviderPool{
		ID:       "pool_b",
		Platform: "openai-chat",
		Mode:     ProviderPoolModeManaged,
		Members: []ProviderPoolMember{
			{ProviderID: 2, Enabled: false}, // pool B 中 provider 2 禁用
			{ProviderID: 3, Enabled: true},
		},
	}

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true},
		{ID: 2, Name: "provider-b", Enabled: true},
		{ID: 3, Name: "provider-c", Enabled: true},
	}

	selectedA, _ := SelectProvidersFromPool(poolA, providers)
	selectedB, _ := SelectProvidersFromPool(poolB, providers)

	if len(selectedA) != 2 {
		t.Fatalf("pool A: expected 2 providers, got %d", len(selectedA))
	}
	if len(selectedB) != 1 {
		t.Fatalf("pool B: expected 1 provider, got %d", len(selectedB))
	}
	if selectedB[0].Name != "provider-c" {
		t.Fatalf("pool B: expected provider-c, got %q", selectedB[0].Name)
	}
}

func TestSelectProvidersFromAccountPoolSynthesizesProviders(t *testing.T) {
	pool := validAccountPoolForTest()
	pool.AccountPoolConfig.Keys = []AccountPoolKey{
		{ID: -101, APIKey: "sk-first-shared-suffix"},
		{ID: -202, APIKey: "sk-second-shared-suffix"},
	}

	selected, err := SelectProvidersFromPool(pool, []Provider{{ID: 1, Name: "ignored"}})
	if err != nil {
		t.Fatalf("SelectProvidersFromPool failed: %v", err)
	}
	if len(selected) != 2 {
		t.Fatalf("selected providers = %#v, want two", selected)
	}
	if selected[0].ID != -101 || selected[1].ID != -202 {
		t.Fatalf("provider order/IDs = %#v", selected)
	}
	if selected[0].Name == selected[1].Name {
		t.Fatalf("account provider names must be unique: %q", selected[0].Name)
	}
	for i, provider := range selected {
		key := pool.AccountPoolConfig.Keys[i]
		if provider.APIURL != pool.AccountPoolConfig.APIURL || provider.ResponsesEndpoint != pool.AccountPoolConfig.ResponsesEndpoint || provider.APIKey != key.APIKey {
			t.Fatalf("provider %d config = %#v", i, provider)
		}
		if !provider.Enabled || provider.Level != 1 || provider.MaxConcurrency != defaultProviderMaxConcurrency {
			t.Fatalf("provider %d runtime defaults = %#v", i, provider)
		}
		if provider.ModelsEndpoint != "/v1/models" {
			t.Fatalf("provider %d models endpoint = %q, want /v1/models", i, provider.ModelsEndpoint)
		}
		if strings.Contains(provider.Name, key.APIKey) {
			t.Fatalf("provider name leaks full API key: %q", provider.Name)
		}
		if strings.Contains(provider.Name, key.APIKey[:len(key.APIKey)-4]) {
			t.Fatalf("provider name exposes API key prefix: %q", provider.Name)
		}
	}

	pool.AccountPoolConfig.APIURL = "https://api.example.com/openai/v1"
	pool.AccountPoolConfig.ResponsesEndpoint = "/responses"
	selected, err = SelectProvidersFromPool(pool, nil)
	if err != nil || len(selected) != 2 || selected[0].ModelsEndpoint != "/models" {
		t.Fatalf("root Responses sibling models endpoint = providers=%#v err=%v", selected, err)
	}
	if got := accountPoolModelsEndpoint("/custom/responses?tenant=a"); got != "/custom/models" {
		t.Fatalf("custom Responses sibling models endpoint = %q, want /custom/models", got)
	}
	if got := accountPoolModelsEndpoint("/v1/responses/"); got != "/v1/models" {
		t.Fatalf("trailing-slash Responses sibling models endpoint = %q, want /v1/models", got)
	}
}

// TestSelectProvidersFromChatAccountPoolSynthesizesChatEndpoint verifies chat
// account keys become runtime providers that route /chat/completions through the
// configured chat endpoint (and derive the sibling models endpoint from it).
func TestSelectProvidersFromChatAccountPoolSynthesizesChatEndpoint(t *testing.T) {
	pool := validChatAccountPoolForTest()
	pool.AccountPoolConfig.Keys = []AccountPoolKey{
		{ID: -101, APIKey: "sk-first-shared-suffix"},
		{ID: -202, APIKey: "sk-second-shared-suffix"},
	}

	selected, err := SelectProvidersFromPool(pool, []Provider{{ID: 1, Name: "ignored"}})
	if err != nil {
		t.Fatalf("SelectProvidersFromPool failed: %v", err)
	}
	if len(selected) != 2 {
		t.Fatalf("selected providers = %#v, want two", selected)
	}
	for i, provider := range selected {
		key := pool.AccountPoolConfig.Keys[i]
		if provider.APIURL != pool.AccountPoolConfig.APIURL || provider.APIKey != key.APIKey {
			t.Fatalf("provider %d config = %#v", i, provider)
		}
		if provider.ChatEndpoint != pool.AccountPoolConfig.ChatEndpoint {
			t.Fatalf("provider %d chat endpoint = %q, want %q", i, provider.ChatEndpoint, pool.AccountPoolConfig.ChatEndpoint)
		}
		if provider.ResponsesEndpoint != "" || provider.APIEndpoint != "" {
			t.Fatalf("chat account provider leaked other endpoints: %#v", provider)
		}
		if provider.ModelsEndpoint != "/v1/models" {
			t.Fatalf("provider %d models endpoint = %q, want /v1/models", i, provider.ModelsEndpoint)
		}
		if got := provider.GetEffectiveEndpoint("/chat/completions"); got != "/v1/chat/completions" {
			t.Fatalf("provider %d effective chat endpoint = %q", i, got)
		}
	}

	// A root-mounted chat endpoint derives its sibling models endpoint from the
	// same base as /v1/chat/completions does.
	pool.AccountPoolConfig.ChatEndpoint = "/chat/completions"
	selected, err = SelectProvidersFromPool(pool, nil)
	if err != nil || len(selected) != 2 || selected[0].ModelsEndpoint != "/models" {
		t.Fatalf("root Chat sibling models endpoint = providers=%#v err=%v", selected, err)
	}
	if got := accountPoolModelsEndpoint("/openai/v1/chat/completions"); got != "/openai/v1/models" {
		t.Fatalf("nested Chat sibling models endpoint = %q, want /openai/v1/models", got)
	}
	// Responses derivation must stay unchanged.
	if got := accountPoolModelsEndpoint("/v1/responses"); got != "/v1/models" {
		t.Fatalf("Responses sibling models endpoint = %q, want /v1/models", got)
	}
}

// ========== 辅助函数 ==========

func int64Ptr(v int64) *int64 {
	return &v
}

// ========== 集成测试 ==========

// TestRelayKeyPoolBinding 测试 relay key 与 pool 的绑定关系
func TestRelayKeyPoolBinding(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	keyService := NewCodexRelayKeyService()
	poolService := NewProviderPoolService()

	// 创建两个 relay key
	key1, _ := keyService.CreateKey("key-1")
	key2, _ := keyService.CreateKey("key-2")

	// 创建默认池子
	_, _ = poolService.EnsureDefaultPool("openai-chat", []Provider{
		{ID: 1, Name: "provider-a", Enabled: true},
		{ID: 2, Name: "provider-b", Enabled: true},
	}, DefaultPoolSeed{Mode: ProviderPoolModeManaged})

	// 创建第二个池子
	pool2 := &ProviderPool{
		Platform: "openai-chat",
		Name:     "专属池子",
		Mode:     ProviderPoolModeManual,
		Members: []ProviderPoolMember{
			{ProviderID: 2, Enabled: true},
		},
		ManualProviderID: int64Ptr(2),
	}
	pool2ID, _ := poolService.SavePool(pool2)

	// key1 绑定默认池子，key2 绑定第二个池子
	_ = keyService.SetPoolBinding(key1.ID, "openai-chat", "pool_openai-chat_default")
	_ = keyService.SetPoolBinding(key2.ID, "openai-chat", pool2ID)

	// 验证 key1 的绑定
	binding1, ok1, _ := keyService.GetPoolBinding(key1.ID, "openai-chat")
	if !ok1 || binding1 != "pool_openai-chat_default" {
		t.Fatalf("key1 binding = %q, ok=%v, expected pool_openai-chat_default", binding1, ok1)
	}

	// 验证 key2 的绑定
	binding2, ok2, _ := keyService.GetPoolBinding(key2.ID, "openai-chat")
	if !ok2 || binding2 != pool2ID {
		t.Fatalf("key2 binding = %q, ok=%v, expected %s", binding2, ok2, pool2ID)
	}

	// 验证通过 ValidateKeyMatch 返回的 PoolBindings
	match1, _ := keyService.ValidateKeyMatch(key1.Key)
	if match1 == nil || match1.PoolBindings == nil || match1.PoolBindings["openai-chat"] != "pool_openai-chat_default" {
		t.Fatalf("key1 match poolBindings incorrect")
	}

	match2, _ := keyService.ValidateKeyMatch(key2.Key)
	if match2 == nil || match2.PoolBindings == nil || match2.PoolBindings["openai-chat"] != pool2ID {
		t.Fatalf("key2 match poolBindings incorrect")
	}
}

// TestEnsureDefaultPoolBindings 测试自动绑定默认池子
func TestEnsureDefaultPoolBindings(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	keyService := NewCodexRelayKeyService()

	// 创建 relay key
	key, _ := keyService.CreateKey("test-key")

	// 确保默认绑定
	platformDefaults := map[string]string{
		"openai-chat":      "pool_openai-chat_default",
		"openai-responses": "pool_openai-responses_default",
	}
	_ = keyService.EnsureDefaultPoolBindings(platformDefaults)

	// 验证绑定
	binding1, ok1, _ := keyService.GetPoolBinding(key.ID, "openai-chat")
	if !ok1 || binding1 != "pool_openai-chat_default" {
		t.Fatalf("expected openai-chat default binding, got %q ok=%v", binding1, ok1)
	}

	binding2, ok2, _ := keyService.GetPoolBinding(key.ID, "openai-responses")
	if !ok2 || binding2 != "pool_openai-responses_default" {
		t.Fatalf("expected openai-responses default binding, got %q ok=%v", binding2, ok2)
	}

	// 未绑定的 platform 应该不存在
	_, ok3, _ := keyService.GetPoolBinding(key.ID, "unknown-platform")
	if ok3 {
		t.Fatal("expected no unknown-platform binding")
	}
}

// TestTwoKeysTwoPoolsIsolation 测试两个 key 绑定两个池子时的隔离性
// 这是设计文档的核心验收场景
func TestTwoKeysTwoPoolsIsolation(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	poolService := NewProviderPoolService()

	// 设置 providers
	configDir := filepath.Join(testHome, ".code-switch")
	_ = os.MkdirAll(configDir, 0o700)

	providers := []Provider{
		{ID: 1, Name: "provider-a", Enabled: true, APIURL: "https://a.example.com", APIKey: "key-a"},
		{ID: 2, Name: "provider-b", Enabled: true, APIURL: "https://b.example.com", APIKey: "key-b"},
		{ID: 3, Name: "provider-c", Enabled: true, APIURL: "https://c.example.com", APIKey: "key-c"},
	}
	payload, _ := json.Marshal(providerEnvelope{Providers: providers})
	_ = os.WriteFile(filepath.Join(configDir, "openai-chat.json"), payload, 0o600)

	// 创建 Pool A (managed, members: provider-a, provider-b)
	poolA := &ProviderPool{
		Platform: "openai-chat",
		Name:     "Pool A",
		Mode:     ProviderPoolModeManaged,
		Members: []ProviderPoolMember{
			{ProviderID: 1, Enabled: true},
			{ProviderID: 2, Enabled: true},
		},
	}
	poolAID, _ := poolService.SavePool(poolA)

	// 创建 Pool B (managed, members: provider-b, provider-c)
	poolB := &ProviderPool{
		Platform: "openai-chat",
		Name:     "Pool B",
		Mode:     ProviderPoolModeManaged,
		Members: []ProviderPoolMember{
			{ProviderID: 2, Enabled: true},
			{ProviderID: 3, Enabled: true},
		},
	}
	poolBID, _ := poolService.SavePool(poolB)

	// 加载所有 providers
	providerService := NewProviderService()
	allProviders, _ := providerService.LoadProviders("openai-chat")

	// Pool A 应该只选择 provider-a 和 provider-b
	poolAObj, _ := poolService.ResolvePoolByID(poolAID)
	selectedA, _ := SelectProvidersFromPool(poolAObj, allProviders)
	if len(selectedA) != 2 {
		t.Fatalf("Pool A: expected 2 providers, got %d", len(selectedA))
	}
	selectedAmap := map[string]bool{}
	for _, p := range selectedA {
		selectedAmap[p.Name] = true
	}
	if !selectedAmap["provider-a"] || !selectedAmap["provider-b"] {
		t.Fatalf("Pool A: expected provider-a and provider-b, got %v", selectedAmap)
	}
	if selectedAmap["provider-c"] {
		t.Fatal("Pool A: should NOT include provider-c")
	}

	// Pool B 应该只选择 provider-b 和 provider-c
	poolBObj, _ := poolService.ResolvePoolByID(poolBID)
	selectedB, _ := SelectProvidersFromPool(poolBObj, allProviders)
	if len(selectedB) != 2 {
		t.Fatalf("Pool B: expected 2 providers, got %d", len(selectedB))
	}
	selectedBmap := map[string]bool{}
	for _, p := range selectedB {
		selectedBmap[p.Name] = true
	}
	if !selectedBmap["provider-b"] || !selectedBmap["provider-c"] {
		t.Fatalf("Pool B: expected provider-b and provider-c, got %v", selectedBmap)
	}
	if selectedBmap["provider-a"] {
		t.Fatal("Pool B: should NOT include provider-a")
	}
}

// TestResolvePoolByIDFailClosed 验证 ResolvePoolByID 只按显式 ID 查找
func TestResolvePoolByIDFailClosed(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()

	// 不存在的 poolID 应返回 nil
	pool, err := service.ResolvePoolByID("nonexistent")
	if err != nil {
		t.Fatalf("ResolvePoolByID should not error for nonexistent pool: %v", err)
	}
	if pool != nil {
		t.Fatal("ResolvePoolByID should return nil for nonexistent pool")
	}

	// 创建默认池子后按 ID 查找
	_, _ = service.EnsureDefaultPool("openai-chat", []Provider{}, DefaultPoolSeed{Mode: ProviderPoolModeManaged})
	pool, err = service.ResolvePoolByID("pool_openai-chat_default")
	if err != nil {
		t.Fatalf("ResolvePoolByID failed: %v", err)
	}
	if pool == nil {
		t.Fatal("expected to find pool by ID")
	}
}

// TestDeletePoolWithoutBindingCheckerDoesNotCheckKeyBindings 验证未注入 checker 时 DeletePool 不负责跨服务检查。
// 生产初始化必须注入 bindingChecker；这个测试只覆盖低层服务的可选依赖行为。
func TestDeletePoolWithoutBindingCheckerDoesNotCheckKeyBindings(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	keyService := NewCodexRelayKeyService()
	poolService := NewProviderPoolService()

	key, _ := keyService.CreateKey("test-key")

	pool := &ProviderPool{
		Platform: "openai-chat",
		Name:     "bound pool",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: 1, Enabled: true}},
	}
	poolID, _ := poolService.SavePool(pool)

	// 绑定 key 到 pool
	_ = keyService.SetPoolBinding(key.ID, "openai-chat", poolID)

	// 检查 pool 是否被 key 绑定
	isBound, boundKeys, _ := keyService.IsPoolBoundToAnyKey(poolID)
	if !isBound {
		t.Fatal("expected pool to be bound to at least one key")
	}
	if len(boundKeys) != 1 || boundKeys[0] != "test-key" {
		t.Fatalf("expected bound key 'test-key', got %v", boundKeys)
	}

	// 未注入 checker 时，底层服务无法读取 relay key store，因此允许删除。
	// web_runtime.go 会注入 checker，生产路径由 TestDeletePoolBlockedByBinding 覆盖。
	err := poolService.DeletePool(poolID)
	if err != nil {
		t.Fatalf("DeletePool should succeed without binding checker: %v", err)
	}

	// 验证 pool 已删除
	found, _ := poolService.GetPool(poolID)
	if found != nil {
		t.Fatal("pool should have been deleted")
	}
}

type failingPoolBindingChecker struct{}

func (failingPoolBindingChecker) IsPoolBoundToAnyKey(poolID string) (bool, []string, error) {
	return false, nil, fmt.Errorf("simulated binding store failure for %s", poolID)
}

// TestDeletePoolBlockedByBinding 验证注入了 bindingChecker 后，被 key 绑定的 pool 不可删除
func TestDeletePoolBlockedByBinding(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	keyService := NewCodexRelayKeyService()
	poolService := NewProviderPoolService()
	poolService.SetBindingChecker(keyService) // 注入 binding checker

	key, _ := keyService.CreateKey("test-key")

	pool := &ProviderPool{
		Platform: "openai-chat",
		Name:     "bound pool",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: 1, Enabled: true}},
	}
	poolID, _ := poolService.SavePool(pool)

	// 绑定 key 到 pool
	_ = keyService.SetPoolBinding(key.ID, "openai-chat", poolID)

	// 删除被 key 绑定的 pool 应该被拒绝
	err := poolService.DeletePool(poolID)
	if err == nil {
		t.Fatal("expected DeletePool to be rejected for key-bound pool")
	}
	if !strings.Contains(err.Error(), "绑定") {
		t.Fatalf("expected error about binding, got: %v", err)
	}

	// pool 应该仍然存在
	found, _ := poolService.GetPool(poolID)
	if found == nil {
		t.Fatal("pool should still exist after failed delete")
	}
}

func TestDeletePoolFailsClosedWhenBindingCheckFails(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	poolService := NewProviderPoolService()
	poolService.SetBindingChecker(failingPoolBindingChecker{})

	pool := &ProviderPool{
		Platform: "openai-chat",
		Name:     "pool with checker failure",
		Mode:     ProviderPoolModeManaged,
		Members:  []ProviderPoolMember{{ProviderID: 1, Enabled: true}},
	}
	poolID, _ := poolService.SavePool(pool)

	err := poolService.DeletePool(poolID)
	if err == nil {
		t.Fatal("expected DeletePool to fail closed when binding checker returns error")
	}
	if !strings.Contains(err.Error(), "检查") {
		t.Fatalf("expected binding check error, got: %v", err)
	}

	found, _ := poolService.GetPool(poolID)
	if found == nil {
		t.Fatal("pool should still exist after binding check failure")
	}
}

// TestMigrationOnlyRunsOnce 验证 relay key 绑定迁移只在 version < 2 时执行
func TestMigrationOnlyRunsOnce(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	poolService := NewProviderPoolService()
	keyService := NewCodexRelayKeyService()

	// 手动写入一个 version=1 的 store，模拟从旧版本升级
	store := &providerPoolStore{Version: 1, Pools: []ProviderPool{}}
	if err := os.MkdirAll(filepath.Dir(poolService.path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := AtomicWriteJSON(poolService.path, store); err != nil {
		t.Fatalf("write store: %v", err)
	}

	// NeedsMigration 应该为 true（version=1 < 2）
	if !poolService.NeedsMigration() {
		t.Fatal("expected NeedsMigration=true before migration (version=1)")
	}

	// 创建 key 并执行绑定
	key, _ := keyService.CreateKey("test-key")
	_, _ = poolService.EnsureDefaultPool("openai-chat", []Provider{
		{ID: 1, Name: "a", Enabled: true},
	}, DefaultPoolSeed{Mode: ProviderPoolModeManaged})
	if !poolService.NeedsMigration() {
		t.Fatal("routine pool save must not suppress the pending version 1 binding migration")
	}

	platformDefaults := map[string]string{"openai-chat": "pool_openai-chat_default"}
	_ = keyService.EnsureDefaultPoolBindings(platformDefaults)

	// 标记迁移完成
	if err := poolService.MarkMigrationCompleted(); err != nil {
		t.Fatalf("MarkMigrationCompleted failed: %v", err)
	}

	// 迁移后 NeedsMigration 应该为 false
	if poolService.NeedsMigration() {
		t.Fatal("expected NeedsMigration=false after migration")
	}

	// 验证绑定已写入
	binding, ok, _ := keyService.GetPoolBinding(key.ID, "openai-chat")
	if !ok || binding != "pool_openai-chat_default" {
		t.Fatalf("existing key should have binding after migration, got %q ok=%v", binding, ok)
	}

	// 新 key 创建后没有 pool binding
	key2, _ := keyService.CreateKey("new-key")
	binding2, ok2, _ := keyService.GetPoolBinding(key2.ID, "openai-chat")
	if ok2 {
		t.Fatalf("new key should NOT have binding, got %q", binding2)
	}
}

func TestProviderPoolStoreVersionTwoDoesNotRepeatBindingMigration(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()
	store := &providerPoolStore{Version: providerPoolsBindingMigrationVersion, Pools: []ProviderPool{}}
	if err := os.MkdirAll(filepath.Dir(service.path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := AtomicWriteJSON(service.path, store); err != nil {
		t.Fatalf("write store: %v", err)
	}
	if service.NeedsMigration() {
		t.Fatal("version 2 store must not repeat the relay-key binding migration")
	}

	pool := validAccountPoolForTest()
	if _, err := service.SavePool(pool); err != nil {
		t.Fatalf("save account pool: %v", err)
	}
	if service.NeedsMigration() {
		t.Fatal("version 3 store must not need the version 2 binding migration")
	}

	futureVersion := providerPoolsStoreVersion + 1
	store = &providerPoolStore{Version: futureVersion, Pools: []ProviderPool{}}
	if err := AtomicWriteJSON(service.path, store); err != nil {
		t.Fatalf("write future-version store: %v", err)
	}
	originalData, err := os.ReadFile(service.path)
	if err != nil {
		t.Fatalf("read initial future-version store: %v", err)
	}
	if _, err := service.SavePool(validAccountPoolForTest()); err == nil {
		t.Fatal("expected writes to a future-version store to be rejected")
	}
	if err := service.MarkMigrationCompleted(); err == nil {
		t.Fatal("expected migration marking on a future-version store to be rejected")
	}
	data, err := os.ReadFile(service.path)
	if err != nil {
		t.Fatalf("read future-version store: %v", err)
	}
	if string(data) != string(originalData) {
		t.Fatal("rejected future-version write changed the store")
	}
}

func TestProviderPoolStoreVersionThreeUpgradesWithDisabledProxyConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	service := NewProviderPoolService()
	pool := validAccountPoolForTest()
	pool.ID = "pool_openai-responses_v3"
	store := &providerPoolStore{Version: 3, Pools: []ProviderPool{*pool}}
	if err := os.MkdirAll(filepath.Dir(service.path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteJSON(service.path, store); err != nil {
		t.Fatal(err)
	}
	loaded, err := service.GetPool(pool.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.ProxyConfig == nil || loaded.ProxyConfig.Enabled || loaded.ProxyConfig.Selection != AccountPoolProxySelectionNone {
		t.Fatalf("loaded v3 proxy config = %#v", loaded)
	}
	if _, err := service.SavePool(loaded); err != nil {
		t.Fatalf("save migrated v3 pool: %v", err)
	}
	data, err := os.ReadFile(service.path)
	if err != nil {
		t.Fatal(err)
	}
	var migrated providerPoolStore
	if err := json.Unmarshal(data, &migrated); err != nil {
		t.Fatal(err)
	}
	if migrated.Version != providerPoolsStoreVersion || len(migrated.Pools) != 1 || migrated.Pools[0].ProxyConfig == nil {
		t.Fatalf("migrated store = %#v", migrated)
	}
}
