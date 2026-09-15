package main

import (
	"codeswitch/services"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUserScopedPoolSaveRejectsEnabledProxyWithoutCatalogNodes(t *testing.T) {
	testUserScopedPoolSaveRejectsEnabledProxyWithoutCatalogNodes(t, "openai-responses", services.ProviderPoolTypeAccount)
}

func TestUserScopedChatPoolSaveRejectsEnabledProxyWithoutCatalogNodes(t *testing.T) {
	testUserScopedPoolSaveRejectsEnabledProxyWithoutCatalogNodes(t, "openai-chat", services.ProviderPoolTypeAccount)
}

func TestUserScopedRelayClearAllProviderBlacklistsOnlyAllowsAccountPools(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	poolService := services.NewProviderPoolService()
	relay := services.NewProviderRelayService(services.NewProviderService(), poolService, nil, nil, nil, services.DefaultRelayBindAddr)
	scoped := &userScopedProviderRelayService{base: relay, poolService: poolService}
	ctx := contextWithAuthenticatedUser(context.Background(), &services.AuthenticatedUser{ID: "user-a", Username: "alice"})

	normalPool := &services.ProviderPool{
		Platform: "openai-responses",
		Name:     "normal pool",
		Mode:     services.ProviderPoolModeManaged,
	}
	if _, err := poolService.SavePoolForUser("user-a", normalPool); err != nil {
		t.Fatalf("save normal pool: %v", err)
	}
	if err := scoped.ClearAllProviderBlacklists(ctx, normalPool.Platform, normalPool.ID); err == nil || !strings.Contains(err.Error(), "仅号池") {
		t.Fatalf("clear normal pool error = %v, want account-pool rejection", err)
	}

	accountPool := &services.ProviderPool{
		Platform: "openai-responses",
		Name:     "account pool",
		PoolType: services.ProviderPoolTypeAccount,
		Mode:     services.ProviderPoolModeManaged,
		AccountPoolConfig: &services.AccountPoolConfig{
			APIURL:            "https://api.example.com",
			ResponsesEndpoint: "/v1/responses",
			Keys:              []services.AccountPoolKey{{APIKey: "sk-test"}},
		},
	}
	if _, err := poolService.SavePoolForUser("user-a", accountPool); err != nil {
		t.Fatalf("save account pool: %v", err)
	}
	if err := scoped.ClearAllProviderBlacklists(ctx, accountPool.Platform, accountPool.ID); err != nil {
		t.Fatalf("clear account pool: %v", err)
	}

	// Chat account pools are first-class too: the same batch clear must be
	// authorized (blacklists are scoped by platform + pool).
	chatAccountPool := &services.ProviderPool{
		Platform: "openai-chat",
		Name:     "chat account pool",
		PoolType: services.ProviderPoolTypeAccount,
		Mode:     services.ProviderPoolModeManaged,
		AccountPoolConfig: &services.AccountPoolConfig{
			APIURL:       "https://api.example.com",
			ChatEndpoint: "/v1/chat/completions",
			Keys:         []services.AccountPoolKey{{APIKey: "sk-chat-test"}},
		},
	}
	if _, err := poolService.SavePoolForUser("user-a", chatAccountPool); err != nil {
		t.Fatalf("save chat account pool: %v", err)
	}
	if err := scoped.ClearAllProviderBlacklists(ctx, chatAccountPool.Platform, chatAccountPool.ID); err != nil {
		t.Fatalf("clear chat account pool: %v", err)
	}
}

func TestAggregateCostUsageByAccountPoolCollapsesAccountKeys(t *testing.T) {
	firstKey := services.AccountPoolKey{ID: -101, APIKey: "sk-account-key-one"}
	secondKey := services.AccountPoolKey{ID: -202, APIKey: "sk-account-key-two"}
	chatKey := services.AccountPoolKey{ID: -303, APIKey: "sk-chat-account-key"}
	pools := []services.ProviderPool{
		{
			Platform: "openai-responses",
			Name:     "Japan Account Pool",
			PoolType: services.ProviderPoolTypeAccount,
			AccountPoolConfig: &services.AccountPoolConfig{Keys: []services.AccountPoolKey{
				firstKey, secondKey,
			}},
		},
		{
			Platform: "openai-chat",
			Name:     "Chat Account Pool",
			PoolType: services.ProviderPoolTypeAccount,
			AccountPoolConfig: &services.AccountPoolConfig{
				ChatEndpoint: "/v1/chat/completions",
				Keys:         []services.AccountPoolKey{chatKey},
			},
		},
	}
	items := []services.CostUsageItem{
		{Platform: "openai-responses", Provider: services.AccountPoolKeyDisplayName(firstKey), Model: "gpt-5", TotalRequests: 2, InputTokens: 10, OutputTokens: 4},
		{Platform: "openai-responses", Provider: services.AccountPoolKeyDisplayName(secondKey), Model: "gpt-5", TotalRequests: 3, InputTokens: 20, OutputTokens: 6},
		{Platform: "openai-responses", Provider: "regular provider", Model: "gpt-5", TotalRequests: 1, InputTokens: 5, OutputTokens: 1},
		{Platform: "openai-chat", Provider: services.AccountPoolKeyDisplayName(chatKey), Model: "gpt-4o-mini", TotalRequests: 4, InputTokens: 40, OutputTokens: 8},
	}

	aggregated := aggregateCostUsageByAccountPool(items, pools, "")
	if len(aggregated) != 3 {
		t.Fatalf("aggregated items = %#v", aggregated)
	}
	var poolItem *services.CostUsageItem
	var chatPoolItem *services.CostUsageItem
	for index := range aggregated {
		if aggregated[index].Provider == "Japan Account Pool" {
			poolItem = &aggregated[index]
		}
		if aggregated[index].Provider == "Chat Account Pool" {
			chatPoolItem = &aggregated[index]
		}
	}
	if poolItem == nil || poolItem.TotalRequests != 5 || poolItem.InputTokens != 30 || poolItem.OutputTokens != 10 {
		t.Fatalf("account-pool aggregation = %#v", poolItem)
	}
	if chatPoolItem == nil || chatPoolItem.Platform != "openai-chat" || chatPoolItem.TotalRequests != 4 || chatPoolItem.InputTokens != 40 {
		t.Fatalf("chat account-pool aggregation = %#v", chatPoolItem)
	}
	filtered := aggregateCostUsageByAccountPool(items, pools, "Japan Account Pool")
	if len(filtered) != 1 || filtered[0].Provider != "Japan Account Pool" || filtered[0].TotalRequests != 5 {
		t.Fatalf("filtered aggregation = %#v", filtered)
	}
}

func TestUserScopedPoolSaveRejectsWhitespacePaddedAccountProxyWithoutCatalogNodes(t *testing.T) {
	testUserScopedPoolSaveRejectsEnabledProxyWithoutCatalogNodes(t, "openai-responses", services.ProviderPoolType(" account "))
}

func testUserScopedPoolSaveRejectsEnabledProxyWithoutCatalogNodes(t *testing.T, platform string, poolType services.ProviderPoolType) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CODE_SWITCH_REFERENCE_PROXY_DIR", t.TempDir())

	proxyService, err := services.NewProxyService()
	if err != nil {
		t.Fatalf("NewProxyService: %v", err)
	}
	poolService := services.NewProviderPoolService()
	scoped := &userScopedProviderPoolService{base: poolService, proxyService: proxyService}
	ctx := contextWithAuthenticatedUser(context.Background(), &services.AuthenticatedUser{ID: "user-a", Username: "alice"})
	accountPoolConfig := &services.AccountPoolConfig{
		APIURL: "https://api.example.com",
		Keys:   []services.AccountPoolKey{{APIKey: "sk-test"}},
	}
	if platform == "openai-chat" {
		accountPoolConfig.ChatEndpoint = "/v1/chat/completions"
	} else {
		accountPoolConfig.ResponsesEndpoint = "/v1/responses"
	}
	pool := &services.ProviderPool{
		Platform:          platform,
		Name:              "account pool",
		PoolType:          poolType,
		Mode:              services.ProviderPoolModeManaged,
		AccountPoolConfig: accountPoolConfig,
		ProxyConfig: &services.AccountPoolProxyConfig{
			Enabled:   true,
			Selection: services.AccountPoolProxySelectionAuto,
		},
	}

	if _, err := scoped.SavePool(ctx, pool); err == nil || !strings.Contains(err.Error(), "至少一个有效的代理配置") {
		t.Fatalf("save enabled proxy without catalog nodes error = %v", err)
	}
	pools, err := poolService.ListPoolsForUser("user-a", platform)
	if err != nil {
		t.Fatalf("ListPoolsForUser: %v", err)
	}
	if len(pools) != 0 {
		t.Fatalf("rejected pool was persisted: %#v", pools)
	}
}

func newUserScopedProxyServiceForTest(t *testing.T) (*userScopedProxyService, *services.ProxyService, context.Context, context.Context, context.Context) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CODE_SWITCH_REFERENCE_PROXY_DIR", t.TempDir())
	if runtime.GOOS == "linux" {
		fakeMihomo := filepath.Join(t.TempDir(), "mihomo")
		script := "#!/bin/sh\nif [ \"$1\" = \"-v\" ]; then\n  echo 'Mihomo Meta v1.19.28'\nfi\nexit 0\n"
		if err := os.WriteFile(fakeMihomo, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CODE_SWITCH_MIHOMO_BINARY", fakeMihomo)
	}
	proxyService, err := services.NewProxyService()
	if err != nil {
		t.Fatalf("NewProxyService: %v", err)
	}
	t.Cleanup(proxyService.Stop)
	userStore := services.NewUserStore()
	alice, err := userStore.AddUser("alice", "password-a")
	if err != nil {
		t.Fatalf("AddUser alice: %v", err)
	}
	bob, err := userStore.AddUser("bob", "password-b")
	if err != nil {
		t.Fatalf("AddUser bob: %v", err)
	}
	carol, err := userStore.AddUser("carol", "password-c")
	if err != nil {
		t.Fatalf("AddUser carol: %v", err)
	}
	poolService := services.NewProviderPoolService()
	scoped := &userScopedProxyService{base: proxyService, poolService: poolService, userStore: userStore}
	return scoped, proxyService,
		contextWithAuthenticatedUser(context.Background(), &services.AuthenticatedUser{ID: alice.ID, Username: alice.Username}),
		contextWithAuthenticatedUser(context.Background(), &services.AuthenticatedUser{ID: bob.ID, Username: bob.Username}),
		contextWithAuthenticatedUser(context.Background(), &services.AuthenticatedUser{ID: carol.ID, Username: carol.Username})
}

const testSharedProxyYAML = "proxies:\n  - name: Hong Kong 01\n    type: http\n    server: proxy.example\n    port: 443\n"

func TestUserScopedImportProxySubscriptionRequiresAuthenticationAndPublicTarget(t *testing.T) {
	scoped, _, aliceCtx, _, _ := newUserScopedProxyServiceForTest(t)
	privateURL := "http://127.0.0.1/subscription"
	if err := scoped.ImportProxySubscription(aliceCtx, privateURL, "private-test"); err == nil || !strings.Contains(err.Error(), "不允许") {
		t.Fatalf("authenticated private subscription error = %v", err)
	}
	if err := scoped.ImportProxySubscription(context.Background(), privateURL, "private-test"); err == nil || !strings.Contains(err.Error(), "authenticated user missing") {
		t.Fatal("unauthenticated subscription import was accepted")
	}
}

func TestUserScopedProxyConfigOwnershipAndHideIsolation(t *testing.T) {
	scoped, _, aliceCtx, bobCtx, carolCtx := newUserScopedProxyServiceForTest(t)
	if err := scoped.UploadProxyConfig(aliceCtx, "shared.yaml", testSharedProxyYAML); err != nil {
		t.Fatalf("UploadProxyConfig: %v", err)
	}
	aliceConfigs, err := scoped.ListProxyConfigs(aliceCtx)
	if err != nil || len(aliceConfigs) != 1 || !aliceConfigs[0].IsOwner || aliceConfigs[0].ID == "" {
		t.Fatalf("alice configs = %#v, err = %v", aliceConfigs, err)
	}
	configID := aliceConfigs[0].ID
	bobConfigs, err := scoped.ListProxyConfigs(bobCtx)
	if err != nil || len(bobConfigs) != 1 || bobConfigs[0].IsOwner || bobConfigs[0].ID != configID {
		t.Fatalf("bob configs = %#v, err = %v", bobConfigs, err)
	}
	if err := scoped.DeleteProxyConfig(bobCtx, configID); err == nil || !strings.Contains(err.Error(), "只有上传者") {
		t.Fatalf("non-owner DeleteProxyConfig error = %v", err)
	}
	if err := scoped.HideProxyConfig(aliceCtx, configID); err == nil || !strings.Contains(err.Error(), "上传者") {
		t.Fatalf("owner HideProxyConfig error = %v", err)
	}
	if err := scoped.HideProxyConfig(bobCtx, configID); err != nil {
		t.Fatalf("HideProxyConfig: %v", err)
	}
	if configs, err := scoped.ListProxyConfigs(bobCtx); err != nil || len(configs) != 0 {
		t.Fatalf("hidden bob configs = %#v, err = %v", configs, err)
	}
	if configs, err := scoped.ListProxyConfigs(aliceCtx); err != nil || len(configs) != 1 || !configs[0].IsOwner {
		t.Fatalf("alice visibility changed = %#v, err = %v", configs, err)
	}
	if configs, err := scoped.ListProxyConfigs(carolCtx); err != nil || len(configs) != 1 || configs[0].IsOwner {
		t.Fatalf("carol visibility changed = %#v, err = %v", configs, err)
	}
	hidden, err := scoped.ListHiddenProxyConfigs(bobCtx)
	if err != nil || len(hidden) != 1 || hidden[0].ID != configID {
		t.Fatalf("bob hidden configs = %#v, err = %v", hidden, err)
	}
	if refreshed, err := scoped.RefreshProxyConfigs(bobCtx); err != nil || len(refreshed) != 0 {
		t.Fatalf("refresh should preserve bob hide preference: %#v, err = %v", refreshed, err)
	}
	if err := scoped.UnhideProxyConfig(bobCtx, configID); err != nil {
		t.Fatalf("UnhideProxyConfig: %v", err)
	}
	if err := scoped.UnhideProxyConfig(bobCtx, configID); err != nil {
		t.Fatalf("idempotent UnhideProxyConfig: %v", err)
	}
	if configs, err := scoped.ListProxyConfigs(bobCtx); err != nil || len(configs) != 1 || configs[0].ID != configID {
		t.Fatalf("unhidden bob configs = %#v, err = %v", configs, err)
	}
	if _, err := scoped.ListProxyConfigs(context.Background()); err == nil {
		t.Fatal("ListProxyConfigs accepted an unauthenticated context")
	}
	if err := scoped.HideProxyConfig(context.Background(), configID); err == nil {
		t.Fatal("HideProxyConfig accepted an unauthenticated context")
	}
	if err := scoped.DeleteProxyConfig(context.Background(), configID); err == nil {
		t.Fatal("DeleteProxyConfig accepted an unauthenticated context")
	}
}

func TestUserScopedProxyConfigDeleteReuploadGetsNewIdentity(t *testing.T) {
	scoped, proxyService, aliceCtx, bobCtx, _ := newUserScopedProxyServiceForTest(t)
	if err := scoped.UploadProxyConfig(aliceCtx, "shared.yaml", testSharedProxyYAML); err != nil {
		t.Fatalf("UploadProxyConfig: %v", err)
	}
	first, err := scoped.ListProxyConfigs(aliceCtx)
	if err != nil || len(first) != 1 {
		t.Fatalf("first configs = %#v, err = %v", first, err)
	}
	firstConfigID := first[0].ID
	firstNodeID := first[0].Nodes[0].ID
	if err := scoped.HideProxyConfig(bobCtx, firstConfigID); err != nil {
		t.Fatalf("HideProxyConfig: %v", err)
	}
	if err := scoped.DeleteProxyConfig(aliceCtx, firstConfigID); err != nil {
		t.Fatalf("DeleteProxyConfig: %v", err)
	}
	if hidden, err := scoped.ListHiddenProxyConfigs(bobCtx); err != nil || len(hidden) != 0 {
		t.Fatalf("deleted config remained hidden for bob: %#v, err = %v", hidden, err)
	}
	if err := scoped.UploadProxyConfig(aliceCtx, "shared.yaml", testSharedProxyYAML); err != nil {
		t.Fatalf("re-upload shared.yaml: %v", err)
	}
	second, err := scoped.ListProxyConfigs(aliceCtx)
	if err != nil || len(second) != 1 {
		t.Fatalf("second configs = %#v, err = %v", second, err)
	}
	if second[0].ID == firstConfigID || second[0].Nodes[0].ID == firstNodeID {
		t.Fatalf("same filename reused config/node identity: first=%#v second=%#v", first[0], second[0])
	}
	if configs, err := scoped.ListProxyConfigs(bobCtx); err != nil || len(configs) != 1 || configs[0].ID != second[0].ID {
		t.Fatalf("re-upload inherited bob hide preference: %#v, err = %v", configs, err)
	}
	if err := proxyService.NormalizePoolProxyConfig(&services.AccountPoolProxyConfig{Enabled: true, Selection: services.AccountPoolProxySelectionNode, ProxyNodeID: firstNodeID}); err == nil {
		t.Fatal("old fixed-node selection resolved to a replacement YAML")
	}
}

func TestUserScopedProxyConfigDeleteRejectsReferencedPools(t *testing.T) {
	t.Run("fixed node", func(t *testing.T) {
		scoped, _, aliceCtx, bobCtx, _ := newUserScopedProxyServiceForTest(t)
		if err := scoped.UploadProxyConfig(aliceCtx, "shared.yaml", testSharedProxyYAML); err != nil {
			t.Fatalf("UploadProxyConfig: %v", err)
		}
		configs, err := scoped.ListProxyConfigs(bobCtx)
		if err != nil || len(configs) != 1 {
			t.Fatalf("bob configs = %#v, err = %v", configs, err)
		}
		poolService := &userScopedProviderPoolService{base: scoped.poolService, proxyService: scoped.base}
		pool := testAccountPoolWithProxy("fixed proxy", &services.AccountPoolProxyConfig{Enabled: true, Selection: services.AccountPoolProxySelectionNode, ProxyNodeID: configs[0].Nodes[0].ID})
		if _, err := poolService.SavePool(bobCtx, pool); err != nil {
			t.Fatalf("SavePool: %v", err)
		}
		if err := scoped.DeleteProxyConfig(aliceCtx, configs[0].ID); err == nil || !strings.Contains(err.Error(), "固定节点") {
			t.Fatalf("DeleteProxyConfig fixed-node reference error = %v", err)
		}
	})

	t.Run("last auto node", func(t *testing.T) {
		scoped, _, aliceCtx, bobCtx, _ := newUserScopedProxyServiceForTest(t)
		if err := scoped.UploadProxyConfig(aliceCtx, "shared.yaml", testSharedProxyYAML); err != nil {
			t.Fatalf("UploadProxyConfig: %v", err)
		}
		configs, err := scoped.ListProxyConfigs(aliceCtx)
		if err != nil || len(configs) != 1 {
			t.Fatalf("alice configs = %#v, err = %v", configs, err)
		}
		poolService := &userScopedProviderPoolService{base: scoped.poolService, proxyService: scoped.base}
		pool := testAccountPoolWithProxy("auto proxy", &services.AccountPoolProxyConfig{Enabled: true, Selection: services.AccountPoolProxySelectionAuto})
		if _, err := poolService.SavePool(bobCtx, pool); err != nil {
			t.Fatalf("SavePool: %v", err)
		}
		if err := scoped.DeleteProxyConfig(aliceCtx, configs[0].ID); err == nil || !strings.Contains(err.Error(), "最后一个") {
			t.Fatalf("DeleteProxyConfig last-auto-node reference error = %v", err)
		}
	})
}

func TestUserScopedTestAllProxyLatenciesAuthorizesPreviewAndHiddenConfigs(t *testing.T) {
	scoped, _, aliceCtx, bobCtx, _ := newUserScopedProxyServiceForTest(t)
	if _, err := scoped.TestAllProxyLatencies(context.Background(), ""); err == nil {
		t.Fatal("TestAllProxyLatencies accepted an unauthenticated context")
	}
	if err := scoped.UploadProxyConfig(aliceCtx, "shared.yaml", testSharedProxyYAML); err != nil {
		t.Fatalf("UploadProxyConfig: %v", err)
	}
	configs, err := scoped.ListProxyConfigs(bobCtx)
	if err != nil || len(configs) != 1 {
		t.Fatalf("bob configs = %#v, err = %v", configs, err)
	}
	if err := scoped.HideProxyConfig(bobCtx, configs[0].ID); err != nil {
		t.Fatalf("HideProxyConfig: %v", err)
	}
	// Empty poolID is the create-pool preview path. The only YAML is hidden for
	// bob, so it must produce no test targets and avoid starting fake Mihomo.
	results, err := scoped.TestAllProxyLatencies(bobCtx, "")
	if err != nil || len(results) != 0 {
		t.Fatalf("hidden preview results = %#v, err = %v", results, err)
	}

	poolService := &userScopedProviderPoolService{base: scoped.poolService, proxyService: scoped.base}
	pool := testAccountPoolWithProxy("alice only", &services.AccountPoolProxyConfig{Enabled: false, Selection: services.AccountPoolProxySelectionNone})
	poolID, err := poolService.SavePool(aliceCtx, pool)
	if err != nil {
		t.Fatalf("SavePool alice: %v", err)
	}
	if _, err := scoped.TestAllProxyLatencies(bobCtx, poolID); err == nil || !strings.Contains(err.Error(), "号池不存在") {
		t.Fatalf("cross-user pool test error = %v", err)
	}
}

func TestUserScopedProxyTestAndSaveRejectHiddenFixedNode(t *testing.T) {
	scoped, _, aliceCtx, bobCtx, _ := newUserScopedProxyServiceForTest(t)
	if err := scoped.UploadProxyConfig(aliceCtx, "shared.yaml", testSharedProxyYAML); err != nil {
		t.Fatalf("UploadProxyConfig: %v", err)
	}
	configs, err := scoped.ListProxyConfigs(bobCtx)
	if err != nil || len(configs) != 1 || len(configs[0].Nodes) != 1 {
		t.Fatalf("bob configs = %#v, err = %v", configs, err)
	}
	nodeID := configs[0].Nodes[0].ID
	if err := scoped.HideProxyConfig(bobCtx, configs[0].ID); err != nil {
		t.Fatalf("HideProxyConfig: %v", err)
	}
	result, err := scoped.TestProxy(bobCtx, "", nodeID, "")
	if err != nil || !strings.Contains(result.ProxyError, "隐藏") {
		t.Fatalf("hidden fixed TestProxy result=%#v err=%v", result, err)
	}
	poolService := &userScopedProviderPoolService{base: scoped.poolService, proxyService: scoped.base}
	pool := testAccountPoolWithProxy("hidden fixed node", &services.AccountPoolProxyConfig{
		Enabled: true, Selection: services.AccountPoolProxySelectionNode, ProxyNodeID: nodeID,
	})
	if _, err := poolService.SavePool(bobCtx, pool); err == nil || !strings.Contains(err.Error(), "隐藏") {
		t.Fatalf("SavePool hidden fixed node error = %v", err)
	}
}

func testAccountPoolWithProxy(name string, proxyConfig *services.AccountPoolProxyConfig) *services.ProviderPool {
	return &services.ProviderPool{
		Platform: "openai-responses",
		Name:     name,
		PoolType: services.ProviderPoolTypeAccount,
		Mode:     services.ProviderPoolModeManaged,
		AccountPoolConfig: &services.AccountPoolConfig{
			APIURL:            "https://api.example.com",
			ResponsesEndpoint: "/v1/responses",
			Keys:              []services.AccountPoolKey{{APIKey: "sk-test"}},
		},
		ProxyConfig: proxyConfig,
	}
}
