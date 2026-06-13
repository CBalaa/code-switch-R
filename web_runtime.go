package main

import (
	"codeswitch/services"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const (
	defaultAdminAddr = "0.0.0.0:8080"
	defaultStaticDir = "frontend/dist"
	defaultRelayAddr = services.DefaultRelayBindAddr
)

type AppService struct{}

func (a *AppService) SetApp(_ any) {}

func (a *AppService) SetTrayWindowHeight(_ int) {}

func (a *AppService) OpenSecondWindow() {}

type appRuntime struct {
	adminAddr          string
	staticDir          string
	eventHub           *services.EventHub
	appService         *AppService
	providerService    *services.ProviderService
	settingsService    *services.SettingsService
	claudeSettings     *services.ClaudeSettingsService
	codexSettings      *services.CodexSettingsService
	cliConfigService   *services.CliConfigService
	logService         *services.LogService
	appSettings        *services.AppSettingsService
	adminAuth          *services.AdminAuthService
	adminSecurity      *adminSecurity
	codexRelayKeys     *services.CodexRelayKeyService
	mcpService         *services.MCPService
	skillService       *services.SkillService
	promptService      *services.PromptService
	envCheckService    *services.EnvCheckService
	deeplinkService    *services.DeepLinkService
	speedTestService   *services.SpeedTestService
	connectivityTest   *services.ConnectivityTestService
	healthCheckService *services.HealthCheckService
	modelMonitor       *services.ModelMonitorService
	versionService     *VersionService
	consoleService     *services.ConsoleService
	customCliService   *services.CustomCliService
	networkService     *services.NetworkService
	providerRelay      *services.ProviderRelayService
	poolService        *services.ProviderPoolService
}

func newAppRuntime() (*appRuntime, error) {
	if err := services.InitDatabase(); err != nil {
		return nil, fmt.Errorf("数据库初始化失败: %w", err)
	}
	if err := services.InitGlobalDBQueue(); err != nil {
		return nil, fmt.Errorf("初始化数据库队列失败: %w", err)
	}

	providerService := services.NewProviderService()
	settingsService := services.NewSettingsService()
	appSettings := services.NewAppSettingsService(nil)
	adminAuth := services.NewAdminAuthService(appSettings)
	adminSecurity, err := newAdminSecurity(appSettings)
	if err != nil {
		return nil, fmt.Errorf("初始化后台安全配置失败: %w", err)
	}
	codexRelayKeys := services.NewCodexRelayKeyService()
	poolService := services.NewProviderPoolService()
	poolService.SetBindingChecker(codexRelayKeys) // 注入 binding checker，删除 pool 时检查 key 绑定
	bootstrapNetworkService := services.NewNetworkService(defaultRelayAddr, nil, nil, codexRelayKeys)
	relayAddr := defaultRelayAddr
	if networkSettings, err := bootstrapNetworkService.GetNetworkSettings(); err != nil {
		log.Printf("读取网络监听设置失败（使用默认 relay 地址）: %v", err)
	} else if addr := strings.TrimSpace(networkSettings.CurrentAddress); addr != "" {
		relayAddr = addr
	}
	eventHub := services.NewEventHub()
	notificationService := services.NewNotificationService(appSettings)
	notificationService.SetEventEmitter(eventHub)
	providerRelay := services.NewProviderRelayService(providerService, poolService, codexRelayKeys, notificationService, appSettings, relayAddr)
	claudeSettings := services.NewClaudeSettingsService(providerRelay.Addr(), codexRelayKeys)
	codexSettings := services.NewCodexSettingsService(providerRelay.Addr(), codexRelayKeys)
	cliConfigService := services.NewCliConfigService(providerRelay.Addr(), codexRelayKeys)
	logService := services.NewLogService()
	mcpService := services.NewMCPService()
	skillService := services.NewSkillService()
	promptService := services.NewPromptService()
	envCheckService := services.NewEnvCheckService()
	deeplinkService := services.NewDeepLinkService(providerService)
	speedTestService := services.NewSpeedTestService()
	connectivityTestService := services.NewConnectivityTestService(providerService, settingsService)
	healthCheckService := services.NewHealthCheckService(providerService, settingsService)
	if err := healthCheckService.Start(); err != nil {
		return nil, fmt.Errorf("初始化健康检查服务失败: %w", err)
	}
	modelMonitor := services.NewModelMonitorService(providerService, adminAuth.UserStore())
	if err := modelMonitor.Start(); err != nil {
		return nil, fmt.Errorf("初始化模型监控服务失败: %w", err)
	}
	versionService := NewVersionService()
	consoleService := services.NewConsoleService()
	customCliService := services.NewCustomCliService(providerRelay.Addr())
	networkService := services.NewNetworkService(providerRelay.Addr(), claudeSettings, codexSettings, codexRelayKeys)

	// 启动前确保默认池子和 relay key 绑定存在
	if err := providerRelay.EnsureDefaultPoolsAndBindings(); err != nil {
		log.Printf("初始化 provider pools 失败: %v", err)
	}

	if err := providerRelay.Start(); err != nil {
		return nil, fmt.Errorf("启动代理服务失败: %w", err)
	}

	if status, err := codexSettings.ProxyStatus(); err == nil && status.Enabled {
		if err := codexSettings.EnableProxy(); err != nil {
			log.Printf("刷新 Codex relay key 失败: %v", err)
		}
	}

	if status, err := claudeSettings.ProxyStatus(); err == nil && status.Enabled {
		if err := claudeSettings.EnableProxy(); err != nil {
			log.Printf("刷新 Claude relay key 失败: %v", err)
		}
	}

	go func() {
		time.Sleep(3 * time.Second)
		settings, err := appSettings.GetAppSettings()
		autoEnabled := true
		if err != nil {
			log.Printf("读取应用设置失败（使用默认值）: %v", err)
		} else {
			autoEnabled = settings.AutoConnectivityTest
		}
		if autoEnabled {
			healthCheckService.SetAutoAvailabilityPolling(true)
			log.Println("自动可用性监控已启动")
		}
	}()

	return &appRuntime{
		adminAddr:          getenvDefault("CODE_SWITCH_WEB_ADDR", defaultAdminAddr),
		staticDir:          getenvDefault("CODE_SWITCH_STATIC_DIR", defaultStaticDir),
		eventHub:           eventHub,
		appService:         &AppService{},
		providerService:    providerService,
		settingsService:    settingsService,
		claudeSettings:     claudeSettings,
		codexSettings:      codexSettings,
		cliConfigService:   cliConfigService,
		logService:         logService,
		appSettings:        appSettings,
		adminAuth:          adminAuth,
		adminSecurity:      adminSecurity,
		codexRelayKeys:     codexRelayKeys,
		mcpService:         mcpService,
		skillService:       skillService,
		promptService:      promptService,
		envCheckService:    envCheckService,
		deeplinkService:    deeplinkService,
		speedTestService:   speedTestService,
		connectivityTest:   connectivityTestService,
		healthCheckService: healthCheckService,
		modelMonitor:       modelMonitor,
		versionService:     versionService,
		consoleService:     consoleService,
		customCliService:   customCliService,
		networkService:     networkService,
		providerRelay:      providerRelay,
		poolService:        poolService,
	}, nil
}

func (rt *appRuntime) shutdown() {
	if rt.healthCheckService != nil {
		rt.healthCheckService.Stop()
	}
	if rt.modelMonitor != nil {
		rt.modelMonitor.Stop()
	}

	if rt.providerRelay != nil {
		if err := rt.providerRelay.Stop(); err != nil {
			log.Printf("停止代理服务失败: %v", err)
		}
	}

	if err := services.ShutdownGlobalDBQueue(10 * time.Second); err != nil {
		log.Printf("数据库队列关闭超时: %v", err)
	}
}

func (rt *appRuntime) registerServices(registry *rpcRegistry) {
	registry.Register("main.AppService", rt.appService)
	registry.Register("main.VersionService", rt.versionService)
	registry.Register("codeswitch/services.ProviderService", &userScopedProviderService{base: rt.providerService})
	registry.Register("codeswitch/services.SettingsService", rt.settingsService)
	registry.Register("codeswitch/services.ClaudeSettingsService", &userScopedClaudeSettingsService{base: rt.claudeSettings})
	registry.Register("codeswitch/services.CodexSettingsService", &userScopedCodexSettingsService{base: rt.codexSettings})
	registry.Register("codeswitch/services.CliConfigService", &userScopedCliConfigService{})
	registry.Register("codeswitch/services.LogService", &userScopedLogService{base: rt.logService})
	registry.Register("codeswitch/services.AppSettingsService", rt.appSettings)
	registry.Register("codeswitch/services.MCPService", rt.mcpService)
	registry.Register("codeswitch/services.SkillService", rt.skillService)
	registry.Register("codeswitch/services.PromptService", rt.promptService)
	registry.Register("codeswitch/services.EnvCheckService", rt.envCheckService)
	registry.Register("codeswitch/services.DeepLinkService", rt.deeplinkService)
	registry.Register("codeswitch/services.SpeedTestService", rt.speedTestService)
	registry.Register("codeswitch/services.ConnectivityTestService", rt.connectivityTest)
	registry.Register("codeswitch/services.HealthCheckService", &userScopedHealthCheckService{base: rt.healthCheckService})
	registry.Register("codeswitch/services.ModelMonitorService", &userScopedModelMonitorService{base: rt.modelMonitor})
	registry.Register("codeswitch/services.ConsoleService", &userScopedConsoleService{logService: rt.logService})
	registry.Register("codeswitch/services.CustomCliService", rt.customCliService)
	registry.Register("codeswitch/services.NetworkService", rt.networkService)
	registry.Register("codeswitch/services.ProviderRelayService", &userScopedProviderRelayService{base: rt.providerRelay, poolService: rt.poolService})
	registry.Register("codeswitch/services.ProviderPoolService", &userScopedProviderPoolService{base: rt.poolService})
	registry.Register("codeswitch/services.CodexRelayKeyService", &userScopedCodexRelayKeyService{base: rt.codexRelayKeys, poolService: rt.poolService})
}

func getenvDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
