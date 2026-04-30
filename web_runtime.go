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
	blacklistService   *services.BlacklistService
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
	importService      *services.ImportService
	deeplinkService    *services.DeepLinkService
	speedTestService   *services.SpeedTestService
	connectivityTest   *services.ConnectivityTestService
	healthCheckService *services.HealthCheckService
	versionService     *VersionService
	updateService      *services.UpdateService
	geminiService      *services.GeminiService
	consoleService     *services.ConsoleService
	customCliService   *services.CustomCliService
	networkService     *services.NetworkService
	providerRelay      *services.ProviderRelayService

	blacklistStopChan chan struct{}
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
	bootstrapNetworkService := services.NewNetworkService(defaultRelayAddr, nil, nil, nil, codexRelayKeys)
	relayAddr := defaultRelayAddr
	if networkSettings, err := bootstrapNetworkService.GetNetworkSettings(); err != nil {
		log.Printf("读取网络监听设置失败（使用默认 relay 地址）: %v", err)
	} else if addr := strings.TrimSpace(networkSettings.CurrentAddress); addr != "" {
		relayAddr = addr
	}
	eventHub := services.NewEventHub()
	notificationService := services.NewNotificationService(appSettings)
	notificationService.SetEventEmitter(eventHub)
	blacklistService := services.NewBlacklistService(settingsService, notificationService)
	geminiService := services.NewGeminiService(relayAddr)
	providerRelay := services.NewProviderRelayService(providerService, geminiService, codexRelayKeys, blacklistService, notificationService, appSettings, relayAddr)
	claudeSettings := services.NewClaudeSettingsService(providerRelay.Addr(), codexRelayKeys)
	codexSettings := services.NewCodexSettingsService(providerRelay.Addr(), codexRelayKeys)
	cliConfigService := services.NewCliConfigService(providerRelay.Addr(), codexRelayKeys)
	logService := services.NewLogService()
	mcpService := services.NewMCPService()
	skillService := services.NewSkillService()
	promptService := services.NewPromptService()
	envCheckService := services.NewEnvCheckService()
	importService := services.NewImportService(providerService, mcpService)
	deeplinkService := services.NewDeepLinkService(providerService)
	speedTestService := services.NewSpeedTestService()
	connectivityTestService := services.NewConnectivityTestService(providerService, blacklistService, settingsService)
	healthCheckService := services.NewHealthCheckService(providerService, blacklistService, settingsService)
	if err := healthCheckService.Start(); err != nil {
		return nil, fmt.Errorf("初始化健康检查服务失败: %w", err)
	}
	versionService := NewVersionService()
	updateService := services.NewUpdateService(AppVersion)
	updateService.SetEventEmitter(eventHub)
	updateService.SetWebMode(true)
	consoleService := services.NewConsoleService()
	customCliService := services.NewCustomCliService(providerRelay.Addr())
	networkService := services.NewNetworkService(providerRelay.Addr(), claudeSettings, codexSettings, geminiService, codexRelayKeys)

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

	blacklistStopChan := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := blacklistService.AutoRecoverExpired(); err != nil {
					log.Printf("自动恢复黑名单失败: %v", err)
				}
			case <-blacklistStopChan:
				log.Println("黑名单定时器已停止")
				return
			}
		}
	}()

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
		blacklistService:   blacklistService,
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
		importService:      importService,
		deeplinkService:    deeplinkService,
		speedTestService:   speedTestService,
		connectivityTest:   connectivityTestService,
		healthCheckService: healthCheckService,
		versionService:     versionService,
		updateService:      updateService,
		geminiService:      geminiService,
		consoleService:     consoleService,
		customCliService:   customCliService,
		networkService:     networkService,
		providerRelay:      providerRelay,
		blacklistStopChan:  blacklistStopChan,
	}, nil
}

func (rt *appRuntime) shutdown() {
	if rt.blacklistStopChan != nil {
		close(rt.blacklistStopChan)
		rt.blacklistStopChan = nil
	}

	if rt.healthCheckService != nil {
		rt.healthCheckService.Stop()
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
	registry.Register("codeswitch/services.ProviderService", rt.providerService)
	registry.Register("codeswitch/services.SettingsService", rt.settingsService)
	registry.Register("codeswitch/services.BlacklistService", rt.blacklistService)
	registry.Register("codeswitch/services.ClaudeSettingsService", rt.claudeSettings)
	registry.Register("codeswitch/services.CodexSettingsService", rt.codexSettings)
	registry.Register("codeswitch/services.CliConfigService", rt.cliConfigService)
	registry.Register("codeswitch/services.LogService", rt.logService)
	registry.Register("codeswitch/services.AppSettingsService", rt.appSettings)
	registry.Register("codeswitch/services.MCPService", rt.mcpService)
	registry.Register("codeswitch/services.SkillService", rt.skillService)
	registry.Register("codeswitch/services.PromptService", rt.promptService)
	registry.Register("codeswitch/services.EnvCheckService", rt.envCheckService)
	registry.Register("codeswitch/services.ImportService", rt.importService)
	registry.Register("codeswitch/services.DeepLinkService", rt.deeplinkService)
	registry.Register("codeswitch/services.SpeedTestService", rt.speedTestService)
	registry.Register("codeswitch/services.ConnectivityTestService", rt.connectivityTest)
	registry.Register("codeswitch/services.HealthCheckService", rt.healthCheckService)
	registry.Register("codeswitch/services.UpdateService", rt.updateService)
	registry.Register("codeswitch/services.GeminiService", rt.geminiService)
	registry.Register("codeswitch/services.ConsoleService", rt.consoleService)
	registry.Register("codeswitch/services.CustomCliService", rt.customCliService)
	registry.Register("codeswitch/services.NetworkService", rt.networkService)
	registry.Register("codeswitch/services.ProviderRelayService", rt.providerRelay)
}

func getenvDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
