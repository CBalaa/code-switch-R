package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

const (
	networkSettingsFile = "network.json"
)

// ListenMode 监听模式
type ListenMode string

const (
	ListenModeLocalhost ListenMode = "localhost"
	ListenModeLAN       ListenMode = "lan"
	ListenModeCustom    ListenMode = "custom"
)

// NetworkSettings 网络设置
type NetworkSettings struct {
	ListenMode     ListenMode `json:"listenMode"`
	CustomAddress  string     `json:"customAddress,omitempty"`
	CurrentAddress string     `json:"currentAddress,omitempty"`
}

// NetworkService 网络配置服务
type NetworkService struct {
	mu           sync.Mutex
	settingsPath string
	relayAddr    string
}

// NewNetworkService 创建网络服务
func NewNetworkService(
	relayAddr string,
	_ *ClaudeSettingsService,
	_ *CodexSettingsService,
	_ *GeminiService,
	_ *CodexRelayKeyService,
) *NetworkService {
	home, err := getUserHomeDir()
	if err != nil {
		home = "."
	}

	return &NetworkService{
		settingsPath: filepath.Join(home, appSettingsDir, networkSettingsFile),
		relayAddr:    relayAddr,
	}
}

// defaultSettings 默认网络设置
func (ns *NetworkService) defaultSettings() NetworkSettings {
	currentAddress := RelayListenAddr(ns.relayAddr)
	listenMode := ListenModeCustom
	customAddress := currentAddress

	switch currentAddress {
	case "127.0.0.1:18100", "localhost:18100":
		listenMode = ListenModeLocalhost
		customAddress = ""
	case "0.0.0.0:18100", "[::]:18100", ":::18100":
		listenMode = ListenModeLAN
		customAddress = ""
	}

	return NetworkSettings{
		ListenMode:     listenMode,
		CustomAddress:  customAddress,
		CurrentAddress: currentAddress,
	}
}

// GetNetworkSettings 获取网络设置
func (ns *NetworkService) GetNetworkSettings() (NetworkSettings, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	settings := ns.defaultSettings()
	data, err := os.ReadFile(ns.settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return settings, nil
		}
		return settings, err
	}

	if len(data) == 0 {
		return settings, nil
	}

	if err := json.Unmarshal(data, &settings); err != nil {
		return ns.defaultSettings(), err
	}

	settings.ListenMode = normalizeListenMode(settings.ListenMode)
	settings.CurrentAddress = ns.computeListenAddress(settings)

	return settings, nil
}

// SaveNetworkSettings 保存网络设置
func (ns *NetworkService) SaveNetworkSettings(settings NetworkSettings) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	settings.ListenMode = normalizeListenMode(settings.ListenMode)
	settings.CurrentAddress = ns.computeListenAddress(settings)

	dir := filepath.Dir(ns.settingsPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	return AtomicWriteBytes(ns.settingsPath, data)
}

func normalizeListenMode(mode ListenMode) ListenMode {
	switch mode {
	case ListenModeLocalhost, ListenModeLAN, ListenModeCustom:
		return mode
	default:
		return ListenModeLocalhost
	}
}

// computeListenAddress 计算监听地址
func (ns *NetworkService) computeListenAddress(settings NetworkSettings) string {
	switch settings.ListenMode {
	case ListenModeLocalhost:
		return "127.0.0.1:18100"
	case ListenModeLAN:
		return "0.0.0.0:18100"
	case ListenModeCustom:
		if settings.CustomAddress != "" {
			return settings.CustomAddress
		}
		return "0.0.0.0:18100"
	default:
		return "127.0.0.1:18100"
	}
}
